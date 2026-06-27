use std::{
    collections::HashSet,
    env,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex as StdSyncMutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use tokio::{
    fs,
    io::AsyncReadExt,
    net::TcpListener,
    process::{Child, Command},
    sync::{Mutex, Semaphore},
    time::{Instant, timeout, timeout_at},
};
use tracing::{error, info, warn};
use webex_generic_account_bot::{
    BotConfig, CodexConfig, CodexRunner, ExecCodexRunner, FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES,
    FollowupTrigger, MessageContext, ReplyFormat, TriggerMode, WEBEX_LIST_PAGE_SIZE,
    followup_reply_marker_search_max_pages, message_matches_prefix, render_prompt, should_trigger,
    trim_to_chars, webex::build_webex_client,
};
use webex_headless_messenger::{
    ApiError, AttemptLease, AttemptStart, Error as WebexError, JsonlStateStore, Page, SidecarEvent,
    WebexClient,
    types::{CreateMessage, ListMessages, Message, Person},
};

const MAX_EVENT_BODY_BYTES: usize = 256 * 1024;
const WEBEX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_LIMIT_CHARS: usize = 6_000;
const FORWARD_MARKDOWN_LIMIT_BYTES: usize = 4_000;
const SOURCE_MARKER_SEARCH_MAX_PAGES: usize = 3;
const JENKINS_ARTIFACT_RETENTION_LIMIT: usize = 32;
const JENKINS_DIAGNOSIS_EXCERPT_LIMIT: usize = 240;
static JENKINS_ARTIFACT_ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_JENKINS_ARTIFACT_DIRS: OnceLock<StdSyncMutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, default_value = "config/example.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "webex_generic_account_bot=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Arc::new(BotConfig::load(&cli.config)?);
    if cli.check_config {
        println!("config_ok=true");
        return Ok(());
    }

    let sidecar_token = sidecar_token(&config)?;
    let webex: Arc<dyn WebexApi> = Arc::new(build_webex_client(&config.webex)?);
    let self_person_id = resolve_self_person_id(&config, webex.as_ref()).await?;
    let state_store = JsonlStateStore::load(config.state_file.clone())?;
    let app = Arc::new(BotApp {
        config: config.clone(),
        sidecar_token,
        self_person_id,
        webex,
        state: Mutex::new(state_store),
        runner: Arc::new(ExecCodexRunner),
        request_slots: Arc::new(Semaphore::new(config.server.max_concurrent_requests.max(1))),
    });

    let event_path = config.server.event_path.clone();
    let health_path = config.server.health_path.clone();
    let router = Router::new()
        .route(&event_path, post(handle_event))
        .route(&health_path, get(handle_health))
        .with_state(AppState { app: app.clone() });
    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .with_context(|| format!("invalid server.bind {}", config.server.bind))?;
    let listener = TcpListener::bind(bind).await?;
    info!(
        bind = %listener.local_addr()?,
        event_path = %event_path,
        health_path = %health_path,
        "webex generic account bot listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    app: Arc<BotApp>,
}

struct BotApp {
    config: Arc<BotConfig>,
    sidecar_token: Option<String>,
    self_person_id: Option<String>,
    webex: Arc<dyn WebexApi>,
    state: Mutex<JsonlStateStore>,
    runner: Arc<dyn CodexRunner>,
    request_slots: Arc<Semaphore>,
}

struct ReplyCreateContext<'a> {
    message_id: &'a str,
    room_id: &'a str,
    parent_id: &'a str,
    reply_marker: &'a str,
    reply_chars: usize,
}

struct ForwardCreateContext<'a> {
    message_id: &'a str,
    output_room_id: &'a str,
    source_marker: &'a str,
}

struct ReplyThread {
    room_id: String,
    parent_id: String,
}

struct FollowupRun {
    reply_thread: ReplyThread,
    source_context: MessageContext,
    thread_context: String,
}

struct CodexReplyRequest<'a> {
    message_id: &'a str,
    reply_format: ReplyFormat,
    reply_marker_search_max_pages: Option<usize>,
    reply_thread: ReplyThread,
    prompt: String,
}

enum ReplyThreadSetup {
    Ready(ReplyThread),
    Finished(BotAction),
}

struct JenkinsPrefetchedContext {
    prompt: String,
    artifact_root: PathBuf,
    console_urls: Vec<String>,
}

struct JenkinsArtifactCleanupGuard {
    artifact_root: Option<PathBuf>,
}

impl JenkinsArtifactCleanupGuard {
    fn new(artifact_root: PathBuf) -> Self {
        Self {
            artifact_root: Some(artifact_root),
        }
    }

    async fn cleanup(mut self) -> Result<()> {
        let Some(artifact_root) = self.artifact_root.take() else {
            return Ok(());
        };
        cleanup_jenkins_artifact_dir(&artifact_root).await
    }
}

impl Drop for JenkinsArtifactCleanupGuard {
    fn drop(&mut self) {
        let Some(artifact_root) = self.artifact_root.take() else {
            return;
        };
        unregister_jenkins_artifact_dir(&artifact_root);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(error) = remove_jenkins_artifact_dir(&artifact_root).await {
                    warn!(
                        artifact_root = %artifact_root.display(),
                        error = %error,
                        "failed to clean Jenkins diagnostics artifacts from drop guard"
                    );
                }
            });
        }
    }
}

#[async_trait]
trait WebexApi: Send + Sync {
    async fn me(&self) -> Result<Person, WebexCallError>;
    async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError>;
    async fn list_thread_messages(
        &self,
        room_id: &str,
        parent_id: &str,
        limit: usize,
    ) -> Result<Vec<Message>, WebexCallError>;
    async fn create_message(&self, request: &CreateMessage) -> Result<Message, WebexCallError>;
    async fn find_message_by_marker(
        &self,
        room_id: &str,
        parent_id: Option<&str>,
        marker: &str,
        self_person_id: Option<&str>,
        max_pages: Option<usize>,
    ) -> Result<Option<Message>, WebexCallError>;
}

#[async_trait]
impl WebexApi for WebexClient {
    async fn me(&self) -> Result<Person, WebexCallError> {
        match timeout(WEBEX_REQUEST_TIMEOUT, WebexClient::me(self)).await {
            Ok(Ok(person)) => Ok(person),
            Ok(Err(error)) => Err(WebexCallError::Client(error)),
            Err(_) => Err(WebexCallError::TimedOut),
        }
    }

    async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError> {
        match timeout(
            WEBEX_REQUEST_TIMEOUT,
            WebexClient::get_message(self, message_id),
        )
        .await
        {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(WebexCallError::Client(error)),
            Err(_) => Err(WebexCallError::TimedOut),
        }
    }

    async fn list_thread_messages(
        &self,
        room_id: &str,
        parent_id: &str,
        limit: usize,
    ) -> Result<Vec<Message>, WebexCallError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let request = ListMessages {
            room_id: room_id.to_owned(),
            parent_id: Some(parent_id.to_owned()),
            max: Some(limit.min(WEBEX_LIST_PAGE_SIZE) as u16),
            ..ListMessages::default()
        };
        let mut page: Page<Message> =
            match timeout(WEBEX_REQUEST_TIMEOUT, self.list_messages(&request)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) if parent_message_listing_is_empty(Some(parent_id), &error) => {
                    return Ok(Vec::new());
                }
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        let mut messages = Vec::new();
        loop {
            for message in page.items {
                if messages.len() >= limit {
                    return Ok(messages);
                }
                messages.push(message);
            }
            let Some(next) = page.next else {
                return Ok(messages);
            };
            page = match timeout(WEBEX_REQUEST_TIMEOUT, self.next_page(next)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        }
    }

    async fn create_message(&self, request: &CreateMessage) -> Result<Message, WebexCallError> {
        match timeout(
            WEBEX_REQUEST_TIMEOUT,
            WebexClient::create_message(self, request),
        )
        .await
        {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(WebexCallError::Client(error)),
            Err(_) => Err(WebexCallError::TimedOut),
        }
    }

    async fn find_message_by_marker(
        &self,
        room_id: &str,
        parent_id: Option<&str>,
        marker: &str,
        self_person_id: Option<&str>,
        max_pages: Option<usize>,
    ) -> Result<Option<Message>, WebexCallError> {
        let request = ListMessages {
            room_id: room_id.to_owned(),
            parent_id: parent_id.map(ToOwned::to_owned),
            max: Some(WEBEX_LIST_PAGE_SIZE as u16),
            ..ListMessages::default()
        };
        let mut page: Page<Message> =
            match timeout(WEBEX_REQUEST_TIMEOUT, self.list_messages(&request)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) if parent_message_listing_is_empty(parent_id, &error) => {
                    return Ok(None);
                }
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        let mut pages_read = 0usize;
        loop {
            pages_read = pages_read.saturating_add(1);
            if let Some(reply) = page
                .items
                .into_iter()
                .find(|reply| reply_matches_marker(reply, marker, self_person_id))
            {
                return Ok(Some(reply));
            }
            if max_pages.is_some_and(|limit| pages_read >= limit) {
                return Ok(None);
            }
            let Some(next) = page.next else {
                return Ok(None);
            };
            page = match timeout(WEBEX_REQUEST_TIMEOUT, self.next_page(next)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        }
    }
}

fn parent_message_listing_is_empty(parent_id: Option<&str>, error: &WebexError) -> bool {
    parent_id.is_some()
        && matches!(
            error,
            WebexError::Api(api) if api.status == StatusCode::NOT_FOUND.as_u16()
        )
}

async fn jenkins_context_prompt(
    policy: &webex_generic_account_bot::RoomPolicy,
    codex_config: &CodexConfig,
    context: &MessageContext,
) -> Result<Option<JenkinsPrefetchedContext>> {
    let Some(config) = &policy.jenkins_context else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    let urls = extract_jenkins_urls(&context.body, config.max_urls);
    if urls.is_empty() {
        return Ok(None);
    }

    ensure_jenkins_artifact_base_root(&codex_config.cwd)
        .await
        .with_context(|| "failed to prepare Jenkins diagnostics artifact root")?;
    prune_jenkins_artifact_dirs(&codex_config.cwd)
        .await
        .with_context(|| "failed to prune old Jenkins diagnostics artifact dirs")?;

    let artifact_root = jenkins_artifact_attempt_dir(&codex_config.cwd, &context.message_id);
    create_private_dir(&artifact_root).await.with_context(|| {
        format!(
            "failed to create Jenkins diagnostics artifact root {}",
            artifact_root.display()
        )
    })?;
    register_jenkins_artifact_dir(&artifact_root);

    let mut sections = Vec::new();
    let mut console_urls = Vec::new();
    let build_result: Result<String> = async {
        for (index, url) in urls.into_iter().enumerate() {
            let artifact_dir = jenkins_artifact_dir(&artifact_root, index + 1);
            reset_jenkins_artifact_dir(&artifact_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to reset Jenkins diagnostics artifact dir {}",
                        artifact_dir.display()
                    )
                })?;
            let output = run_jenkins_context_helper(config, &url, &artifact_dir).await?;
            for console_url in extract_jenkins_console_urls(&output) {
                if !console_urls.contains(&console_url) {
                    console_urls.push(console_url);
                }
            }
            sections.push(format!(
                "URL: {url}\nDiagnostics artifact directory: `{}`\n```text\n{}\n```",
                artifact_dir.display(),
                trim_to_chars(output.trim(), config.output_limit_chars)
            ));
        }

        Ok(format!(
            "Prefetched Jenkins diagnostics (read-only helper output and local artifact files; use these instead of running Jenkins commands from Codex):\n\n{}",
            sections.join("\n\n")
        ))
    }
    .await;

    match build_result {
        Ok(prompt) => Ok(Some(JenkinsPrefetchedContext {
            prompt,
            artifact_root,
            console_urls,
        })),
        Err(error) => {
            if let Err(cleanup_error) = cleanup_jenkins_artifact_dir(&artifact_root).await {
                warn!(
                    artifact_root = %artifact_root.display(),
                    error = %cleanup_error,
                    "failed to clean Jenkins diagnostics artifacts after prefetch failure"
                );
            }
            Err(error)
        }
    }
}

async fn reset_jenkins_artifact_dir(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to remove existing Jenkins artifact dir {}",
                    path.display()
                )
            });
        }
    }
    create_private_dir(path).await.with_context(|| {
        format!(
            "failed to create Jenkins diagnostics artifact dir {}",
            path.display()
        )
    })?;
    Ok(())
}

async fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    set_private_dir_permissions(path).await
}

async fn set_private_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| format!("failed to chmod 0700 {}", path.display()))?;
    }
    Ok(())
}

async fn cleanup_jenkins_artifact_dir(path: &Path) -> Result<()> {
    let result = remove_jenkins_artifact_dir(path).await;
    unregister_jenkins_artifact_dir(path);
    result
}

async fn remove_jenkins_artifact_dir(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove Jenkins diagnostics artifact dir {}",
                path.display()
            )
        }),
    }
}

async fn run_jenkins_context_helper(
    config: &webex_generic_account_bot::JenkinsContextConfig,
    url: &str,
    artifact_dir: &Path,
) -> Result<String> {
    const SERVICE_MAX_JENKINS_NODES: &str = "32";
    const SERVICE_MAX_TOTAL_LOG_BYTES: &str = "104857600";
    const SERVICE_MAX_LOG_BYTES_PER_NODE: &str = "10485760";
    const SERVICE_MAX_API_RESPONSE_BYTES: &str = "1048576";
    const SERVICE_FETCH_RETRIES: &str = "3";
    const SERVICE_MAX_PARALLEL_FETCHES: &str = "4";

    let mut command = Command::new(&config.node_bin);
    let script_dir = config.script.parent().unwrap_or_else(|| Path::new("/"));
    configure_jenkins_helper_process(&mut command);
    apply_jenkins_helper_env(&mut command);
    command
        .arg(&config.script)
        .arg("--env-file")
        .arg(&config.env_file)
        .arg("--artifact-dir")
        .arg(artifact_dir)
        .arg("diagnose")
        .arg("--url")
        .arg(url)
        .arg("--max-nodes")
        .arg(SERVICE_MAX_JENKINS_NODES)
        .arg("--max-total-log-bytes")
        .arg(SERVICE_MAX_TOTAL_LOG_BYTES)
        .arg("--max-log-bytes-per-node")
        .arg(SERVICE_MAX_LOG_BYTES_PER_NODE)
        .arg("--max-api-response-bytes")
        .arg(SERVICE_MAX_API_RESPONSE_BYTES)
        .arg("--max-fetch-seconds")
        .arg(config.timeout_secs.max(1).to_string())
        .arg("--fetch-retries")
        .arg(SERVICE_FETCH_RETRIES)
        .arg("--max-parallel-fetches")
        .arg(SERVICE_MAX_PARALLEL_FETCHES)
        .current_dir(script_dir)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to spawn Jenkins diagnostics helper {}",
            config.node_bin
        )
    })?;
    #[cfg(unix)]
    let process_group = child.id().map(|pid| -(pid as i32));
    let capture_limit = helper_capture_limit_bytes(config.output_limit_chars);
    let stdout_task = read_limited_pipe(child.stdout.take(), capture_limit);
    let stderr_task = read_limited_pipe(child.stderr.take(), capture_limit);
    let deadline = Instant::now() + config.timeout();
    let status = match timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            terminate_jenkins_helper(&mut child).await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(error).context("failed to run Jenkins diagnostics helper");
        }
        Err(_) => {
            terminate_jenkins_helper(&mut child).await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(anyhow!(
                "Jenkins diagnostics helper timed out after {} seconds",
                config.timeout_secs
            ));
        }
    };
    #[cfg(unix)]
    terminate_jenkins_helper_process_group(process_group, SIGTERM);
    let (stdout, stderr) =
        match timeout_at(deadline, join_helper_output(stdout_task, stderr_task)).await {
            Ok(output) => output?,
            Err(_) => {
                #[cfg(unix)]
                terminate_jenkins_helper_process_group(process_group, SIGKILL);
                return Err(anyhow!(
                    "Jenkins diagnostics helper timed out after {} seconds",
                    config.timeout_secs
                ));
            }
        };

    if status.success() {
        return Ok(compact_jenkins_helper_output(&stdout));
    }

    Ok(format!(
        "helper_exit_status={}\nstdout:\n{}\nstderr:\n{}",
        status,
        compact_jenkins_helper_output(&stdout),
        stderr
    ))
}

async fn prune_jenkins_artifact_dirs(codex_cwd: &Path) -> Result<()> {
    prune_jenkins_artifact_process_roots_in(
        &jenkins_artifact_base_root(codex_cwd),
        &jenkins_artifact_process_root(codex_cwd),
    )
    .await
}

async fn prune_jenkins_artifact_process_roots_in(
    base_root: &Path,
    current_process_root: &Path,
) -> Result<()> {
    let mut entries = match fs::read_dir(base_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", base_root.display()));
        }
    };

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", path.display()));
            }
        };
        if !metadata.is_dir() {
            continue;
        }

        if path == current_process_root {
            prune_jenkins_artifact_dirs_in(&path).await?;
            continue;
        }

        let Some(pid) = jenkins_artifact_process_root_pid(&path) else {
            continue;
        };
        if process_may_be_running(pid) {
            continue;
        }

        match fs::remove_dir_all(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to remove stale Jenkins process artifact root {}",
                        path.display()
                    )
                });
            }
        }
    }

    Ok(())
}

async fn prune_jenkins_artifact_dirs_in(root: &Path) -> Result<()> {
    let active_dirs = active_jenkins_artifact_dirs()
        .lock()
        .expect("active Jenkins artifact dirs mutex poisoned")
        .clone();
    let mut entries = match fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", root.display()));
        }
    };
    let mut dirs = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if active_dirs.contains(&path) {
            continue;
        }
        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", path.display()));
            }
        };
        if metadata.is_dir() {
            dirs.push((
                metadata.modified().unwrap_or(UNIX_EPOCH),
                entry.file_name(),
                path,
            ));
        }
    }
    if dirs.len() <= JENKINS_ARTIFACT_RETENTION_LIMIT {
        return Ok(());
    }
    dirs.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    for (_, _, path) in dirs.into_iter().skip(JENKINS_ARTIFACT_RETENTION_LIMIT) {
        match fs::remove_dir_all(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to remove old Jenkins artifact dir {}",
                        path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

async fn ensure_jenkins_artifact_base_root(codex_cwd: &Path) -> Result<PathBuf> {
    let codex_tmp_root = absolute_lexical(codex_cwd).join(".codex-tmp");
    let base_root = jenkins_artifact_base_root(codex_cwd);
    let process_root = jenkins_artifact_process_root(codex_cwd);
    create_private_dir(&codex_tmp_root).await?;
    create_private_dir(&base_root).await?;
    create_private_dir(&process_root).await?;
    Ok(process_root)
}

fn jenkins_artifact_base_root(codex_cwd: &Path) -> PathBuf {
    absolute_lexical(codex_cwd)
        .join(".codex-tmp")
        .join("jenkins-diagnostics")
}

fn jenkins_artifact_process_root(codex_cwd: &Path) -> PathBuf {
    jenkins_artifact_base_root(codex_cwd).join(format!("process-{}", std::process::id()))
}

fn jenkins_artifact_process_root_pid(path: &Path) -> Option<u32> {
    path.file_name()?
        .to_str()?
        .strip_prefix("process-")?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn process_may_be_running(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_may_be_running(pid: u32) -> bool {
    pid == std::process::id()
}

fn absolute_lexical(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return normalize_lexical(path);
    }
    let base = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    normalize_lexical(&base.join(path))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

fn jenkins_artifact_attempt_dir(codex_cwd: &Path, message_id: &str) -> PathBuf {
    let counter = JENKINS_ARTIFACT_ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    jenkins_artifact_process_root(codex_cwd).join(format!(
        "{}-{nanos}-{counter}-{}",
        std::process::id(),
        safe_path_fragment(message_id)
    ))
}

fn jenkins_artifact_dir(attempt_root: &Path, index: usize) -> PathBuf {
    attempt_root.join(format!("url-{index}"))
}

fn active_jenkins_artifact_dirs() -> &'static StdSyncMutex<HashSet<PathBuf>> {
    ACTIVE_JENKINS_ARTIFACT_DIRS.get_or_init(|| StdSyncMutex::new(HashSet::new()))
}

fn register_jenkins_artifact_dir(path: &Path) {
    active_jenkins_artifact_dirs()
        .lock()
        .expect("active Jenkins artifact dirs mutex poisoned")
        .insert(path.to_path_buf());
}

fn unregister_jenkins_artifact_dir(path: &Path) {
    active_jenkins_artifact_dirs()
        .lock()
        .expect("active Jenkins artifact dirs mutex poisoned")
        .remove(path);
}

fn safe_path_fragment(value: &str) -> String {
    let fragment: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let fragment = fragment.trim_matches('_');
    if fragment.is_empty() {
        "unknown".to_owned()
    } else {
        fragment.chars().take(160).collect()
    }
}

async fn join_helper_output(
    stdout_task: tokio::task::JoinHandle<Result<String>>,
    stderr_task: tokio::task::JoinHandle<Result<String>>,
) -> Result<(String, String)> {
    let stdout = stdout_task
        .await
        .context("failed to join Jenkins stdout reader")??;
    let stderr = stderr_task
        .await
        .context("failed to join Jenkins stderr reader")??;
    Ok((stdout, stderr))
}

fn apply_jenkins_helper_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in webex_generic_account_bot::runner::scrubbed_env() {
        command.env(key, value);
    }
}

fn configure_jenkins_helper_process(command: &mut Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
        unsafe {
            command.pre_exec(|| {
                umask(0o077);
                Ok(())
            });
        }
    }
}

async fn terminate_jenkins_helper(child: &mut Child) {
    #[cfg(unix)]
    {
        terminate_jenkins_helper_group(child).await;
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(unix)]
async fn terminate_jenkins_helper_group(child: &mut Child) {
    if let Some(pid) = child.id() {
        let process_group = -(pid as i32);
        terminate_jenkins_helper_process_group(Some(process_group), SIGTERM);
        if timeout(Duration::from_millis(250), child.wait())
            .await
            .is_ok()
        {
            return;
        }
        terminate_jenkins_helper_process_group(Some(process_group), SIGKILL);
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
fn terminate_jenkins_helper_process_group(process_group: Option<i32>, signal: i32) {
    if let Some(process_group) = process_group {
        unsafe {
            kill(process_group, signal);
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn umask(mask: u32) -> u32;
}

fn read_limited_pipe<R>(
    pipe: Option<R>,
    max_bytes: usize,
) -> tokio::task::JoinHandle<Result<String>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let Some(mut pipe) = pipe else {
            return Ok(String::new());
        };
        read_limited(&mut pipe, max_bytes).await
    })
}

async fn read_limited<R>(reader: &mut R, max_bytes: usize) -> Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(kept.len());
        if remaining == 0 {
            truncated = true;
            continue;
        }
        let to_keep = read.min(remaining);
        kept.extend_from_slice(&buffer[..to_keep]);
        if to_keep < read {
            truncated = true;
        }
    }
    let mut value = String::from_utf8_lossy(&kept).to_string();
    if truncated {
        value.push_str("\n[truncated]");
    }
    Ok(value)
}

fn helper_capture_limit_bytes(output_limit_chars: usize) -> usize {
    output_limit_chars
        .max(1)
        .saturating_mul(4)
        .saturating_add(1024)
        .max(256 * 1024)
}

fn compact_jenkins_helper_output(output: &str) -> String {
    let mut lines = Vec::new();
    for line in output.lines() {
        if line.trim() == "console_tail:" {
            break;
        }
        lines.push(line);
    }
    let compacted = lines.join("\n").trim().to_owned();
    if compacted.is_empty() {
        output.trim().to_owned()
    } else {
        compacted
    }
}

fn extract_jenkins_urls(body: &str, max_urls: usize) -> Vec<String> {
    let mut urls = Vec::new();
    for token in body.split(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'')) {
        let trimmed = token.trim_matches(|ch: char| matches!(ch, '(' | ')' | '[' | ']'));
        let Some(rest) = trimmed.strip_prefix("https://engci-private-sjc.cisco.com/") else {
            continue;
        };
        let url = format!(
            "https://engci-private-sjc.cisco.com/{}",
            rest.trim_end_matches([')', ']', '.', ',', ';', ':'])
        );
        if !urls.contains(&url) {
            urls.push(url);
        }
        if urls.len() >= max_urls {
            break;
        }
    }
    urls
}

fn append_prefetched_context(prompt: &str, context: &str) -> String {
    format!("{prompt}\n\n{context}")
}

impl BotApp {
    async fn process_event(&self, event: SidecarEvent) -> Result<BotAction, HttpError> {
        if event.version != 1 {
            return Ok(BotAction::ignored("unsupported_event_version", None, None));
        }
        if event.resource != "messages" || event.event != "created" {
            return Ok(BotAction::ignored(
                "unsupported_event",
                Some(event.resource),
                None,
            ));
        }

        let mut message: Message = serde_json::from_value(event.data)
            .map_err(|error| HttpError::bad_request(format!("invalid message payload: {error}")))?;
        let Some(message_id) = message.id.clone() else {
            return Ok(BotAction::ignored("missing_message_id", None, None));
        };
        let attempt = match self.begin_attempt(&message_id).await? {
            AttemptStart::Started(attempt) => attempt,
            AttemptStart::Processed => {
                return Ok(BotAction::ignored(
                    "duplicate_message",
                    Some(message_id),
                    message.room_id.clone(),
                ));
            }
            AttemptStart::Leased(retry_after) => {
                return Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("message {message_id} already has an active attempt lease"),
                    retry_after,
                ));
            }
        };

        if message.room_id.is_none() {
            match self.get_message(&message_id).await {
                Ok(hydrated) => merge_message(&mut message, hydrated),
                Err(error) => {
                    return self
                        .handle_get_message_failure(&attempt, &message_id, &message, error)
                        .await;
                }
            }
        }

        let Some(room_id) = message.room_id.clone() else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "missing_room_id",
                Some(message_id),
                None,
            ));
        };
        let direct_policy = self.config.policy_for_room(&room_id);
        let followup_policies = self.config.followup_policies_for_event_room(&room_id);
        if direct_policy.is_none() && followup_policies.is_empty() {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "no_room_policy",
                Some(message_id),
                Some(room_id),
            ));
        };
        if event_message_needs_hydration(direct_policy, &followup_policies, &message) {
            match self.get_message(&message_id).await {
                Ok(hydrated) => merge_message(&mut message, hydrated),
                Err(error) => {
                    return self
                        .handle_get_message_failure(&attempt, &message_id, &message, error)
                        .await;
                }
            }
        }
        if self
            .self_person_id
            .as_deref()
            .is_some_and(|self_id| message.person_id.as_deref() == Some(self_id))
        {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "self_message",
                Some(message_id),
                Some(room_id),
            ));
        }

        for policy in followup_policies {
            let followup_run = match self
                .resolve_followup(policy, &message, &message_id, &room_id)
                .await
            {
                Ok(Some(run)) => run,
                Ok(None) => continue,
                Err(error) => {
                    return self
                        .handle_reconciliation_failure(&attempt, &message_id, error)
                        .await;
                }
            };
            let Some(context) = MessageContext::from_message(&message) else {
                self.mark_processed(&attempt).await?;
                return Ok(BotAction::ignored(
                    "incomplete_message_context",
                    Some(message_id),
                    Some(room_id),
                ));
            };
            let prompt = render_followup_prompt(
                &policy.followup.prompt_template,
                &context,
                &followup_run.source_context,
                &followup_run.thread_context,
            );
            return self
                .run_codex_reply(
                    &attempt,
                    policy,
                    CodexReplyRequest {
                        message_id: &message_id,
                        reply_format: policy.followup.reply_format.unwrap_or(policy.reply_format),
                        reply_marker_search_max_pages: Some(
                            followup_reply_marker_search_max_pages(
                                policy.followup.max_thread_messages,
                            ),
                        ),
                        reply_thread: followup_run.reply_thread,
                        prompt,
                    },
                    Some(&followup_run.source_context),
                )
                .await;
        }

        if message.parent_id.is_some() && self.config.room_is_read_only_source(&room_id) {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "not_followup",
                Some(message_id),
                Some(room_id),
            ));
        }

        let Some(policy) = direct_policy else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "not_followup",
                Some(message_id),
                Some(room_id),
            ));
        };

        let trigger = should_trigger(policy, &message, self.self_person_id.as_deref());
        if !matches!(trigger, webex_generic_account_bot::TriggerDecision::Matched) {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                trigger_reason(&trigger),
                Some(message_id),
                Some(room_id),
            ));
        }

        let parent_id = message
            .parent_id
            .clone()
            .unwrap_or_else(|| message_id.clone());
        let reply_thread = match self
            .prepare_reply_thread(
                policy,
                &message,
                &message_id,
                &room_id,
                &parent_id,
                &attempt,
            )
            .await?
        {
            ReplyThreadSetup::Ready(reply_thread) => reply_thread,
            ReplyThreadSetup::Finished(action) => return Ok(action),
        };

        let Some(context) = MessageContext::from_message(&message) else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "incomplete_message_context",
                Some(message_id),
                Some(room_id),
            ));
        };
        let prompt = render_prompt(&policy.prompt_template, &context);
        self.run_codex_reply(
            &attempt,
            policy,
            CodexReplyRequest {
                message_id: &message_id,
                reply_format: policy.reply_format,
                reply_marker_search_max_pages: None,
                reply_thread,
                prompt,
            },
            Some(&context),
        )
        .await
    }

    async fn run_codex_reply(
        &self,
        attempt: &AttemptLease,
        policy: &webex_generic_account_bot::RoomPolicy,
        mut request: CodexReplyRequest<'_>,
        jenkins_context: Option<&MessageContext>,
    ) -> Result<BotAction, HttpError> {
        let message_id = request.message_id;
        let reply_marker_search_max_pages = request.reply_marker_search_max_pages;
        let reply_thread = request.reply_thread;
        let reply_marker = reply_marker(message_id);
        match self
            .find_existing_message_by_marker(
                &reply_thread.room_id,
                Some(&reply_thread.parent_id),
                &reply_marker,
                reply_marker_search_max_pages,
            )
            .await
        {
            Ok(Some(reply)) => {
                let reply_chars = existing_reply_chars(&reply);
                self.mark_processed(attempt).await?;
                return Ok(BotAction::replied(
                    message_id.to_owned(),
                    reply_thread.room_id,
                    reply.id,
                    reply_chars,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return self
                    .handle_reconciliation_failure(attempt, message_id, error)
                    .await;
            }
        }

        let codex_config = self.config.codex_for_policy(policy);
        let mut prefetched_console_urls = Vec::new();
        let mut jenkins_artifact_cleanup = None;
        if let Some(jenkins_context) = jenkins_context {
            match jenkins_context_prompt(policy, &codex_config, jenkins_context).await {
                Ok(Some(context_bundle)) => {
                    let JenkinsPrefetchedContext {
                        prompt,
                        artifact_root,
                        console_urls,
                    } = context_bundle;
                    request.prompt = append_prefetched_context(&request.prompt, &prompt);
                    prefetched_console_urls = console_urls;
                    jenkins_artifact_cleanup =
                        Some(JenkinsArtifactCleanupGuard::new(artifact_root));
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(message_id = %message_id, error = %error, "failed to prefetch Jenkins diagnostics");
                    request.prompt = append_prefetched_context(
                        &request.prompt,
                        &format!("Jenkins diagnostics helper failed before Codex run: {error}"),
                    );
                }
            }
        }
        let run_result = self
            .runner
            .run(&codex_config, &request.prompt, message_id)
            .await;
        if let Some(cleanup_guard) = jenkins_artifact_cleanup {
            if let Err(error) = cleanup_guard.cleanup().await {
                warn!(
                    message_id = %message_id,
                    error = %error,
                    "failed to clean Jenkins diagnostics artifacts after Codex run"
                );
            }
        }
        let reply_text = match run_result {
            Ok(output) => render_reply_text_with_allowed_urls(
                request.reply_format,
                &output.final_message,
                &prefetched_console_urls,
            ),
            Err(error) => {
                warn!(message_id = %message_id, error = %error, "codex run failed");
                "Codex run failed. Check the bot service logs for details.".to_owned()
            }
        };
        let reply_markdown = prepare_reply_markdown(&reply_text, &reply_marker);
        let reply_request = reply_markdown_message(
            &reply_thread.room_id,
            &reply_thread.parent_id,
            &reply_markdown,
        );
        let reply = match self.create_message(&reply_request).await {
            Ok(reply) => reply,
            Err(error) => {
                return self
                    .handle_create_message_failure(
                        attempt,
                        ReplyCreateContext {
                            message_id,
                            room_id: &reply_thread.room_id,
                            parent_id: reply_request.parent_id.as_deref().unwrap_or(message_id),
                            reply_marker: &reply_marker,
                            reply_chars: reply_markdown.len(),
                        },
                        error,
                    )
                    .await;
            }
        };
        let action = BotAction::replied(
            message_id.to_owned(),
            reply_thread.room_id,
            reply.id,
            reply_markdown.len(),
        );
        if let Err(error) = self.mark_processed(attempt).await {
            error!(
                error = %error.message,
                "failed to mark message processed after Webex accepted reply"
            );
        }
        Ok(action)
    }

    async fn resolve_followup(
        &self,
        policy: &webex_generic_account_bot::RoomPolicy,
        message: &Message,
        message_id: &str,
        event_room_id: &str,
    ) -> Result<Option<FollowupRun>, WebexCallError> {
        if !followup_candidate_matches(policy, message, self.self_person_id.as_deref()) {
            return Ok(None);
        }
        let Some(parent_id) = message.parent_id.as_deref() else {
            return Ok(None);
        };

        let root_message = match self.webex.get_message(parent_id).await {
            Ok(message) => message,
            Err(error) if webex_call_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let thread_fetch_limit = policy
            .followup
            .max_thread_messages
            .max(FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES);
        let mut thread_messages = self
            .webex
            .list_thread_messages(event_room_id, parent_id, thread_fetch_limit)
            .await?;
        if !thread_messages
            .iter()
            .any(|thread_message| thread_message.id.as_deref() == Some(message_id))
        {
            thread_messages.push(message.clone());
        }
        let thread_context_messages = thread_messages
            .iter()
            .take(policy.followup.max_thread_messages)
            .cloned()
            .collect::<Vec<_>>();

        let source_message_id = if event_room_id == policy.room_id
            && policy.read_only_source
            && policy.output_room_id.is_some()
        {
            parent_id.to_owned()
        } else {
            let Some(source_message_id) = followup_source_message_id(
                &root_message,
                &thread_messages,
                message,
                self.self_person_id.as_deref(),
            ) else {
                return Ok(None);
            };
            source_message_id
        };
        let source_message = if root_message.id.as_deref() == Some(source_message_id.as_str()) {
            root_message.clone()
        } else {
            match self.webex.get_message(&source_message_id).await {
                Ok(message) => message,
                Err(error) if webex_call_is_not_found(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
        };
        let Some(source_context) = MessageContext::from_message(&source_message) else {
            return Ok(None);
        };
        if source_context.room_id != policy.room_id {
            return Ok(None);
        }

        let reply_thread = if event_room_id == policy.room_id && policy.read_only_source {
            let Some(output_room_id) = policy.output_room_id.as_deref() else {
                return Ok(None);
            };
            let source_marker = source_marker(&source_context.message_id);
            let forward = self
                .find_existing_message_by_marker(
                    output_room_id,
                    None,
                    &source_marker,
                    source_marker_search_max_pages(
                        &source_message,
                        self.config.server.attempt_lease(),
                    ),
                )
                .await?;
            let Some(parent_id) = forward.and_then(|message| message.id) else {
                return Ok(None);
            };
            ReplyThread {
                room_id: output_room_id.to_owned(),
                parent_id,
            }
        } else {
            ReplyThread {
                room_id: event_room_id.to_owned(),
                parent_id: parent_id.to_owned(),
            }
        };

        let thread_context = render_thread_context(
            &root_message,
            &thread_context_messages,
            message_id,
            self.self_person_id.as_deref(),
            policy.followup.max_thread_context_chars,
        );
        Ok(Some(FollowupRun {
            reply_thread,
            source_context,
            thread_context,
        }))
    }

    async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError> {
        self.webex.get_message(message_id).await
    }

    async fn create_message(&self, request: &CreateMessage) -> Result<Message, WebexCallError> {
        if let Some(room_id) = request.room_id.as_deref() {
            if self.config.room_is_read_only_source(room_id) {
                return Err(WebexCallError::WriteBlocked(room_id.to_owned()));
            }
        }
        self.webex.create_message(request).await
    }

    async fn find_existing_message_by_marker(
        &self,
        room_id: &str,
        parent_id: Option<&str>,
        marker: &str,
        max_pages: Option<usize>,
    ) -> Result<Option<Message>, WebexCallError> {
        self.webex
            .find_message_by_marker(
                room_id,
                parent_id,
                marker,
                self.self_person_id.as_deref(),
                max_pages,
            )
            .await
    }

    async fn prepare_reply_thread(
        &self,
        policy: &webex_generic_account_bot::RoomPolicy,
        message: &Message,
        message_id: &str,
        source_room_id: &str,
        source_parent_id: &str,
        attempt: &AttemptLease,
    ) -> Result<ReplyThreadSetup, HttpError> {
        let Some(output_room_id) = policy.output_room_id.as_deref() else {
            return Ok(ReplyThreadSetup::Ready(ReplyThread {
                room_id: source_room_id.to_owned(),
                parent_id: source_parent_id.to_owned(),
            }));
        };

        let source_marker = source_marker(message_id);
        match self
            .find_existing_message_by_marker(
                output_room_id,
                None,
                &source_marker,
                source_marker_search_max_pages(message, self.config.server.attempt_lease()),
            )
            .await
        {
            Ok(Some(forward)) => {
                if let Some(parent_id) = forward.id {
                    return Ok(ReplyThreadSetup::Ready(ReplyThread {
                        room_id: output_room_id.to_owned(),
                        parent_id,
                    }));
                }
            }
            Ok(None) => {}
            Err(error) => {
                return self
                    .handle_forward_reconciliation_failure(
                        attempt,
                        message_id,
                        output_room_id,
                        error,
                    )
                    .await;
            }
        }

        let forward_markdown =
            prepare_forward_markdown(message, source_room_id, message_id, &source_marker);
        let forward_request = top_level_markdown_message(output_room_id, &forward_markdown);
        match self.create_message(&forward_request).await {
            Ok(forward) => match forward.id {
                Some(parent_id) => Ok(ReplyThreadSetup::Ready(ReplyThread {
                    room_id: output_room_id.to_owned(),
                    parent_id,
                })),
                None => {
                    self.defer_attempt(attempt, self.config.server.attempt_lease())
                        .await?;
                    Err(HttpError::retry_after(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("forwarded Webex source message {message_id} had no message id"),
                        self.config.server.attempt_lease(),
                    ))
                }
            },
            Err(error) => {
                self.handle_forward_create_failure(
                    attempt,
                    ForwardCreateContext {
                        message_id,
                        output_room_id,
                        source_marker: &source_marker,
                    },
                    error,
                )
                .await
            }
        }
    }

    async fn handle_get_message_failure(
        &self,
        attempt: &AttemptLease,
        message_id: &str,
        message: &Message,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "message_unavailable",
                    Some(message_id.to_owned()),
                    message.room_id.clone(),
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("failed to hydrate message {message_id}: {error}"),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_reconciliation_failure(
        &self,
        attempt: &AttemptLease,
        message_id: &str,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                warn!(message_id = %message_id, error = %error, "failed to reconcile existing Webex reply before Codex run");
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "reply_reconciliation_failed",
                    Some(message_id.to_owned()),
                    None,
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "failed to reconcile existing Webex reply for message {message_id}: {error}"
                    ),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_forward_reconciliation_failure(
        &self,
        attempt: &AttemptLease,
        message_id: &str,
        output_room_id: &str,
        error: WebexCallError,
    ) -> Result<ReplyThreadSetup, HttpError> {
        match classify_webex_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                warn!(message_id = %message_id, output_room_id = %output_room_id, error = %error, "failed to reconcile forwarded source message before Codex run");
                self.mark_processed(attempt).await?;
                Ok(ReplyThreadSetup::Finished(BotAction::ignored(
                    "source_forward_reconciliation_failed",
                    Some(message_id.to_owned()),
                    Some(output_room_id.to_owned()),
                )))
            }
            WebexFailureAction::Retry(retry_after) => {
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("failed to reconcile forwarded source message {message_id}: {error}"),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_forward_create_failure(
        &self,
        attempt: &AttemptLease,
        context: ForwardCreateContext<'_>,
        error: WebexCallError,
    ) -> Result<ReplyThreadSetup, HttpError> {
        match classify_webex_create_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                self.mark_processed(attempt).await?;
                Ok(ReplyThreadSetup::Finished(BotAction::ignored(
                    "source_forward_rejected",
                    Some(context.message_id.to_owned()),
                    Some(context.output_room_id.to_owned()),
                )))
            }
            WebexFailureAction::Retry(retry_after) => {
                match self
                    .find_existing_message_by_marker(
                        context.output_room_id,
                        None,
                        context.source_marker,
                        None,
                    )
                    .await
                {
                    Ok(Some(forward)) => {
                        if let Some(parent_id) = forward.id {
                            return Ok(ReplyThreadSetup::Ready(ReplyThread {
                                room_id: context.output_room_id.to_owned(),
                                parent_id,
                            }));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(message_id = %context.message_id, output_room_id = %context.output_room_id, error = %error, "failed to reconcile forwarded source message after create failure");
                    }
                }
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "failed to forward Webex source message {}: {error}",
                        context.message_id
                    ),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_create_message_failure(
        &self,
        attempt: &AttemptLease,
        context: ReplyCreateContext<'_>,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_create_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "reply_rejected",
                    Some(context.message_id.to_owned()),
                    Some(context.room_id.to_owned()),
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                match self
                    .find_existing_message_by_marker(
                        context.room_id,
                        Some(context.parent_id),
                        context.reply_marker,
                        None,
                    )
                    .await
                {
                    Ok(Some(reply)) => {
                        self.mark_processed(attempt).await?;
                        return Ok(BotAction::replied(
                            context.message_id.to_owned(),
                            context.room_id.to_owned(),
                            reply.id,
                            context.reply_chars,
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(message_id = %context.message_id, error = %error, "failed to reconcile existing Webex reply after create failure");
                    }
                }
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "failed to send Webex reply for message {}: {error}",
                        context.message_id
                    ),
                    retry_after,
                ))
            }
        }
    }

    async fn begin_attempt(&self, message_id: &str) -> Result<AttemptStart, HttpError> {
        let mut state = self.state.lock().await;
        state
            .begin_attempt(message_id, self.config.server.attempt_lease())
            .map_err(HttpError::state_error)
    }

    async fn mark_processed(&self, attempt: &AttemptLease) -> Result<(), HttpError> {
        let mut state = self.state.lock().await;
        state
            .mark_processed(attempt)
            .map_err(HttpError::state_error)
    }

    async fn defer_attempt(
        &self,
        attempt: &AttemptLease,
        lease: Duration,
    ) -> Result<(), HttpError> {
        let mut state = self.state.lock().await;
        state
            .defer_attempt(attempt, lease)
            .map_err(HttpError::state_error)
    }
}

async fn handle_event(State(state): State<AppState>, request: Request<Body>) -> Response {
    if let Err(error) = authorize(&state.app, request.headers()) {
        return error.into_response();
    }
    let _permit = match state.app.request_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return HttpError::retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "server busy",
                Duration::from_secs(5),
            )
            .into_response();
        }
    };
    let body = match to_bytes(request.into_body(), MAX_EVENT_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return HttpError::bad_request(format!("failed to read sidecar event body: {error}"))
                .into_response();
        }
    };
    let event = match serde_json::from_slice::<SidecarEvent>(&body) {
        Ok(event) => event,
        Err(error) => {
            return HttpError::bad_request(format!("invalid sidecar event payload: {error}"))
                .into_response();
        }
    };
    match state.app.process_event(event).await {
        Ok(action) => {
            let status = if action.action == "replied" {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (status, Json(json!({ "ok": true, "action": action }))).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn handle_health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize(&state.app, &headers) {
        return error.into_response();
    }
    let state_path = {
        let store = state.app.state.lock().await;
        store.path().display().to_string()
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "rooms": state.app.config.rooms.len(),
            "selfPersonIdKnown": state.app.self_person_id.is_some(),
            "stateFile": state_path,
        })),
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BotAction {
    action: &'static str,
    reason: Option<String>,
    message_id: Option<String>,
    room_id: Option<String>,
    reply_id: Option<String>,
    reply_chars: Option<usize>,
}

impl BotAction {
    fn ignored(
        reason: impl Into<String>,
        message_id: Option<String>,
        room_id: Option<String>,
    ) -> Self {
        Self {
            action: "ignored",
            reason: Some(reason.into()),
            message_id,
            room_id,
            reply_id: None,
            reply_chars: None,
        }
    }

    fn replied(
        message_id: String,
        room_id: String,
        reply_id: Option<String>,
        reply_chars: usize,
    ) -> Self {
        Self {
            action: "replied",
            reason: None,
            message_id: Some(message_id),
            room_id: Some(room_id),
            reply_id,
            reply_chars: Some(reply_chars),
        }
    }
}

#[derive(Debug)]
enum WebexCallError {
    Client(WebexError),
    TimedOut,
    WriteBlocked(String),
}

impl std::fmt::Display for WebexCallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(error) => write!(formatter, "{error}"),
            Self::TimedOut => write!(formatter, "request timed out after 30 seconds"),
            Self::WriteBlocked(room_id) => {
                write!(
                    formatter,
                    "write blocked for read-only source room {room_id}"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebexFailureAction {
    Stop,
    Retry(Duration),
}

fn classify_webex_failure(error: &WebexCallError, default_retry: Duration) -> WebexFailureAction {
    match error {
        WebexCallError::TimedOut => WebexFailureAction::Retry(default_retry),
        WebexCallError::Client(WebexError::Api(api)) => {
            classify_webex_api_error(api, default_retry)
        }
        WebexCallError::Client(_) => WebexFailureAction::Retry(default_retry),
        WebexCallError::WriteBlocked(_) => WebexFailureAction::Stop,
    }
}

fn classify_webex_api_error(api: &ApiError, default_retry: Duration) -> WebexFailureAction {
    if api.status == 429 {
        return WebexFailureAction::Retry(api.retry_after.unwrap_or(default_retry));
    }
    if matches!(api.status, 400 | 403 | 404 | 410 | 422) {
        return WebexFailureAction::Stop;
    }
    WebexFailureAction::Retry(api.retry_after.unwrap_or(default_retry))
}

fn webex_call_is_not_found(error: &WebexCallError) -> bool {
    matches!(
        error,
        WebexCallError::Client(WebexError::Api(api))
            if api.status == StatusCode::NOT_FOUND.as_u16()
    )
}

fn classify_webex_create_failure(
    error: &WebexCallError,
    default_retry: Duration,
) -> WebexFailureAction {
    classify_webex_failure(error, default_retry)
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
    retry_after: Option<Duration>,
}

impl HttpError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            retry_after: None,
        }
    }

    fn retry_after(status: StatusCode, message: impl Into<String>, retry_after: Duration) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
        }
    }

    fn state_error(error: webex_headless_messenger::Error) -> Self {
        Self::retry_after(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("state store error: {error}"),
            Duration::from_secs(30),
        )
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "ok": false,
            "error": self.message,
        }));
        let mut response = (self.status, body).into_response();
        if let Some(retry_after) = self.retry_after {
            if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

fn trigger_reason(trigger: &webex_generic_account_bot::TriggerDecision) -> &'static str {
    match trigger {
        webex_generic_account_bot::TriggerDecision::Matched => "matched",
        webex_generic_account_bot::TriggerDecision::RoomDisabled => "room_disabled",
        webex_generic_account_bot::TriggerDecision::SenderNotAllowed => "sender_not_allowed",
        webex_generic_account_bot::TriggerDecision::MissingSelfPersonId => "missing_self_person_id",
        webex_generic_account_bot::TriggerDecision::NotMentioned => "not_mentioned",
        webex_generic_account_bot::TriggerDecision::PrefixNotMatched => "prefix_not_matched",
    }
}

fn authorize(app: &BotApp, headers: &HeaderMap) -> Result<(), HttpError> {
    let Some(token) = &app.sidecar_token else {
        return Ok(());
    };
    let expected = format!("Bearer {token}");
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected);
    if authorized {
        Ok(())
    } else {
        Err(HttpError {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_owned(),
            retry_after: None,
        })
    }
}

fn sidecar_token(config: &BotConfig) -> Result<Option<String>> {
    let token = env::var(&config.server.sidecar_token_env)
        .ok()
        .filter(|value| !value.trim().is_empty());
    if token.is_none() && !config.server.allow_unauthenticated {
        return Err(anyhow!(
            "set {} or server.allow_unauthenticated = true",
            config.server.sidecar_token_env
        ));
    }
    if token.is_none() {
        warn!("sidecar forwarding is unauthenticated");
    }
    Ok(token)
}

async fn resolve_self_person_id(
    config: &BotConfig,
    webex: &dyn WebexApi,
) -> Result<Option<String>> {
    if let Some(person_id) = &config.self_person_id {
        return Ok(Some(person_id.clone()));
    }
    let me = webex.me().await.map_err(|error| match error {
        WebexCallError::TimedOut => {
            anyhow!("timed out resolving Webex people/me after 30 seconds")
        }
        WebexCallError::Client(error) => anyhow!("failed to resolve Webex people/me: {error}"),
        WebexCallError::WriteBlocked(room_id) => {
            anyhow!("failed to resolve Webex people/me: write blocked for {room_id}")
        }
    })?;
    Ok(me.id)
}

fn merge_message(target: &mut Message, hydrated: Message) {
    let promote_hydrated_marker_body = !message_contains_marker(target, "wgb-ref:")
        && message_contains_marker(&hydrated, "wgb-ref:");
    let hydrated_text = hydrated.text.clone();
    let hydrated_markdown = hydrated.markdown.clone();
    let hydrated_html = hydrated.html.clone();
    if target.id.is_none() {
        target.id = hydrated.id;
    }
    if target.parent_id.is_none() {
        target.parent_id = hydrated.parent_id;
    }
    if target.room_id.is_none() {
        target.room_id = hydrated.room_id;
    }
    if target.room_type.is_none() {
        target.room_type = hydrated.room_type;
    }
    if target.person_id.is_none() {
        target.person_id = hydrated.person_id;
    }
    if target.person_email.is_none() {
        target.person_email = hydrated.person_email;
    }
    if target.text.is_none() {
        target.text = hydrated.text;
    }
    if target.markdown.is_none() {
        target.markdown = hydrated.markdown;
    }
    if target.html.is_none() {
        target.html = hydrated.html;
    }
    if target.mentioned_people.is_empty() {
        target.mentioned_people = hydrated.mentioned_people;
    }
    if target.mentioned_groups.is_empty() {
        target.mentioned_groups = hydrated.mentioned_groups;
    }
    if promote_hydrated_marker_body {
        target.text = hydrated_text;
        target.markdown = hydrated_markdown;
        target.html = hydrated_html;
    }
}

fn event_message_needs_hydration(
    direct_policy: Option<&webex_generic_account_bot::RoomPolicy>,
    followup_policies: &[&webex_generic_account_bot::RoomPolicy],
    message: &Message,
) -> bool {
    direct_policy.is_some_and(|policy| message_needs_hydration(policy, message))
        || followup_policies
            .iter()
            .any(|policy| followup_event_needs_hydration(policy, message))
}

fn message_needs_hydration(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    message.room_id.is_none()
        || message.person_id.is_none()
        || message.person_email.is_none()
        || (message.text.is_none() && message.markdown.is_none())
        || (matches!(policy.trigger, TriggerMode::Mention) && message.mentioned_people.is_empty())
}

fn followup_message_needs_hydration(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    let mention_needs_hydration = policy.followup.triggers.contains(&FollowupTrigger::Mention)
        && message.mentioned_people.is_empty()
        && !message_matches_prefix(message, &policy.prefixes);
    let quoted_reply_needs_hydration = policy
        .followup
        .triggers
        .contains(&FollowupTrigger::QuotedBotReply)
        && !message_contains_marker(message, "wgb-ref:");

    message.room_id.is_none()
        || message.parent_id.is_none()
        || message.person_id.is_none()
        || message.person_email.is_none()
        || (message.text.is_none() && message.markdown.is_none() && message.html.is_none())
        || mention_needs_hydration
        || quoted_reply_needs_hydration
}

fn followup_event_needs_hydration(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    if !followup_event_may_match(policy, message) {
        return false;
    }
    followup_message_needs_hydration(policy, message)
}

fn followup_event_may_match(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    if message.parent_id.is_some() {
        return true;
    }

    policy
        .followup
        .triggers
        .iter()
        .any(|trigger| match trigger {
            FollowupTrigger::Mention => {
                !message.mentioned_people.is_empty()
                    || message_matches_prefix(message, &policy.prefixes)
            }
            FollowupTrigger::QuotedBotReply => message_contains_marker(message, "wgb-ref:"),
        })
}

fn followup_candidate_matches(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
    self_person_id: Option<&str>,
) -> bool {
    if message.parent_id.is_none() || !followup_sender_allowed(policy, message) {
        return false;
    }

    policy
        .followup
        .triggers
        .iter()
        .any(|trigger| match trigger {
            FollowupTrigger::Mention => {
                self_person_id.is_some_and(|self_id| {
                    message
                        .mentioned_people
                        .iter()
                        .any(|person_id| person_id == self_id)
                }) || message_matches_prefix(message, &policy.prefixes)
            }
            FollowupTrigger::QuotedBotReply => message_contains_marker(message, "wgb-ref:"),
        })
}

fn followup_sender_allowed(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    let followup = &policy.followup;
    if followup.allow_all_senders {
        return true;
    }
    if followup.allowed_person_ids.is_empty() && followup.allowed_person_emails.is_empty() {
        return webex_generic_account_bot::policy::sender_allowed(policy, message);
    }

    let person_id_allowed = message
        .person_id
        .as_deref()
        .is_some_and(|person_id| followup.allowed_person_ids.iter().any(|id| id == person_id));
    let person_email_allowed = message.person_email.as_deref().is_some_and(|email| {
        followup
            .allowed_person_emails
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(email))
    });

    person_id_allowed || person_email_allowed
}

fn followup_source_message_id(
    root_message: &Message,
    thread_messages: &[Message],
    current_message: &Message,
    self_person_id: Option<&str>,
) -> Option<String> {
    let current_message_id = current_message.id.as_deref();
    let mut ordered_thread_messages = thread_messages.iter().collect::<Vec<_>>();
    ordered_thread_messages.sort_by_key(|message| message.created);
    let root_reply_markers = if message_contains_marker(root_message, "wgb-source-ref:") {
        Vec::new()
    } else {
        marker_message_ids(root_message, "wgb-ref:", self_person_id, true)
    };

    root_reply_markers
        .into_iter()
        .chain(ordered_thread_messages.iter().flat_map(|message| {
            if message.id.as_deref() == current_message_id {
                Vec::new()
            } else {
                marker_message_ids(message, "wgb-ref:", self_person_id, true)
            }
        }))
        .next()
}

fn message_contains_marker(message: &Message, marker_prefix: &str) -> bool {
    reply_body(message).contains(marker_prefix)
}

fn marker_message_ids(
    message: &Message,
    marker_prefix: &str,
    self_person_id: Option<&str>,
    require_self_message: bool,
) -> Vec<String> {
    if require_self_message {
        let Some(self_person_id) = self_person_id else {
            return Vec::new();
        };
        if message.person_id.as_deref() != Some(self_person_id) {
            return Vec::new();
        }
    }
    marker_message_ids_from_body(&reply_body(message), marker_prefix)
}

fn marker_message_ids_from_body(body: &str, marker_prefix: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut remaining = body;
    while let Some(index) = remaining.find(marker_prefix) {
        let after_prefix = &remaining[index + marker_prefix.len()..];
        let hex: String = after_prefix
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect();
        if let Some(message_id) = decode_marker_hex(&hex) {
            if !ids.contains(&message_id) {
                ids.push(message_id);
            }
        }
        remaining = &after_prefix[hex.len()..];
    }
    ids
}

fn decode_marker_hex(hex: &str) -> Option<String> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn render_followup_prompt(
    template: &str,
    context: &MessageContext,
    source_context: &MessageContext,
    thread_context: &str,
) -> String {
    render_template_once(
        template,
        &[
            ("{room_id}", &context.room_id),
            ("{message_id}", &context.message_id),
            ("{person_id}", context.person_id.as_deref().unwrap_or("")),
            (
                "{person_email}",
                context.person_email.as_deref().unwrap_or(""),
            ),
            ("{body}", &context.body),
            ("{original_room_id}", &source_context.room_id),
            ("{original_message_id}", &source_context.message_id),
            (
                "{original_person_id}",
                source_context.person_id.as_deref().unwrap_or(""),
            ),
            (
                "{original_person_email}",
                source_context.person_email.as_deref().unwrap_or(""),
            ),
            ("{original_body}", &source_context.body),
            ("{thread_context}", thread_context),
        ],
    )
}

fn render_template_once(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut remaining = template;
    while !remaining.is_empty() {
        if let Some((placeholder, value)) = replacements
            .iter()
            .find(|(placeholder, _)| remaining.starts_with(*placeholder))
        {
            rendered.push_str(value);
            remaining = &remaining[placeholder.len()..];
            continue;
        }

        let ch = remaining
            .chars()
            .next()
            .expect("remaining template is not empty");
        rendered.push(ch);
        remaining = &remaining[ch.len_utf8()..];
    }
    rendered
}

fn render_thread_context(
    root_message: &Message,
    thread_messages: &[Message],
    current_message_id: &str,
    self_person_id: Option<&str>,
    max_chars: usize,
) -> String {
    let root_entry = render_thread_message("root", root_message, self_person_id, max_chars);
    let mut replies = thread_messages.to_vec();
    replies.sort_by_key(|message| message.created);
    let reply_entries = replies
        .into_iter()
        .filter(|message| message.id.as_deref() != Some(current_message_id))
        .map(|message| render_thread_message("reply", &message, self_person_id, max_chars))
        .filter(|entry| !entry.trim().is_empty())
        .collect::<Vec<_>>();

    let max_chars = max_chars.max(1);
    let root_entry = trim_to_chars(&root_entry, max_chars);
    let mut selected_replies = Vec::new();
    let mut selected_chars = root_entry.chars().count();
    for entry in reply_entries.into_iter().rev() {
        let separator_chars = if root_entry.trim().is_empty() && selected_replies.is_empty() {
            0
        } else {
            2
        };
        let entry_chars = entry.chars().count();
        if selected_chars
            .saturating_add(separator_chars)
            .saturating_add(entry_chars)
            > max_chars
        {
            break;
        }
        selected_chars += separator_chars + entry_chars;
        selected_replies.push(entry);
    }
    selected_replies.reverse();

    let mut entries = Vec::with_capacity(selected_replies.len().saturating_add(1));
    entries.push(root_entry);
    entries.extend(selected_replies);
    let rendered = entries
        .into_iter()
        .filter(|entry| !entry.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    trim_to_chars(&rendered, max_chars)
}

fn render_thread_message(
    role: &str,
    message: &Message,
    self_person_id: Option<&str>,
    max_chars: usize,
) -> String {
    let id = message.id.as_deref().unwrap_or("unknown");
    let sender =
        if self_person_id.is_some_and(|self_id| message.person_id.as_deref() == Some(self_id)) {
            "bot"
        } else {
            message
                .person_email
                .as_deref()
                .or(message.person_id.as_deref())
                .unwrap_or("unknown")
        };
    let created = message
        .created
        .map(|created| created.to_rfc3339())
        .unwrap_or_else(|| "unknown-time".to_owned());
    let body_limit = max_chars.clamp(1, 1_200);
    let body = trim_to_chars(&clean_prompt_message_body(message), body_limit);
    format!("[{role}] {created} {sender} ({id})\n{body}")
}

fn clean_prompt_message_body(message: &Message) -> String {
    let body = message
        .markdown
        .as_deref()
        .or(message.text.as_deref())
        .or(message.html.as_deref())
        .unwrap_or("");
    body.lines()
        .filter(|line| !line.contains("<!-- wgb-ref:") && !line.contains("<!-- wgb-source-ref:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn source_marker_search_max_pages(message: &Message, recovery_age: Duration) -> Option<usize> {
    if message_is_at_least_age(message, recovery_age) {
        None
    } else {
        Some(SOURCE_MARKER_SEARCH_MAX_PAGES)
    }
}

fn message_is_at_least_age(message: &Message, min_age: Duration) -> bool {
    let Some(created) = message.created else {
        return false;
    };
    let created_ms = created.timestamp_millis();
    if created_ms < 0 {
        return true;
    }
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    now.as_millis().saturating_sub(created_ms as u128) >= min_age.as_millis()
}

fn sanitize_reply_markdown(markdown: &str) -> String {
    markdown.replace("<@", "&lt;@")
}

#[derive(Debug, Deserialize)]
struct JenkinsDiagnosisReply {
    verdict: JenkinsDiagnosisVerdict,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    log_url: Option<String>,
    #[serde(default)]
    excerpt: Option<String>,
    #[serde(
        default,
        alias = "excerpt_style",
        deserialize_with = "deserialize_jenkins_excerpt_format"
    )]
    excerpt_format: JenkinsDiagnosisExcerptFormat,
}

#[derive(Debug, Deserialize)]
struct JenkinsFollowupReply {
    #[serde(default)]
    answer: String,
    #[serde(default)]
    include_evidence: bool,
    #[serde(default)]
    log_url: Option<String>,
    #[serde(default)]
    excerpt: Option<String>,
    #[serde(
        default,
        alias = "excerpt_style",
        deserialize_with = "deserialize_jenkins_excerpt_format"
    )]
    excerpt_format: JenkinsDiagnosisExcerptFormat,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JenkinsDiagnosisVerdict {
    InfraFalseAlarm,
    LikelyProductTestFailure,
    NotEnoughEvidence,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum JenkinsDiagnosisExcerptFormat {
    #[default]
    #[serde(alias = "backtick", alias = "inline")]
    InlineCode,
    #[serde(alias = "blockquote", alias = "quote")]
    BlockQuote,
}

fn deserialize_jenkins_excerpt_format<'de, D>(
    deserializer: D,
) -> std::result::Result<JenkinsDiagnosisExcerptFormat, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(JenkinsDiagnosisExcerptFormat::default());
    };
    let Some(value) = value.as_str() else {
        return Ok(JenkinsDiagnosisExcerptFormat::default());
    };
    Ok(match value.trim().to_ascii_lowercase().as_str() {
        "block_quote" | "blockquote" | "quote" => JenkinsDiagnosisExcerptFormat::BlockQuote,
        _ => JenkinsDiagnosisExcerptFormat::InlineCode,
    })
}

#[cfg(test)]
fn render_reply_text(
    format: ReplyFormat,
    output: &str,
    prefetched_context: Option<&str>,
) -> String {
    let allowed_log_urls = prefetched_context
        .map(extract_jenkins_console_urls)
        .unwrap_or_default();
    render_reply_text_with_allowed_urls(format, output, &allowed_log_urls)
}

fn render_reply_text_with_allowed_urls(
    format: ReplyFormat,
    output: &str,
    allowed_log_urls: &[String],
) -> String {
    match format {
        ReplyFormat::Markdown => output.to_owned(),
        ReplyFormat::JenkinsDiagnosisJson => {
            render_jenkins_diagnosis_json_with_allowed_urls(output, allowed_log_urls)
        }
        ReplyFormat::JenkinsFollowupJson => {
            render_jenkins_followup_json_with_allowed_urls(output, allowed_log_urls)
        }
    }
}

fn render_jenkins_diagnosis_json_with_allowed_urls(
    output: &str,
    allowed_log_urls: &[String],
) -> String {
    let fallback_log_url = if allowed_log_urls.len() == 1 {
        allowed_log_urls.first().map(String::as_str)
    } else {
        None
    };
    match parse_jenkins_diagnosis_json(output) {
        Ok(reply) => render_jenkins_diagnosis_reply(&reply, allowed_log_urls, fallback_log_url),
        Err(_) => render_jenkins_diagnosis_reply(
            &JenkinsDiagnosisReply {
                verdict: JenkinsDiagnosisVerdict::NotEnoughEvidence,
                reason: "Codex did not return valid diagnosis JSON".to_owned(),
                log_url: fallback_log_url.map(ToOwned::to_owned),
                excerpt: None,
                excerpt_format: JenkinsDiagnosisExcerptFormat::default(),
            },
            allowed_log_urls,
            fallback_log_url,
        ),
    }
}

fn parse_jenkins_diagnosis_json(output: &str) -> Result<JenkinsDiagnosisReply> {
    let json = extract_json_object(output)
        .ok_or_else(|| anyhow!("Codex output did not contain a JSON object"))?;
    serde_json::from_str(json).context("failed to parse Jenkins diagnosis JSON")
}

fn render_jenkins_followup_json_with_allowed_urls(
    output: &str,
    allowed_log_urls: &[String],
) -> String {
    match parse_jenkins_followup_json(output) {
        Ok(reply) => render_jenkins_followup_reply(&reply, allowed_log_urls),
        Err(_) => render_jenkins_followup_reply(
            &JenkinsFollowupReply {
                answer: "I could not parse the follow-up answer".to_owned(),
                include_evidence: false,
                log_url: None,
                excerpt: None,
                excerpt_format: JenkinsDiagnosisExcerptFormat::default(),
            },
            allowed_log_urls,
        ),
    }
}

fn parse_jenkins_followup_json(output: &str) -> Result<JenkinsFollowupReply> {
    let json = extract_json_object(output)
        .ok_or_else(|| anyhow!("Codex output did not contain a JSON object"))?;
    serde_json::from_str(json).context("failed to parse Jenkins follow-up JSON")
}

fn extract_json_object(output: &str) -> Option<&str> {
    let trimmed = output.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Some(trimmed);
    }
    let start = output.find('{')?;
    let end = output.rfind('}')?;
    if end < start {
        return None;
    }
    Some(output[start..=end].trim())
}

fn render_jenkins_followup_reply(
    reply: &JenkinsFollowupReply,
    allowed_log_urls: &[String],
) -> String {
    let answer = concise_followup_answer(&reply.answer);
    let answer = escape_markdown_plain_text(&answer);
    let (log_url, excerpt) = if reply.include_evidence {
        (
            reply
                .log_url
                .as_deref()
                .and_then(normalized_jenkins_console_url)
                .filter(|url| allowed_log_urls.iter().any(|allowed| allowed == url)),
            reply.excerpt.as_deref(),
        )
    } else {
        (None, None)
    };
    match log_url {
        Some(url) => append_jenkins_excerpt(
            format!("{answer} [log](<{url}>)"),
            excerpt,
            reply.excerpt_format,
        ),
        None => append_jenkins_excerpt(answer, excerpt, reply.excerpt_format),
    }
}

fn render_jenkins_diagnosis_reply(
    reply: &JenkinsDiagnosisReply,
    allowed_log_urls: &[String],
    fallback_log_url: Option<&str>,
) -> String {
    let reason_is_blank = reply.reason.split_whitespace().next().is_none();
    let verdict = if reason_is_blank {
        JenkinsDiagnosisVerdict::NotEnoughEvidence
    } else {
        reply.verdict
    };
    let prefix = match verdict {
        JenkinsDiagnosisVerdict::InfraFalseAlarm => "**Jenkins infra false alarm:**",
        JenkinsDiagnosisVerdict::LikelyProductTestFailure => "**Likely product/test failure:**",
        JenkinsDiagnosisVerdict::NotEnoughEvidence => "**Not enough evidence:**",
    };
    let reason = if reason_is_blank {
        "diagnostic evidence is inconclusive".to_owned()
    } else {
        escape_markdown_plain_text(&concise_reason(&reply.reason))
    };
    let log_url = reply
        .log_url
        .as_deref()
        .and_then(normalized_jenkins_console_url)
        .filter(|url| allowed_log_urls.iter().any(|allowed| allowed == url))
        .or_else(|| fallback_log_url.and_then(normalized_jenkins_console_url));
    match log_url {
        Some(url) => append_jenkins_excerpt(
            format!("{prefix} {reason} [log](<{url}>)"),
            reply.excerpt.as_deref(),
            reply.excerpt_format,
        ),
        None => append_jenkins_excerpt(
            format!("{prefix} {reason}"),
            reply.excerpt.as_deref(),
            reply.excerpt_format,
        ),
    }
}

fn concise_followup_answer(answer: &str) -> String {
    let normalised = answer.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalised = normalised.trim_matches(['.', '!', '?', ' ', '\t']).trim();
    if normalised.is_empty() {
        "I do not have enough evidence to answer that follow-up".to_owned()
    } else {
        webex_generic_account_bot::policy::trim_to_chars(normalised, REPLY_LIMIT_CHARS / 2)
    }
}

fn append_jenkins_excerpt(
    mut reply: String,
    excerpt: Option<&str>,
    format: JenkinsDiagnosisExcerptFormat,
) -> String {
    let Some(excerpt) = excerpt.and_then(sanitize_jenkins_excerpt) else {
        return reply;
    };
    match effective_excerpt_format(&excerpt, format) {
        JenkinsDiagnosisExcerptFormat::InlineCode => {
            reply.push('\n');
            reply.push('`');
            reply.push_str(&excerpt);
            reply.push('`');
        }
        JenkinsDiagnosisExcerptFormat::BlockQuote => {
            reply.push('\n');
            reply.push_str(&blockquote_excerpt(&excerpt));
        }
    }
    reply
}

fn sanitize_jenkins_excerpt(value: &str) -> Option<String> {
    let mut sanitized = String::new();
    for ch in value.trim().chars() {
        if ch.is_control() && !matches!(ch, '\n' | '\t') {
            continue;
        }
        sanitized.push(ch);
    }
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        None
    } else {
        Some(webex_generic_account_bot::policy::trim_to_chars(
            sanitized,
            JENKINS_DIAGNOSIS_EXCERPT_LIMIT,
        ))
    }
}

fn effective_excerpt_format(
    excerpt: &str,
    requested: JenkinsDiagnosisExcerptFormat,
) -> JenkinsDiagnosisExcerptFormat {
    if requested == JenkinsDiagnosisExcerptFormat::InlineCode
        && !excerpt.contains('`')
        && !excerpt.contains('\n')
    {
        JenkinsDiagnosisExcerptFormat::InlineCode
    } else {
        JenkinsDiagnosisExcerptFormat::BlockQuote
    }
}

fn blockquote_excerpt(excerpt: &str) -> String {
    excerpt
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                ">".to_owned()
            } else {
                format!("> {}", escape_blockquote_excerpt(line))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_blockquote_excerpt(value: &str) -> String {
    escape_markdown_plain_text(value)
}

fn concise_reason(reason: &str) -> String {
    let normalised = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalised = normalised.trim_matches(['.', '!', '?', ' ', '\t']).trim();
    if normalised.is_empty() {
        return "diagnostic evidence is inconclusive".to_owned();
    }
    let mut boundary = normalised.len();
    for (index, ch) in normalised.char_indices() {
        if matches!(ch, '.' | '!' | '?')
            && normalised[index + ch.len_utf8()..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        {
            boundary = index;
            break;
        }
    }
    normalised[..boundary]
        .trim_matches(['.', '!', '?', ' ', '\t'])
        .to_owned()
}

fn escape_markdown_plain_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn extract_jenkins_console_urls(context: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let has_explicit_block = context
        .lines()
        .any(|line| line.trim() == "prefetched_jenkins_console_urls:");
    let mut in_explicit_block = false;
    for line in context.lines() {
        let trimmed = line.trim();
        if has_explicit_block {
            if trimmed == "prefetched_jenkins_console_urls:" {
                in_explicit_block = true;
                continue;
            }
            if !in_explicit_block {
                continue;
            }
            let Some(value) = trimmed.strip_prefix("- jenkins_console:") else {
                in_explicit_block = false;
                continue;
            };
            if let Some(url) = normalized_jenkins_console_url(value) {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
            continue;
        }

        let value = if let Some(value) = trimmed.strip_prefix("jenkins_console:") {
            value
        } else if let Some(value) = trimmed.strip_prefix("- jenkins_console:") {
            value
        } else {
            continue;
        };
        if let Some(url) = normalized_jenkins_console_url(value) {
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    urls
}

fn normalized_jenkins_console_url(url: &str) -> Option<String> {
    let url = url.trim();
    if is_valid_jenkins_console_url(url) {
        Some(url.trim_end_matches('/').to_owned())
    } else {
        None
    }
}

fn is_valid_jenkins_console_url(url: &str) -> bool {
    let url = url.trim();
    let path = url.trim_end_matches('/');
    (url.starts_with("https://") || url.starts_with("http://"))
        && path.ends_with("/console")
        && !url.contains("consoleText")
        && !url.chars().any(|ch| matches!(ch, '<' | '>'))
        && !url.chars().any(char::is_whitespace)
        && !url.chars().any(char::is_control)
}

fn reply_marker(message_id: &str) -> String {
    format!("wgb-ref:{}", marker_hex(message_id))
}

fn source_marker(message_id: &str) -> String {
    format!("wgb-source-ref:{}", marker_hex(message_id))
}

fn marker_hex(message_id: &str) -> String {
    message_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn hidden_marker_comment(marker: &str) -> String {
    format!("<!-- {marker} -->")
}

fn prepare_forward_markdown(
    message: &Message,
    source_room_id: &str,
    message_id: &str,
    marker: &str,
) -> String {
    let sender = message
        .person_email
        .as_deref()
        .or(message.person_id.as_deref())
        .unwrap_or("unknown");
    let prefix = format!(
        "**Forwarded Webex message for staging triage**\n\nSource room: `{source_room_id}`\nSource message: `{message_id}`\nSender: `{sender}`\n\n"
    );
    let suffix = format!("\n\n{}", hidden_marker_comment(marker));
    let body_limit = FORWARD_MARKDOWN_LIMIT_BYTES
        .saturating_sub(prefix.len())
        .saturating_sub(suffix.len())
        .max(1);
    let body = sanitize_reply_markdown(
        message
            .markdown
            .as_deref()
            .or(message.text.as_deref())
            .or(message.html.as_deref())
            .unwrap_or(""),
    );
    let quoted_body = if body.trim().is_empty() {
        "> [empty message]".to_owned()
    } else {
        body.lines()
            .map(|line| {
                if line.trim().is_empty() {
                    ">".to_owned()
                } else {
                    format!("> {line}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let quoted_body = trim_to_utf8_bytes(&quoted_body, body_limit);
    format!("{prefix}{quoted_body}{suffix}")
}

fn trim_to_utf8_bytes(value: &str, max_bytes: usize) -> String {
    const SUFFIX: &str = "\n[truncated]";
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    if max_bytes == 0 {
        return String::new();
    }
    if max_bytes <= SUFFIX.len() {
        return SUFFIX[..max_bytes].to_owned();
    }
    let visible_limit = max_bytes - SUFFIX.len();
    let mut end = 0usize;
    for (index, ch) in value.char_indices() {
        let next = index + ch.len_utf8();
        if next > visible_limit {
            break;
        }
        end = next;
    }
    format!("{}{}", &value[..end], SUFFIX)
}

fn prepare_reply_markdown(markdown: &str, marker: &str) -> String {
    let marker_footer = hidden_marker_comment(marker);
    let marker_chars = marker_footer.chars().count().saturating_add(2);
    let truncation_suffix = "\n[truncated]".chars().count();
    let visible_limit = REPLY_LIMIT_CHARS
        .saturating_sub(marker_chars)
        .saturating_sub(truncation_suffix)
        .max(1);
    let visible = webex_generic_account_bot::policy::trim_to_chars(
        &sanitize_reply_markdown(markdown),
        visible_limit,
    );
    format!("{visible}\n\n{marker_footer}")
}

fn reply_matches_marker(reply: &Message, marker: &str, self_person_id: Option<&str>) -> bool {
    if let Some(self_person_id) = self_person_id {
        if reply.person_id.as_deref() != Some(self_person_id) {
            return false;
        }
    }
    reply_body(reply).contains(marker)
}

fn existing_reply_chars(reply: &Message) -> usize {
    reply
        .markdown
        .as_deref()
        .or(reply.text.as_deref())
        .unwrap_or_default()
        .chars()
        .count()
}

fn reply_body(reply: &Message) -> String {
    [
        reply.markdown.as_deref(),
        reply.text.as_deref(),
        reply.html.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n")
}

fn reply_markdown_message(
    room_id: impl Into<String>,
    parent_id: impl Into<String>,
    markdown: impl Into<String>,
) -> CreateMessage {
    CreateMessage {
        room_id: Some(room_id.into()),
        parent_id: Some(parent_id.into()),
        markdown: Some(markdown.into()),
        ..CreateMessage::default()
    }
}

fn top_level_markdown_message(
    room_id: impl Into<String>,
    markdown: impl Into<String>,
) -> CreateMessage {
    CreateMessage {
        room_id: Some(room_id.into()),
        markdown: Some(markdown.into()),
        ..CreateMessage::default()
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                error!(%error, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use webex_generic_account_bot::CodexRunOutput;

    const ROOM_ID: &str = "room-1";
    const OUTPUT_ROOM_ID: &str = "staging-room-1";
    const SELF_PERSON_ID: &str = "bot-person";
    const SENDER_PERSON_ID: &str = "sender-person";
    const SENDER_EMAIL: &str = "sender@example.com";
    type MarkerSearchRequest = (
        String,
        Option<String>,
        String,
        Option<String>,
        Option<usize>,
    );
    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[tokio::test]
    async fn process_event_runs_codex_and_sends_markdown_reply() {
        let harness = TestHarness::new();
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("reply-1")));
        harness.runner.push_output("## Diagnosis\n\n- Looks good");

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "please inspect",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.message_id.as_deref(), Some("message-1"));
        assert_eq!(action.room_id.as_deref(), Some(ROOM_ID));
        assert_eq!(action.reply_id.as_deref(), Some("reply-1"));
        let created = harness.webex.created_requests();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].room_id.as_deref(), Some(ROOM_ID));
        assert_eq!(created[0].parent_id.as_deref(), Some("message-1"));
        let markdown = created[0].markdown.as_deref().unwrap();
        assert!(markdown.contains("## Diagnosis"));
        assert!(markdown.contains(&reply_marker("message-1")));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("message-1").await);
    }

    #[tokio::test]
    async fn codex_runner_failure_skips_json_reply_rendering() {
        let state_path = unique_state_path();
        let mut config = (*test_config(state_path)).clone();
        config.rooms[0].reply_format = ReplyFormat::JenkinsDiagnosisJson;
        let harness = TestHarness::with_config(Arc::new(config));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("reply-1")));
        harness.runner.push_error("runner crashed");

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "Jenkins failed",
            )))
            .await
            .unwrap();

        assert_eq!(action.reply_id.as_deref(), Some("reply-1"));
        let created = harness.webex.created_requests();
        let markdown = created[0].markdown.as_deref().unwrap();
        assert!(markdown.contains("Codex run failed. Check the bot service logs for details."));
        assert!(!markdown.contains("Not enough evidence"));
    }

    #[tokio::test]
    async fn process_event_removes_jenkins_artifacts_after_codex_run() {
        let helper_dir = unique_state_path().with_extension("helper-cleanup-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        fs::write(
            &script,
            "artifact_dir=\n\
             while [ \"$#\" -gt 0 ]; do\n\
             case \"$1\" in\n\
             --artifact-dir) artifact_dir=\"$2\"; shift 2 ;;\n\
             *) shift ;;\n\
             esac\n\
             done\n\
             mkdir -p \"$artifact_dir\"\n\
             printf evidence > \"$artifact_dir/evidence.txt\"\n\
             printf 'jenkins_console: https://jenkins.example/job/foo/1/console\\n'\n",
        )
        .unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let state_path = unique_state_path();
        let mut config = (*test_config(state_path)).clone();
        config.rooms[0].reply_format = ReplyFormat::JenkinsDiagnosisJson;
        config.rooms[0].jenkins_context = Some(webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script,
            env_file,
            timeout_secs: 5,
            max_urls: 1,
            output_limit_chars: 1024,
            enabled: true,
        });
        let codex_cwd = config.codex.cwd.clone();
        let harness = TestHarness::with_config(Arc::new(config));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("reply-1")));
        harness.runner.push_output(
            r#"{
                "verdict": "infra_false_alarm",
                "reason": "agent capacity failure",
                "log_url": "https://jenkins.example/job/foo/1/console"
            }"#,
        );

        harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "Jenkins failed: https://engci-private-sjc.cisco.com/jenkins/job/foo/1/",
            )))
            .await
            .unwrap();

        let calls = harness.runner.calls();
        let artifact_dir = first_artifact_dir_from_prompt(&calls[0].1);
        let artifact_root = artifact_dir.parent().unwrap();
        assert!(artifact_root.starts_with(jenkins_artifact_process_root(&codex_cwd)));
        assert!(!artifact_root.exists());
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[tokio::test]
    async fn process_event_reuses_existing_marker_without_codex_run() {
        let harness = TestHarness::new();
        let marker = reply_marker("message-1");
        harness
            .webex
            .push_reply_search(Ok(vec![reply_with_marker("reply-existing", &marker)]));

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "already handled",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("reply-existing"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("message-1").await);
    }

    #[tokio::test]
    async fn retryable_reconciliation_failure_defers_without_codex_run() {
        let harness = TestHarness::new();
        harness
            .webex
            .push_reply_search(Err(WebexCallError::Client(WebexError::Api(Box::new(
                api_error(503, Some(Duration::from_secs(42))),
            )))));

        let error = harness
            .app
            .process_event(message_event(inbound_message("message-1", "retry later")))
            .await
            .unwrap_err();

        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.retry_after, Some(Duration::from_secs(42)));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(!harness.processed("message-1").await);

        let leased = harness
            .app
            .process_event(message_event(inbound_message("message-1", "retry later")))
            .await
            .unwrap_err();
        assert_eq!(leased.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(leased.message.contains("active attempt lease"));
    }

    #[tokio::test]
    async fn create_timeout_reconciles_existing_reply_and_marks_processed() {
        let harness = TestHarness::new();
        let marker = reply_marker("message-1");
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Err(WebexCallError::TimedOut));
        harness
            .webex
            .push_reply_search(Ok(vec![reply_with_marker("reply-after-timeout", &marker)]));
        harness.runner.push_output("The reply reached Webex.");

        let action = harness
            .app
            .process_event(message_event(inbound_message("message-1", "timeout path")))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("reply-after-timeout"));
        assert_eq!(harness.runner.calls().len(), 1);
        assert_eq!(harness.webex.created_requests().len(), 1);
        assert_eq!(harness.webex.marker_searches().len(), 2);
        assert!(harness.processed("message-1").await);
    }

    #[tokio::test]
    async fn staging_policy_forwards_source_then_replies_under_output_message() {
        let harness = TestHarness::with_config(staging_test_config(unique_state_path()));
        let source_marker = source_marker("message-1");
        let reply_marker = reply_marker("message-1");
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("forward-1", OUTPUT_ROOM_ID)));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("reply-1", OUTPUT_ROOM_ID)));
        harness
            .runner
            .push_output("**Jenkins infra false alarm:** DNS issue [log](https://example/log)");

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "Jenkins failed at https://example/job/1",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(action.reply_id.as_deref(), Some("reply-1"));
        let searches = harness.webex.marker_searches();
        assert_eq!(searches.len(), 2);
        assert_eq!(
            searches[0],
            (
                OUTPUT_ROOM_ID.to_owned(),
                None,
                source_marker.clone(),
                Some(SELF_PERSON_ID.to_owned()),
                Some(SOURCE_MARKER_SEARCH_MAX_PAGES)
            )
        );
        assert_eq!(
            searches[1],
            (
                OUTPUT_ROOM_ID.to_owned(),
                Some("forward-1".to_owned()),
                reply_marker.clone(),
                Some(SELF_PERSON_ID.to_owned()),
                None
            )
        );

        let created = harness.webex.created_requests();
        assert_eq!(created.len(), 2);
        assert_eq!(created[0].room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(created[0].parent_id, None);
        let forward_markdown = created[0].markdown.as_deref().unwrap();
        assert!(forward_markdown.contains("Forwarded Webex message"));
        assert!(forward_markdown.contains("Source room: `room-1`"));
        assert!(forward_markdown.contains("Source message: `message-1`"));
        assert!(forward_markdown.contains("Jenkins failed"));
        assert!(forward_markdown.contains(&source_marker));
        assert!(!forward_markdown.contains("_Ref:"));
        assert!(forward_markdown.contains("<!-- wgb-source-ref:"));
        assert_eq!(created[1].room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(created[1].parent_id.as_deref(), Some("forward-1"));
        let reply_markdown = created[1].markdown.as_deref().unwrap();
        assert!(reply_markdown.contains(&reply_marker));
        assert!(!reply_markdown.contains("_Ref:"));
        assert!(reply_markdown.contains("<!-- wgb-ref:"));
        assert!(
            created
                .iter()
                .all(|request| request.room_id.as_deref() != Some(ROOM_ID))
        );
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("message-1").await);
    }

    #[tokio::test]
    async fn staging_policy_reuses_existing_forward_and_reply_without_codex_run() {
        let harness = TestHarness::with_config(staging_test_config(unique_state_path()));
        harness.webex.push_reply_search(Ok(vec![message_with_marker(
            "forward-existing",
            OUTPUT_ROOM_ID,
            &source_marker("message-1"),
        )]));
        harness.webex.push_reply_search(Ok(vec![message_with_marker(
            "reply-existing",
            OUTPUT_ROOM_ID,
            &reply_marker("message-1"),
        )]));

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "message-1",
                "already mirrored",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(action.reply_id.as_deref(), Some("reply-existing"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("message-1").await);
    }

    #[tokio::test]
    async fn mention_in_existing_source_thread_runs_followup_prompt() {
        let harness = TestHarness::with_config(followup_test_config(unique_state_path()));
        let mut prior_reply = message_with_marker("bot-reply-1", ROOM_ID, &reply_marker("root-1"));
        prior_reply.parent_id = Some("root-1".to_owned());
        prior_reply.markdown = Some(format!(
            "Previous diagnosis\n\n{}",
            hidden_marker_comment(&reply_marker("root-1"))
        ));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness.webex.push_thread_messages(Ok(vec![prior_reply]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "root-1",
                "@miku.gen can you explain why this is infra?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(ROOM_ID));
        assert_eq!(action.reply_id.as_deref(), Some("followup-reply-1"));
        assert_eq!(
            harness.webex.thread_requests(),
            vec![(
                ROOM_ID.to_owned(),
                "root-1".to_owned(),
                FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES
            )]
        );
        let calls = harness.runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "followup-1");
        assert!(
            calls[0]
                .1
                .contains("Original root-1: Original Jenkins failure")
        );
        assert!(calls[0].1.contains("Previous diagnosis"));
        assert!(calls[0].1.contains("Follow-up followup-1"));
        let created = harness.webex.created_requests();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].parent_id.as_deref(), Some("root-1"));
        assert_eq!(
            harness.webex.marker_searches(),
            vec![(
                ROOM_ID.to_owned(),
                Some("root-1".to_owned()),
                reply_marker("followup-1"),
                Some(SELF_PERSON_ID.to_owned()),
                Some(followup_reply_marker_search_max_pages(30))
            )]
        );
        assert!(
            created[0]
                .markdown
                .as_deref()
                .unwrap()
                .contains(&reply_marker("followup-1"))
        );
        assert!(harness.processed("followup-1").await);
    }

    #[test]
    fn followup_prompt_preserves_literal_placeholder_text() {
        let context = MessageContext {
            message_id: "followup-1".to_owned(),
            room_id: ROOM_ID.to_owned(),
            person_id: Some(SENDER_PERSON_ID.to_owned()),
            person_email: Some(SENDER_EMAIL.to_owned()),
            body: "Please explain {thread_context} without expanding it".to_owned(),
        };
        let source_context = MessageContext {
            message_id: "root-1".to_owned(),
            room_id: ROOM_ID.to_owned(),
            person_id: Some("source-person".to_owned()),
            person_email: Some("source@example.com".to_owned()),
            body: "Original body with {body} literally".to_owned(),
        };

        let prompt = render_followup_prompt(
            "Current: {body}\nOriginal: {original_body}\nThread: {thread_context}",
            &context,
            &source_context,
            "Rendered thread context",
        );

        assert!(prompt.contains("Current: Please explain {thread_context} without expanding it"));
        assert!(prompt.contains("Original: Original body with {body} literally"));
        assert!(prompt.contains("Thread: Rendered thread context"));
    }

    #[test]
    fn followup_thread_context_keeps_recent_replies_when_trimmed() {
        let root = inbound_message("root-1", "Root failure");
        let mut old_reply = inbound_thread_message(
            "old-reply",
            ROOM_ID,
            "root-1",
            "old reply should be trimmed",
        );
        old_reply.created = Some(serde_json::from_str("\"2026-06-24T01:00:00Z\"").unwrap());
        let mut recent_reply =
            inbound_thread_message("recent-reply", ROOM_ID, "root-1", "recent reply must stay");
        recent_reply.created = Some(serde_json::from_str("\"2026-06-24T03:00:00Z\"").unwrap());
        let mut current = inbound_thread_message("current", ROOM_ID, "root-1", "current follow-up");
        current.created = Some(serde_json::from_str("\"2026-06-24T04:00:00Z\"").unwrap());

        let context = render_thread_context(
            &root,
            &[old_reply, recent_reply, current],
            "current",
            Some(SELF_PERSON_ID),
            170,
        );

        assert!(context.contains("Root failure"));
        assert!(context.contains("recent reply must stay"));
        assert!(!context.contains("old reply should be trimmed"));
        assert!(!context.contains("current follow-up"));
    }

    #[tokio::test]
    async fn followup_can_use_sender_allowlist_separate_from_root_trigger() {
        let state_path = unique_state_path();
        let mut config = (*test_config(state_path)).clone();
        config.server.attempt_lease_secs = 600;
        config.rooms[0].allow_all_senders = false;
        config.rooms[0].allowed_person_emails = vec!["wmejenkin@sparkbot.io".to_owned()];
        config.rooms[0].followup.enabled = true;
        config.rooms[0].followup.allowed_person_emails = vec![SENDER_EMAIL.to_owned()];
        config.validate().unwrap();
        let harness = TestHarness::with_config(Arc::new(config));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                ROOM_ID,
                &reply_marker("root-1"),
            )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "root-1",
                "@miku.gen please expand",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn followup_mention_trigger_accepts_configured_text_prefix() {
        let state_path = unique_state_path();
        let mut config = (*followup_test_config(state_path)).clone();
        config.rooms[0].prefixes = vec!["@miku.gen".to_owned()];
        config.validate().unwrap();
        let harness = TestHarness::with_config(Arc::new(config));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                ROOM_ID,
                &reply_marker("root-1"),
            )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");
        let mut followup =
            inbound_thread_message("followup-1", ROOM_ID, "root-1", "@miku.gen please expand");
        followup.mentioned_people.clear();

        let action = harness
            .app
            .process_event(message_event(followup))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("followup-reply-1"));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn top_level_message_in_followup_room_does_not_hydrate_as_followup() {
        let harness = TestHarness::with_config(followup_test_config(unique_state_path()));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("reply-1")));
        harness.runner.push_output("Top-level answer");

        let action = harness
            .app
            .process_event(message_event(inbound_message(
                "root-command-1",
                "top-level command",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("reply-1"));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.webex.get_message_requests().is_empty());
        assert_eq!(harness.webex.thread_requests(), Vec::new());
        assert!(harness.processed("root-command-1").await);
    }

    #[tokio::test]
    async fn top_level_output_room_message_does_not_hydrate_as_quoted_followup() {
        let state_path = unique_state_path();
        let mut config = (*staging_followup_test_config(state_path)).clone();
        config.rooms[0].followup.triggers = vec![FollowupTrigger::QuotedBotReply];
        let harness = TestHarness::with_config(Arc::new(config));
        let mut message = inbound_message("output-top-level-1", "ordinary output-room message");
        message.room_id = Some(OUTPUT_ROOM_ID.to_owned());

        let action = harness
            .app
            .process_event(message_event(message))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.webex.get_message_requests().is_empty());
        assert_eq!(harness.webex.thread_requests(), Vec::new());
        assert!(harness.runner.calls().is_empty());
        assert!(harness.processed("output-top-level-1").await);
    }

    #[tokio::test]
    async fn quoted_bot_reply_marker_can_trigger_followup_without_mention() {
        let state_path = unique_state_path();
        let mut config = (*followup_test_config(state_path)).clone();
        config.rooms[0].followup.triggers = vec![FollowupTrigger::QuotedBotReply];
        let harness = TestHarness::with_config(Arc::new(config));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                ROOM_ID,
                &reply_marker("root-1"),
            )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Quoted follow-up answer");
        let mut followup =
            inbound_thread_message("followup-1", ROOM_ID, "root-1", "Can you expand?");
        followup.mentioned_people.clear();
        followup.markdown = Some(format!(
            "Can you expand?\n\n{}",
            hidden_marker_comment(&reply_marker("root-1"))
        ));

        let action = harness
            .app
            .process_event(message_event(followup))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("followup-reply-1"));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn quoted_reply_payload_without_marker_is_hydrated_before_followup_check() {
        let state_path = unique_state_path();
        let mut config = (*followup_test_config(state_path)).clone();
        config.rooms[0].followup.triggers = vec![FollowupTrigger::QuotedBotReply];
        let harness = TestHarness::with_config(Arc::new(config));
        let mut hydrated =
            inbound_thread_message("followup-1", ROOM_ID, "root-1", "Can you expand?");
        hydrated.mentioned_people.clear();
        hydrated.markdown = Some(format!(
            "Can you expand?\n\n{}",
            hidden_marker_comment(&reply_marker("root-1"))
        ));
        harness.webex.push_get_message(Ok(hydrated));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                ROOM_ID,
                &reply_marker("root-1"),
            )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness
            .runner
            .push_output("Hydrated quoted follow-up answer");
        let mut followup =
            inbound_thread_message("followup-1", ROOM_ID, "root-1", "Can you expand?");
        followup.mentioned_people.clear();

        let action = harness
            .app
            .process_event(message_event(followup))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.reply_id.as_deref(), Some("followup-reply-1"));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn user_pasted_reply_marker_does_not_establish_followup_scope() {
        let state_path = unique_state_path();
        let mut config = (*staging_followup_test_config(state_path)).clone();
        config.rooms[0].followup.triggers = vec![FollowupTrigger::QuotedBotReply];
        let harness = TestHarness::with_config(Arc::new(config));
        harness.webex.push_get_message(Ok(message_with_room(
            "forward-without-marker",
            OUTPUT_ROOM_ID,
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));
        let mut followup = inbound_thread_message(
            "followup-1",
            OUTPUT_ROOM_ID,
            "forward-without-marker",
            "Can you expand?",
        );
        followup.mentioned_people.clear();
        followup.markdown = Some(format!(
            "Can you expand?\n\n{}",
            hidden_marker_comment(&reply_marker("source-1"))
        ));

        let action = harness
            .app
            .process_event(message_event(followup))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn followup_prefers_oldest_bot_reply_marker_as_source() {
        let harness = TestHarness::with_config(followup_test_config(unique_state_path()));
        let mut original_diagnosis =
            message_with_marker("bot-reply-1", ROOM_ID, &reply_marker("root-1"));
        original_diagnosis.parent_id = Some("root-1".to_owned());
        original_diagnosis.created =
            Some(serde_json::from_str("\"2026-06-24T01:00:00Z\"").unwrap());
        original_diagnosis.markdown = Some(format!(
            "Original diagnosis\n\n{}",
            hidden_marker_comment(&reply_marker("root-1"))
        ));
        let mut later_followup =
            message_with_marker("bot-reply-2", ROOM_ID, &reply_marker("followup-old"));
        later_followup.parent_id = Some("root-1".to_owned());
        later_followup.created = Some(serde_json::from_str("\"2026-06-24T02:00:00Z\"").unwrap());
        later_followup.markdown = Some(format!(
            "Later follow-up\n\n{}",
            hidden_marker_comment(&reply_marker("followup-old"))
        ));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![later_followup, original_diagnosis]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "root-1",
                "@miku.gen can you explain more?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        let calls = harness.runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .1
                .contains("Original root-1: Original Jenkins failure")
        );
        assert!(!calls[0].1.contains("Original followup-old"));
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn output_thread_missing_parent_id_is_hydrated_before_followup_check() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(inbound_thread_message(
            "followup-1",
            OUTPUT_ROOM_ID,
            "forward-1",
            "@miku.gen can you check this?",
        )));
        harness.webex.push_get_message(Ok(message_with_marker(
            "forward-1",
            OUTPUT_ROOM_ID,
            &source_marker("source-1"),
        )));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                OUTPUT_ROOM_ID,
                &reply_marker("source-1"),
            )]));
        harness.webex.push_get_message(Ok(inbound_message(
            "source-1",
            "Original production failure",
        )));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("followup-reply-1", OUTPUT_ROOM_ID)));
        harness
            .runner
            .push_output("Hydrated staging follow-up answer");
        let mut event = inbound_message("followup-1", "@miku.gen can you check this?");
        event.room_id = Some(OUTPUT_ROOM_ID.to_owned());
        event.mentioned_people = vec![SELF_PERSON_ID.to_owned()];

        let action = harness
            .app
            .process_event(message_event(event))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn mention_in_staging_output_thread_maps_back_to_source_message() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(message_with_marker(
            "forward-1",
            OUTPUT_ROOM_ID,
            &source_marker("source-1"),
        )));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                OUTPUT_ROOM_ID,
                &reply_marker("source-1"),
            )]));
        harness.webex.push_get_message(Ok(inbound_message(
            "source-1",
            "Original production failure",
        )));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("followup-reply-1", OUTPUT_ROOM_ID)));
        harness.runner.push_output("Staging follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                OUTPUT_ROOM_ID,
                "forward-1",
                "@miku.gen can you check the downstream job?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        let calls = harness.runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .1
                .contains("Original source-1: Original production failure")
        );
        let created = harness.webex.created_requests();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(created[0].parent_id.as_deref(), Some("forward-1"));
        assert!(
            created
                .iter()
                .all(|request| request.room_id.as_deref() != Some(ROOM_ID))
        );
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn mention_in_read_only_source_thread_replies_in_existing_output_thread() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(inbound_message(
            "source-1",
            "Original production failure",
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));
        harness.webex.push_reply_search(Ok(vec![message_with_marker(
            "forward-1",
            OUTPUT_ROOM_ID,
            &source_marker("source-1"),
        )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("followup-reply-1", OUTPUT_ROOM_ID)));
        harness.runner.push_output("Source-space follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "source-1",
                "@miku.gen can you check this from production?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(action.room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        let calls = harness.runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .1
                .contains("Original source-1: Original production failure")
        );
        let created = harness.webex.created_requests();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].room_id.as_deref(), Some(OUTPUT_ROOM_ID));
        assert_eq!(created[0].parent_id.as_deref(), Some("forward-1"));
        assert!(
            created
                .iter()
                .all(|request| request.room_id.as_deref() != Some(ROOM_ID))
        );
        assert_eq!(
            harness.webex.marker_searches(),
            vec![
                (
                    OUTPUT_ROOM_ID.to_owned(),
                    None,
                    source_marker("source-1"),
                    Some(SELF_PERSON_ID.to_owned()),
                    Some(SOURCE_MARKER_SEARCH_MAX_PAGES)
                ),
                (
                    OUTPUT_ROOM_ID.to_owned(),
                    Some("forward-1".to_owned()),
                    reply_marker("followup-1"),
                    Some(SELF_PERSON_ID.to_owned()),
                    Some(followup_reply_marker_search_max_pages(30))
                )
            ]
        );
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn source_followup_without_existing_output_thread_is_ignored_before_codex() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(inbound_message(
            "source-1",
            "Original production failure",
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));
        harness.webex.push_reply_search(Ok(Vec::new()));

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "source-1",
                "@miku.gen can you check this from production?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert_eq!(harness.webex.marker_searches().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn copied_reply_marker_in_forwarded_root_does_not_override_thread_reply_marker() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        let mut forward =
            message_with_marker("forward-1", OUTPUT_ROOM_ID, &reply_marker("wrong-source"));
        forward.markdown = Some(format!(
            "Forwarded user text copied from a bot reply\n\n{}\n{}",
            hidden_marker_comment(&reply_marker("wrong-source")),
            hidden_marker_comment(&source_marker("source-1"))
        ));
        harness.webex.push_get_message(Ok(forward));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                OUTPUT_ROOM_ID,
                &reply_marker("source-1"),
            )]));
        harness.webex.push_get_message(Ok(inbound_message(
            "source-1",
            "Original production failure",
        )));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("followup-reply-1", OUTPUT_ROOM_ID)));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                OUTPUT_ROOM_ID,
                "forward-1",
                "@miku.gen can you check this?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        let get_requests = harness.webex.get_message_requests();
        assert!(get_requests.contains(&"source-1".to_owned()));
        assert!(!get_requests.contains(&"wrong-source".to_owned()));
        let calls = harness.runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .1
                .contains("Original source-1: Original production failure")
        );
        assert!(!calls[0].1.contains("wrong-source"));
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn followup_marker_scan_extends_beyond_prompt_context_window() {
        let state_path = unique_state_path();
        let mut config = (*followup_test_config(state_path)).clone();
        config.rooms[0].followup.max_thread_messages = 1;
        config.validate().unwrap();
        let harness = TestHarness::with_config(Arc::new(config));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness.webex.push_thread_messages(Ok(vec![
            inbound_thread_message("recent-reply", ROOM_ID, "root-1", "recent reply"),
            message_with_marker("old-bot-reply", ROOM_ID, &reply_marker("root-1")),
        ]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "root-1",
                "@miku.gen can you explain more?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(
            harness.webex.thread_requests(),
            vec![(
                ROOM_ID.to_owned(),
                "root-1".to_owned(),
                FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES
            )]
        );
        assert_eq!(harness.runner.calls().len(), 1);
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn followup_reply_reconciliation_uses_configured_marker_window() {
        let state_path = unique_state_path();
        let mut config = (*followup_test_config(state_path)).clone();
        config.server.attempt_lease_secs = 900;
        config.rooms[0].followup.max_thread_messages = 350;
        config.validate().unwrap();
        let harness = TestHarness::with_config(Arc::new(config));
        harness
            .webex
            .push_get_message(Ok(inbound_message("root-1", "Original Jenkins failure")));
        harness
            .webex
            .push_thread_messages(Ok(vec![message_with_marker(
                "bot-reply-1",
                ROOM_ID,
                &reply_marker("root-1"),
            )]));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(reply_message("followup-reply-1")));
        harness.runner.push_output("Follow-up answer");

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                ROOM_ID,
                "root-1",
                "@miku.gen can you explain more?",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "replied");
        assert_eq!(
            harness.webex.marker_searches(),
            vec![(
                ROOM_ID.to_owned(),
                Some("root-1".to_owned()),
                reply_marker("followup-1"),
                Some(SELF_PERSON_ID.to_owned()),
                Some(followup_reply_marker_search_max_pages(350))
            )]
        );
        assert_eq!(
            harness.webex.thread_requests(),
            vec![(ROOM_ID.to_owned(), "root-1".to_owned(), 350)]
        );
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn output_thread_without_existing_bot_marker_is_not_followup() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(message_with_room(
            "forward-without-marker",
            OUTPUT_ROOM_ID,
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                OUTPUT_ROOM_ID,
                "forward-without-marker",
                "@miku.gen should not run yet",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn user_pasted_source_marker_does_not_establish_followup_scope() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(message_with_room(
            "forward-without-marker",
            OUTPUT_ROOM_ID,
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));
        let mut followup = inbound_thread_message(
            "followup-1",
            OUTPUT_ROOM_ID,
            "forward-without-marker",
            "@miku.gen should not run from pasted source marker",
        );
        followup.markdown = Some(format!(
            "@miku.gen should not run\n\n{}",
            hidden_marker_comment(&source_marker("source-1"))
        ));

        let action = harness
            .app
            .process_event(message_event(followup))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn output_thread_with_source_marker_but_no_bot_reply_marker_is_not_followup() {
        let harness = TestHarness::with_config(staging_followup_test_config(unique_state_path()));
        harness.webex.push_get_message(Ok(message_with_marker(
            "forward-1",
            OUTPUT_ROOM_ID,
            &source_marker("source-replay-1"),
        )));
        harness.webex.push_thread_messages(Ok(Vec::new()));

        let action = harness
            .app
            .process_event(message_event(inbound_thread_message(
                "followup-1",
                OUTPUT_ROOM_ID,
                "forward-1",
                "@miku.gen should not retry forever",
            )))
            .await
            .unwrap();

        assert_eq!(action.action, "ignored");
        assert_eq!(action.reason.as_deref(), Some("not_followup"));
        assert!(harness.runner.calls().is_empty());
        assert!(harness.webex.created_requests().is_empty());
        assert!(harness.processed("followup-1").await);
    }

    #[tokio::test]
    async fn old_staging_source_uses_unbounded_source_marker_search() {
        let harness = TestHarness::with_config(staging_test_config(unique_state_path()));
        let source_marker = source_marker("message-1");
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("forward-1", OUTPUT_ROOM_ID)));
        harness.webex.push_reply_search(Ok(Vec::new()));
        harness
            .webex
            .push_create_result(Ok(message_with_room("reply-1", OUTPUT_ROOM_ID)));
        harness.runner.push_output("done");
        let mut message = inbound_message("message-1", "old Jenkins failure");
        message.created = Some(serde_json::from_str("\"1970-01-01T00:00:00Z\"").unwrap());

        harness
            .app
            .process_event(message_event(message))
            .await
            .unwrap();

        let searches = harness.webex.marker_searches();
        assert_eq!(
            searches[0],
            (
                OUTPUT_ROOM_ID.to_owned(),
                None,
                source_marker,
                Some(SELF_PERSON_ID.to_owned()),
                None
            )
        );
    }

    #[tokio::test]
    async fn read_only_source_guard_blocks_writes_to_source_room() {
        let harness = TestHarness::with_config(staging_test_config(unique_state_path()));

        let error = harness
            .app
            .create_message(&top_level_markdown_message(ROOM_ID, "must not write"))
            .await
            .unwrap_err();

        match error {
            WebexCallError::WriteBlocked(room_id) => assert_eq!(room_id, ROOM_ID),
            other => panic!("unexpected error: {other}"),
        }
        assert!(harness.webex.created_requests().is_empty());
    }

    #[test]
    fn bot_action_serializes_reason() {
        let action = BotAction::ignored(
            "not_mentioned",
            Some("message-1".to_owned()),
            Some("room-1".to_owned()),
        );
        let value = serde_json::to_value(action).unwrap();

        assert_eq!(value["action"], "ignored");
        assert_eq!(value["reason"], "not_mentioned");
    }

    #[test]
    fn merge_message_fills_missing_fields() {
        let mut target = Message {
            id: Some("message-1".to_owned()),
            ..Message::default()
        };
        let hydrated = Message {
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            mentioned_people: vec!["bot-person".to_owned()],
            ..Message::default()
        };

        merge_message(&mut target, hydrated);

        assert_eq!(target.room_id.as_deref(), Some("room-1"));
        assert_eq!(target.person_id.as_deref(), Some("person-1"));
        assert_eq!(target.mentioned_people, vec!["bot-person"]);
    }

    #[test]
    fn metadata_only_message_needs_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            ..Message::default()
        };

        assert!(message_needs_hydration(&policy, &message));
    }

    #[test]
    fn complete_mention_message_does_not_need_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            person_email: Some("joey@example.com".to_owned()),
            markdown: Some("@bot run".to_owned()),
            mentioned_people: vec!["bot-person".to_owned()],
            ..Message::default()
        };

        assert!(!message_needs_hydration(&policy, &message));
    }

    #[test]
    fn prefix_message_does_not_need_mentions_to_skip_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            trigger: TriggerMode::Prefix,
            prefixes: vec!["/codex".to_owned()],
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            person_email: Some("joey@example.com".to_owned()),
            text: Some("/codex run".to_owned()),
            ..Message::default()
        };

        assert!(!message_needs_hydration(&policy, &message));
    }

    #[test]
    fn reply_message_uses_markdown_body() {
        let value =
            serde_json::to_value(reply_markdown_message("room-1", "parent-1", "**ok**")).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "roomId": "room-1",
                "parentId": "parent-1",
                "markdown": "**ok**"
            })
        );
    }

    #[test]
    fn reply_markdown_escapes_webex_mentions() {
        assert_eq!(
            sanitize_reply_markdown("hello <@all> and <@person:123>"),
            "hello &lt;@all> and &lt;@person:123>"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_reply_is_rendered_deterministically() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "the failed job could not find any nodes to run the ARM conformance task. Ignore the wrapper failure.",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** the failed job could not find any nodes to run the ARM conformance task [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_allows_inline_exact_excerpt() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure prevented the ARM conformance task from starting",
            "excerpt": "Still waiting to schedule task; no agents are available",
            "excerpt_format": "inline_code",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure prevented the ARM conformance task from starting [log](<https://jenkins.example/job/foo/1/console>)\n`Still waiting to schedule task; no agents are available`"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_allows_block_quote_exact_excerpt() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "the failed trigger job did not start because no ARM executor was available",
            "excerpt": "Trigger build failed before dispatch\nNo nodes are available",
            "excerpt_format": "block_quote",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** the failed trigger job did not start because no ARM executor was available [log](<https://jenkins.example/job/foo/1/console>)\n> Trigger build failed before dispatch\n> No nodes are available"
        );
    }

    #[test]
    fn jenkins_followup_json_answers_without_diagnosis_prefix() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "answer": "No Jenkins agent machine, IP address, or username was assigned because Jenkins could not find any nodes to run the job.",
            "include_evidence": true,
            "excerpt": "Failed: cannot find any nodes to run the job",
            "excerpt_format": "inline_code",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsFollowupJson, output, Some(context)),
            "No Jenkins agent machine, IP address, or username was assigned because Jenkins could not find any nodes to run the job [log](<https://jenkins.example/job/foo/1/console>)\n`Failed: cannot find any nodes to run the job`"
        );
    }

    #[test]
    fn jenkins_followup_json_ignores_log_and_excerpt_without_evidence_gate() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "answer": "No Jenkins agent machine, IP address, or username was assigned.",
            "excerpt": "Failed: cannot find any nodes to run the job",
            "excerpt_format": "inline_code",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsFollowupJson, output, Some(context)),
            "No Jenkins agent machine, IP address, or username was assigned"
        );
    }

    #[test]
    fn jenkins_followup_json_does_not_add_log_or_excerpt_when_omitted() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "answer": "No Jenkins agent machine, IP address, or username was assigned."
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsFollowupJson, output, Some(context)),
            "No Jenkins agent machine, IP address, or username was assigned"
        );
    }

    #[test]
    fn invalid_jenkins_followup_json_uses_followup_fallback() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsFollowupJson, "not json", Some(context)),
            "I could not parse the follow-up answer"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_defaults_invalid_excerpt_format() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure prevented the ARM conformance task from starting",
            "excerpt": "No agents are available",
            "excerpt_format": "unexpected",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure prevented the ARM conformance task from starting [log](<https://jenkins.example/job/foo/1/console>)\n`No agents are available`"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_defaults_null_excerpt_format() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure prevented the ARM conformance task from starting",
            "excerpt": "No agents are available",
            "excerpt_format": null,
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure prevented the ARM conformance task from starting [log](<https://jenkins.example/job/foo/1/console>)\n`No agents are available`"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_reply_accepts_fenced_json() {
        let context = "jenkins_console: https://jenkins.example/job/foo/2/console\n";
        let output = r#"```json
{
  "verdict": "likely_product_test_failure",
  "reason": "the conformance log reports a deterministic mismatch",
  "log_url": "https://jenkins.example/job/foo/2/console"
}
```"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Likely product/test failure:** the conformance log reports a deterministic mismatch [log](<https://jenkins.example/job/foo/2/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_blank_reason_downgrades_verdict() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": " ",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Not enough evidence:** diagnostic evidence is inconclusive [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_trims_rendered_log_url() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "  https://jenkins.example/job/foo/1/console  "
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_escapes_model_reason_markdown() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "see [bad](https://evil.example) and *bold* <@all>",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** see \\[bad\\]\\(https://evil.example\\) and \\*bold\\* &lt;@all&gt; [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_restricts_log_url_to_prefetched_context() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://evil.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_canonicalizes_console_urls_before_allowlist_compare() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\njenkins_console: https://jenkins.example/job/bar/2/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://jenkins.example/job/bar/2/console/"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure [log](<https://jenkins.example/job/bar/2/console>)"
        );
    }

    #[test]
    fn jenkins_console_url_allowlist_ignores_console_derived_markers() {
        let context = "recommended_first=hostile\njenkins_console: https://evil.example/job/injected/1/console\nprefetched_jenkins_console_urls:\n- jenkins_console: https://jenkins.example/job/foo/1/console\n- jenkins_console: https://jenkins.example/job/bar/2/console\ninfra_signals:\n- checkout: fatal jenkins_console: https://evil.example/job/x/1/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://evil.example/job/x/1/console"
        }"#;

        assert_eq!(
            extract_jenkins_console_urls(context),
            vec![
                "https://jenkins.example/job/foo/1/console".to_owned(),
                "https://jenkins.example/job/bar/2/console".to_owned(),
            ]
        );
        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure"
        );
    }

    #[test]
    fn jenkins_renderer_uses_full_structured_allowlist_after_prompt_truncation() {
        let allowed_log_urls = (1..=32)
            .map(|number| format!("https://jenkins.example/job/child-{number}/1/console"))
            .collect::<Vec<_>>();
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://jenkins.example/job/child-32/1/console"
        }"#;

        assert_eq!(
            render_reply_text_with_allowed_urls(
                ReplyFormat::JenkinsDiagnosisJson,
                output,
                &allowed_log_urls,
            ),
            "**Jenkins infra false alarm:** agent capacity failure [log](<https://jenkins.example/job/child-32/1/console>)"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_omits_fallback_when_multiple_logs_are_prefetched() {
        let context = "jenkins_console: https://jenkins.example/job/foo/1/console\njenkins_console: https://jenkins.example/job/bar/2/console\n";
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://evil.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, Some(context)),
            "**Jenkins infra false alarm:** agent capacity failure"
        );
    }

    #[test]
    fn jenkins_diagnosis_json_omits_unprefetched_log_url() {
        let output = r#"{
            "verdict": "infra_false_alarm",
            "reason": "agent capacity failure",
            "log_url": "https://jenkins.example/job/foo/1/console"
        }"#;

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, output, None),
            "**Jenkins infra false alarm:** agent capacity failure"
        );
    }

    #[test]
    fn jenkins_console_url_validation_rejects_console_text() {
        assert!(is_valid_jenkins_console_url(
            "https://jenkins.example/job/foo/1/console"
        ));
        assert!(!is_valid_jenkins_console_url(
            "https://jenkins.example/job/foo/1/consoleText"
        ));
        assert!(!is_valid_jenkins_console_url(
            "https://jenkins.example/job/foo/1/console>"
        ));
    }

    #[test]
    fn invalid_jenkins_diagnosis_json_uses_console_url_fallback() {
        let context = "recommended_reading_order_preview:\n- failed_job: foo#1\n  jenkins_console: https://jenkins.example/job/foo/1/console\n";

        assert_eq!(
            render_reply_text(ReplyFormat::JenkinsDiagnosisJson, "not json", Some(context),),
            "**Not enough evidence:** Codex did not return valid diagnosis JSON [log](<https://jenkins.example/job/foo/1/console>)"
        );
    }

    #[test]
    fn safe_path_fragment_truncates_without_suffix() {
        let fragment = safe_path_fragment(&format!("{}{}", "a".repeat(200), " / bad"));

        assert_eq!(fragment.len(), 160);
        assert!(!fragment.contains("[truncated]"));
        assert!(!fragment.chars().any(char::is_whitespace));
    }

    #[test]
    fn jenkins_artifact_attempt_dirs_are_unique_workspace_paths() {
        let codex_cwd = unique_state_path().with_extension("codex-cwd");
        let first = jenkins_artifact_attempt_dir(&codex_cwd, "message-1");
        let second = jenkins_artifact_attempt_dir(&codex_cwd, "message-1");
        let process_root = jenkins_artifact_process_root(&codex_cwd);

        assert_ne!(first, second);
        assert!(first.is_absolute());
        assert!(first.starts_with(&process_root));
        assert!(
            process_root.starts_with(
                absolute_lexical(&codex_cwd)
                    .join(".codex-tmp")
                    .join("jenkins-diagnostics")
            )
        );
        let process_dir = format!("process-{}", std::process::id());
        assert!(process_root.ends_with(Path::new(&process_dir)));
        assert_eq!(jenkins_artifact_dir(&first, 1), first.join("url-1"));
    }

    #[tokio::test]
    async fn prune_jenkins_artifact_dirs_keeps_recent_message_dirs() {
        let root = unique_state_path().with_extension("jenkins-retention-root");
        for index in 0..(JENKINS_ARTIFACT_RETENTION_LIMIT + 3) {
            fs::create_dir_all(root.join(format!("message-{index}"))).unwrap();
        }

        prune_jenkins_artifact_dirs_in(&root).await.unwrap();

        let remaining = fs::read_dir(&root).unwrap().count();
        assert_eq!(remaining, JENKINS_ARTIFACT_RETENTION_LIMIT);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_private_jenkins_artifact_dirs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_state_path().with_extension("jenkins-private-dir");

        create_private_dir(&dir).await.unwrap();

        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_jenkins_artifact_roots_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let codex_cwd = unique_state_path().with_extension("codex-cwd");
        let codex_tmp_root = absolute_lexical(&codex_cwd).join(".codex-tmp");
        let base_root = jenkins_artifact_base_root(&codex_cwd);
        let process_root = ensure_jenkins_artifact_base_root(&codex_cwd).await.unwrap();

        for path in [&codex_tmp_root, &base_root, &process_root] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "unexpected mode for {}", path.display());
        }
        fs::remove_dir_all(codex_cwd).unwrap();
    }

    #[tokio::test]
    async fn prune_jenkins_artifact_dirs_skips_active_dirs() {
        let root = unique_state_path().with_extension("jenkins-active-root");
        for index in 0..(JENKINS_ARTIFACT_RETENTION_LIMIT + 3) {
            fs::create_dir_all(root.join(format!("message-{index:02}"))).unwrap();
        }
        let active = root.join(format!(
            "message-{:02}",
            JENKINS_ARTIFACT_RETENTION_LIMIT + 2
        ));
        register_jenkins_artifact_dir(&active);

        prune_jenkins_artifact_dirs_in(&root).await.unwrap();

        assert!(active.exists());
        unregister_jenkins_artifact_dir(&active);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn prune_jenkins_artifact_dirs_removes_dead_process_roots() {
        let codex_cwd = unique_state_path().with_extension("codex-cwd");
        let base_root = jenkins_artifact_base_root(&codex_cwd);
        let current_root = jenkins_artifact_process_root(&codex_cwd);
        let stale_root = base_root.join("process-99999999");
        fs::create_dir_all(stale_root.join("message-1")).unwrap();
        fs::create_dir_all(&current_root).unwrap();

        prune_jenkins_artifact_dirs(&codex_cwd).await.unwrap();

        assert!(!stale_root.exists());
        assert!(current_root.exists());
        fs::remove_dir_all(codex_cwd).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prune_jenkins_artifact_dirs_ignores_already_removed_entries() {
        let root = unique_state_path().with_extension("jenkins-race-root");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(root.join("missing-target"), root.join("broken-entry")).unwrap();

        prune_jenkins_artifact_dirs_in(&root).await.unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn jenkins_artifact_cleanup_guard_removes_artifacts_on_drop() {
        let dir = unique_state_path().with_extension("jenkins-drop-guard");
        create_private_dir(&dir).await.unwrap();
        register_jenkins_artifact_dir(&dir);

        {
            let _guard = JenkinsArtifactCleanupGuard::new(dir.clone());
        }

        for _ in 0..50 {
            if !dir.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!dir.exists());
        assert!(
            !active_jenkins_artifact_dirs()
                .lock()
                .unwrap()
                .contains(&dir)
        );
    }

    #[test]
    fn prepared_reply_includes_reference_marker_within_limit() {
        let marker = reply_marker("message-1");
        let reply = prepare_reply_markdown(&"x".repeat(7_000), &marker);

        assert!(reply.contains(&marker));
        assert!(reply.chars().count() <= REPLY_LIMIT_CHARS);
    }

    #[test]
    fn forwarded_source_markdown_keeps_marker_within_byte_limit() {
        let marker = source_marker("message-1");
        let message = Message {
            markdown: Some("測".repeat(5_000)),
            person_email: Some("sender@example.com".to_owned()),
            ..Message::default()
        };

        let markdown = prepare_forward_markdown(&message, ROOM_ID, "message-1", &marker);

        assert!(markdown.contains(&marker));
        assert!(markdown.contains("[truncated]"));
        assert!(markdown.len() <= FORWARD_MARKDOWN_LIMIT_BYTES);
        assert!(markdown.is_char_boundary(markdown.len()));
    }

    #[test]
    fn reply_marker_hex_encodes_message_id() {
        let marker = reply_marker("message-->1");

        assert_eq!(marker, "wgb-ref:6d6573736167652d2d3e31");
        assert!(!marker.contains("message-->1"));
    }

    #[test]
    fn reply_marker_match_requires_self_identity_when_known() {
        let marker = reply_marker("message-1");
        let matching = Message {
            markdown: Some(format!("done\n\n{marker}")),
            person_id: Some("self-person".to_owned()),
            ..Message::default()
        };
        let wrong_sender = Message {
            markdown: Some(marker.clone()),
            person_id: Some("other-person".to_owned()),
            ..Message::default()
        };

        assert!(reply_matches_marker(
            &matching,
            &marker,
            Some("self-person")
        ));
        assert!(!reply_matches_marker(
            &wrong_sender,
            &marker,
            Some("self-person")
        ));
    }

    #[test]
    fn extract_jenkins_urls_deduplicates_and_trims_punctuation() {
        let body = "job <https://engci-private-sjc.cisco.com/jenkins/job/a/1/>, \
            duplicate https://engci-private-sjc.cisco.com/jenkins/job/a/1/. \
            next https://engci-private-sjc.cisco.com/jenkins/job/b/2/)";

        assert_eq!(
            extract_jenkins_urls(body, 2),
            vec![
                "https://engci-private-sjc.cisco.com/jenkins/job/a/1/".to_owned(),
                "https://engci-private-sjc.cisco.com/jenkins/job/b/2/".to_owned()
            ]
        );
    }

    #[test]
    fn append_prefetched_context_keeps_original_prompt() {
        let prompt = append_prefetched_context("base prompt", "diagnostics");

        assert_eq!(prompt, "base prompt\n\ndiagnostics");
    }

    #[test]
    fn compact_jenkins_helper_output_drops_console_tail() {
        let output =
            "jenkins_readonly=true\ninfra_signals:\n- dns failure\n\nconsole_tail:\nraw log";

        assert_eq!(
            compact_jenkins_helper_output(output),
            "jenkins_readonly=true\ninfra_signals:\n- dns failure"
        );
    }

    #[tokio::test]
    async fn jenkins_helper_runs_from_script_directory() {
        let helper_dir = unique_state_path().with_extension("helper-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        let artifact_dir = helper_dir.join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            &script,
            "printf 'pwd=%s\\n' \"$PWD\"\nprintf 'args=%s\\n' \"$*\"\n",
        )
        .unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let config = webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script: script.clone(),
            env_file,
            timeout_secs: 5,
            max_urls: 1,
            output_limit_chars: 1024,
            enabled: true,
        };

        let output = run_jenkins_context_helper(
            &config,
            "https://engci-private-sjc.cisco.com/job/1",
            &artifact_dir,
        )
        .await
        .unwrap();

        assert!(output.contains(&format!("pwd={}", helper_dir.display())));
        assert!(output.contains("--max-total-log-bytes 104857600"));
        assert!(output.contains("--max-log-bytes-per-node 10485760"));
        assert!(output.contains("--max-api-response-bytes 1048576"));
        assert!(output.contains("--max-nodes 32"));
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[tokio::test]
    async fn jenkins_helper_uses_scrubbed_environment() {
        unsafe {
            env::set_var("WEBEX_ACCESS_TOKEN", "secret-webex-token");
            env::set_var("WEBEX_SIDECAR_TOKEN", "secret-sidecar-token");
        }
        let helper_dir = unique_state_path().with_extension("helper-env-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        let artifact_dir = helper_dir.join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            &script,
            "printf 'webex=%s\\n' \"${WEBEX_ACCESS_TOKEN-unset}\"\n\
             printf 'sidecar=%s\\n' \"${WEBEX_SIDECAR_TOKEN-unset}\"\n",
        )
        .unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let config = webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script,
            env_file,
            timeout_secs: 5,
            max_urls: 1,
            output_limit_chars: 1024,
            enabled: true,
        };

        let output = run_jenkins_context_helper(
            &config,
            "https://engci-private-sjc.cisco.com/job/1",
            &artifact_dir,
        )
        .await
        .unwrap();

        assert!(output.contains("webex=unset"));
        assert!(output.contains("sidecar=unset"));
        assert!(!output.contains("secret-webex-token"));
        assert!(!output.contains("secret-sidecar-token"));
        unsafe {
            env::remove_var("WEBEX_ACCESS_TOKEN");
            env::remove_var("WEBEX_SIDECAR_TOKEN");
        }
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[tokio::test]
    async fn jenkins_helper_output_is_bounded_before_compaction() {
        let helper_dir = unique_state_path().with_extension("helper-output-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        let artifact_dir = helper_dir.join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(&script, "/usr/bin/yes x | /usr/bin/head -c 300000\n").unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let config = webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script,
            env_file,
            timeout_secs: 5,
            max_urls: 1,
            output_limit_chars: 8,
            enabled: true,
        };

        let output = run_jenkins_context_helper(
            &config,
            "https://engci-private-sjc.cisco.com/job/1",
            &artifact_dir,
        )
        .await
        .unwrap();

        assert!(output.contains("[truncated]"));
        assert!(output.len() < 263_000);
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn jenkins_helper_writes_artifacts_with_private_umask() {
        use std::os::unix::fs::PermissionsExt;

        let helper_dir = unique_state_path().with_extension("helper-umask-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        let artifact_dir = helper_dir.join("artifacts");
        create_private_dir(&artifact_dir).await.unwrap();
        fs::write(
            &script,
            "artifact_dir=\n\
             while [ \"$#\" -gt 0 ]; do\n\
             case \"$1\" in\n\
             --artifact-dir) artifact_dir=\"$2\"; shift 2 ;;\n\
             *) shift ;;\n\
             esac\n\
             done\n\
             printf secret > \"$artifact_dir/secret.txt\"\n",
        )
        .unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let config = webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script,
            env_file,
            timeout_secs: 5,
            max_urls: 1,
            output_limit_chars: 1024,
            enabled: true,
        };

        run_jenkins_context_helper(
            &config,
            "https://engci-private-sjc.cisco.com/job/1",
            &artifact_dir,
        )
        .await
        .unwrap();

        let mode = fs::metadata(artifact_dir.join("secret.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[tokio::test]
    async fn jenkins_helper_kills_process_group_before_joining_pipes() {
        let helper_dir = unique_state_path().with_extension("helper-pipe-dir");
        fs::create_dir_all(&helper_dir).unwrap();
        let script = helper_dir.join("helper.sh");
        let env_file = helper_dir.join("jenkins.env");
        let artifact_dir = helper_dir.join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(&script, "sleep 5 &\nprintf 'parent_done\\n'\n").unwrap();
        fs::write(&env_file, "JENKINS_TOKEN=test\n").unwrap();
        let config = webex_generic_account_bot::JenkinsContextConfig {
            node_bin: "/bin/sh".to_owned(),
            script,
            env_file,
            timeout_secs: 1,
            max_urls: 1,
            output_limit_chars: 1024,
            enabled: true,
        };

        let output = timeout(
            Duration::from_secs(2),
            run_jenkins_context_helper(
                &config,
                "https://engci-private-sjc.cisco.com/job/1",
                &artifact_dir,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(output.contains("parent_done"));
        fs::remove_dir_all(helper_dir).unwrap();
    }

    #[test]
    fn webex_404_errors_stop_retries() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(404, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    #[test]
    fn parent_message_listing_404_is_empty_only_for_parent_searches() {
        let error = WebexError::Api(Box::new(api_error(404, None)));

        assert!(parent_message_listing_is_empty(Some("parent-1"), &error));
        assert!(!parent_message_listing_is_empty(None, &error));
    }

    #[test]
    fn webex_429_errors_use_retry_after() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(
            429,
            Some(Duration::from_secs(42)),
        ))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(42))
        );
    }

    #[test]
    fn webex_401_errors_retry_for_token_reload() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(401, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_403_errors_stop_retries() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(403, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    #[test]
    fn webex_timeout_errors_retry_with_default_lease() {
        assert_eq!(
            classify_webex_failure(&WebexCallError::TimedOut, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_timeout_errors_retry_to_avoid_lost_replies() {
        assert_eq!(
            classify_webex_create_failure(&WebexCallError::TimedOut, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_server_errors_retry() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(503, None))));

        assert_eq!(
            classify_webex_create_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_permanent_client_errors_stop() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(404, None))));

        assert_eq!(
            classify_webex_create_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    fn api_error(status: u16, retry_after: Option<Duration>) -> ApiError {
        ApiError {
            status,
            reason: "status".to_owned(),
            message: None,
            tracking_id: None,
            retry_after,
            details: Vec::new(),
            body: None,
        }
    }

    struct TestHarness {
        app: BotApp,
        webex: Arc<FakeWebex>,
        runner: Arc<FakeRunner>,
        state_path: PathBuf,
    }

    impl TestHarness {
        fn new() -> Self {
            let state_path = unique_state_path();
            Self::with_config(test_config(state_path))
        }

        fn with_config(config: Arc<BotConfig>) -> Self {
            let state_path = config.state_file.clone();
            let state = JsonlStateStore::load(config.state_file.clone()).unwrap();
            let webex = Arc::new(FakeWebex::default());
            let runner = Arc::new(FakeRunner::default());
            let app = BotApp {
                config,
                sidecar_token: None,
                self_person_id: Some(SELF_PERSON_ID.to_owned()),
                webex: webex.clone(),
                state: Mutex::new(state),
                runner: runner.clone(),
                request_slots: Arc::new(Semaphore::new(4)),
            };
            Self {
                app,
                webex,
                runner,
                state_path,
            }
        }

        async fn processed(&self, message_id: &str) -> bool {
            self.app
                .state
                .lock()
                .await
                .contains_processed_message(message_id)
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.state_path);
        }
    }

    #[derive(Default)]
    struct FakeWebex {
        get_message_results: StdMutex<VecDeque<Result<Message, WebexCallError>>>,
        get_message_requests: StdMutex<Vec<String>>,
        thread_results: StdMutex<VecDeque<Result<Vec<Message>, WebexCallError>>>,
        marker_search_results: StdMutex<VecDeque<Result<Vec<Message>, WebexCallError>>>,
        create_results: StdMutex<VecDeque<Result<Message, WebexCallError>>>,
        created_requests: StdMutex<Vec<CreateMessage>>,
        thread_requests: StdMutex<Vec<(String, String, usize)>>,
        marker_search_requests: StdMutex<Vec<MarkerSearchRequest>>,
    }

    impl FakeWebex {
        fn push_get_message(&self, result: Result<Message, WebexCallError>) {
            self.get_message_results.lock().unwrap().push_back(result);
        }

        fn get_message_requests(&self) -> Vec<String> {
            self.get_message_requests.lock().unwrap().clone()
        }

        fn push_thread_messages(&self, result: Result<Vec<Message>, WebexCallError>) {
            self.thread_results.lock().unwrap().push_back(result);
        }

        fn push_reply_search(&self, result: Result<Vec<Message>, WebexCallError>) {
            self.marker_search_results.lock().unwrap().push_back(result);
        }

        fn push_create_result(&self, result: Result<Message, WebexCallError>) {
            self.create_results.lock().unwrap().push_back(result);
        }

        fn created_requests(&self) -> Vec<CreateMessage> {
            self.created_requests.lock().unwrap().clone()
        }

        fn marker_searches(&self) -> Vec<MarkerSearchRequest> {
            self.marker_search_requests.lock().unwrap().clone()
        }

        fn thread_requests(&self) -> Vec<(String, String, usize)> {
            self.thread_requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WebexApi for FakeWebex {
        async fn me(&self) -> Result<Person, WebexCallError> {
            Ok(Person {
                id: Some(SELF_PERSON_ID.to_owned()),
                ..Person::default()
            })
        }

        async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError> {
            self.get_message_requests
                .lock()
                .unwrap()
                .push(message_id.to_owned());
            self.get_message_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected message hydration in test"))
        }

        async fn list_thread_messages(
            &self,
            room_id: &str,
            parent_id: &str,
            limit: usize,
        ) -> Result<Vec<Message>, WebexCallError> {
            self.thread_requests.lock().unwrap().push((
                room_id.to_owned(),
                parent_id.to_owned(),
                limit,
            ));
            self.thread_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
        }

        async fn create_message(&self, request: &CreateMessage) -> Result<Message, WebexCallError> {
            self.created_requests.lock().unwrap().push(request.clone());
            self.create_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(reply_message("reply-default")))
        }

        async fn find_message_by_marker(
            &self,
            room_id: &str,
            parent_id: Option<&str>,
            marker: &str,
            self_person_id: Option<&str>,
            max_pages: Option<usize>,
        ) -> Result<Option<Message>, WebexCallError> {
            self.marker_search_requests.lock().unwrap().push((
                room_id.to_owned(),
                parent_id.map(ToOwned::to_owned),
                marker.to_owned(),
                self_person_id.map(ToOwned::to_owned),
                max_pages,
            ));
            self.marker_search_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
                .map(|replies| {
                    replies
                        .into_iter()
                        .find(|reply| reply_matches_marker(reply, marker, self_person_id))
                })
        }
    }

    #[derive(Default)]
    struct FakeRunner {
        outputs: StdMutex<VecDeque<std::result::Result<CodexRunOutput, String>>>,
        calls: StdMutex<Vec<(String, String)>>,
    }

    impl FakeRunner {
        fn push_output(&self, final_message: impl Into<String>) {
            self.outputs.lock().unwrap().push_back(Ok(CodexRunOutput {
                final_message: final_message.into(),
                stdout: String::new(),
                stderr: String::new(),
            }));
        }

        fn push_error(&self, message: impl Into<String>) {
            self.outputs.lock().unwrap().push_back(Err(message.into()));
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CodexRunner for FakeRunner {
        async fn run(
            &self,
            _config: &webex_generic_account_bot::config::CodexConfig,
            prompt: &str,
            message_id: &str,
        ) -> Result<CodexRunOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((message_id.to_owned(), prompt.to_owned()));
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(CodexRunOutput {
                        final_message: "Codex reply".to_owned(),
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                })
                .map_err(|message| anyhow!(message))
        }
    }

    fn test_config(state_path: PathBuf) -> Arc<BotConfig> {
        let config = BotConfig {
            state_file: state_path,
            self_person_id: Some(SELF_PERSON_ID.to_owned()),
            server: webex_generic_account_bot::ServerConfig {
                allow_unauthenticated: true,
                attempt_lease_secs: 300,
                ..webex_generic_account_bot::ServerConfig::default()
            },
            codex: webex_generic_account_bot::CodexConfig {
                cwd: PathBuf::from("/tmp/webex-generic-account-bot-work"),
                codex_home: PathBuf::from("/tmp/webex-generic-account-bot-codex-home"),
                timeout_secs: 30,
                ..webex_generic_account_bot::CodexConfig::default()
            },
            rooms: vec![webex_generic_account_bot::RoomPolicy {
                room_id: ROOM_ID.to_owned(),
                trigger: TriggerMode::Always,
                allow_all_senders: true,
                prompt_template: "Message {message_id}: {body}".to_owned(),
                ..webex_generic_account_bot::RoomPolicy::default()
            }],
            ..BotConfig::default()
        };
        config.validate().unwrap();
        Arc::new(config)
    }

    fn staging_test_config(state_path: PathBuf) -> Arc<BotConfig> {
        let config = BotConfig {
            state_file: state_path,
            self_person_id: Some(SELF_PERSON_ID.to_owned()),
            server: webex_generic_account_bot::ServerConfig {
                allow_unauthenticated: true,
                attempt_lease_secs: 600,
                ..webex_generic_account_bot::ServerConfig::default()
            },
            codex: webex_generic_account_bot::CodexConfig {
                cwd: PathBuf::from("/tmp/webex-generic-account-bot-work"),
                codex_home: PathBuf::from("/tmp/webex-generic-account-bot-codex-home"),
                timeout_secs: 30,
                ..webex_generic_account_bot::CodexConfig::default()
            },
            rooms: vec![webex_generic_account_bot::RoomPolicy {
                room_id: ROOM_ID.to_owned(),
                output_room_id: Some(OUTPUT_ROOM_ID.to_owned()),
                forward_source_message: true,
                read_only_source: true,
                trigger: TriggerMode::Always,
                allow_all_senders: true,
                prompt_template: "Message {message_id}: {body}".to_owned(),
                ..webex_generic_account_bot::RoomPolicy::default()
            }],
            ..BotConfig::default()
        };
        config.validate().unwrap();
        Arc::new(config)
    }

    fn followup_test_config(state_path: PathBuf) -> Arc<BotConfig> {
        let mut config = (*test_config(state_path)).clone();
        config.server.attempt_lease_secs = 600;
        config.rooms[0].followup.enabled = true;
        config.rooms[0].followup.prompt_template =
            "Original {original_message_id}: {original_body}\nThread:\n{thread_context}\nFollow-up {message_id}: {body}".to_owned();
        config.validate().unwrap();
        Arc::new(config)
    }

    fn staging_followup_test_config(state_path: PathBuf) -> Arc<BotConfig> {
        let mut config = (*staging_test_config(state_path)).clone();
        config.rooms[0].followup.enabled = true;
        config.rooms[0].followup.prompt_template =
            "Original {original_message_id}: {original_body}\nThread:\n{thread_context}\nFollow-up {message_id}: {body}".to_owned();
        config.validate().unwrap();
        Arc::new(config)
    }

    fn unique_state_path() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "webex-generic-account-bot-test-{}-{counter}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    fn first_artifact_dir_from_prompt(prompt: &str) -> PathBuf {
        let prefix = "Diagnostics artifact directory: `";
        let start = prompt.find(prefix).unwrap() + prefix.len();
        let end = start + prompt[start..].find('`').unwrap();
        PathBuf::from(&prompt[start..end])
    }

    fn message_event(message: Message) -> SidecarEvent {
        SidecarEvent::message_created(serde_json::to_value(message).unwrap())
    }

    fn inbound_message(message_id: &str, body: &str) -> Message {
        Message {
            id: Some(message_id.to_owned()),
            room_id: Some(ROOM_ID.to_owned()),
            person_id: Some(SENDER_PERSON_ID.to_owned()),
            person_email: Some(SENDER_EMAIL.to_owned()),
            text: Some(body.to_owned()),
            markdown: Some(body.to_owned()),
            ..Message::default()
        }
    }

    fn inbound_thread_message(
        message_id: &str,
        room_id: &str,
        parent_id: &str,
        body: &str,
    ) -> Message {
        let mut message = inbound_message(message_id, body);
        message.room_id = Some(room_id.to_owned());
        message.parent_id = Some(parent_id.to_owned());
        message.mentioned_people = vec![SELF_PERSON_ID.to_owned()];
        message
    }

    fn reply_message(reply_id: &str) -> Message {
        message_with_room(reply_id, ROOM_ID)
    }

    fn message_with_room(message_id: &str, room_id: &str) -> Message {
        Message {
            id: Some(message_id.to_owned()),
            room_id: Some(room_id.to_owned()),
            person_id: Some(SELF_PERSON_ID.to_owned()),
            ..Message::default()
        }
    }

    fn reply_with_marker(reply_id: &str, marker: &str) -> Message {
        message_with_marker(reply_id, ROOM_ID, marker)
    }

    fn message_with_marker(message_id: &str, room_id: &str, marker: &str) -> Message {
        Message {
            id: Some(message_id.to_owned()),
            room_id: Some(room_id.to_owned()),
            person_id: Some(SELF_PERSON_ID.to_owned()),
            markdown: Some(format!("done\n\n_Ref: `{marker}`_")),
            ..Message::default()
        }
    }
}

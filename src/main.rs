use std::{
    env, net::SocketAddr, path::Path, path::PathBuf, process::Stdio, sync::Arc, time::Duration,
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
use serde::Serialize;
use serde_json::json;
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    process::{Child, Command},
    sync::{Mutex, Semaphore},
    time::timeout,
};
use tracing::{error, info, warn};
use webex_generic_account_bot::{
    BotConfig, CodexRunner, ExecCodexRunner, MessageContext, TriggerMode, render_prompt,
    should_trigger, trim_to_chars, webex::build_webex_client,
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

enum ReplyThreadSetup {
    Ready(ReplyThread),
    Finished(BotAction),
}

#[async_trait]
trait WebexApi: Send + Sync {
    async fn me(&self) -> Result<Person, WebexCallError>;
    async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError>;
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
            max: Some(100),
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
    context: &MessageContext,
) -> Result<Option<String>> {
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

    let mut sections = Vec::new();
    for url in urls {
        let output = run_jenkins_context_helper(config, &url).await?;
        sections.push(format!(
            "URL: {url}\n```text\n{}\n```",
            trim_to_chars(output.trim(), config.output_limit_chars)
        ));
    }

    Ok(Some(format!(
        "Prefetched Jenkins diagnostics (read-only helper output; use this instead of running Jenkins commands from Codex):\n\n{}",
        sections.join("\n\n")
    )))
}

async fn run_jenkins_context_helper(
    config: &webex_generic_account_bot::JenkinsContextConfig,
    url: &str,
) -> Result<String> {
    let mut command = Command::new(&config.node_bin);
    let script_dir = config.script.parent().unwrap_or_else(|| Path::new("/"));
    configure_jenkins_helper_process(&mut command);
    apply_jenkins_helper_env(&mut command);
    command
        .arg(&config.script)
        .arg("--env-file")
        .arg(&config.env_file)
        .arg("diagnose")
        .arg("--url")
        .arg(url)
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
    let capture_limit = helper_capture_limit_bytes(config.output_limit_chars);
    let stdout_task = read_limited_pipe(child.stdout.take(), capture_limit);
    let stderr_task = read_limited_pipe(child.stderr.take(), capture_limit);
    let status = match timeout(config.timeout(), child.wait()).await {
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
    let stdout = stdout_task
        .await
        .context("failed to join Jenkins stdout reader")??;
    let stderr = stderr_task
        .await
        .context("failed to join Jenkins stderr reader")??;

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
    const SIGTERM: i32 = 15;
    const SIGKILL: i32 = 9;

    if let Some(pid) = child.id() {
        let process_group = -(pid as i32);
        unsafe {
            kill(process_group, SIGTERM);
        }
        if timeout(Duration::from_millis(250), child.wait())
            .await
            .is_ok()
        {
            return;
        }
        unsafe {
            kill(process_group, SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
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
        let Some(policy) = self.config.policy_for_room(&room_id) else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "no_room_policy",
                Some(message_id),
                Some(room_id),
            ));
        };
        if message_needs_hydration(policy, &message) {
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
        let reply_marker = reply_marker(&message_id);
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
        match self
            .find_existing_message_by_marker(
                &reply_thread.room_id,
                Some(&reply_thread.parent_id),
                &reply_marker,
                None,
            )
            .await
        {
            Ok(Some(reply)) => {
                let reply_chars = existing_reply_chars(&reply);
                self.mark_processed(&attempt).await?;
                return Ok(BotAction::replied(
                    message_id,
                    reply_thread.room_id,
                    reply.id,
                    reply_chars,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return self
                    .handle_reconciliation_failure(&attempt, &message_id, error)
                    .await;
            }
        }

        let Some(context) = MessageContext::from_message(&message) else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "incomplete_message_context",
                Some(message_id),
                Some(room_id),
            ));
        };
        let codex_config = self.config.codex_for_policy(policy);
        let mut prompt = render_prompt(&policy.prompt_template, &context);
        match jenkins_context_prompt(policy, &context).await {
            Ok(Some(context_prompt)) => {
                prompt = append_prefetched_context(&prompt, &context_prompt);
            }
            Ok(None) => {}
            Err(error) => {
                warn!(message_id = %message_id, error = %error, "failed to prefetch Jenkins diagnostics");
                prompt = append_prefetched_context(
                    &prompt,
                    &format!("Jenkins diagnostics helper failed before Codex run: {error}"),
                );
            }
        }
        let reply_text = match self.runner.run(&codex_config, &prompt, &message_id).await {
            Ok(output) => output.final_message,
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
                        &attempt,
                        ReplyCreateContext {
                            message_id: &message_id,
                            room_id: &reply_thread.room_id,
                            parent_id: reply_request.parent_id.as_deref().unwrap_or(&message_id),
                            reply_marker: &reply_marker,
                            reply_chars: reply_markdown.len(),
                        },
                        error,
                    )
                    .await;
            }
        };
        let action = BotAction::replied(
            message_id,
            reply_thread.room_id,
            reply.id,
            reply_markdown.len(),
        );
        if let Err(error) = self.mark_processed(&attempt).await {
            error!(
                error = %error.message,
                "failed to mark message processed after Webex accepted reply"
            );
        }
        Ok(action)
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
                Some(SOURCE_MARKER_SEARCH_MAX_PAGES),
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
                        Some(SOURCE_MARKER_SEARCH_MAX_PAGES),
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
    if target.mentioned_people.is_empty() {
        target.mentioned_people = hydrated.mentioned_people;
    }
    if target.mentioned_groups.is_empty() {
        target.mentioned_groups = hydrated.mentioned_groups;
    }
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

fn sanitize_reply_markdown(markdown: &str) -> String {
    markdown.replace("<@", "&lt;@")
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
        fs::write(&script, "printf 'pwd=%s\\n' \"$PWD\"\n").unwrap();
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

        let output =
            run_jenkins_context_helper(&config, "https://engci-private-sjc.cisco.com/job/1")
                .await
                .unwrap();

        assert!(output.contains(&format!("pwd={}", helper_dir.display())));
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

        let output =
            run_jenkins_context_helper(&config, "https://engci-private-sjc.cisco.com/job/1")
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
        fs::write(
            &script,
            "i=0\nwhile [ \"$i\" -lt 4096 ]; do printf x; i=$((i + 1)); done\n",
        )
        .unwrap();
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

        let output =
            run_jenkins_context_helper(&config, "https://engci-private-sjc.cisco.com/job/1")
                .await
                .unwrap();

        assert!(output.contains("[truncated]"));
        assert!(output.len() < 1_200);
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
        marker_search_results: StdMutex<VecDeque<Result<Vec<Message>, WebexCallError>>>,
        create_results: StdMutex<VecDeque<Result<Message, WebexCallError>>>,
        created_requests: StdMutex<Vec<CreateMessage>>,
        marker_search_requests: StdMutex<Vec<MarkerSearchRequest>>,
    }

    impl FakeWebex {
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
    }

    #[async_trait]
    impl WebexApi for FakeWebex {
        async fn me(&self) -> Result<Person, WebexCallError> {
            Ok(Person {
                id: Some(SELF_PERSON_ID.to_owned()),
                ..Person::default()
            })
        }

        async fn get_message(&self, _message_id: &str) -> Result<Message, WebexCallError> {
            panic!("unexpected message hydration in test")
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
                attempt_lease_secs: 180,
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
                attempt_lease_secs: 420,
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

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::Permissions,
    path::{Path, PathBuf},
    process::{self, ExitStatus, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    time::{sleep, timeout},
};

use crate::{
    config::{CodexConfig, IsolationMode},
    policy::trim_to_chars,
};

#[derive(Debug, Clone)]
pub struct CodexRunOutput {
    pub final_message: String,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait CodexRunner: Send + Sync {
    async fn run(
        &self,
        config: &CodexConfig,
        prompt: &str,
        message_id: &str,
    ) -> Result<CodexRunOutput>;
}

#[derive(Debug, Clone, Copy)]
struct CodexInvocation<'a> {
    config: &'a CodexConfig,
    prompt: &'a str,
    message_id: &'a str,
}

#[async_trait]
trait CodexExecutionBackend: Send + Sync {
    async fn execute(&self, invocation: CodexInvocation<'_>) -> Result<CodexRunOutput>;
}

#[derive(Debug, Default)]
struct CurrentUserExecBackend;

#[derive(Debug, Clone, Default)]
pub struct ExecCodexRunner;

struct CodexBackendDispatcher<'a> {
    current_user_backend: &'a dyn CodexExecutionBackend,
}

impl<'a> CodexBackendDispatcher<'a> {
    fn new(current_user_backend: &'a dyn CodexExecutionBackend) -> Self {
        Self {
            current_user_backend,
        }
    }

    fn backend_for(&self, mode: IsolationMode) -> Result<&dyn CodexExecutionBackend> {
        match mode {
            IsolationMode::CurrentUser => Ok(self.current_user_backend),
            IsolationMode::EphemeralLinuxUser => Err(ephemeral_backend_unavailable()),
        }
    }

    async fn execute(
        &self,
        config: &CodexConfig,
        prompt: &str,
        message_id: &str,
    ) -> Result<CodexRunOutput> {
        config.validate()?;
        let invocation = CodexInvocation {
            config,
            prompt,
            message_id,
        };

        self.backend_for(config.isolation.mode)?
            .execute(invocation)
            .await
    }
}

#[async_trait]
impl CodexRunner for ExecCodexRunner {
    async fn run(
        &self,
        config: &CodexConfig,
        prompt: &str,
        message_id: &str,
    ) -> Result<CodexRunOutput> {
        let current_user_backend = CurrentUserExecBackend;
        CodexBackendDispatcher::new(&current_user_backend)
            .execute(config, prompt, message_id)
            .await
    }
}

fn ephemeral_backend_unavailable() -> anyhow::Error {
    anyhow!("ephemeral-linux-user Codex execution backend is unavailable")
}

#[async_trait]
impl CodexExecutionBackend for CurrentUserExecBackend {
    async fn execute(&self, invocation: CodexInvocation<'_>) -> Result<CodexRunOutput> {
        let CodexInvocation {
            config,
            prompt,
            message_id,
        } = invocation;
        let output_path = output_path(message_id).await?;
        let mut command = Command::new(&config.bin);
        command.args(codex_exec_args(config, &output_path));
        configure_child_process(&mut command);
        apply_runner_env(&mut command, config);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to spawn codex executable {} in {}",
                config.bin,
                config.cwd.display()
            )
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open codex stdin"))?;

        let capture_limit = capture_limit_bytes(config.output_limit_chars);
        let stdout_task = read_pipe(child.stdout.take(), capture_limit);
        let stderr_task = read_pipe(child.stderr.take(), capture_limit);
        let status = match timeout(
            config.timeout(),
            write_prompt_and_wait(&mut child, stdin, prompt),
        )
        .await
        {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => {
                terminate_child(&mut child).await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                let _ = fs::remove_file(&output_path).await;
                return Err(error);
            }
            Err(_) => {
                terminate_child(&mut child).await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                let _ = fs::remove_file(&output_path).await;
                return Err(anyhow!(
                    "codex exec timed out after {} seconds",
                    config.timeout_secs.max(1)
                ));
            }
        };
        let stdout = stdout_task
            .await
            .context("failed to join codex stdout reader")??;
        let stderr = stderr_task
            .await
            .context("failed to join codex stderr reader")??;
        if !status.success() {
            let _ = fs::remove_file(&output_path).await;
            return Err(anyhow!(
                "codex exec exited with status {status}; stderr: {}",
                trim_to_chars(&stderr, 2_000)
            ));
        }

        let final_message = read_limited_file(&output_path, capture_limit)
            .await
            .unwrap_or_else(|_| stdout.clone());
        let _ = fs::remove_file(&output_path).await;
        let final_message = normalize_final_message(&final_message, config.output_limit_chars)?;
        Ok(CodexRunOutput {
            final_message,
            stdout,
            stderr,
        })
    }
}

async fn write_prompt_and_wait(
    child: &mut Child,
    mut stdin: ChildStdin,
    prompt: &str,
) -> Result<ExitStatus> {
    stdin
        .write_all(prompt.as_bytes())
        .await
        .context("failed to write prompt to codex stdin")?;
    stdin.shutdown().await.ok();
    drop(stdin);
    child
        .wait()
        .await
        .context("failed while waiting for codex process")
}

fn codex_exec_args(config: &CodexConfig, output_path: &Path) -> Vec<OsString> {
    let mut args = vec![
        "--ask-for-approval".into(),
        config.approval_policy.clone().into(),
        "exec".into(),
        "--color".into(),
        "never".into(),
        "--ignore-user-config".into(),
        "--ignore-rules".into(),
        "--sandbox".into(),
        config.sandbox.clone().into(),
        "--cd".into(),
        config.cwd.as_os_str().into(),
        "--output-last-message".into(),
        output_path.as_os_str().into(),
    ];
    if config.skip_git_repo_check {
        args.push("--skip-git-repo-check".into());
    }
    if config.ephemeral {
        args.push("--ephemeral".into());
    }
    if let Some(profile) = &config.profile {
        args.push("--profile".into());
        args.push(profile.into());
    }
    if let Some(model) = &config.model {
        args.push("--model".into());
        args.push(model.into());
    }
    if let Some(reasoning_effort) = &config.model_reasoning_effort {
        args.push("-c".into());
        args.push(format!("model_reasoning_effort=\"{reasoning_effort}\"").into());
    }
    args.push("-".into());
    args
}

fn configure_child_process(command: &mut Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
    }
}

async fn terminate_child(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        terminate_child_group(child).await;
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(unix)]
async fn terminate_child_group(child: &mut tokio::process::Child) {
    const SIGTERM: i32 = 15;
    const SIGKILL: i32 = 9;

    if let Some(pid) = child.id() {
        let process_group = -(pid as i32);
        unsafe {
            kill(process_group, SIGTERM);
        }
        if timeout(std::time::Duration::from_millis(250), child.wait())
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

fn read_pipe<R>(pipe: Option<R>, max_bytes: usize) -> tokio::task::JoinHandle<Result<String>>
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

async fn read_limited_file(path: &Path, max_bytes: usize) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    read_limited(&mut file, max_bytes).await
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
    Ok(limited_string(kept, truncated))
}

fn limited_string(bytes: Vec<u8>, truncated: bool) -> String {
    let mut value = String::from_utf8_lossy(&bytes).to_string();
    if truncated {
        value.push_str("\n[truncated]");
    }
    value
}

fn normalize_final_message(value: &str, max_chars: usize) -> Result<String> {
    let trimmed = trim_to_chars(value.trim(), max_chars);
    if trimmed.trim().is_empty() {
        return Err(anyhow!("codex exec produced an empty final message"));
    }
    Ok(trimmed)
}

fn capture_limit_bytes(output_limit_chars: usize) -> usize {
    output_limit_chars
        .max(1)
        .saturating_mul(4)
        .saturating_add(1024)
}

async fn output_path(message_id: &str) -> Result<PathBuf> {
    let dir = env::temp_dir().join("webex-generic-account-bot");
    fs::create_dir_all(&dir).await?;
    set_private_dir_permissions(&dir).await?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = dir.join(format!(
        "codex-output-{}-{}-{timestamp}.txt",
        process::id(),
        sanitize_path_fragment(message_id)
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await?;
    drop(file);
    set_private_file_permissions(&path).await?;
    Ok(path)
}

#[cfg(unix)]
async fn set_private_dir_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, Permissions::from_mode(0o700)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn set_private_file_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn sanitize_path_fragment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').chars().take(80).collect()
}

pub fn scrubbed_env() -> BTreeMap<String, String> {
    const PASSTHROUGH: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ];

    PASSTHROUGH
        .iter()
        .filter_map(|key| env::var(key).ok().map(|value| ((*key).to_owned(), value)))
        .collect()
}

fn runner_env(config: &CodexConfig) -> BTreeMap<String, String> {
    let mut env = scrubbed_env();
    env.insert(
        "CODEX_HOME".to_owned(),
        config.codex_home.to_string_lossy().to_string(),
    );
    env
}

fn apply_runner_env(command: &mut Command, config: &CodexConfig) {
    command.env_clear();
    for (key, value) in runner_env(config) {
        command.env(key, value);
    }
}

#[allow(dead_code)]
async fn brief_pause_for_kill() {
    sleep(std::time::Duration::from_millis(10)).await;
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        env, fs as std_fs,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::SystemTime,
    };

    use super::*;

    struct AssertingBackend {
        expected_config_address: usize,
        expected_prompt: String,
        expected_message_id: String,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CodexExecutionBackend for AssertingBackend {
        async fn execute(&self, invocation: CodexInvocation<'_>) -> Result<CodexRunOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                invocation.config as *const CodexConfig as usize,
                self.expected_config_address
            );
            assert_eq!(invocation.prompt, self.expected_prompt);
            assert_eq!(invocation.message_id, self.expected_message_id);
            Ok(CodexRunOutput {
                final_message: "dispatched output".to_owned(),
                stdout: "dispatched stdout".to_owned(),
                stderr: "dispatched stderr".to_owned(),
            })
        }
    }

    #[derive(Default)]
    struct CountingBackend {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CodexExecutionBackend for CountingBackend {
        async fn execute(&self, _invocation: CodexInvocation<'_>) -> Result<CodexRunOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("unexpected current-user backend execution"))
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "webex-generic-account-bot-runner-{name}-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn current_user_dispatch_forwards_exact_invocation() {
        let config = CodexConfig::default();
        let backend = Arc::new(AssertingBackend {
            expected_config_address: &config as *const CodexConfig as usize,
            expected_prompt: "exact prompt".to_owned(),
            expected_message_id: "message-exact".to_owned(),
            calls: AtomicUsize::new(0),
        });
        let dispatcher = CodexBackendDispatcher::new(backend.as_ref());

        let output = dispatcher
            .execute(&config, "exact prompt", "message-exact")
            .await
            .unwrap();

        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        assert_eq!(output.final_message, "dispatched output");
        assert_eq!(output.stdout, "dispatched stdout");
        assert_eq!(output.stderr, "dispatched stderr");
    }

    #[tokio::test]
    async fn ephemeral_mode_is_rejected_by_config_before_current_user_backend() {
        let mut config = CodexConfig::default();
        config.isolation.mode = IsolationMode::EphemeralLinuxUser;
        let backend = Arc::new(CountingBackend::default());
        let dispatcher = CodexBackendDispatcher::new(backend.as_ref());

        let error = dispatcher
            .execute(&config, "prompt", "message-ephemeral")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("ephemeral-linux-user"));
        assert!(error.to_string().contains("planned but not implemented"));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unavailable_ephemeral_backend_never_falls_back_to_current_user() {
        let backend = Arc::new(CountingBackend::default());
        let dispatcher = CodexBackendDispatcher::new(backend.as_ref());

        let error = dispatcher
            .backend_for(IsolationMode::EphemeralLinuxUser)
            .err()
            .expect("ephemeral backend must be unavailable");

        assert!(error.to_string().contains("backend is unavailable"));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn path_fragment_is_sanitized() {
        assert_eq!(sanitize_path_fragment("abc/def?ghi"), "abc-def-ghi");
    }

    #[test]
    fn runner_env_does_not_forward_webex_tokens() {
        unsafe {
            env::set_var("WEBEX_ACCESS_TOKEN", "secret");
            env::set_var("WEBEX_SIDECAR_TOKEN", "secret");
            env::set_var("CODEX_HOME", "/tmp/codex-home-with-extra-config");
        }

        let env = scrubbed_env();

        assert!(!env.contains_key("WEBEX_ACCESS_TOKEN"));
        assert!(!env.contains_key("WEBEX_SIDECAR_TOKEN"));
        assert!(!env.contains_key("CODEX_HOME"));
        assert_ne!(
            runner_env(&CodexConfig::default())
                .get("CODEX_HOME")
                .map(String::as_str),
            Some("/tmp/codex-home-with-extra-config")
        );

        unsafe {
            env::remove_var("WEBEX_ACCESS_TOKEN");
            env::remove_var("WEBEX_SIDECAR_TOKEN");
            env::remove_var("CODEX_HOME");
        }
    }

    #[test]
    fn runner_env_uses_configured_codex_home() {
        unsafe {
            env::set_var("CODEX_HOME", "/tmp/inherited-codex-home");
        }
        let config = CodexConfig {
            codex_home: PathBuf::from("/var/lib/webex-bot/codex-home"),
            ..CodexConfig::default()
        };

        let env = runner_env(&config);

        assert_eq!(
            env.get("CODEX_HOME").map(String::as_str),
            Some("/var/lib/webex-bot/codex-home")
        );

        unsafe {
            env::remove_var("CODEX_HOME");
        }
    }

    #[test]
    fn trims_long_output() {
        assert_eq!(trim_to_chars("abcdef", 3), "abc\n[truncated]");
    }

    #[test]
    fn empty_final_message_is_rejected() {
        assert!(
            normalize_final_message(" \n\t", 100)
                .unwrap_err()
                .to_string()
                .contains("empty final message")
        );
    }

    #[test]
    fn limited_string_caps_bytes_before_decoding() {
        assert_eq!(limited_string(b"abc".to_vec(), true), "abc\n[truncated]");
    }

    #[tokio::test]
    async fn read_limited_drains_after_limit() {
        let (mut writer, mut reader) = tokio::io::duplex(4);
        let reader_task = tokio::spawn(async move { read_limited(&mut reader, 3).await.unwrap() });
        writer.write_all(b"abcdef").await.unwrap();
        writer.shutdown().await.unwrap();

        assert_eq!(reader_task.await.unwrap(), "abc\n[truncated]");
    }

    #[test]
    fn capture_limit_allows_utf8_expansion_headroom() {
        assert_eq!(capture_limit_bytes(3), 1036);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_path_uses_private_permissions() {
        let path = output_path("message-1").await.unwrap();
        let dir = path.parent().unwrap();

        assert_eq!(
            std_fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std_fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std_fs::remove_file(path);
    }

    #[test]
    fn codex_config_defaults_to_read_only_sandbox() {
        let config = CodexConfig::default();

        assert_eq!(config.sandbox, "read-only");
        assert_eq!(config.approval_policy, "never");
        assert!(config.ephemeral);
    }

    #[test]
    fn approval_policy_is_passed_before_exec_subcommand() {
        let args = codex_exec_args(&CodexConfig::default(), std::path::Path::new("/tmp/out"));
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(args[0], "--ask-for-approval");
        assert_eq!(args[1], "never");
        assert_eq!(args[2], "exec");
        assert!(
            !args
                .windows(2)
                .any(|pair| pair == ["exec", "--ask-for-approval"])
        );
    }

    #[test]
    fn codex_exec_ignores_user_config_and_rules() {
        let args = codex_exec_args(&CodexConfig::default(), std::path::Path::new("/tmp/out"));
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(args.iter().any(|arg| arg == "--ignore-user-config"));
        assert!(args.iter().any(|arg| arg == "--ignore-rules"));
    }

    #[test]
    fn model_reasoning_effort_is_passed_as_codex_config_override() {
        let config = CodexConfig {
            model: Some("gpt-5.5".to_owned()),
            model_reasoning_effort: Some("xhigh".to_owned()),
            ..CodexConfig::default()
        };
        let args = codex_exec_args(&config, std::path::Path::new("/tmp/out"));
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(args.windows(2).any(|pair| pair == ["--model", "gpt-5.5"]));
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["-c", "model_reasoning_effort=\"xhigh\""] })
        );
    }

    #[test]
    fn accepts_existing_cwd_path_type() {
        let config = CodexConfig {
            cwd: std::path::Path::new(".").to_path_buf(),
            ..CodexConfig::default()
        };

        config.validate().unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_codex_process_group() {
        let root = temp_path("process-group");
        std_fs::create_dir_all(&root).unwrap();
        let fake_codex = root.join("fake-codex.sh");
        let pid_file = root.join("sleep.pid");
        std_fs::write(
            &fake_codex,
            format!(
                "#!/bin/sh\nsleep 20 &\necho $! > {}\nwait\n",
                pid_file.display()
            ),
        )
        .unwrap();
        std_fs::set_permissions(&fake_codex, std_fs::Permissions::from_mode(0o700)).unwrap();

        let config = CodexConfig {
            bin: fake_codex.display().to_string(),
            cwd: root.clone(),
            timeout_secs: 1,
            ..CodexConfig::default()
        };
        let result = ExecCodexRunner.run(&config, "prompt", "message-1").await;

        assert!(result.unwrap_err().to_string().contains("timed out"));
        let pid = std_fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        sleep(std::time::Duration::from_millis(100)).await;
        assert!(!process_exists(pid));

        let _ = std_fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_covers_blocked_stdin_write() {
        let root = temp_path("stdin-timeout");
        std_fs::create_dir_all(&root).unwrap();
        let fake_codex = root.join("fake-codex.sh");
        std_fs::write(&fake_codex, "#!/bin/sh\nsleep 20\n").unwrap();
        std_fs::set_permissions(&fake_codex, std_fs::Permissions::from_mode(0o700)).unwrap();

        let config = CodexConfig {
            bin: fake_codex.display().to_string(),
            cwd: root.clone(),
            timeout_secs: 1,
            ..CodexConfig::default()
        };
        let prompt = "x".repeat(2_000_000);
        let result = ExecCodexRunner
            .run(&config, &prompt, "message-stdin-timeout")
            .await;

        assert!(result.unwrap_err().to_string().contains("timed out"));

        let _ = std_fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdout_is_drained_while_child_runs() {
        let root = temp_path("stdout-drain");
        std_fs::create_dir_all(&root).unwrap();
        let fake_codex = root.join("fake-codex.sh");
        std_fs::write(
            &fake_codex,
            r#"#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    out="$1"
  fi
  shift
done
yes stdout | head -c 200000
printf 'final from fake codex\n' > "$out"
"#,
        )
        .unwrap();
        std_fs::set_permissions(&fake_codex, std_fs::Permissions::from_mode(0o700)).unwrap();

        let config = CodexConfig {
            bin: fake_codex.display().to_string(),
            cwd: root.clone(),
            timeout_secs: 5,
            ..CodexConfig::default()
        };
        let result = ExecCodexRunner
            .run(&config, "prompt", "message-stdout-drain")
            .await
            .unwrap();

        assert_eq!(result.final_message, "final from fake codex");

        let _ = std_fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn process_exists(pid: i32) -> bool {
        unsafe { kill(pid, 0) == 0 }
    }
}

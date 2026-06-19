use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::{sleep, timeout},
};

use crate::{config::CodexConfig, policy::trim_to_chars};

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

#[derive(Debug, Clone, Default)]
pub struct ExecCodexRunner;

#[async_trait]
impl CodexRunner for ExecCodexRunner {
    async fn run(
        &self,
        config: &CodexConfig,
        prompt: &str,
        message_id: &str,
    ) -> Result<CodexRunOutput> {
        run_codex_exec(config, prompt, message_id).await
    }
}

async fn run_codex_exec(
    config: &CodexConfig,
    prompt: &str,
    message_id: &str,
) -> Result<CodexRunOutput> {
    config.validate()?;
    let output_path = output_path(message_id).await?;
    let mut command = Command::new(&config.bin);
    command.args(codex_exec_args(config, &output_path));
    apply_scrubbed_env(&mut command);
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

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open codex stdin"))?;
    stdin
        .write_all(prompt.as_bytes())
        .await
        .context("failed to write prompt to codex stdin")?;
    stdin.shutdown().await.ok();
    drop(stdin);

    let capture_limit = capture_limit_bytes(config.output_limit_chars);
    let stdout_task = read_pipe(child.stdout.take(), capture_limit);
    let stderr_task = read_pipe(child.stderr.take(), capture_limit);
    let status = match timeout(config.timeout(), child.wait()).await {
        Ok(status) => status.context("failed while waiting for codex process")?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = fs::remove_file(&output_path).await;
            return Err(anyhow!(
                "codex exec timed out after {} seconds",
                config.timeout_secs.max(1)
            ));
        }
    };
    let stdout = stdout_task.await??;
    let stderr = stderr_task.await??;
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
    Ok(CodexRunOutput {
        final_message: trim_to_chars(final_message.trim(), config.output_limit_chars),
        stdout,
        stderr,
    })
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

fn capture_limit_bytes(output_limit_chars: usize) -> usize {
    output_limit_chars
        .max(1)
        .saturating_mul(4)
        .saturating_add(1024)
}

async fn output_path(message_id: &str) -> Result<PathBuf> {
    let dir = env::temp_dir().join("webex-generic-account-bot");
    fs::create_dir_all(&dir).await?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(dir.join(format!(
        "codex-output-{}-{timestamp}.txt",
        sanitize_path_fragment(message_id)
    )))
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

fn apply_scrubbed_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in scrubbed_env() {
        command.env(key, value);
    }
}

#[allow(dead_code)]
async fn brief_pause_for_kill() {
    sleep(std::time::Duration::from_millis(10)).await;
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

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

        unsafe {
            env::remove_var("WEBEX_ACCESS_TOKEN");
            env::remove_var("WEBEX_SIDECAR_TOKEN");
            env::remove_var("CODEX_HOME");
        }
    }

    #[test]
    fn trims_long_output() {
        assert_eq!(trim_to_chars("abcdef", 3), "abc\n[truncated]");
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
}

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const EPHEMERAL_CONFIG: &str = r#"
[server]
attempt_lease_secs = 3600

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#;

#[test]
fn structural_check_accepts_ephemeral_config_without_host_preflight() {
    let config = TempConfig::new(EPHEMERAL_CONFIG);
    let output = run_bot(config.path(), &["--check-config-structure"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "config_structure_ok=true"
    );
}

#[test]
fn structural_check_still_rejects_invalid_config() {
    let config = TempConfig::new("[server]\nattempt_lease_secs = 3600\n");
    let output = run_bot(config.path(), &["--check-config-structure"]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("at least one [[rooms]] policy is required"));
}

#[test]
fn config_check_modes_are_mutually_exclusive() {
    let config = TempConfig::new(EPHEMERAL_CONFIG);
    let output = run_bot(
        config.path(),
        &["--check-config", "--check-config-structure"],
    );
    let stderr = stderr(&output);

    assert!(!output.status.success());
    assert!(
        stderr.contains(
            "the argument '--check-config' cannot be used with '--check-config-structure'"
        )
    );
}

fn run_bot(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_webex-generic-account-bot"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("failed to run webex-generic-account-bot")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

struct TempConfig {
    path: PathBuf,
}

impl TempConfig {
    fn new(contents: &str) -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "webex-config-check-cli-{}-{counter}-{nanos}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("failed to write temporary config");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

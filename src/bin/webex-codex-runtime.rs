#[cfg(target_os = "linux")]
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use clap::{Parser, ValueEnum};
#[cfg(target_os = "linux")]
use webex_generic_account_bot::launcher_protocol::OUTPUT_MAX_BYTES;

#[cfg(target_os = "linux")]
const CODEX_PATH: &str = "/opt/codex/bin/codex";
#[cfg(target_os = "linux")]
const WORKSPACE_PATH: &str = "/workspace";
#[cfg(target_os = "linux")]
const CREDENTIAL_NAME: &str = "codex-auth.json";
#[cfg(target_os = "linux")]
const MAIN_HOME: &str = "/tmp/webex-codex-main-home";
#[cfg(target_os = "linux")]
const CODEX_HOME: &str = "/tmp/webex-codex-main";
#[cfg(target_os = "linux")]
const TOOL_HOME: &str = "/tmp/webex-codex-tool-home";
#[cfg(target_os = "linux")]
const TOOL_TMP: &str = "/tmp/webex-codex-tool-tmp";
#[cfg(target_os = "linux")]
const FINAL_OUTPUT_PATH: &str = "/tmp/webex-codex-main/final-message.txt";
#[cfg(target_os = "linux")]
const AUTH_MAX_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const FINAL_OUTPUT_MAX_BYTES: u64 = OUTPUT_MAX_BYTES as u64;
#[cfg(target_os = "linux")]
const MAIN_PATH: &str = "/opt/codex/codex-resources:/opt/codex/codex-path:/bin";
#[cfg(target_os = "linux")]
const PERMISSION_PROFILE: &str = concat!(
    "permissions.webex-isolated.filesystem={",
    "\":minimal\"=\"read\",",
    "\":workspace_roots\"={\".\"=\"read\"},",
    "\"/tmp/webex-codex-tool-home\"=\"write\",",
    "\"/tmp/webex-codex-tool-tmp\"=\"write\",",
    "\"/tmp/webex-codex-main\"=\"deny\",",
    "\"/tmp/webex-codex-main-home\"=\"deny\",",
    "\"/run/credentials\"=\"deny\",",
    "\"/run/systemd\"=\"deny\",",
    "\"/run/dbus\"=\"deny\",",
    "\"/run/webex-codex-launcher\"=\"deny\",",
    "\"/run/webex-config-pull\"=\"deny\",",
    "\"/opt/codex/bin\"=\"deny\",",
    "\"/opt/codex/codex-resources\"=\"deny\",",
    "\"/usr/libexec\"=\"deny\"",
    "}",
);

#[cfg(target_os = "linux")]
const TOOL_ENVIRONMENT: &str = concat!(
    "shell_environment_policy.set={",
    "PATH=\"/opt/codex/codex-path:/bin\",",
    "HOME=\"/tmp/webex-codex-tool-home\",",
    "TMPDIR=\"/tmp/webex-codex-tool-tmp\",",
    "SHELL=\"/bin/sh\",",
    "LANG=\"C.UTF-8\"",
    "}",
);

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[arg(long, value_parser = validate_workspace)]
    workspace: PathBuf,

    #[arg(long, value_parser = validate_model)]
    model: String,

    #[arg(long, value_enum)]
    reasoning_effort: Option<ReasoningEffort>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

#[cfg(target_os = "linux")]
impl ReasoningEffort {
    fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    prepare_private_directories()?;
    install_run_credential(&credential_path()?)?;
    harden_process()?;
    close_nonstandard_descriptors()?;

    let mut command = Command::new(CODEX_PATH);
    command.args(codex_args(&cli));
    command.env_clear();
    command
        .env("HOME", MAIN_HOME)
        .env("CODEX_HOME", CODEX_HOME)
        .env("PATH", MAIN_PATH)
        .env("SHELL", "/bin/sh")
        .env("LANG", "C.UTF-8")
        .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");

    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let output = run_codex(&mut command, Path::new(FINAL_OUTPUT_PATH))?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_codex(command: &mut Command, output_path: &Path) -> Result<Vec<u8>> {
    match fs::symlink_metadata(output_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(anyhow!("final Codex message path already exists")),
        Err(error) => return Err(error.into()),
    }
    let status = command
        .status()
        .context("failed to start the fixed Codex runtime")?;
    if !status.success() {
        return Err(anyhow!("fixed Codex runtime failed: {status}"));
    }
    read_final_output(output_path)
}

#[cfg(target_os = "linux")]
fn validate_workspace(value: &str) -> std::result::Result<PathBuf, String> {
    if value != WORKSPACE_PATH {
        return Err(format!("workspace must be {WORKSPACE_PATH}"));
    }
    Ok(PathBuf::from(value))
}

#[cfg(target_os = "linux")]
fn validate_model(value: &str) -> std::result::Result<String, String> {
    if value != "gpt-5.5" {
        return Err("model is not allowlisted".to_owned());
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn credential_path() -> Result<PathBuf> {
    let directory = env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or_else(|| anyhow!("systemd credential directory is unavailable"))?;
    let directory = PathBuf::from(directory);
    let text = directory
        .to_str()
        .ok_or_else(|| anyhow!("systemd credential directory is invalid"))?;
    if !text.starts_with("/run/credentials/")
        || text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(anyhow!("systemd credential directory is invalid"));
    }
    Ok(directory.join(CREDENTIAL_NAME))
}

#[cfg(target_os = "linux")]
fn prepare_private_directories() -> Result<()> {
    for path in [MAIN_HOME, CODEX_HOME, TOOL_HOME, TOOL_TMP] {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("failed to create private runtime directory {path}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_run_credential(source: &Path) -> Result<()> {
    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)
        .context("failed to open the systemd Codex credential")?;
    let metadata = source_file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > AUTH_MAX_BYTES {
        return Err(anyhow!("systemd Codex credential is invalid"));
    }

    let mut contents = Vec::with_capacity(metadata.len() as usize);
    source_file
        .read_to_end(&mut contents)
        .context("failed to read the systemd Codex credential")?;
    let value: serde_json::Value =
        serde_json::from_slice(&contents).context("Codex credential is not valid JSON")?;
    if !value.is_object() {
        return Err(anyhow!("Codex credential is not a JSON object"));
    }

    let destination = Path::new(CODEX_HOME).join("auth.json");
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&destination)
        .context("failed to create the per-run Codex credential")?;
    destination_file
        .write_all(&contents)
        .context("failed to write the per-run Codex credential")?;
    destination_file.sync_all()?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn harden_process() -> Result<()> {
    // SAFETY: these prctl operations do not dereference userspace pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to disable process dumping");
    }
    // SAFETY: these prctl operations do not dereference userspace pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set no_new_privs");
    }
    // SAFETY: umask has no pointer arguments.
    unsafe { libc::umask(0o077) };
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_nonstandard_descriptors() -> Result<()> {
    // SAFETY: close_range closes only descriptors numbered 3 and above.
    let status = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to close inherited runtime descriptors");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_final_output(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("failed to open the final Codex message")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        // SAFETY: geteuid has no arguments and only returns process metadata.
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > FINAL_OUTPUT_MAX_BYTES
    {
        return Err(anyhow!("final Codex message metadata is invalid"));
    }
    let mut output = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut output)?;
    std::str::from_utf8(&output).context("final Codex message is not UTF-8")?;
    Ok(output)
}

#[cfg(target_os = "linux")]
fn codex_args(cli: &Cli) -> Vec<OsString> {
    let mut args = vec![
        "--ask-for-approval".into(),
        "never".into(),
        "--strict-config".into(),
        "--model".into(),
        cli.model.clone().into(),
        "-c".into(),
        "default_permissions=\"webex-isolated\"".into(),
        "-c".into(),
        PERMISSION_PROFILE.into(),
        "-c".into(),
        "permissions.webex-isolated.network.enabled=false".into(),
        "-c".into(),
        "shell_environment_policy.inherit=\"none\"".into(),
        "-c".into(),
        "shell_environment_policy.ignore_default_excludes=false".into(),
        "-c".into(),
        TOOL_ENVIRONMENT.into(),
        "-c".into(),
        "shell_environment_policy.include_only=[\"PATH\",\"HOME\",\"TMPDIR\",\"SHELL\",\"LANG\"]"
            .into(),
        "-c".into(),
        "web_search=\"disabled\"".into(),
        "-c".into(),
        "project_doc_max_bytes=0".into(),
        "-c".into(),
        "allow_login_shell=false".into(),
        "-c".into(),
        "features.apps=false".into(),
        "-c".into(),
        "features.hooks=false".into(),
        "-c".into(),
        "features.memories=false".into(),
        "-c".into(),
        "features.multi_agent=false".into(),
        "-c".into(),
        "features.shell_snapshot=false".into(),
        "exec".into(),
        "--ignore-user-config".into(),
        "--ignore-rules".into(),
        "--color".into(),
        "never".into(),
        "--ephemeral".into(),
        "--cd".into(),
        cli.workspace.as_os_str().into(),
        "--skip-git-repo-check".into(),
        "--output-last-message".into(),
        FINAL_OUTPUT_PATH.into(),
    ];
    if let Some(reasoning_effort) = cli.reasoning_effort {
        args.push("-c".into());
        args.push(format!("model_reasoning_effort=\"{}\"", reasoning_effort.as_str()).into());
    }
    args.push(OsStr::new("-").into());
    args
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Err(anyhow!(
        "the isolated Codex runtime is supported only on Linux"
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn cli() -> Cli {
        Cli {
            workspace: PathBuf::from(WORKSPACE_PATH),
            model: "gpt-5.5".to_owned(),
            reasoning_effort: Some(ReasoningEffort::Xhigh),
        }
    }

    #[test]
    fn accepts_only_the_fixed_workspace_and_model() {
        assert_eq!(
            validate_workspace(WORKSPACE_PATH).unwrap(),
            Path::new(WORKSPACE_PATH)
        );
        assert!(validate_workspace("/tmp/workspace").is_err());
        assert_eq!(validate_model("gpt-5.5").unwrap(), "gpt-5.5");
        assert!(validate_model("other-model").is_err());
    }

    #[test]
    fn codex_arguments_pin_the_permission_and_feature_boundary() {
        let args = codex_args(&cli());
        let rendered = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();

        for required in [
            "--strict-config",
            "--ignore-user-config",
            "--ignore-rules",
            "default_permissions=\"webex-isolated\"",
            PERMISSION_PROFILE,
            "permissions.webex-isolated.network.enabled=false",
            "shell_environment_policy.inherit=\"none\"",
            TOOL_ENVIRONMENT,
            "web_search=\"disabled\"",
            "features.hooks=false",
            "features.multi_agent=false",
            "features.shell_snapshot=false",
            "--ephemeral",
            "--skip-git-repo-check",
            "--output-last-message",
            FINAL_OUTPUT_PATH,
        ] {
            assert!(rendered.iter().any(|value| value == required), "{required}");
        }
        let strict_config = rendered
            .iter()
            .position(|value| value == "--strict-config")
            .unwrap();
        let exec = rendered.iter().position(|value| value == "exec").unwrap();
        let skip_git = rendered
            .iter()
            .position(|value| value == "--skip-git-repo-check")
            .unwrap();
        let final_output = rendered
            .iter()
            .position(|value| value == "--output-last-message")
            .unwrap();
        assert!(strict_config < exec);
        assert!(skip_git > exec);
        assert!(final_output > exec);
        assert!(PERMISSION_PROFILE.contains("/tmp/webex-codex-main\"=\"deny"));
        assert!(PERMISSION_PROFILE.contains("/run/credentials\"=\"deny"));
        assert!(PERMISSION_PROFILE.contains("/opt/codex/codex-resources\"=\"deny"));
        assert!(!rendered.iter().any(|value| value.contains("auth.json")));
        assert!(
            !rendered
                .iter()
                .any(|value| value.contains("CODEX_ACCESS_TOKEN"))
        );
    }

    #[test]
    fn reasoning_effort_is_passed_as_a_fixed_config_override() {
        let args = codex_args(&cli());
        assert!(
            args.iter()
                .any(|value| value == "model_reasoning_effort=\"xhigh\"")
        );
    }

    #[test]
    fn final_output_must_be_private_bounded_utf8() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "webex-codex-final-output-{}-{suffix}",
            std::process::id()
        ));
        fs::write(&path, b"final response\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_final_output(&path).unwrap(), b"final response\n");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_final_output(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn supervisor_returns_only_the_final_output_file() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "webex-codex-supervised-output-{}-{suffix}",
            std::process::id()
        ));
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "umask 077; printf 'final response\\n' > \"$1\"; printf 'progress noise\\n'",
                "webex-codex-test",
            ])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert_eq!(run_codex(&mut command, &path).unwrap(), b"final response\n");
        fs::remove_file(path).unwrap();
    }
}

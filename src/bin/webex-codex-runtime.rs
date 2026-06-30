#[cfg(target_os = "linux")]
use std::{
    env,
    ffi::{CString, OsStr, OsString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use clap::{Parser, ValueEnum};
#[cfg(target_os = "linux")]
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
#[cfg(target_os = "linux")]
use webex_generic_account_bot::launcher_protocol::OUTPUT_MAX_BYTES;
#[cfg(target_os = "linux")]
use webex_generic_account_bot::{
    canary_exec,
    canary_protocol::{
        RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT, RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT,
        RuntimeCanaryFixtureInputs, RuntimeCanaryReport, RuntimeCanaryRuntimeEvidence,
        runtime_canary_codex_home_fixture_path, runtime_canary_credential_path,
        runtime_canary_final_output_fixture_path, runtime_canary_forbidden_ip_allowed,
        runtime_canary_main_home_fixture_path, runtime_canary_workspace_fixture_path,
        validate_runtime_canary_nonce,
    },
};

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
const RUNTIME_CANARY_FIXTURE_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const RUNTIME_CANARY_DESCRIPTOR_SECRET_BYTES: usize = 32;
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
    "\"/run/webex-codex-canary\"=\"deny\",",
    "\"/run/webex-config-pull\"=\"deny\",",
    "\"/var/lib/webex-generic-account-bot/canary-fixtures\"=\"deny\",",
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
#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true)]
struct RuntimeCanaryCli {
    #[arg(long, required = true)]
    runtime_canary: bool,

    #[arg(long, value_parser = validate_runtime_canary_nonce_cli)]
    nonce: String,

    #[arg(long, value_parser = validate_forbidden_tcp)]
    forbidden_tcp: String,

    #[arg(long, value_parser = validate_bot_tcp)]
    bot_tcp: String,

    #[arg(long)]
    host_unix: PathBuf,

    #[arg(long)]
    host_protected_path: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct ValidatedRuntimeCanaryCli {
    nonce: String,
    forbidden_tcp: String,
    bot_tcp: String,
    host_unix: String,
    host_protected_path: String,
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
    if env::args_os().any(|argument| argument == OsStr::new("--runtime-canary")) {
        return run_runtime_canary(RuntimeCanaryCli::parse());
    }
    run_normal_runtime(Cli::parse())
}

#[cfg(target_os = "linux")]
fn run_normal_runtime(cli: Cli) -> Result<()> {
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
fn run_runtime_canary(cli: RuntimeCanaryCli) -> Result<()> {
    let cli = validate_runtime_canary_cli(cli)?;
    prepare_private_directories()?;
    let credential = credential_path()?;
    let expected_credential = PathBuf::from(runtime_canary_credential_path(&cli.nonce)?);
    if credential != expected_credential {
        return Err(anyhow!(
            "systemd credential path does not match the runtime canary nonce"
        ));
    }
    install_run_credential(&credential)?;
    harden_process()?;
    close_nonstandard_descriptors()?;

    let descriptor_secret = create_runtime_canary_descriptor_secret()?;
    let main_pid = std::process::id();
    let inputs = RuntimeCanaryFixtureInputs {
        main_pid,
        fd_secret_sha256: descriptor_secret.sha256.clone(),
        forbidden_tcp: cli.forbidden_tcp,
        bot_tcp: cli.bot_tcp,
        host_unix: cli.host_unix,
        host_protected_path: cli.host_protected_path,
    };
    let rendered = canary_exec::render_runtime_canary_exec(&cli.nonce, &inputs)?;
    let fixture_paths = create_runtime_canary_fixtures(&cli.nonce)?;
    let snapshots = RuntimeCanarySnapshots::capture(&credential, &fixture_paths)?;

    let mut command = Command::new(CODEX_PATH);
    command.args(runtime_canary_codex_args());
    command.env_clear();
    command
        .env("HOME", MAIN_HOME)
        .env("CODEX_HOME", CODEX_HOME)
        .env("PATH", MAIN_PATH)
        .env("SHELL", "/bin/sh")
        .env("LANG", "C.UTF-8")
        .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
    command.stderr(Stdio::inherit());

    let report = run_runtime_canary_codex(
        &mut command,
        Path::new(FINAL_OUTPUT_PATH),
        &rendered.prompt,
        &cli.nonce,
        &inputs,
    )?;
    let integrity = snapshots.verify_after();
    verify_descriptor_secret_is_held(&descriptor_secret)?;
    let evidence = RuntimeCanaryRuntimeEvidence {
        nonce: cli.nonce.clone(),
        fixture_binding: rendered.fixture_binding.clone(),
        report,
        main_pid,
        fd_secret_sha256: descriptor_secret.sha256.clone(),
        credential_path_regular_file_before: true,
        credential_path_regular_file_after: integrity.credential.regular_file_after,
        credential_path_identity_unchanged: integrity.credential.identity_unchanged,
        credential_path_contents_unchanged: integrity.credential.contents_unchanged,
        main_home_fixture_regular_file_before: true,
        main_home_fixture_regular_file_after: integrity.main_home.regular_file_after,
        main_home_fixture_identity_unchanged: integrity.main_home.identity_unchanged,
        main_home_fixture_contents_unchanged: integrity.main_home.contents_unchanged,
        codex_home_fixture_regular_file_before: true,
        codex_home_fixture_regular_file_after: integrity.codex_home.regular_file_after,
        codex_home_fixture_identity_unchanged: integrity.codex_home.identity_unchanged,
        codex_home_fixture_contents_unchanged: integrity.codex_home.contents_unchanged,
        final_output_fixture_regular_file_before: true,
        final_output_fixture_regular_file_after: integrity.final_output.regular_file_after,
        final_output_fixture_identity_unchanged: integrity.final_output.identity_unchanged,
        final_output_fixture_contents_unchanged: integrity.final_output.contents_unchanged,
        workspace_fixture_regular_file_before: true,
        workspace_fixture_regular_file_after: integrity.workspace.regular_file_after,
        workspace_fixture_identity_unchanged: integrity.workspace.identity_unchanged,
        workspace_fixture_contents_unchanged: integrity.workspace.contents_unchanged,
    };
    evidence.validate(&cli.nonce, &rendered.fixture_binding, &inputs)?;
    let output = evidence.to_json_line()?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_runtime_canary_cli(cli: RuntimeCanaryCli) -> Result<ValidatedRuntimeCanaryCli> {
    if !cli.runtime_canary || cli.forbidden_tcp == cli.bot_tcp {
        return Err(anyhow!("runtime canary mode inputs are invalid"));
    }
    let expected_unix = format!("{RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT}/{}.sock", cli.nonce);
    let expected_protected = format!("{RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT}/{}", cli.nonce);
    if cli.host_unix != Path::new(&expected_unix)
        || cli.host_protected_path != Path::new(&expected_protected)
    {
        return Err(anyhow!("host runtime canary paths do not match the nonce"));
    }
    Ok(ValidatedRuntimeCanaryCli {
        nonce: cli.nonce,
        forbidden_tcp: cli.forbidden_tcp,
        bot_tcp: cli.bot_tcp,
        host_unix: expected_unix,
        host_protected_path: expected_protected,
    })
}

#[cfg(target_os = "linux")]
fn validate_runtime_canary_nonce_cli(value: &str) -> std::result::Result<String, String> {
    validate_runtime_canary_nonce(value)
        .map(|()| value.to_owned())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn validate_forbidden_tcp(value: &str) -> std::result::Result<String, String> {
    let endpoint = value
        .parse::<SocketAddr>()
        .map_err(|_| "forbidden runtime canary TCP endpoint is invalid".to_owned())?;
    if endpoint.port() == 0
        || !runtime_canary_forbidden_ip_allowed(endpoint.ip())
        || endpoint.to_string() != value
    {
        return Err(
            "forbidden runtime canary TCP endpoint must be canonical non-loopback unicast"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn validate_bot_tcp(value: &str) -> std::result::Result<String, String> {
    let endpoint = value
        .parse::<SocketAddr>()
        .map_err(|_| "bot runtime canary TCP endpoint is invalid".to_owned())?;
    if endpoint.port() == 0 || !endpoint.ip().is_loopback() || endpoint.to_string() != value {
        return Err(
            "bot runtime canary TCP endpoint must be canonical loopback with a nonzero port"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
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
fn run_runtime_canary_codex(
    command: &mut Command,
    output_path: &Path,
    prompt: &str,
    nonce: &str,
    inputs: &RuntimeCanaryFixtureInputs,
) -> Result<RuntimeCanaryReport> {
    match fs::symlink_metadata(output_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(anyhow!("final Codex message path already exists")),
        Err(error) => return Err(error.into()),
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command
        .spawn()
        .context("failed to start the fixed Codex runtime canary")?;

    let write_result = (|| -> Result<()> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("fixed Codex runtime canary stdin is unavailable"))?;
        stdin
            .write_all(prompt.as_bytes())
            .context("failed to write the fixed runtime canary prompt")?;
        stdin.flush()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        terminate_child(&mut child);
        return Err(error);
    }

    let read_result = (|| -> Result<Vec<u8>> {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("fixed Codex runtime canary stdout is unavailable"))?;
        let mut jsonl = Vec::new();
        Read::by_ref(&mut stdout)
            .take(canary_exec::CODEX_EXEC_CANARY_JSONL_MAX_BYTES as u64 + 1)
            .read_to_end(&mut jsonl)
            .context("failed to read fixed Codex runtime canary JSONL")?;
        if jsonl.len() > canary_exec::CODEX_EXEC_CANARY_JSONL_MAX_BYTES {
            return Err(anyhow!("fixed Codex runtime canary JSONL is too large"));
        }
        Ok(jsonl)
    })();
    let jsonl = match read_result {
        Ok(jsonl) => jsonl,
        Err(error) => {
            terminate_child(&mut child);
            return Err(error);
        }
    };

    let status = child
        .wait()
        .context("failed to wait for the fixed Codex runtime canary")?;
    if !status.success() {
        return Err(anyhow!("fixed Codex runtime canary failed: {status}"));
    }
    let report = canary_exec::parse_runtime_canary_exec_jsonl(&jsonl, nonce, inputs)?;
    let final_output = read_final_output(output_path)?;
    verify_runtime_canary_final_output(&final_output, &report.final_line)?;
    Ok(report)
}

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn verify_runtime_canary_final_output(output: &[u8], expected_line: &str) -> Result<()> {
    let expected = expected_line.as_bytes();
    if output != expected
        && !(output.len() == expected.len() + 1
            && output.starts_with(expected)
            && output.last() == Some(&b'\n'))
    {
        return Err(anyhow!(
            "final Codex canary message does not match its fixture binding"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct RuntimeCanaryDescriptorSecret {
    file: File,
    sha256: String,
}

#[cfg(target_os = "linux")]
fn create_runtime_canary_descriptor_secret() -> Result<RuntimeCanaryDescriptorSecret> {
    let mut secret = [0_u8; RUNTIME_CANARY_DESCRIPTOR_SECRET_BYTES];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow!("failed to generate the runtime canary descriptor secret"))?;
    let name = CString::new("webex-codex-runtime-canary-secret")
        .expect("fixed runtime canary memfd name contains no NUL");
    // SAFETY: name is a live NUL-terminated string and the flags are valid for memfd_create.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create the runtime canary descriptor secret");
    }
    // SAFETY: descriptor is newly owned after a successful memfd_create call.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(&secret)?;
    file.flush()?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: file owns descriptor and F_ADD_SEALS takes only the integer seal mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to seal the runtime canary descriptor secret");
    }
    let sha256 = hex_digest(digest(&SHA256, &secret).as_ref());
    secret.fill(0);
    let descriptor_secret = RuntimeCanaryDescriptorSecret { file, sha256 };
    verify_descriptor_secret_is_held(&descriptor_secret)?;
    Ok(descriptor_secret)
}

#[cfg(target_os = "linux")]
fn verify_descriptor_secret_is_held(secret: &RuntimeCanaryDescriptorSecret) -> Result<()> {
    // SAFETY: F_GETFD reads flags from the live descriptor without pointer arguments.
    let flags = unsafe { libc::fcntl(secret.file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(anyhow!(
            "runtime canary descriptor secret is not held with CLOEXEC"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RuntimeCanaryFixturePaths {
    main_home: PathBuf,
    codex_home: PathBuf,
    final_output: PathBuf,
    workspace: PathBuf,
}

#[cfg(target_os = "linux")]
fn create_runtime_canary_fixtures(nonce: &str) -> Result<RuntimeCanaryFixturePaths> {
    let paths = RuntimeCanaryFixturePaths {
        main_home: runtime_canary_main_home_fixture_path(nonce)?.into(),
        codex_home: runtime_canary_codex_home_fixture_path(nonce)?.into(),
        final_output: runtime_canary_final_output_fixture_path(nonce)?.into(),
        workspace: runtime_canary_workspace_fixture_path(nonce)?.into(),
    };
    create_runtime_canary_fixture(&paths.main_home, "main-home", nonce)?;
    create_runtime_canary_fixture(&paths.codex_home, "codex-home", nonce)?;
    create_runtime_canary_fixture(&paths.final_output, "final-output-sibling", nonce)?;
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn create_runtime_canary_fixture(path: &Path, label: &str, nonce: &str) -> Result<()> {
    let contents = format!("webex-codex-runtime-canary {label} {nonce}\n");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to create runtime canary fixture {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let identity = RegularFileIdentity::from_metadata(&file.metadata()?);
    if !identity.is_valid(RUNTIME_CANARY_FIXTURE_MAX_BYTES, Some(0o600))
        // SAFETY: geteuid has no arguments and returns process metadata.
        || identity.uid != unsafe { libc::geteuid() }
    {
        return Err(anyhow!("runtime canary fixture metadata is invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegularFileIdentity {
    device: u64,
    inode: u64,
    file_type: u32,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
}

#[cfg(target_os = "linux")]
impl RegularFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            file_type: metadata.mode() & libc::S_IFMT,
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.len(),
        }
    }

    fn is_valid(&self, max_bytes: u64, required_mode: Option<u32>) -> bool {
        self.file_type == libc::S_IFREG
            && self.links == 1
            && self.size > 0
            && self.size <= max_bytes
            && required_mode.is_none_or(|mode| self.mode == mode)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RegularFileSnapshot {
    path: PathBuf,
    identity: RegularFileIdentity,
    content_sha256: [u8; 32],
    max_bytes: u64,
    required_mode: Option<u32>,
}

#[cfg(target_os = "linux")]
impl RegularFileSnapshot {
    fn capture(path: &Path, max_bytes: u64, required_mode: Option<u32>) -> Result<Self> {
        let (identity, content_sha256) =
            capture_regular_file_state(path, max_bytes, required_mode)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            content_sha256,
            max_bytes,
            required_mode,
        })
    }

    fn verify_after(&self) -> FileIntegrityEvidence {
        let regular_file_after = fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            RegularFileIdentity::from_metadata(&metadata)
                .is_valid(self.max_bytes, self.required_mode)
        });
        let Ok((identity, content_sha256)) =
            capture_regular_file_state(&self.path, self.max_bytes, self.required_mode)
        else {
            return FileIntegrityEvidence {
                regular_file_after,
                identity_unchanged: false,
                contents_unchanged: false,
            };
        };
        FileIntegrityEvidence {
            regular_file_after,
            identity_unchanged: identity == self.identity,
            contents_unchanged: content_sha256 == self.content_sha256,
        }
    }
}

#[cfg(target_os = "linux")]
fn capture_regular_file_state(
    path: &Path,
    max_bytes: u64,
    required_mode: Option<u32>,
) -> Result<(RegularFileIdentity, [u8; 32])> {
    let path_identity =
        RegularFileIdentity::from_metadata(&fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to inspect runtime canary fixture {}",
                path.display()
            )
        })?);
    if !path_identity.is_valid(max_bytes, required_mode) {
        return Err(anyhow!("runtime canary fixture metadata is invalid"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open runtime canary fixture {}", path.display()))?;
    let open_identity = RegularFileIdentity::from_metadata(&file.metadata()?);
    if open_identity != path_identity || !open_identity.is_valid(max_bytes, required_mode) {
        return Err(anyhow!("runtime canary fixture identity changed"));
    }
    let content_sha256 = hash_bounded_file(&mut file, open_identity.size, max_bytes)?;
    let final_open_identity = RegularFileIdentity::from_metadata(&file.metadata()?);
    let final_path_identity = RegularFileIdentity::from_metadata(&fs::symlink_metadata(path)?);
    if final_open_identity != open_identity || final_path_identity != open_identity {
        return Err(anyhow!("runtime canary fixture changed while it was read"));
    }
    Ok((open_identity, content_sha256))
}

#[cfg(target_os = "linux")]
fn hash_bounded_file(file: &mut File, expected_size: u64, max_bytes: u64) -> Result<[u8; 32]> {
    let mut context = ring::digest::Context::new(&SHA256);
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("runtime canary fixture size overflowed"))?;
        if total > max_bytes {
            return Err(anyhow!("runtime canary fixture exceeds its size limit"));
        }
        context.update(&buffer[..count]);
    }
    if total != expected_size {
        return Err(anyhow!("runtime canary fixture size changed while hashing"));
    }
    context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("SHA-256 returned an unexpected digest length"))
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RuntimeCanarySnapshots {
    credential: RegularFileSnapshot,
    main_home: RegularFileSnapshot,
    codex_home: RegularFileSnapshot,
    final_output: RegularFileSnapshot,
    workspace: RegularFileSnapshot,
}

#[cfg(target_os = "linux")]
impl RuntimeCanarySnapshots {
    fn capture(credential: &Path, fixtures: &RuntimeCanaryFixturePaths) -> Result<Self> {
        Ok(Self {
            credential: RegularFileSnapshot::capture(credential, AUTH_MAX_BYTES, None)?,
            main_home: RegularFileSnapshot::capture(
                &fixtures.main_home,
                RUNTIME_CANARY_FIXTURE_MAX_BYTES,
                Some(0o600),
            )?,
            codex_home: RegularFileSnapshot::capture(
                &fixtures.codex_home,
                RUNTIME_CANARY_FIXTURE_MAX_BYTES,
                Some(0o600),
            )?,
            final_output: RegularFileSnapshot::capture(
                &fixtures.final_output,
                RUNTIME_CANARY_FIXTURE_MAX_BYTES,
                Some(0o600),
            )?,
            workspace: RegularFileSnapshot::capture(
                &fixtures.workspace,
                RUNTIME_CANARY_FIXTURE_MAX_BYTES,
                None,
            )?,
        })
    }

    fn verify_after(&self) -> RuntimeCanaryIntegrityEvidence {
        RuntimeCanaryIntegrityEvidence {
            credential: self.credential.verify_after(),
            main_home: self.main_home.verify_after(),
            codex_home: self.codex_home.verify_after(),
            final_output: self.final_output.verify_after(),
            workspace: self.workspace.verify_after(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct FileIntegrityEvidence {
    regular_file_after: bool,
    identity_unchanged: bool,
    contents_unchanged: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RuntimeCanaryIntegrityEvidence {
    credential: FileIntegrityEvidence,
    main_home: FileIntegrityEvidence,
    codex_home: FileIntegrityEvidence,
    final_output: FileIntegrityEvidence,
    workspace: FileIntegrityEvidence,
}

#[cfg(target_os = "linux")]
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
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
    Read::by_ref(&mut file)
        .take(FINAL_OUTPUT_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut output)?;
    if output.len() as u64 > FINAL_OUTPUT_MAX_BYTES {
        return Err(anyhow!("final Codex message exceeds its size limit"));
    }
    let final_metadata = file.metadata()?;
    if !same_final_output_metadata(&metadata, &final_metadata)
        || final_metadata.len() != output.len() as u64
    {
        return Err(anyhow!("final Codex message changed while it was read"));
    }
    std::str::from_utf8(&output).context("final Codex message is not UTF-8")?;
    Ok(output)
}

#[cfg(target_os = "linux")]
fn same_final_output_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
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

#[cfg(target_os = "linux")]
fn runtime_canary_codex_args() -> Vec<OsString> {
    let cli = Cli {
        workspace: PathBuf::from(WORKSPACE_PATH),
        model: "gpt-5.5".to_owned(),
        reasoning_effort: Some(ReasoningEffort::Xhigh),
    };
    let mut args = codex_args(&cli);
    let exec = args
        .iter()
        .position(|argument| argument == OsStr::new("exec"))
        .expect("fixed Codex arguments contain exec");
    args.insert(exec + 1, OsString::from("--json"));
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
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;
    use webex_generic_account_bot::canary_protocol::{
        RUNTIME_CANARY_CHECKS, expected_runtime_canary_final_line, runtime_canary_fixture_binding,
    };

    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FD_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "webex-codex-runtime-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cli() -> Cli {
        Cli {
            workspace: PathBuf::from(WORKSPACE_PATH),
            model: "gpt-5.5".to_owned(),
            reasoning_effort: Some(ReasoningEffort::Xhigh),
        }
    }

    fn runtime_canary_cli_args() -> Vec<String> {
        vec![
            "webex-codex-runtime".to_owned(),
            "--runtime-canary".to_owned(),
            "--nonce".to_owned(),
            NONCE.to_owned(),
            "--forbidden-tcp".to_owned(),
            "192.0.2.10:41001".to_owned(),
            "--bot-tcp".to_owned(),
            "127.0.0.1:41002".to_owned(),
            "--host-unix".to_owned(),
            format!("{RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT}/{NONCE}.sock"),
            "--host-protected-path".to_owned(),
            format!("{RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT}/{NONCE}"),
        ]
    }

    fn fixture_inputs() -> RuntimeCanaryFixtureInputs {
        RuntimeCanaryFixtureInputs {
            main_pid: 42,
            fd_secret_sha256: FD_DIGEST.to_owned(),
            forbidden_tcp: "192.0.2.10:41001".to_owned(),
            bot_tcp: "127.0.0.1:41002".to_owned(),
            host_unix: format!("{RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT}/{NONCE}.sock"),
            host_protected_path: format!("{RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT}/{NONCE}"),
        }
    }

    fn passing_report() -> RuntimeCanaryReport {
        RuntimeCanaryReport::new(
            NONCE.to_owned(),
            runtime_canary_fixture_binding(NONCE, &fixture_inputs()).unwrap(),
            RUNTIME_CANARY_CHECKS
                .iter()
                .map(|name| ((*name).to_owned(), true))
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap()
    }

    fn success_jsonl() -> Vec<u8> {
        let rendered = canary_exec::render_runtime_canary_exec(NONCE, &fixture_inputs()).unwrap();
        let report = passing_report();
        let report_output = String::from_utf8(report.to_json_line().unwrap()).unwrap();
        let events = [
            json!({"type": "thread.started", "thread_id": "thread-1"}),
            json!({"type": "turn.started"}),
            json!({
                "type": "item.started",
                "item": {
                    "id": "item-1",
                    "type": "command_execution",
                    "command": rendered.event_command,
                    "status": "in_progress"
                }
            }),
            json!({
                "type": "item.completed",
                "item": {
                    "id": "item-1",
                    "type": "command_execution",
                    "command": rendered.event_command,
                    "aggregated_output": report_output,
                    "exit_code": 0,
                    "status": "completed"
                }
            }),
            json!({
                "type": "item.completed",
                "item": {
                    "id": "item-2",
                    "type": "agent_message",
                    "text": expected_runtime_canary_final_line(
                        NONCE,
                        &rendered.fixture_binding
                    )
                }
            }),
            json!({
                "type": "turn.completed",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        ];
        let mut output = Vec::new();
        for event in events {
            output.extend(serde_json::to_vec(&event).unwrap());
            output.push(b'\n');
        }
        output
    }

    fn write_test_file(path: &Path, contents: &[u8], mode: u32) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
        file.set_permissions(fs::Permissions::from_mode(mode))
            .unwrap();
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
    fn runtime_canary_cli_accepts_only_canonical_bound_inputs() {
        let parsed = RuntimeCanaryCli::try_parse_from(runtime_canary_cli_args()).unwrap();
        let validated = validate_runtime_canary_cli(parsed).unwrap();
        assert_eq!(validated.nonce, NONCE);
        assert_eq!(validated.forbidden_tcp, "192.0.2.10:41001");
        assert_eq!(validated.bot_tcp, "127.0.0.1:41002");

        let mut missing_mode = runtime_canary_cli_args();
        missing_mode.remove(1);
        assert!(RuntimeCanaryCli::try_parse_from(missing_mode).is_err());

        let mut uppercase_nonce = runtime_canary_cli_args();
        uppercase_nonce[3] = NONCE.to_ascii_uppercase();
        assert!(RuntimeCanaryCli::try_parse_from(uppercase_nonce).is_err());

        let mut loopback_forbidden = runtime_canary_cli_args();
        loopback_forbidden[5] = "127.0.0.1:41001".to_owned();
        assert!(RuntimeCanaryCli::try_parse_from(loopback_forbidden).is_err());

        let mut noncanonical_bot = runtime_canary_cli_args();
        noncanonical_bot[7] = "[0:0:0:0:0:0:0:1]:41002".to_owned();
        assert!(RuntimeCanaryCli::try_parse_from(noncanonical_bot).is_err());

        let mut wrong_path = runtime_canary_cli_args();
        wrong_path[9].push_str(".other");
        let parsed = RuntimeCanaryCli::try_parse_from(wrong_path).unwrap();
        assert!(validate_runtime_canary_cli(parsed).is_err());
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
        assert!(PERMISSION_PROFILE.contains("/run/webex-codex-canary\"=\"deny"));
        assert!(
            PERMISSION_PROFILE
                .contains("/var/lib/webex-generic-account-bot/canary-fixtures\"=\"deny")
        );
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
    fn runtime_canary_arguments_add_only_json_to_the_fixed_exec_boundary() {
        let mut expected = codex_args(&Cli {
            workspace: PathBuf::from(WORKSPACE_PATH),
            model: "gpt-5.5".to_owned(),
            reasoning_effort: Some(ReasoningEffort::Xhigh),
        });
        let exec = expected
            .iter()
            .position(|argument| argument == OsStr::new("exec"))
            .unwrap();
        expected.insert(exec + 1, "--json".into());

        let actual = runtime_canary_codex_args();
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .iter()
                .filter(|argument| *argument == OsStr::new("--json"))
                .count(),
            1
        );
    }

    #[test]
    fn descriptor_secret_is_random_sealed_and_cloexec() {
        let first = create_runtime_canary_descriptor_secret().unwrap();
        let second = create_runtime_canary_descriptor_secret().unwrap();
        verify_descriptor_secret_is_held(&first).unwrap();
        assert_eq!(first.sha256.len(), 64);
        assert!(first.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first.sha256, second.sha256);

        // SAFETY: F_GET_SEALS reads the seal mask from the live memfd.
        let seals = unsafe { libc::fcntl(first.file.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(
            seals
                & (libc::F_SEAL_SEAL
                    | libc::F_SEAL_SHRINK
                    | libc::F_SEAL_GROW
                    | libc::F_SEAL_WRITE),
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE
        );
    }

    #[test]
    fn snapshots_verify_all_interior_files_and_detect_workspace_mutation() {
        let directory = TestDirectory::new("snapshots");
        let credential = directory.join("credential");
        let main_home = directory.join("main-home");
        let codex_home = directory.join("codex-home");
        let final_output = directory.join("final-output-sibling");
        let workspace = directory.join("workspace");
        write_test_file(&credential, b"{\"token\":\"not-emitted\"}\n", 0o400);
        write_test_file(&main_home, b"main\n", 0o600);
        write_test_file(&codex_home, b"codex\n", 0o600);
        write_test_file(&final_output, b"final\n", 0o600);
        write_test_file(&workspace, b"sealed\n", 0o400);
        let paths = RuntimeCanaryFixturePaths {
            main_home: main_home.clone(),
            codex_home,
            final_output: final_output.clone(),
            workspace: workspace.clone(),
        };
        let snapshots = RuntimeCanarySnapshots::capture(&credential, &paths).unwrap();
        let before_mutation = snapshots.verify_after();
        for evidence in [
            before_mutation.credential,
            before_mutation.main_home,
            before_mutation.codex_home,
            before_mutation.final_output,
            before_mutation.workspace,
        ] {
            assert!(evidence.regular_file_after);
            assert!(evidence.identity_unchanged);
            assert!(evidence.contents_unchanged);
        }

        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&workspace, b"opened\n").unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o400)).unwrap();
        let after_mutation = snapshots.verify_after();
        assert!(after_mutation.workspace.regular_file_after);
        assert!(after_mutation.workspace.identity_unchanged);
        assert!(!after_mutation.workspace.contents_unchanged);
        assert!(after_mutation.credential.contents_unchanged);
        assert!(after_mutation.main_home.contents_unchanged);
        assert!(after_mutation.codex_home.contents_unchanged);
        assert!(after_mutation.final_output.contents_unchanged);

        let replacement = directory.join("replacement");
        write_test_file(&replacement, b"main\n", 0o600);
        fs::rename(replacement, &main_home).unwrap();
        let hardlink = directory.join("final-hardlink");
        fs::hard_link(&final_output, hardlink).unwrap();
        let after_identity_changes = snapshots.verify_after();
        assert!(after_identity_changes.main_home.regular_file_after);
        assert!(!after_identity_changes.main_home.identity_unchanged);
        assert!(after_identity_changes.main_home.contents_unchanged);
        assert!(!after_identity_changes.final_output.regular_file_after);
        assert!(!after_identity_changes.final_output.identity_unchanged);
        assert!(!after_identity_changes.final_output.contents_unchanged);
    }

    #[test]
    fn final_canary_line_allows_at_most_one_trailing_lf() {
        let expected = "WEBEX_CODEX_CANARY_OK nonce binding";
        verify_runtime_canary_final_output(expected.as_bytes(), expected).unwrap();
        verify_runtime_canary_final_output(format!("{expected}\n").as_bytes(), expected).unwrap();
        assert!(
            verify_runtime_canary_final_output(format!("{expected}\n\n").as_bytes(), expected)
                .is_err()
        );
        assert!(verify_runtime_canary_final_output(b"other", expected).is_err());
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

        fs::write(&path, vec![b'x'; FINAL_OUTPUT_MAX_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_final_output(&path).is_err());

        fs::write(&path, b"final response\n").unwrap();
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

    #[test]
    fn runtime_canary_supervisor_writes_prompt_and_parses_captured_jsonl() {
        let directory = TestDirectory::new("canary-supervisor");
        let prompt_path = directory.join("prompt");
        let jsonl_path = directory.join("events.jsonl");
        let output_path = directory.join("final-message");
        fs::write(&jsonl_path, success_jsonl()).unwrap();
        let rendered = canary_exec::render_runtime_canary_exec(NONCE, &fixture_inputs()).unwrap();
        let expected_final = expected_runtime_canary_final_line(NONCE, &rendered.fixture_binding);
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "cat > \"$1\"; cat \"$2\"; umask 077; printf '%s' \"$3\" > \"$4\"",
                "webex-codex-runtime-canary-test",
            ])
            .arg(&prompt_path)
            .arg(&jsonl_path)
            .arg(&expected_final)
            .arg(&output_path)
            .stderr(Stdio::null());

        let report = run_runtime_canary_codex(
            &mut command,
            &output_path,
            &rendered.prompt,
            NONCE,
            &fixture_inputs(),
        )
        .unwrap();
        assert_eq!(report, passing_report());
        assert_eq!(fs::read_to_string(prompt_path).unwrap(), rendered.prompt);
    }
}

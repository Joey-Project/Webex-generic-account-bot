#[cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::anyhow;
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use ring::digest::{Context as DigestContext, SHA256};
#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    task::JoinHandle,
    time::sleep,
};

#[cfg(target_os = "linux")]
use crate::{
    codex_launcher::AuthorisedPeer,
    launcher_protocol::{ExecuteRequest, OUTPUT_MAX_BYTES, ReasoningEffort},
};

pub const RUNTIME_ROOT: &str = "/opt/webex-generic-account-bot/runtime";
pub const RUNTIME_ACTIVE_MANIFEST_PATH: &str = "/opt/webex-generic-account-bot/runtime/active.json";
pub const CODEX_AUTH_CREDENTIAL_PATH: &str = "/etc/webex-generic-account-bot/codex-auth.json";
pub const CODEX_INPUT_ROOT: &str = "/var/lib/webex-codex-inputs";
pub const CODEX_CONSUMED_INPUT_ROOT: &str = "/var/lib/webex-codex-inputs-consumed";
pub const RUNTIME_EXECUTABLE_PATH: &str = "/usr/libexec/webex-codex-runtime";

#[cfg(target_os = "linux")]
const SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
#[cfg(target_os = "linux")]
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
#[cfg(target_os = "linux")]
const CODEX_INPUT_GROUP: &str = "webex-codex-input";
#[cfg(target_os = "linux")]
const ISOLATED_EXECUTION_ACTIVATED: bool = false;
#[cfg(target_os = "linux")]
const ACTIVE_MANIFEST_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const RUNTIME_IMAGE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const CODEX_AUTH_MAX_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const OUTPUT_CAPTURE_BYTES: usize = OUTPUT_MAX_BYTES + 1024;
#[cfg(target_os = "linux")]
const STDERR_CAPTURE_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const PEER_POLL_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(target_os = "linux")]
const CLEANUP_MARGIN: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";
#[cfg(target_os = "linux")]
const SUPPORTED_CODEX_VERSION: &str = "0.142.3";
#[cfg(target_os = "linux")]
const SUPPORTED_CODEX_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(target_os = "linux")]
const SUPPORTED_CODEX_LAYOUT_VERSION: u16 = 1;
#[cfg(target_os = "linux")]
const EXPECTED_MKSQUASHFS_ARGV_SHA256: &str =
    "700c3e735fb100cddedd05dec3e8a45866e330522b74d2f96389ea2300564bd5";
#[cfg(target_os = "linux")]
const WORKSPACE_ENTRY_MAX: usize = 8_192;
#[cfg(target_os = "linux")]
const WORKSPACE_DEPTH_MAX: usize = 32;
#[cfg(target_os = "linux")]
const WORKSPACE_TOTAL_BYTES_MAX: u64 = 2 * 1024 * 1024 * 1024 + 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
type CaptureTask = JoinHandle<Result<(String, bool)>>;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct VerifiedRuntime {
    pub image: PathBuf,
    pub codex_version: String,
    input_gid: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct VerifiedWorkspace {
    path: PathBuf,
    bind_source: String,
    _guard: File,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransientRunPlan {
    pub unit: String,
    pub executable: &'static str,
    pub args: Vec<OsString>,
    pub workspace: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolatedRunResult {
    Completed { output: String, truncated: bool },
    TimedOut,
    Failed,
}

#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum IsolatedExecutionError {
    #[error("isolated Codex runtime is unavailable")]
    Unavailable(#[source] anyhow::Error),
    #[error("isolated Codex execution failed internally")]
    Failed(#[source] anyhow::Error),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRuntimeManifest {
    version: u16,
    builder_version: u16,
    codex_version: String,
    codex_target: String,
    codex_layout_version: u16,
    image: String,
    image_sha256: String,
    image_size: u64,
    source_manifest_sha256: String,
    mksquashfs_sha256: String,
    mksquashfs_argv_sha256: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct RuntimePaths {
    root: PathBuf,
    active_manifest: PathBuf,
    credential: PathBuf,
    systemd_run: PathBuf,
    systemctl: PathBuf,
    input_root: PathBuf,
    consumed_input_root: PathBuf,
    group_file: PathBuf,
    passwd_file: PathBuf,
}

#[cfg(target_os = "linux")]
impl Default for RuntimePaths {
    fn default() -> Self {
        Self {
            root: PathBuf::from(RUNTIME_ROOT),
            active_manifest: PathBuf::from(RUNTIME_ACTIVE_MANIFEST_PATH),
            credential: PathBuf::from(CODEX_AUTH_CREDENTIAL_PATH),
            systemd_run: PathBuf::from(SYSTEMD_RUN_PATH),
            systemctl: PathBuf::from(SYSTEMCTL_PATH),
            input_root: PathBuf::from(CODEX_INPUT_ROOT),
            consumed_input_root: PathBuf::from(CODEX_CONSUMED_INPUT_ROOT),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn preflight() -> Result<VerifiedRuntime> {
    ensure_activation_enabled()?;
    verify_runtime(&RuntimePaths::default(), 0)
}

#[cfg(target_os = "linux")]
pub async fn execute(
    request: &ExecuteRequest,
    peer: &AuthorisedPeer,
) -> std::result::Result<IsolatedRunResult, IsolatedExecutionError> {
    ensure_activation_enabled().map_err(IsolatedExecutionError::Unavailable)?;
    validate_execution_policy(request).map_err(IsolatedExecutionError::Failed)?;
    let paths = RuntimePaths::default();
    let runtime = verify_runtime(&paths, 0).map_err(IsolatedExecutionError::Unavailable)?;
    let launcher_unit = current_launcher_unit().map_err(IsolatedExecutionError::Failed)?;
    let workspace = verify_workspace(
        &paths.input_root,
        &paths.consumed_input_root,
        request,
        runtime.input_gid,
    )
    .map_err(IsolatedExecutionError::Failed)?;
    let plan = build_transient_run_plan(
        request,
        &runtime,
        &workspace.path,
        &workspace.bind_source,
        &launcher_unit,
    )
    .map_err(IsolatedExecutionError::Failed)?;
    run_transient(plan, request, peer, workspace)
        .await
        .map_err(IsolatedExecutionError::Failed)
}

#[cfg(target_os = "linux")]
fn ensure_activation_enabled() -> Result<()> {
    if !ISOLATED_EXECUTION_ACTIVATED {
        return Err(anyhow!(
            "isolated Codex execution awaits production capability canaries"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_execution_policy(request: &ExecuteRequest) -> Result<()> {
    request.validate().map_err(|error| anyhow!(error))?;
    if request.model.as_deref() != Some("gpt-5.5") {
        return Err(anyhow!("runtime model is not allowlisted"));
    }
    if !request.skip_git_repo_check {
        return Err(anyhow!(
            "isolated runtime requires the fixed Git repository bypass"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_runtime(paths: &RuntimePaths, expected_uid: u32) -> Result<VerifiedRuntime> {
    trusted_file(
        &paths.active_manifest,
        expected_uid,
        FilePolicy::ReadOnlyData,
    )?;
    trusted_file(
        &paths.credential,
        expected_uid,
        FilePolicy::PrivateCredential,
    )?;
    trusted_file(&paths.systemd_run, expected_uid, FilePolicy::Executable)?;
    trusted_file(&paths.systemctl, expected_uid, FilePolicy::Executable)?;
    trusted_file(&paths.group_file, expected_uid, FilePolicy::HostData)?;
    trusted_file(&paths.passwd_file, expected_uid, FilePolicy::HostData)?;
    let manifest_bytes = read_bounded_file(&paths.active_manifest, ACTIVE_MANIFEST_MAX_BYTES)?;
    let manifest: ActiveRuntimeManifest =
        serde_json::from_slice(&manifest_bytes).context("runtime active manifest is invalid")?;
    validate_active_manifest(&manifest)?;

    let image = paths.root.join(&manifest.image);
    if !image.starts_with(paths.root.join("images")) {
        return Err(anyhow!("runtime image path is outside the content store"));
    }
    trusted_file(&image, expected_uid, FilePolicy::ReadOnlyData)?;
    let metadata = fs::metadata(&image)?;
    if metadata.len() != manifest.image_size || metadata.len() > RUNTIME_IMAGE_MAX_BYTES {
        return Err(anyhow!("runtime image size does not match its manifest"));
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&image)?;
    let mut magic = [0_u8; SQUASHFS_MAGIC.len()];
    file.read_exact(&mut magic)?;
    if &magic != SQUASHFS_MAGIC {
        return Err(anyhow!("runtime image is not SquashFS"));
    }
    let digest = hash_reader(file, &magic)?;
    if digest != manifest.image_sha256 {
        return Err(anyhow!("runtime image digest does not match its manifest"));
    }
    let credential = read_bounded_file(&paths.credential, CODEX_AUTH_MAX_BYTES)?;
    if !serde_json::from_slice::<serde_json::Value>(&credential)
        .is_ok_and(|value| value.is_object())
    {
        return Err(anyhow!("Codex credential is not a JSON object"));
    }
    let input_gid = resolve_group_gid(&paths.group_file, CODEX_INPUT_GROUP)?;
    reject_primary_gid_users(&paths.passwd_file, input_gid)?;
    trusted_input_root(&paths.input_root, input_gid)?;
    trusted_directory(&paths.consumed_input_root, 0, true)?;
    let consumed_metadata = fs::symlink_metadata(&paths.consumed_input_root)?;
    if consumed_metadata.mode() & 0o777 != 0o700 {
        return Err(anyhow!("consumed runtime input root metadata is invalid"));
    }
    Ok(VerifiedRuntime {
        image,
        codex_version: manifest.codex_version,
        input_gid,
    })
}

#[cfg(target_os = "linux")]
fn validate_active_manifest(manifest: &ActiveRuntimeManifest) -> Result<()> {
    if manifest.version != 1 || manifest.builder_version != 1 {
        return Err(anyhow!("runtime active manifest version is unsupported"));
    }
    if manifest.codex_version != SUPPORTED_CODEX_VERSION
        || manifest.codex_target != SUPPORTED_CODEX_TARGET
        || manifest.codex_layout_version != SUPPORTED_CODEX_LAYOUT_VERSION
        || !valid_digest(&manifest.image_sha256)
        || !valid_digest(&manifest.source_manifest_sha256)
        || !valid_digest(&manifest.mksquashfs_sha256)
        || manifest.mksquashfs_argv_sha256 != EXPECTED_MKSQUASHFS_ARGV_SHA256
        || manifest.image_size <= SQUASHFS_MAGIC.len() as u64
        || manifest.image_size > RUNTIME_IMAGE_MAX_BYTES
    {
        return Err(anyhow!("runtime active manifest fields are invalid"));
    }
    let expected_image = format!("images/{}.squashfs", manifest.image_sha256);
    if manifest.image != expected_image {
        return Err(anyhow!(
            "runtime active manifest image is not content-addressed"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_workspace(
    input_root: &Path,
    consumed_input_root: &Path,
    request: &ExecuteRequest,
    input_gid: u32,
) -> Result<VerifiedWorkspace> {
    trusted_input_root(input_root, input_gid)?;
    let expected = input_root.join(&request.run_id);
    if request.workspace != expected {
        return Err(anyhow!(
            "runtime workspace does not match the run identifier"
        ));
    }
    use std::os::unix::fs::OpenOptionsExt;
    let guard = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&request.workspace)?;
    let metadata = guard.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != input_gid
        || metadata.mode() & 0o777 != 0o550
    {
        return Err(anyhow!("runtime workspace metadata is invalid"));
    }
    validate_workspace_tree(&guard, 0, input_gid)?;
    if fs::canonicalize(&request.workspace)? != request.workspace {
        return Err(anyhow!("runtime workspace path is not canonical"));
    }
    let bind_source = format!("/proc/{}/fd/{}", std::process::id(), guard.as_raw_fd());
    for forbidden in [".codex", ".agents", ".git", "AGENTS.md", "hooks.json"] {
        match fs::symlink_metadata(Path::new(&bind_source).join(forbidden)) {
            Ok(_) => {
                return Err(anyhow!(
                    "runtime workspace contains forbidden control files"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let current = fs::symlink_metadata(&request.workspace)?;
    if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Err(anyhow!("runtime workspace changed during verification"));
    }
    let consumed_path = consumed_input_root.join(transient_unit_name(&request.run_id));
    fs::rename(&request.workspace, &consumed_path)
        .context("failed to consume the verified runtime workspace")?;
    let consumed = fs::symlink_metadata(&consumed_path)?;
    if consumed.dev() != metadata.dev() || consumed.ino() != metadata.ino() {
        return Err(anyhow!("consumed runtime workspace identity changed"));
    }
    Ok(VerifiedWorkspace {
        path: consumed_path,
        bind_source,
        _guard: guard,
    })
}

#[cfg(target_os = "linux")]
fn validate_workspace_tree(root: &File, expected_uid: u32, input_gid: u32) -> Result<()> {
    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    validate_workspace_directory(
        root,
        expected_uid,
        input_gid,
        0,
        &mut entries,
        &mut total_bytes,
    )
}

#[cfg(target_os = "linux")]
fn validate_workspace_directory(
    directory: &File,
    expected_uid: u32,
    input_gid: u32,
    depth: usize,
    entries: &mut usize,
    total_bytes: &mut u64,
) -> Result<()> {
    if depth > WORKSPACE_DEPTH_MAX {
        return Err(anyhow!("runtime workspace nesting exceeds its limit"));
    }
    let directory_path = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        directory.as_raw_fd()
    ));
    for entry in fs::read_dir(&directory_path)? {
        let entry = entry?;
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("runtime workspace entry count overflowed"))?;
        if *entries > WORKSPACE_ENTRY_MAX {
            return Err(anyhow!("runtime workspace has too many entries"));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.gid() != input_gid
        {
            return Err(anyhow!("runtime workspace entry metadata is invalid"));
        }
        use std::os::unix::fs::OpenOptionsExt;
        if metadata.is_dir() {
            if metadata.mode() & 0o777 != 0o550 {
                return Err(anyhow!("runtime workspace directory mode is invalid"));
            }
            let child = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)?;
            if !same_file_identity(&metadata, &child.metadata()?) {
                return Err(anyhow!("runtime workspace directory changed"));
            }
            validate_workspace_directory(
                &child,
                expected_uid,
                input_gid,
                depth + 1,
                entries,
                total_bytes,
            )?;
        } else if metadata.is_file() {
            if metadata.mode() & 0o777 != 0o440 || metadata.nlink() != 1 {
                return Err(anyhow!("runtime workspace file metadata is invalid"));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)?;
            let opened = file.metadata()?;
            if !same_file_identity(&metadata, &opened) {
                return Err(anyhow!("runtime workspace file changed"));
            }
            *total_bytes = total_bytes
                .checked_add(opened.len())
                .ok_or_else(|| anyhow!("runtime workspace size overflowed"))?;
            if *total_bytes > WORKSPACE_TOTAL_BYTES_MAX {
                return Err(anyhow!("runtime workspace exceeds its size limit"));
            }
        } else {
            return Err(anyhow!("runtime workspace contains a special file"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(target_os = "linux")]
fn current_launcher_unit() -> Result<String> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    parse_launcher_unit(&cgroup)
}

#[cfg(target_os = "linux")]
fn parse_launcher_unit(cgroup: &str) -> Result<String> {
    if cgroup.len() > 4096 {
        return Err(anyhow!("launcher cgroup metadata is oversized"));
    }
    let unit = cgroup.lines().find_map(|line| {
        let (hierarchy, value) = line.split_once("::")?;
        if hierarchy != "0" {
            return None;
        }
        value.strip_prefix("/system.slice/")
    });
    let unit = unit.ok_or_else(|| anyhow!("launcher systemd unit is unavailable"))?;
    if unit.len() > 255
        || !unit.starts_with("webex-codex-launcher@")
        || !unit.ends_with(".service")
        || unit.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'\\'))
        })
    {
        return Err(anyhow!("launcher systemd unit is invalid"));
    }
    Ok(unit.to_owned())
}

#[cfg(target_os = "linux")]
fn build_transient_run_plan(
    request: &ExecuteRequest,
    runtime: &VerifiedRuntime,
    workspace: &Path,
    workspace_bind_source: &str,
    launcher_unit: &str,
) -> Result<TransientRunPlan> {
    validate_execution_policy(request)?;
    validate_launcher_unit(launcher_unit)?;
    validate_workspace_bind_source(workspace_bind_source)?;
    let unit = transient_unit_name(&request.run_id);
    let runtime_timeout = request
        .timeout_seconds
        .saturating_add(CLEANUP_MARGIN.as_secs());
    let timeout = format!("{runtime_timeout}s");
    let image = runtime
        .image
        .to_str()
        .ok_or_else(|| anyhow!("runtime image path is not UTF-8"))?;
    let mut args: Vec<OsString> = vec![
        "--quiet".into(),
        "--wait".into(),
        "--pipe".into(),
        "--collect".into(),
        "--service-type=exec".into(),
        format!("--unit={unit}").into(),
        "--working-directory=/workspace".into(),
    ];
    for property in [
        format!("BindsTo={launcher_unit}"),
        format!("After={launcher_unit}"),
        "DynamicUser=yes".to_owned(),
        format!("RootImage={image}"),
        "RootImageOptions=root:ro,nosuid,nodev".to_owned(),
        "MountAPIVFS=yes".to_owned(),
        format!("BindReadOnlyPaths={workspace_bind_source}:/workspace"),
        format!("LoadCredential=codex-auth.json:{CODEX_AUTH_CREDENTIAL_PATH}"),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "AmbientCapabilities=".to_owned(),
        format!("SupplementaryGroups={CODEX_INPUT_GROUP}"),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "PrivateIPC=yes".to_owned(),
        "ProtectClock=yes".to_owned(),
        "ProtectControlGroups=yes".to_owned(),
        "ProtectHostname=yes".to_owned(),
        "ProtectKernelLogs=yes".to_owned(),
        "ProtectKernelModules=yes".to_owned(),
        "ProtectKernelTunables=yes".to_owned(),
        "ProtectProc=invisible".to_owned(),
        "ProcSubset=pid".to_owned(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_owned(),
        "RestrictSUIDSGID=yes".to_owned(),
        "RestrictRealtime=yes".to_owned(),
        "LockPersonality=yes".to_owned(),
        "MemoryDenyWriteExecute=yes".to_owned(),
        "SystemCallFilter=~@debug process_vm_readv process_vm_writev process_madvise kcmp"
            .to_owned(),
        "SystemCallErrorNumber=EPERM".to_owned(),
        "SystemCallArchitectures=native".to_owned(),
        "DevicePolicy=closed".to_owned(),
        "KeyringMode=private".to_owned(),
        "UMask=0077".to_owned(),
        "KillMode=control-group".to_owned(),
        "SendSIGKILL=yes".to_owned(),
        "OOMPolicy=kill".to_owned(),
        "TasksMax=128".to_owned(),
        "CPUQuota=200%".to_owned(),
        "MemoryMax=2G".to_owned(),
        "MemorySwapMax=0".to_owned(),
        "LimitNOFILE=256".to_owned(),
        "LimitNPROC=128".to_owned(),
        "LimitFSIZE=256M".to_owned(),
        "LimitCORE=0".to_owned(),
        format!("RuntimeMaxSec={timeout}"),
        "TimeoutStopSec=10s".to_owned(),
        "TemporaryFileSystem=/tmp:rw,nosuid,nodev,size=512M,mode=1777".to_owned(),
        "TemporaryFileSystem=/var/tmp:rw,nosuid,nodev,size=64M,mode=1777".to_owned(),
        "InaccessiblePaths=-/run/systemd -/run/dbus -/run/webex-codex-launcher -/run/webex-config-pull"
            .to_owned(),
        "BindReadOnlyPaths=/etc/resolv.conf".to_owned(),
        "BindReadOnlyPaths=/etc/hosts".to_owned(),
        "BindReadOnlyPaths=/etc/nsswitch.conf".to_owned(),
    ] {
        args.push("--property".into());
        args.push(property.into());
    }
    args.push(RUNTIME_EXECUTABLE_PATH.into());
    args.push("--workspace".into());
    args.push("/workspace".into());
    args.push("--model".into());
    args.push("gpt-5.5".into());
    if let Some(reasoning_effort) = request.reasoning_effort {
        args.push("--reasoning-effort".into());
        args.push(reasoning_effort_text(reasoning_effort)?.into());
    }
    Ok(TransientRunPlan {
        unit,
        executable: SYSTEMD_RUN_PATH,
        args,
        workspace: workspace.to_owned(),
    })
}

#[cfg(target_os = "linux")]
async fn run_transient(
    plan: TransientRunPlan,
    request: &ExecuteRequest,
    peer: &AuthorisedPeer,
    _workspace: VerifiedWorkspace,
) -> Result<IsolatedRunResult> {
    peer.ensure_alive()
        .context("authorised bot caller exited before Codex execution")?;
    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
    let mut command = Command::new(plan.executable);
    command
        .args(&plan.args)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.process_group(0);
    let mut child = command
        .spawn()
        .context("failed to start the fixed transient Codex unit")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("transient Codex stdin is unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("transient Codex stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("transient Codex stderr is unavailable"))?;
    let stdout_task = tokio::spawn(read_limited(stdout, OUTPUT_CAPTURE_BYTES));
    let stderr_task = tokio::spawn(read_limited(stderr, STDERR_CAPTURE_BYTES));
    let write_outcome = {
        let prompt_write = async {
            stdin.write_all(request.prompt.as_bytes()).await?;
            stdin.shutdown().await
        };
        tokio::pin!(prompt_write);
        loop {
            tokio::select! {
                result = &mut prompt_write => break PromptWriteOutcome::Completed(result),
                _ = sleep(PEER_POLL_INTERVAL) => {
                    if peer.ensure_alive().is_err() {
                        break PromptWriteOutcome::PeerExited;
                    }
                    if Instant::now() >= deadline {
                        break PromptWriteOutcome::TimedOut;
                    }
                }
            }
        }
    };
    drop(stdin);
    match write_outcome {
        PromptWriteOutcome::Completed(Ok(())) => {}
        PromptWriteOutcome::Completed(Err(error)) => {
            terminate_and_discard_captures(&plan.unit, &mut child, stdout_task, stderr_task)
                .await?;
            return Err(error).context("failed to write the bounded Codex prompt");
        }
        PromptWriteOutcome::PeerExited => {
            terminate_and_discard_captures(&plan.unit, &mut child, stdout_task, stderr_task)
                .await?;
            return Err(anyhow!(
                "authorised bot caller exited during Codex prompt delivery"
            ));
        }
        PromptWriteOutcome::TimedOut => {
            terminate_and_discard_captures(&plan.unit, &mut child, stdout_task, stderr_task)
                .await?;
            return Ok(IsolatedRunResult::TimedOut);
        }
    }

    let status = loop {
        tokio::select! {
            result = child.wait() => match result {
                Ok(status) => break status,
                Err(error) => {
                    terminate_and_discard_captures(
                        &plan.unit,
                        &mut child,
                        stdout_task,
                        stderr_task,
                    )
                    .await?;
                    return Err(error).context("failed while waiting for transient Codex unit");
                }
            },
            _ = sleep(PEER_POLL_INTERVAL) => {
                if peer.ensure_alive().is_err() {
                    terminate_and_discard_captures(
                        &plan.unit,
                        &mut child,
                        stdout_task,
                        stderr_task,
                    )
                    .await?;
                    return Err(anyhow!("authorised bot caller exited during Codex execution"));
                }
                if Instant::now() >= deadline {
                    terminate_and_discard_captures(
                        &plan.unit,
                        &mut child,
                        stdout_task,
                        stderr_task,
                    )
                    .await?;
                    return Ok(IsolatedRunResult::TimedOut);
                }
            }
        }
    };
    let (stdout_result, stderr_result) = tokio::join!(
        collect_capture(stdout_task, "stdout"),
        collect_capture(stderr_task, "stderr")
    );
    let (stdout, stdout_truncated) = stdout_result?;
    let (_stderr, _stderr_truncated) = stderr_result?;
    if !status.success() {
        if Instant::now() >= deadline {
            return Ok(IsolatedRunResult::TimedOut);
        }
        return Ok(IsolatedRunResult::Failed);
    }
    let output = stdout.trim();
    if output.is_empty() {
        return Ok(IsolatedRunResult::Failed);
    }
    let mut output = output.to_owned();
    let character_limit = request.output_char_limit as usize;
    let character_truncated = output.chars().count() > character_limit;
    if character_truncated {
        output = output.chars().take(character_limit).collect();
    }
    Ok(IsolatedRunResult::Completed {
        output,
        truncated: stdout_truncated || character_truncated,
    })
}

#[cfg(target_os = "linux")]
enum PromptWriteOutcome {
    Completed(std::io::Result<()>),
    PeerExited,
    TimedOut,
}

#[cfg(target_os = "linux")]
async fn terminate_systemd_run(child: &mut Child) {
    if let Some(pid) = child.id() {
        // SAFETY: a negative PID targets only the process group created for this child.
        unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
        if !matches!(
            tokio::time::timeout(CLEANUP_MARGIN, child.wait()).await,
            Ok(Ok(_))
        ) {
            // SAFETY: a negative PID targets only the same process group.
            unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            let _ = child.wait().await;
        }
    } else {
        let _ = child.wait().await;
    }
}

#[cfg(target_os = "linux")]
async fn terminate_transient_unit(unit: &str, systemd_run: &mut Child) -> Result<()> {
    let mut command = Command::new(SYSTEMCTL_PATH);
    command
        .args([
            "--no-pager",
            "--no-ask-password",
            "--job-mode=replace-irreversibly",
            "stop",
            unit,
        ])
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.process_group(0);
    let stop_result = async {
        let mut stop = command
            .spawn()
            .context("failed to start fixed transient-unit cleanup")?;
        let wait = tokio::time::timeout(CLEANUP_MARGIN, stop.wait()).await;
        let status = match wait {
            Ok(result) => result.context("failed while waiting for transient-unit cleanup")?,
            Err(_) => {
                terminate_systemd_run(&mut stop).await;
                return Err(anyhow!("transient-unit cleanup timed out"));
            }
        };
        if !status.success() {
            return Err(anyhow!("transient-unit cleanup failed"));
        }
        Ok(())
    }
    .await;
    terminate_systemd_run(systemd_run).await;
    stop_result
}

#[cfg(target_os = "linux")]
async fn collect_capture(mut task: CaptureTask, stream: &str) -> Result<(String, bool)> {
    match tokio::time::timeout(CLEANUP_MARGIN, &mut task).await {
        Ok(result) => result.with_context(|| format!("failed to join Codex {stream} capture"))?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(anyhow!("Codex {stream} capture did not close"))
        }
    }
}

#[cfg(target_os = "linux")]
async fn discard_captures(stdout: CaptureTask, stderr: CaptureTask) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

#[cfg(target_os = "linux")]
async fn terminate_and_discard_captures(
    unit: &str,
    systemd_run: &mut Child,
    stdout: CaptureTask,
    stderr: CaptureTask,
) -> Result<()> {
    let result = terminate_transient_unit(unit, systemd_run).await;
    discard_captures(stdout, stderr).await;
    result
}

#[cfg(target_os = "linux")]
async fn read_limited<R>(mut reader: R, limit: usize) -> Result<(String, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        let to_keep = read.min(remaining);
        kept.extend_from_slice(&buffer[..to_keep]);
        truncated |= to_keep < read;
    }
    Ok((String::from_utf8_lossy(&kept).to_string(), truncated))
}

#[cfg(target_os = "linux")]
fn transient_unit_name(run_id: &str) -> String {
    let digest = ring::digest::digest(&SHA256, run_id.as_bytes());
    let suffix = hex(digest.as_ref());
    format!("webex-codex-run-{}.service", &suffix[..24])
}

#[cfg(target_os = "linux")]
fn validate_launcher_unit(unit: &str) -> Result<()> {
    if unit.len() > 255
        || !unit.starts_with("webex-codex-launcher@")
        || !unit.ends_with(".service")
        || unit.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'\\'))
        })
    {
        return Err(anyhow!("launcher systemd unit is invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_workspace_bind_source(source: &str) -> Result<()> {
    let Some(rest) = source.strip_prefix("/proc/") else {
        return Err(anyhow!("runtime workspace bind source is invalid"));
    };
    let mut parts = rest.split('/');
    if !matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(pid), Some("fd"), Some(fd), None)
            if !pid.is_empty()
                && !fd.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && fd.bytes().all(|byte| byte.is_ascii_digit())
    ) {
        return Err(anyhow!("runtime workspace bind source is invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reasoning_effort_text(reasoning_effort: ReasoningEffort) -> Result<&'static str> {
    match reasoning_effort {
        ReasoningEffort::Minimal => Ok("minimal"),
        ReasoningEffort::Low => Ok("low"),
        ReasoningEffort::Medium => Ok("medium"),
        ReasoningEffort::High => Ok("high"),
        ReasoningEffort::Xhigh => Ok("xhigh"),
        ReasoningEffort::Unknown => Err(anyhow!("runtime reasoning effort is invalid")),
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum FilePolicy {
    Executable,
    ReadOnlyData,
    PrivateCredential,
    HostData,
}

#[cfg(target_os = "linux")]
fn trusted_file(path: &Path, expected_uid: u32, policy: FilePolicy) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow!("trusted runtime path is not absolute"));
    }
    trusted_directory(
        path.parent()
            .ok_or_else(|| anyhow!("trusted runtime path has no parent"))?,
        expected_uid,
        true,
    )?;
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode();
    let mode_valid = file_policy_mode_valid(policy, mode);
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || !mode_valid
    {
        return Err(anyhow!("trusted runtime file metadata is invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn file_policy_mode_valid(policy: FilePolicy, mode: u32) -> bool {
    match policy {
        FilePolicy::Executable => mode & 0o111 != 0 && mode & 0o022 == 0,
        FilePolicy::ReadOnlyData => mode & 0o777 == 0o444,
        FilePolicy::PrivateCredential => matches!(mode & 0o777, 0o400 | 0o600),
        FilePolicy::HostData => mode & 0o022 == 0 && mode & 0o400 != 0,
    }
}

#[cfg(target_os = "linux")]
fn trusted_directory(path: &Path, expected_uid: u32, include_ancestors: bool) -> Result<()> {
    let mut current = Some(path);
    while let Some(directory) = current {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(anyhow!("trusted runtime directory metadata is invalid"));
        }
        if !include_ancestors {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_input_root(path: &Path, input_gid: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime input root has no parent"))?;
    trusted_directory(parent, 0, true)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != input_gid
        || !input_root_mode_valid(metadata.mode())
    {
        return Err(anyhow!("runtime input root metadata is invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn input_root_mode_valid(mode: u32) -> bool {
    mode & 0o7777 == 0o1730
}

#[cfg(target_os = "linux")]
fn resolve_group_gid(group_file: &Path, expected_name: &str) -> Result<u32> {
    let bytes = read_bounded_file(group_file, 1024 * 1024)?;
    let contents = std::str::from_utf8(&bytes).context("host group database is not UTF-8")?;
    parse_group_gid(contents, expected_name)
}

#[cfg(target_os = "linux")]
fn parse_group_gid(contents: &str, expected_name: &str) -> Result<u32> {
    let mut result = None;
    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first().copied() != Some(expected_name) {
            continue;
        }
        if fields.len() != 4 || !fields[3].is_empty() || result.is_some() {
            return Err(anyhow!("Codex input group database entry is invalid"));
        }
        let gid = fields[2]
            .parse::<u32>()
            .context("Codex input group identifier is invalid")?;
        if gid == 0 {
            return Err(anyhow!("Codex input group must not be root"));
        }
        result = Some(gid);
    }
    let expected_gid = result.ok_or_else(|| anyhow!("Codex input group is unavailable"))?;
    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() == 4
            && fields[0] != expected_name
            && fields[2].parse::<u32>().ok() == Some(expected_gid)
        {
            return Err(anyhow!("Codex input group identifier is aliased"));
        }
    }
    Ok(expected_gid)
}

#[cfg(target_os = "linux")]
fn reject_primary_gid_users(passwd_file: &Path, input_gid: u32) -> Result<()> {
    let bytes = read_bounded_file(passwd_file, 1024 * 1024)?;
    let contents = std::str::from_utf8(&bytes).context("host passwd database is not UTF-8")?;
    if contents.lines().any(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        fields.len() >= 4 && fields[3].parse::<u32>().ok() == Some(input_gid)
    }) {
        return Err(anyhow!(
            "Codex input group is used as a static primary group"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(anyhow!("trusted runtime file is outside its size limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn hash_reader(mut reader: File, prefix: &[u8]) -> Result<String> {
    let mut context = DigestContext::new(&SHA256);
    context.update(prefix);
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(hex(context.finish().as_ref()))
}

#[cfg(target_os = "linux")]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(target_os = "linux")]
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(not(target_os = "linux"))]
pub fn unsupported_platform_error() -> anyhow::Error {
    anyhow!("isolated Codex execution is supported only on Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn request() -> ExecuteRequest {
        ExecuteRequest {
            run_id: "run-1".to_owned(),
            message_id: "message-1".to_owned(),
            prompt: "Inspect the isolated input".to_owned(),
            workspace: PathBuf::from("/var/lib/webex-codex-inputs/run-1"),
            model: Some("gpt-5.5".to_owned()),
            reasoning_effort: Some(ReasoningEffort::Xhigh),
            timeout_seconds: 600,
            output_char_limit: 6_000,
            skip_git_repo_check: true,
        }
    }

    fn runtime() -> VerifiedRuntime {
        VerifiedRuntime {
            image: PathBuf::from(
                "/opt/webex-generic-account-bot/runtime/images/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.squashfs",
            ),
            codex_version: "0.142.3".to_owned(),
            input_gid: 1234,
        }
    }

    #[test]
    fn active_manifest_requires_a_content_addressed_image() {
        let manifest = ActiveRuntimeManifest {
            version: 1,
            builder_version: 1,
            codex_version: "0.142.3".to_owned(),
            codex_target: "x86_64-unknown-linux-musl".to_owned(),
            codex_layout_version: 1,
            image: format!("images/{}.squashfs", "a".repeat(64)),
            image_sha256: "a".repeat(64),
            image_size: 4096,
            source_manifest_sha256: "b".repeat(64),
            mksquashfs_sha256: "c".repeat(64),
            mksquashfs_argv_sha256: EXPECTED_MKSQUASHFS_ARGV_SHA256.to_owned(),
        };
        validate_active_manifest(&manifest).unwrap();

        let mut invalid = manifest;
        invalid.image = format!("images/{}.squashfs", "e".repeat(64));
        assert!(validate_active_manifest(&invalid).is_err());
        invalid.image = format!("images/{}.squashfs", "a".repeat(64));
        invalid.mksquashfs_argv_sha256 = "d".repeat(64);
        assert!(validate_active_manifest(&invalid).is_err());
    }

    #[test]
    fn input_group_resolution_is_exact_and_non_root() {
        assert_eq!(
            parse_group_gid("root:x:0:\nwebex-codex-input:x:4321:\n", CODEX_INPUT_GROUP).unwrap(),
            4321
        );
        assert!(parse_group_gid("webex-codex-input:x:0:\n", CODEX_INPUT_GROUP).is_err());
        assert!(
            parse_group_gid(
                "webex-codex-input:x:4321:webex-generic-account-bot\n",
                CODEX_INPUT_GROUP
            )
            .is_err()
        );
        assert!(
            parse_group_gid(
                "shared:x:4321:\nwebex-codex-input:x:4321:\n",
                CODEX_INPUT_GROUP
            )
            .is_err()
        );
        assert!(
            parse_group_gid(
                "webex-codex-input:x:4321:\nwebex-codex-input:x:4322:\n",
                CODEX_INPUT_GROUP
            )
            .is_err()
        );
    }

    #[test]
    fn input_group_cannot_be_a_static_users_primary_group() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "webex-codex-passwd-{}-{suffix}",
            std::process::id()
        ));
        fs::write(&path, b"root:x:0:0:root:/root:/bin/sh\n").unwrap();
        assert!(reject_primary_gid_users(&path, 4321).is_ok());
        fs::write(
            &path,
            b"root:x:0:0:root:/root:/bin/sh\nbot:x:1000:4321:bot:/tmp:/bin/false\n",
        )
        .unwrap();
        assert!(reject_primary_gid_users(&path, 4321).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn activation_and_private_credentials_fail_closed() {
        assert!(ensure_activation_enabled().is_err());
        assert!(file_policy_mode_valid(FilePolicy::PrivateCredential, 0o400));
        assert!(file_policy_mode_valid(FilePolicy::PrivateCredential, 0o600));
        for mode in [0o200, 0o500, 0o640, 0o777] {
            assert!(!file_policy_mode_valid(FilePolicy::PrivateCredential, mode));
        }
    }

    #[test]
    fn input_root_requires_sticky_group_write_without_group_read() {
        assert!(input_root_mode_valid(0o1730));
        for mode in [0o730, 0o1700, 0o1750, 0o1770, 0o1732, 0o3730, 0o5730] {
            assert!(!input_root_mode_valid(mode), "accepted mode {mode:o}");
        }
    }

    #[test]
    fn sealed_workspace_tree_rejects_mutable_and_linked_entries() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "webex-codex-workspace-tree-{}-{suffix}",
            std::process::id()
        ));
        let nested = root.join("logs");
        let evidence = nested.join("console.log");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(&evidence, b"sealed evidence\n").unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o550)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o550)).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let guard = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&root)
            .unwrap();

        validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).is_err());
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();

        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        symlink("logs/console.log", root.join("linked.log")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o550)).unwrap();
        assert!(validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).is_err());

        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        fs::remove_file(root.join("linked.log")).unwrap();
        fs::hard_link(&evidence, root.join("hard-linked.log")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o550)).unwrap();
        assert!(validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).is_err());

        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o640)).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn transient_plan_uses_only_fixed_execution_and_hardening_properties() {
        let request = request();
        let plan = build_transient_run_plan(
            &request,
            &runtime(),
            &request.workspace,
            "/proc/123/fd/7",
            "webex-codex-launcher@42.service",
        )
        .unwrap();
        assert_eq!(plan.executable, SYSTEMD_RUN_PATH);
        assert!(plan.unit.starts_with("webex-codex-run-"));
        let args = plan
            .args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        for required in [
            "--wait",
            "--pipe",
            "--collect",
            "DynamicUser=yes",
            "BindReadOnlyPaths=/proc/123/fd/7:/workspace",
            "SupplementaryGroups=webex-codex-input",
            "CapabilityBoundingSet=",
            "NoNewPrivileges=yes",
            "ProtectProc=invisible",
            "TasksMax=128",
            "MemoryMax=2G",
            "MemorySwapMax=0",
            "SystemCallFilter=~@debug process_vm_readv process_vm_writev process_madvise kcmp",
            "SystemCallErrorNumber=EPERM",
            "LimitCORE=0",
            "RuntimeMaxSec=610s",
            RUNTIME_EXECUTABLE_PATH,
            "gpt-5.5",
            "xhigh",
        ] {
            assert!(args.iter().any(|value| value == required), "{required}");
        }
        assert!(!args.iter().any(|value| value.contains(&request.prompt)));
        assert!(!args.iter().any(|value| value.contains(&request.message_id)));
        assert!(
            !args
                .iter()
                .any(|value| value.contains("systemd-run") && value != SYSTEMD_RUN_PATH)
        );
    }

    #[test]
    fn unit_names_are_stable_and_do_not_expose_run_ids() {
        let first = transient_unit_name("message-sensitive-run-id");
        assert_eq!(first, transient_unit_name("message-sensitive-run-id"));
        assert_ne!(first, transient_unit_name("another-run-id"));
        assert!(!first.contains("sensitive"));
    }

    #[test]
    fn launcher_cgroup_requires_the_explicit_system_slice_layout() {
        assert_eq!(
            parse_launcher_unit("0::/system.slice/webex-codex-launcher@42.service\n").unwrap(),
            "webex-codex-launcher@42.service"
        );
        assert!(
            parse_launcher_unit(
                "0::/system.slice/system-webex\\x2dcodex\\x2dlauncher.slice/webex-codex-launcher@42.service\n"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unallowlisted_models_and_launcher_units() {
        let mut unallowlisted = request();
        unallowlisted.model = Some("other-model".to_owned());
        assert!(validate_execution_policy(&unallowlisted).is_err());
        let mut git_check_enabled = request();
        git_check_enabled.skip_git_repo_check = false;
        assert!(validate_execution_policy(&git_check_enabled).is_err());
        assert!(
            build_transient_run_plan(
                &unallowlisted,
                &runtime(),
                &unallowlisted.workspace,
                "/proc/123/fd/7",
                "webex-codex-launcher@42.service"
            )
            .is_err()
        );
        let request = request();
        assert!(
            build_transient_run_plan(
                &request,
                &runtime(),
                &request.workspace,
                "/proc/123/fd/7",
                "other.service"
            )
            .is_err()
        );
        assert!(
            build_transient_run_plan(
                &request,
                &runtime(),
                &request.workspace,
                "/var/lib/webex-codex-inputs/run-1",
                "webex-codex-launcher@42.service"
            )
            .is_err()
        );
    }
}

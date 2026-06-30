#[cfg(target_os = "linux")]
use std::{
    env,
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Component, Path, PathBuf},
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
    activation::{self, ActivationPaths, VerifiedActivation},
    codex_launcher::AuthorisedPeer,
    input_sealer::{self, ensure_posix_acl_absent},
    launcher_protocol::{
        ExecuteRequest, LAUNCHER_CLEANUP_PROCESS_TIMEOUT_SECONDS, LAUNCHER_CLEANUP_STEP_SECONDS,
        LAUNCHER_PREPARATION_PROCESS_TIMEOUT_SECONDS, LAUNCHER_PREPARATION_WORK_TIMEOUT_SECONDS,
        OUTPUT_MAX_BYTES, ProtocolError, ReasoningEffort,
    },
    work_budget::{
        WorkBudget, WorkBudgetError, WorkCancellation, run_blocking_with_process_watchdog,
    },
};

pub const RUNTIME_ROOT: &str = "/opt/webex-generic-account-bot/runtime";
pub const RUNTIME_ACTIVE_MANIFEST_PATH: &str = "/opt/webex-generic-account-bot/runtime/active.json";
pub const CODEX_AUTH_CREDENTIAL_PATH: &str = "/etc/webex-generic-account-bot/codex-auth.json";
pub const CODEX_INPUT_STORE_ROOT: &str = "/var/lib/webex-codex-runtime-inputs";
pub const CODEX_INPUT_ROOT: &str = "/var/lib/webex-codex-runtime-inputs/ready";
pub const CODEX_CONSUMED_INPUT_ROOT: &str = "/var/lib/webex-codex-runtime-inputs/consumed";
pub const RUNTIME_EXECUTABLE_PATH: &str = "/usr/libexec/webex-codex-runtime";

#[cfg(target_os = "linux")]
const SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
#[cfg(target_os = "linux")]
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
#[cfg(target_os = "linux")]
const CODEX_INPUT_GROUP: &str = "webex-codex-input";
#[cfg(target_os = "linux")]
const CODEX_LAUNCH_GROUP: &str = "webex-codex-launch";
#[cfg(target_os = "linux")]
const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
#[cfg(target_os = "linux")]
const ACTIVATION_BOOT_ID_CREDENTIAL_NAME: &str = "activation-boot-id";
#[cfg(target_os = "linux")]
const SYSTEMD_CREDENTIAL_ROOT: &str = "/run/credentials";
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
const CLEANUP_MARGIN: Duration = Duration::from_secs(LAUNCHER_CLEANUP_STEP_SECONDS);
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
#[derive(Debug, Clone, Default)]
pub struct ExecutionCancellation {
    inner: WorkCancellation,
}

#[cfg(target_os = "linux")]
impl ExecutionCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CodexGroupIds {
    pub(crate) launch: u32,
    pub(crate) input: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct VerifiedWorkspace {
    path: PathBuf,
    bind_source: String,
    consumed_root: File,
    consumed_name: CString,
    expected_device: u64,
    expected_inode: u64,
    cleanup_armed: bool,
    _guard: File,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceAccess {
    Private,
    GroupReadable,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkspaceMetadataPolicy {
    expected_uid: u32,
    input_gid: u32,
    access: WorkspaceAccess,
}

#[cfg(target_os = "linux")]
impl VerifiedWorkspace {
    fn cleanup(&mut self) -> Result<()> {
        if !self.cleanup_armed {
            return Ok(());
        }
        input_sealer::remove_owned_tree_at(
            &self.consumed_root,
            &self.consumed_name,
            self.expected_device,
            self.expected_inode,
        )?;
        self.cleanup_armed = false;
        self.consumed_root
            .sync_all()
            .context("failed to persist consumed runtime workspace cleanup")
    }
}

#[cfg(target_os = "linux")]
impl Drop for VerifiedWorkspace {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(
                workspace = %self.path.display(),
                error = %error,
                "failed to clean a consumed runtime workspace"
            );
        }
    }
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
    #[error("isolated Codex execution was cancelled")]
    Cancelled,
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
    preflight_with_deadline(None)
}

#[cfg(target_os = "linux")]
pub async fn preflight_bounded(cancellation: &ExecutionCancellation) -> Result<VerifiedRuntime> {
    let deadline = WorkBudget::with_cancellation(
        Duration::from_secs(LAUNCHER_PREPARATION_WORK_TIMEOUT_SECONDS),
        cancellation.inner.clone(),
    );
    run_blocking_with_process_watchdog(
        "isolated Codex preflight",
        Duration::from_secs(LAUNCHER_PREPARATION_PROCESS_TIMEOUT_SECONDS),
        move || preflight_with_deadline(Some(deadline)),
    )
    .await?
}

#[cfg(target_os = "linux")]
fn preflight_with_deadline(deadline: Option<WorkBudget>) -> Result<VerifiedRuntime> {
    let activation = ensure_activation_enabled_with_deadline(deadline.clone())?;
    input_sealer::preflight()?;
    verify_runtime_with_deadline(&RuntimePaths::default(), 0, &activation, deadline)
}

#[cfg(target_os = "linux")]
pub(crate) fn production_codex_group_ids() -> Result<CodexGroupIds> {
    let paths = RuntimePaths::default();
    trusted_file(&paths.group_file, 0, FilePolicy::HostData)?;
    trusted_file(&paths.passwd_file, 0, FilePolicy::HostData)?;
    resolve_codex_group_ids(&paths.group_file, &paths.passwd_file)
}

#[cfg(target_os = "linux")]
pub async fn execute(
    request: &ExecuteRequest,
    peer: &AuthorisedPeer,
    cancellation: &ExecutionCancellation,
) -> std::result::Result<IsolatedRunResult, IsolatedExecutionError> {
    let request_for_preparation = request.clone();
    let source_uid = peer.credentials().uid;
    let deadline = WorkBudget::with_cancellation(
        Duration::from_secs(LAUNCHER_PREPARATION_WORK_TIMEOUT_SECONDS),
        cancellation.inner.clone(),
    );
    let prepared = run_blocking_with_process_watchdog(
        "isolated Codex preparation",
        Duration::from_secs(LAUNCHER_PREPARATION_PROCESS_TIMEOUT_SECONDS),
        move || prepare_execution(&request_for_preparation, source_uid, deadline),
    )
    .await
    .map_err(IsolatedExecutionError::Failed)?;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(IsolatedExecutionError::Failed(error)) if is_cancellation_error(&error) => {
            return Err(IsolatedExecutionError::Cancelled);
        }
        Err(error) => return Err(error),
    };
    let PreparedExecution { plan, workspace } = prepared;
    let execution = run_transient(plan, request, peer, cancellation, &workspace).await;
    let cleanup = run_blocking_with_process_watchdog(
        "consumed runtime workspace cleanup",
        Duration::from_secs(LAUNCHER_CLEANUP_PROCESS_TIMEOUT_SECONDS),
        move || {
            let mut workspace = workspace;
            workspace.cleanup()
        },
    )
    .await
    .and_then(|result| result);
    finalise_execution(execution, cleanup)
}

#[cfg(target_os = "linux")]
fn finalise_execution(
    execution: Result<IsolatedRunResult>,
    cleanup: Result<()>,
) -> std::result::Result<IsolatedRunResult, IsolatedExecutionError> {
    match (execution, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) if is_cancellation_error(&error) => {
            Err(IsolatedExecutionError::Cancelled)
        }
        (Err(error), Ok(())) => Err(IsolatedExecutionError::Failed(error)),
        (Ok(_), Err(error)) => Err(IsolatedExecutionError::Failed(
            error.context("failed to clean consumed runtime workspace"),
        )),
        (Err(execution_error), Err(cleanup_error)) => Err(IsolatedExecutionError::Failed(anyhow!(
            "{execution_error:#}; failed to clean consumed runtime workspace: {cleanup_error:#}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn is_cancellation_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<WorkBudgetError>(),
            Some(WorkBudgetError::Cancelled { .. })
        )
    })
}

#[cfg(target_os = "linux")]
struct PreparedExecution {
    plan: TransientRunPlan,
    workspace: VerifiedWorkspace,
}

#[cfg(target_os = "linux")]
fn prepare_execution(
    request: &ExecuteRequest,
    source_uid: u32,
    deadline: WorkBudget,
) -> std::result::Result<PreparedExecution, IsolatedExecutionError> {
    deadline
        .check("isolated Codex preparation")
        .map_err(|error| IsolatedExecutionError::Failed(error.into()))?;
    validate_execution_policy(request).map_err(|error| {
        IsolatedExecutionError::Failed(anyhow!("isolated request policy is invalid: {error}"))
    })?;
    let activation = ensure_activation_enabled_with_deadline(Some(deadline.clone()))
        .map_err(IsolatedExecutionError::Unavailable)?;
    let paths = RuntimePaths::default();
    let expected_workspace = paths.input_root.join(&request.run_id);
    if request.workspace != expected_workspace {
        return Err(IsolatedExecutionError::Failed(anyhow!(
            "runtime workspace does not match the run identifier"
        )));
    }
    let runtime = verify_runtime_with_deadline(&paths, 0, &activation, Some(deadline.clone()))
        .map_err(IsolatedExecutionError::Unavailable)?;
    let launcher_unit = current_launcher_unit().map_err(IsolatedExecutionError::Failed)?;
    let sealed_workspace = input_sealer::seal_workspace_with_deadline(
        &request.run_id,
        source_uid,
        Some(deadline.clone()),
    )
    .map_err(IsolatedExecutionError::Failed)?;
    if sealed_workspace.path() != expected_workspace {
        return Err(IsolatedExecutionError::Failed(anyhow!(
            "sealed workspace path does not match the launcher request"
        )));
    }
    let workspace = verify_workspace(
        &paths.input_root,
        &paths.consumed_input_root,
        request,
        runtime.input_gid,
        Some(deadline),
        sealed_workspace,
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
    Ok(PreparedExecution { plan, workspace })
}

#[cfg(target_os = "linux")]
#[cfg(test)]
fn ensure_activation_enabled() -> Result<VerifiedActivation> {
    ensure_activation_enabled_with_deadline(None)
}

#[cfg(target_os = "linux")]
fn ensure_activation_enabled_with_deadline(
    deadline: Option<WorkBudget>,
) -> Result<VerifiedActivation> {
    let directory = env::var_os(CREDENTIALS_DIRECTORY_ENV)
        .ok_or_else(|| anyhow!("launcher credential directory is unavailable"))?;
    let boot_id = boot_id_credential_path(&directory)?;
    let paths = ActivationPaths::production_for_launcher_with_boot_id(boot_id);
    activation::verify_activation_with_deadline(&paths, deadline)
        .context("isolated Codex execution awaits current production capability canaries")
}

#[cfg(target_os = "linux")]
fn boot_id_credential_path(directory: &OsStr) -> Result<PathBuf> {
    let directory = Path::new(directory);
    let credential_root = Path::new(SYSTEMD_CREDENTIAL_ROOT);
    if !directory.is_absolute()
        || directory == credential_root
        || !directory.starts_with(credential_root)
        || directory
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(anyhow!("launcher credential directory is invalid"));
    }
    Ok(directory.join(ACTIVATION_BOOT_ID_CREDENTIAL_NAME))
}

#[cfg(target_os = "linux")]
pub fn validate_execution_policy(
    request: &ExecuteRequest,
) -> std::result::Result<(), ProtocolError> {
    request.validate()?;
    if request.model.as_deref() != Some("gpt-5.5") {
        return Err(ProtocolError::InvalidModel);
    }
    if request.workspace != Path::new(CODEX_INPUT_ROOT).join(&request.run_id) {
        return Err(ProtocolError::InvalidWorkspace);
    }
    if !request.skip_git_repo_check {
        return Err(ProtocolError::InvalidRequestJson);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_runtime_with_deadline(
    paths: &RuntimePaths,
    expected_uid: u32,
    activation: &VerifiedActivation,
    deadline: Option<WorkBudget>,
) -> Result<VerifiedRuntime> {
    if let Some(deadline) = deadline.as_ref() {
        deadline.check("isolated runtime verification")?;
    }
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
    validate_active_manifest_binding(activation, &manifest_bytes, &manifest)?;

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
    let digest = hash_reader(file, &magic, deadline)?;
    if digest != manifest.image_sha256 {
        return Err(anyhow!("runtime image digest does not match its manifest"));
    }
    validate_runtime_image_binding(activation, &digest)?;
    let credential = read_bounded_file(&paths.credential, CODEX_AUTH_MAX_BYTES)?;
    if !serde_json::from_slice::<serde_json::Value>(&credential)
        .is_ok_and(|value| value.is_object())
    {
        return Err(anyhow!("Codex credential is not a JSON object"));
    }
    let groups = resolve_codex_group_ids(&paths.group_file, &paths.passwd_file)?;
    trusted_input_root(&paths.input_root, groups.input)?;
    trusted_directory(&paths.consumed_input_root, 0, true)?;
    let consumed_metadata = fs::symlink_metadata(&paths.consumed_input_root)?;
    if consumed_metadata.mode() & 0o777 != 0o700 {
        return Err(anyhow!("consumed runtime input root metadata is invalid"));
    }
    Ok(VerifiedRuntime {
        image,
        codex_version: manifest.codex_version,
        input_gid: groups.input,
    })
}

#[cfg(target_os = "linux")]
fn validate_active_manifest_binding(
    activation: &VerifiedActivation,
    manifest_bytes: &[u8],
    manifest: &ActiveRuntimeManifest,
) -> Result<()> {
    let digest = hex(ring::digest::digest(&SHA256, manifest_bytes).as_ref());
    if digest != activation.active_manifest_sha256
        || manifest.codex_version != activation.codex_version
    {
        return Err(anyhow!(
            "runtime active manifest does not match the verified activation"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_runtime_image_binding(
    activation: &VerifiedActivation,
    image_sha256: &str,
) -> Result<()> {
    if image_sha256 != activation.runtime_image_sha256 {
        return Err(anyhow!(
            "runtime image does not match the verified activation"
        ));
    }
    Ok(())
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
    deadline: Option<WorkBudget>,
    mut published_workspace: input_sealer::PublishedWorkspace,
) -> Result<VerifiedWorkspace> {
    if let Some(deadline) = deadline.as_ref() {
        deadline.check("sealed workspace verification")?;
    }
    trusted_input_root(input_root, input_gid)?;
    use std::os::unix::fs::OpenOptionsExt;
    let input_root_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(input_root)?;
    let consumed_root_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(consumed_input_root)?;
    let expected = input_root.join(&request.run_id);
    if request.workspace != expected {
        return Err(anyhow!(
            "runtime workspace does not match the run identifier"
        ));
    }
    let guard = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&request.workspace)?;
    let metadata = guard.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != input_gid
        || !workspace_directory_mode_valid(metadata.mode(), WorkspaceAccess::Private)
    {
        return Err(anyhow!("runtime workspace metadata is invalid"));
    }
    let validation_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&request.workspace)?;
    if !same_file_identity(&metadata, &validation_directory.metadata()?) {
        return Err(anyhow!("runtime workspace changed before validation"));
    }
    validate_workspace_tree_with_deadline(
        &validation_directory,
        0,
        input_gid,
        WorkspaceAccess::Private,
        deadline.clone(),
    )?;
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
    let source_name = CString::new(request.run_id.as_bytes())
        .map_err(|_| anyhow!("runtime run identifier contains a NUL byte"))?;
    let consumed_name = CString::new(transient_unit_name(&request.run_id))
        .expect("validated run identifiers produce NUL-free unit names");
    let cleanup_root = consumed_root_directory.try_clone()?;
    rename_workspace(
        &input_root_directory,
        &source_name,
        &consumed_root_directory,
        &consumed_name,
    )?;
    let consumed_path = consumed_input_root.join(consumed_name.to_string_lossy().as_ref());
    let workspace = VerifiedWorkspace {
        path: consumed_path.clone(),
        bind_source,
        consumed_root: cleanup_root,
        consumed_name: consumed_name.clone(),
        expected_device: metadata.dev(),
        expected_inode: metadata.ino(),
        cleanup_armed: true,
        _guard: guard,
    };
    published_workspace.disarm();
    let validation = (|| {
        consumed_root_directory
            .sync_all()
            .context("failed to persist the consumed runtime workspace")?;
        input_root_directory
            .sync_all()
            .context("failed to persist removal of the public runtime workspace")?;
        grant_workspace_group_read(&validation_directory, 0, input_gid, deadline.clone())?;
        validate_workspace_tree_with_deadline(
            &validation_directory,
            0,
            input_gid,
            WorkspaceAccess::GroupReadable,
            deadline,
        )?;
        let consumed = fs::symlink_metadata(&consumed_path)?;
        if consumed.dev() != metadata.dev() || consumed.ino() != metadata.ino() {
            return Err(anyhow!("consumed runtime workspace identity changed"));
        }
        Ok(())
    })();
    finalise_workspace_preparation(workspace, validation)
}

#[cfg(target_os = "linux")]
fn finalise_workspace_preparation(
    mut workspace: VerifiedWorkspace,
    validation: Result<()>,
) -> Result<VerifiedWorkspace> {
    match validation {
        Ok(()) => Ok(workspace),
        Err(validation_error) => match workspace.cleanup() {
            Ok(()) => Err(validation_error),
            Err(cleanup_error) => Err(anyhow!(
                "{validation_error:#}; failed to clean consumed runtime workspace after preparation failure: {cleanup_error:#}"
            )),
        },
    }
}

#[cfg(all(test, target_os = "linux"))]
fn consume_workspace(
    input_root: &File,
    source_name: &CStr,
    consumed_root: &File,
    consumed_name: &CStr,
) -> Result<()> {
    rename_workspace(input_root, source_name, consumed_root, consumed_name)?;
    consumed_root
        .sync_all()
        .context("failed to persist the consumed runtime workspace")?;
    input_root
        .sync_all()
        .context("failed to persist removal of the public runtime workspace")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_workspace(
    input_root: &File,
    source_name: &CStr,
    consumed_root: &File,
    consumed_name: &CStr,
) -> Result<()> {
    // SAFETY: both directory descriptors and NUL-terminated names remain live
    // for the syscall; RENAME_NOREPLACE preserves any stale consumed entry.
    if unsafe {
        libc::renameat2(
            input_root.as_raw_fd(),
            source_name.as_ptr(),
            consumed_root.as_raw_fd(),
            consumed_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to consume the verified runtime workspace");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn validate_workspace_tree(root: &File, expected_uid: u32, input_gid: u32) -> Result<()> {
    validate_workspace_tree_with_deadline(
        root,
        expected_uid,
        input_gid,
        WorkspaceAccess::GroupReadable,
        None,
    )
}

#[cfg(target_os = "linux")]
fn validate_workspace_tree_with_deadline(
    root: &File,
    expected_uid: u32,
    input_gid: u32,
    access: WorkspaceAccess,
    deadline: Option<WorkBudget>,
) -> Result<()> {
    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    let policy = WorkspaceMetadataPolicy {
        expected_uid,
        input_gid,
        access,
    };
    validate_workspace_directory(root, &policy, 0, &mut entries, &mut total_bytes, deadline)
}

#[cfg(target_os = "linux")]
fn validate_workspace_directory(
    directory: &File,
    policy: &WorkspaceMetadataPolicy,
    depth: usize,
    entries: &mut usize,
    total_bytes: &mut u64,
    deadline: Option<WorkBudget>,
) -> Result<()> {
    if let Some(deadline) = deadline.as_ref() {
        deadline.check("sealed workspace tree verification")?;
    }
    if depth > WORKSPACE_DEPTH_MAX {
        return Err(anyhow!("runtime workspace nesting exceeds its limit"));
    }
    ensure_posix_acl_absent(directory, "runtime workspace directory")?;
    let directory_path = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        directory.as_raw_fd()
    ));
    for entry in fs::read_dir(&directory_path)? {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("sealed workspace tree verification")?;
        }
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
            || metadata.uid() != policy.expected_uid
            || metadata.gid() != policy.input_gid
        {
            return Err(anyhow!("runtime workspace entry metadata is invalid"));
        }
        use std::os::unix::fs::OpenOptionsExt;
        if metadata.is_dir() {
            if !workspace_directory_mode_valid(metadata.mode(), policy.access) {
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
                policy,
                depth + 1,
                entries,
                total_bytes,
                deadline.clone(),
            )?;
        } else if metadata.is_file() {
            if !workspace_file_mode_valid(metadata.mode(), policy.access) || metadata.nlink() != 1 {
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
            ensure_posix_acl_absent(&file, "runtime workspace file")?;
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
fn grant_workspace_group_read(
    root: &File,
    expected_uid: u32,
    input_gid: u32,
    deadline: Option<WorkBudget>,
) -> Result<()> {
    let mut entries = 0_usize;
    grant_workspace_directory_group_read(root, expected_uid, input_gid, 0, &mut entries, deadline)
}

#[cfg(target_os = "linux")]
fn grant_workspace_directory_group_read(
    directory: &File,
    expected_uid: u32,
    input_gid: u32,
    depth: usize,
    entries: &mut usize,
    deadline: Option<WorkBudget>,
) -> Result<()> {
    if let Some(deadline) = deadline.as_ref() {
        deadline.check("consumed workspace access grant")?;
    }
    if depth > WORKSPACE_DEPTH_MAX {
        return Err(anyhow!("runtime workspace nesting exceeds its limit"));
    }
    let directory_metadata = directory.metadata()?;
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != expected_uid
        || directory_metadata.gid() != input_gid
        || !workspace_directory_mode_valid(directory_metadata.mode(), WorkspaceAccess::Private)
    {
        return Err(anyhow!("private runtime workspace directory is invalid"));
    }
    ensure_posix_acl_absent(directory, "private runtime workspace directory")?;
    let directory_path = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        directory.as_raw_fd()
    ));
    for entry in fs::read_dir(&directory_path)? {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("consumed workspace access grant")?;
        }
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
            return Err(anyhow!("private runtime workspace entry is invalid"));
        }
        use std::os::unix::fs::OpenOptionsExt;
        if metadata.is_dir() {
            if !workspace_directory_mode_valid(metadata.mode(), WorkspaceAccess::Private) {
                return Err(anyhow!(
                    "private runtime workspace directory mode is invalid"
                ));
            }
            let child = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)?;
            if !same_file_identity(&metadata, &child.metadata()?) {
                return Err(anyhow!("private runtime workspace directory changed"));
            }
            grant_workspace_directory_group_read(
                &child,
                expected_uid,
                input_gid,
                depth + 1,
                entries,
                deadline.clone(),
            )?;
        } else if metadata.is_file() {
            if !workspace_file_mode_valid(metadata.mode(), WorkspaceAccess::Private)
                || metadata.nlink() != 1
            {
                return Err(anyhow!("private runtime workspace file is invalid"));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)?;
            if !same_file_identity(&metadata, &file.metadata()?) {
                return Err(anyhow!("private runtime workspace file changed"));
            }
            ensure_posix_acl_absent(&file, "private runtime workspace file")?;
            set_fd_mode(&file, 0o440)?;
            file.sync_all()
                .context("failed to persist consumed workspace file access")?;
        } else {
            return Err(anyhow!("private runtime workspace contains a special file"));
        }
    }
    set_fd_mode(directory, 0o550)?;
    directory
        .sync_all()
        .context("failed to persist consumed workspace directory access")
}

#[cfg(target_os = "linux")]
fn set_fd_mode(file: &File, mode: libc::mode_t) -> Result<()> {
    // SAFETY: fchmod uses the live descriptor and does not dereference pointers.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set consumed workspace access mode");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn workspace_directory_mode_valid(mode: u32, access: WorkspaceAccess) -> bool {
    let expected = match access {
        WorkspaceAccess::Private => 0o500,
        WorkspaceAccess::GroupReadable => 0o550,
    };
    mode & 0o7777 == expected
}

#[cfg(target_os = "linux")]
fn workspace_file_mode_valid(mode: u32, access: WorkspaceAccess) -> bool {
    let expected = match access {
        WorkspaceAccess::Private => 0o400,
        WorkspaceAccess::GroupReadable => 0o440,
    };
    mode & 0o7777 == expected
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
        "InaccessiblePaths=-/run/systemd -/run/dbus -/run/webex-codex-activation -/run/webex-codex-launcher -/run/webex-config-pull"
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
    cancellation: &ExecutionCancellation,
    _workspace: &VerifiedWorkspace,
) -> Result<IsolatedRunResult> {
    if cancellation.is_cancelled() {
        return Err(WorkBudgetError::cancelled("isolated Codex execution before start").into());
    }
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
                    if cancellation.is_cancelled() {
                        break PromptWriteOutcome::Cancelled;
                    }
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
        PromptWriteOutcome::Cancelled => {
            terminate_and_discard_captures(&plan.unit, &mut child, stdout_task, stderr_task)
                .await?;
            return Err(WorkBudgetError::cancelled("isolated Codex prompt delivery").into());
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
                if cancellation.is_cancelled() {
                    terminate_and_discard_captures(
                        &plan.unit,
                        &mut child,
                        stdout_task,
                        stderr_task,
                    )
                    .await?;
                    return Err(WorkBudgetError::cancelled("isolated Codex execution").into());
                }
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
    if Instant::now() >= deadline {
        discard_captures(stdout_task, stderr_task).await;
        return Ok(IsolatedRunResult::TimedOut);
    }
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
    Cancelled,
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
            let _ = tokio::time::timeout(CLEANUP_MARGIN, child.wait()).await;
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
    use std::os::unix::fs::OpenOptionsExt;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    ensure_posix_acl_absent(&directory, "runtime input root")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn input_root_mode_valid(mode: u32) -> bool {
    mode & 0o7777 == 0o1730
}

#[cfg(target_os = "linux")]
fn resolve_codex_group_ids(group_file: &Path, passwd_file: &Path) -> Result<CodexGroupIds> {
    let bytes = read_bounded_file(group_file, 1024 * 1024)?;
    let contents = std::str::from_utf8(&bytes).context("host group database is not UTF-8")?;
    let launch = parse_group_gid(contents, CODEX_LAUNCH_GROUP)?;
    let input = parse_group_gid(contents, CODEX_INPUT_GROUP)?;
    if launch == input {
        return Err(anyhow!("Codex launch and input groups must be distinct"));
    }
    reject_primary_gid_users(passwd_file, launch)?;
    reject_primary_gid_users(passwd_file, input)?;
    Ok(CodexGroupIds { launch, input })
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
            return Err(anyhow!("Codex group database entry is invalid"));
        }
        let gid = fields[2]
            .parse::<u32>()
            .context("Codex group identifier is invalid")?;
        if gid == 0 {
            return Err(anyhow!("Codex group must not be root"));
        }
        result = Some(gid);
    }
    let expected_gid = result.ok_or_else(|| anyhow!("Codex group is unavailable"))?;
    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() == 4
            && fields[0] != expected_name
            && fields[2].parse::<u32>().ok() == Some(expected_gid)
        {
            return Err(anyhow!("Codex group identifier is aliased"));
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
fn hash_reader(mut reader: File, prefix: &[u8], deadline: Option<WorkBudget>) -> Result<String> {
    let mut context = DigestContext::new(&SHA256);
    context.update(prefix);
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("isolated runtime image hashing")?;
        }
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
            workspace: PathBuf::from("/var/lib/webex-codex-runtime-inputs/ready/run-1"),
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
    fn verified_activation_binds_the_runtime_manifest_and_image() {
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "builder_version": 1,
            "codex_version": SUPPORTED_CODEX_VERSION,
            "codex_target": SUPPORTED_CODEX_TARGET,
            "codex_layout_version": SUPPORTED_CODEX_LAYOUT_VERSION,
            "image": format!("images/{}.squashfs", "a".repeat(64)),
            "image_sha256": "a".repeat(64),
            "image_size": 4096,
            "source_manifest_sha256": "b".repeat(64),
            "mksquashfs_sha256": "c".repeat(64),
            "mksquashfs_argv_sha256": EXPECTED_MKSQUASHFS_ARGV_SHA256
        }))
        .unwrap();
        let manifest: ActiveRuntimeManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        let activation = VerifiedActivation {
            schema_version: 1,
            boot_id: "boot-id".to_owned(),
            active_manifest_sha256: hex(ring::digest::digest(&SHA256, &manifest_bytes).as_ref()),
            runtime_image_sha256: "a".repeat(64),
            bot_executable_sha256: "d".repeat(64),
            launcher_executable_sha256: "e".repeat(64),
            runtime_executable_sha256: "f".repeat(64),
            codex_version: SUPPORTED_CODEX_VERSION.to_owned(),
            model: "gpt-5.5".to_owned(),
            canaries: vec!["runner".to_owned()],
        };

        validate_active_manifest_binding(&activation, &manifest_bytes, &manifest).unwrap();
        validate_runtime_image_binding(&activation, &manifest.image_sha256).unwrap();

        let mut drifted_manifest = activation.clone();
        drifted_manifest.active_manifest_sha256 = "0".repeat(64);
        assert!(
            validate_active_manifest_binding(&drifted_manifest, &manifest_bytes, &manifest)
                .is_err()
        );
        let mut drifted_image = activation;
        drifted_image.runtime_image_sha256 = "0".repeat(64);
        assert!(validate_runtime_image_binding(&drifted_image, &manifest.image_sha256).is_err());
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

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "webex-codex-groups-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let group_file = directory.join("group");
        let passwd_file = directory.join("passwd");
        fs::write(
            &group_file,
            b"webex-codex-launch:x:4320:\nwebex-codex-input:x:4321:\n",
        )
        .unwrap();
        fs::write(&passwd_file, b"root:x:0:0:root:/root:/bin/sh\n").unwrap();
        assert_eq!(
            resolve_codex_group_ids(&group_file, &passwd_file).unwrap(),
            CodexGroupIds {
                launch: 4320,
                input: 4321,
            }
        );
        for privileged_gid in [4320, 4321] {
            fs::write(
                &passwd_file,
                format!("root:x:0:0:root:/root:/bin/sh\nuser:x:1000:{privileged_gid}:user:/tmp:/bin/false\n"),
            )
            .unwrap();
            assert!(resolve_codex_group_ids(&group_file, &passwd_file).is_err());
        }
        fs::write(&passwd_file, b"root:x:0:0:root:/root:/bin/sh\n").unwrap();
        fs::write(
            &group_file,
            b"webex-codex-launch:x:4321:\nwebex-codex-input:x:4321:\n",
        )
        .unwrap();
        assert!(resolve_codex_group_ids(&group_file, &passwd_file).is_err());
        fs::remove_dir_all(directory).unwrap();
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
        assert_eq!(
            boot_id_credential_path(OsStr::new(
                "/run/credentials/webex-codex-launcher@1.service"
            ))
            .unwrap(),
            Path::new("/run/credentials/webex-codex-launcher@1.service/activation-boot-id")
        );
        for invalid in [
            "relative",
            "/run/credentials",
            "/run/credentials/../escape",
            "/tmp/credentials/unit",
        ] {
            assert!(boot_id_credential_path(OsStr::new(invalid)).is_err());
        }
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
    fn sealed_workspace_modes_reject_special_bits() {
        assert!(workspace_directory_mode_valid(
            0o500,
            WorkspaceAccess::Private
        ));
        assert!(workspace_file_mode_valid(0o400, WorkspaceAccess::Private));
        assert!(workspace_directory_mode_valid(
            0o550,
            WorkspaceAccess::GroupReadable
        ));
        assert!(workspace_file_mode_valid(
            0o440,
            WorkspaceAccess::GroupReadable
        ));
        for mode in [0o1500, 0o2500, 0o4500] {
            assert!(!workspace_directory_mode_valid(
                mode,
                WorkspaceAccess::Private
            ));
        }
        for mode in [0o1400, 0o2400, 0o4400] {
            assert!(!workspace_file_mode_valid(mode, WorkspaceAccess::Private));
        }
    }

    #[test]
    fn consumed_workspace_access_is_granted_only_after_private_validation() {
        use std::os::unix::fs::PermissionsExt;

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "webex-codex-private-workspace-{}-{suffix}",
            std::process::id()
        ));
        let nested = root.join("logs");
        let evidence = nested.join("console.log");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(&evidence, b"evidence").unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        let root_file = File::open(&root).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        grant_workspace_group_read(&root_file, uid, gid, None).unwrap();
        validate_workspace_tree(&root_file, uid, gid).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o550);
        assert_eq!(fs::metadata(&nested).unwrap().mode() & 0o7777, 0o550);
        assert_eq!(fs::metadata(&evidence).unwrap().mode() & 0o7777, 0o440);

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
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
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&root)
            .unwrap();

        validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).is_err());
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();

        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o640)).unwrap();
        if install_test_access_acl(&evidence) {
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();
            assert!(validate_workspace_tree(&guard, metadata.uid(), metadata.gid()).is_err());
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o640)).unwrap();
            remove_test_access_acl(&evidence);
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();
        } else {
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o440)).unwrap();
        }

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
    fn workspace_consumption_is_durable_and_does_not_replace() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "webex-codex-consume-{}-{suffix}",
            std::process::id()
        ));
        let input = base.join("input");
        let consumed = base.join("consumed");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir(&consumed).unwrap();
        let input_directory = File::open(&input).unwrap();
        let consumed_directory = File::open(&consumed).unwrap();

        fs::create_dir(input.join("first")).unwrap();
        consume_workspace(
            &input_directory,
            c"first",
            &consumed_directory,
            c"first-consumed",
        )
        .unwrap();
        assert!(!input.join("first").exists());
        assert!(consumed.join("first-consumed").is_dir());

        fs::create_dir(input.join("duplicate")).unwrap();
        fs::create_dir(consumed.join("already-there")).unwrap();
        assert!(
            consume_workspace(
                &input_directory,
                c"duplicate",
                &consumed_directory,
                c"already-there",
            )
            .is_err()
        );
        assert!(input.join("duplicate").is_dir());
        assert!(consumed.join("already-there").is_dir());

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn verified_workspace_drop_removes_only_the_consumed_inode() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "webex-codex-drop-consumed-{}-{suffix}",
            std::process::id()
        ));
        let consumed_root = base.join("consumed");
        let workspace_path = consumed_root.join("run-one");
        fs::create_dir_all(workspace_path.join("logs")).unwrap();
        fs::write(workspace_path.join("logs/console.log"), b"evidence\n").unwrap();
        let consumed_root_file = File::open(&consumed_root).unwrap();
        let guard = File::open(&workspace_path).unwrap();
        let metadata = guard.metadata().unwrap();

        let workspace = VerifiedWorkspace {
            path: workspace_path.clone(),
            bind_source: "/proc/self/fd/test".to_owned(),
            consumed_root: consumed_root_file,
            consumed_name: CString::new("run-one").unwrap(),
            expected_device: metadata.dev(),
            expected_inode: metadata.ino(),
            cleanup_armed: true,
            _guard: guard,
        };
        drop(workspace);

        assert!(!workspace_path.exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn workspace_preparation_failure_reports_cleanup_failure() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "webex-codex-clean-consumed-{}-{suffix}",
            std::process::id()
        ));
        let consumed_root = base.join("consumed");
        let workspace_path = consumed_root.join("run-one");
        let retained_path = consumed_root.join("retained");
        fs::create_dir_all(&workspace_path).unwrap();
        let consumed_root_file = File::open(&consumed_root).unwrap();
        let guard = File::open(&workspace_path).unwrap();
        let metadata = guard.metadata().unwrap();
        fs::rename(&workspace_path, &retained_path).unwrap();
        fs::create_dir(&workspace_path).unwrap();

        let workspace = VerifiedWorkspace {
            path: workspace_path.clone(),
            bind_source: "/proc/self/fd/test".to_owned(),
            consumed_root: consumed_root_file,
            consumed_name: CString::new("run-one").unwrap(),
            expected_device: metadata.dev(),
            expected_inode: metadata.ino(),
            cleanup_armed: true,
            _guard: guard,
        };
        let error = finalise_workspace_preparation(
            workspace,
            Err(anyhow!("post-rename validation failed")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("post-rename validation failed"), "{error}");
        assert!(
            error.contains("failed to clean consumed runtime workspace"),
            "{error}"
        );
        assert!(workspace_path.exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn workspace_preparation_failure_removes_the_consumed_tree() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "webex-codex-prepare-cleanup-{}-{suffix}",
            std::process::id()
        ));
        let consumed_root = base.join("consumed");
        let workspace_path = consumed_root.join("run-one");
        fs::create_dir_all(&workspace_path).unwrap();
        let consumed_root_file = File::open(&consumed_root).unwrap();
        let guard = File::open(&workspace_path).unwrap();
        let metadata = guard.metadata().unwrap();
        let workspace = VerifiedWorkspace {
            path: workspace_path.clone(),
            bind_source: "/proc/self/fd/test".to_owned(),
            consumed_root: consumed_root_file,
            consumed_name: CString::new("run-one").unwrap(),
            expected_device: metadata.dev(),
            expected_inode: metadata.ino(),
            cleanup_armed: true,
            _guard: guard,
        };

        let error = finalise_workspace_preparation(
            workspace,
            Err(anyhow!("post-rename validation failed")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("post-rename validation failed"), "{error}");
        assert!(!workspace_path.exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_failure_overrides_a_successful_execution_result() {
        let result = finalise_execution(
            Ok(IsolatedRunResult::Completed {
                output: "done".to_owned(),
                truncated: false,
            }),
            Err(anyhow!("cleanup failed")),
        );

        assert!(matches!(result, Err(IsolatedExecutionError::Failed(_))));
    }

    #[test]
    fn cancellation_is_successful_only_after_cleanup() {
        let cancelled = finalise_execution(
            Err(WorkBudgetError::cancelled("test execution").into()),
            Ok(()),
        );
        assert!(matches!(cancelled, Err(IsolatedExecutionError::Cancelled)));

        let cleanup_failed = finalise_execution(
            Err(WorkBudgetError::cancelled("test execution").into()),
            Err(anyhow!("cleanup failed")),
        );
        assert!(matches!(
            cleanup_failed,
            Err(IsolatedExecutionError::Failed(_))
        ));
    }

    fn install_test_access_acl(path: &Path) -> bool {
        let mut acl = Vec::new();
        acl.extend_from_slice(&2_u32.to_le_bytes());
        // SAFETY: `geteuid` has no preconditions.
        let named_uid = unsafe { libc::geteuid() };
        for (tag, permissions, id) in [
            (0x01_u16, 0o6_u16, u32::MAX),
            (0x02_u16, 0o4_u16, named_uid),
            (0x04_u16, 0o4_u16, u32::MAX),
            (0x10_u16, 0o4_u16, u32::MAX),
            (0x20_u16, 0o0_u16, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let name = c"system.posix_acl_access";
        // SAFETY: the path and name are NUL-terminated and `acl` remains live.
        if unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        } == 0
        {
            return true;
        }
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::ENOTSUP)
            ),
            "failed to install test ACL: {error}"
        );
        false
    }

    fn remove_test_access_acl(path: &Path) {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let name = c"system.posix_acl_access";
        // SAFETY: the path and name are valid NUL-terminated strings.
        assert_eq!(
            unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) },
            0
        );
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
            "LoadCredential=codex-auth.json:/etc/webex-generic-account-bot/codex-auth.json",
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
            "InaccessiblePaths=-/run/systemd -/run/dbus -/run/webex-codex-activation -/run/webex-codex-launcher -/run/webex-config-pull",
            RUNTIME_EXECUTABLE_PATH,
            "gpt-5.5",
            "xhigh",
        ] {
            assert!(args.iter().any(|value| value == required), "{required}");
        }
        assert!(!args.iter().any(|value| value.contains(&request.prompt)));
        assert!(!args.iter().any(|value| value.contains(&request.message_id)));
        assert!(!args.iter().any(|value| value.contains("-/run/credentials")));
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
    fn canary_credential_path_tracks_the_transient_unit_name() {
        const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            crate::canary_protocol::runtime_canary_credential_path(NONCE).unwrap(),
            format!(
                "{SYSTEMD_CREDENTIAL_ROOT}/{}/codex-auth.json",
                transient_unit_name(NONCE)
            )
        );
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
                "/var/lib/webex-codex-runtime-inputs/ready/run-1",
                "webex-codex-launcher@42.service"
            )
            .is_err()
        );
    }
}

#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::{process::Command, time::sleep};

use crate::{
    activation::{self, REQUIRED_CANARIES, VerifiedActivation},
    canary_host::{
        BoundedRegularFileSnapshot, InstrumentedTcpListener, InstrumentedUnixListener,
        bind_assigned_non_loopback_listener, bind_loopback_bot_listener,
    },
    canary_protocol::{
        RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT, RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT,
        RuntimeCanaryFixtureInputs, RuntimeCanaryHostEvidence, RuntimeCanaryRuntimeEvidence,
        parse_runtime_canary_runtime_evidence, runtime_canary_fixture_binding,
        validate_runtime_canary_nonce,
    },
    codex_launcher::LAUNCHER_SOCKET_PATH,
    config_actions::CONFIG_ACTION_SOCKET,
    isolated_execution::{
        ACTIVATION_RENEWAL_UNIT, ExecutionCancellation, RuntimeCanaryLaunchRequest,
        execute_runtime_canary,
    },
    runner_input::stage_runtime_canary_workspace,
};

const ACTIVATION_LOCK_PATH: &str = "/run/webex-codex-activation/renew.lock";
const REBOOT_CHALLENGE_PATH: &str =
    "/var/lib/webex-generic-account-bot/canary-fixtures/reboot-challenge.json";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const SHELL_PATH: &str = "/bin/sh";
const FIXTURE_MAX_BYTES: u64 = 64 * 1024;
const CHALLENGE_MAX_BYTES: u64 = 4 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const UNIT_STATE_TIMEOUT: Duration = Duration::from_secs(15);
const DEPENDENCY_SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(60);
const REBOOT_CHALLENGE_VERSION: u16 = 2;
const REBOOT_MARKER_CONTENTS: &[u8] = b"webex-runtime-reboot-canary-v1\n";

#[derive(Clone, Copy, Debug)]
struct PrivateFileOwner {
    uid: u32,
    gid: u32,
}

const ROOT_FILE_OWNER: PrivateFileOwner = PrivateFileOwner { uid: 0, gid: 0 };

#[derive(Debug, Serialize)]
pub struct RebootChallengePreparationReport {
    version: u16,
    mode: &'static str,
    status: &'static str,
    writes_performed: u8,
    activation_binding: ActivationBindingReport,
    challenge: RebootChallengeReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationBindingReport {
    active_manifest_sha256: String,
    runtime_image_sha256: String,
    bot_executable_sha256: String,
    launcher_executable_sha256: String,
    runtime_executable_sha256: String,
    codex_version: String,
    model: String,
}

#[derive(Debug, Serialize)]
struct RebootChallengeReport {
    state: &'static str,
    current_boot_matches: bool,
    validated: bool,
    marker_valid: bool,
}

pub async fn ensure_activation_receipt() -> Result<VerifiedActivation> {
    ensure_root()?;
    ensure_activation_receipt_with(
        || activation::verify_activation_with(&activation::ActivationPaths::production()),
        renew_activation_receipt,
    )
    .await
}

async fn ensure_activation_receipt_with<Verify, Renew, Renewal>(
    verify: Verify,
    renew: Renew,
) -> Result<VerifiedActivation>
where
    Verify: FnOnce() -> Result<VerifiedActivation>,
    Renew: FnOnce() -> Renewal,
    Renewal: Future<Output = Result<VerifiedActivation>>,
{
    match verify() {
        Ok(verified) => Ok(verified),
        Err(verification_error) => renew().await.map_err(|renewal_error| {
            anyhow!(
                "activation receipt verification failed: {verification_error:#}; renewal failed: {renewal_error:#}"
            )
        }),
    }
}

pub async fn renew_activation_receipt() -> Result<VerifiedActivation> {
    ensure_root()?;
    let _lock = RenewalLock::acquire()?;
    let candidate = activation::begin_activation_renewal()?;
    let result = async {
        verify_reboot_cleanup_challenge(&candidate)?;
        let runtime = run_runtime_boundary_canary(&candidate).await?;
        run_timeout_cleanup_canary(&runtime.nonce).await?;
        run_owner_crash_cleanup_canary(&runtime.nonce, "launcher").await?;
        run_bot_peer_exit_cleanup_canary(&runtime.nonce).await?;
        let canaries = passing_receipt_canaries(&runtime);
        activation::commit_activation_receipt(&candidate, canaries)
    }
    .await;
    match result {
        Ok(verified) => Ok(verified),
        Err(error) => match activation::abort_activation_renewal() {
            Ok(()) => Err(error),
            Err(abort_error) => Err(anyhow!(
                "{error:#}; failed to preserve the invalid activation state: {abort_error:#}"
            )),
        },
    }
}

pub fn prepare_activation_reboot_challenge(
    apply: bool,
) -> Result<RebootChallengePreparationReport> {
    ensure_root()?;
    let _lock = if apply {
        Some(RenewalLock::acquire()?)
    } else {
        None
    };
    let binding = activation::verify_preactivation_candidate()?;
    let expected_binding = ActivationBindingReport::from(&binding);
    let (status, writes_performed, challenge) =
        prepare_reboot_cleanup_challenge(apply, &expected_binding)?;
    Ok(RebootChallengePreparationReport {
        version: REBOOT_CHALLENGE_VERSION,
        mode: if apply { "applied" } else { "dry-run" },
        status,
        writes_performed,
        activation_binding: expected_binding,
        challenge,
    })
}

impl From<&VerifiedActivation> for ActivationBindingReport {
    fn from(binding: &VerifiedActivation) -> Self {
        Self {
            active_manifest_sha256: binding.active_manifest_sha256.clone(),
            runtime_image_sha256: binding.runtime_image_sha256.clone(),
            bot_executable_sha256: binding.bot_executable_sha256.clone(),
            launcher_executable_sha256: binding.launcher_executable_sha256.clone(),
            runtime_executable_sha256: binding.runtime_executable_sha256.clone(),
            codex_version: binding.codex_version.clone(),
            model: binding.model.clone(),
        }
    }
}

struct RenewalLock(File);

impl RenewalLock {
    fn acquire() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(ACTIVATION_LOCK_PATH)
            .context("failed to open the activation renewal lock")?;
        validate_private_root_file(&file.metadata()?, "activation renewal lock")?;
        // SAFETY: flock operates only on the live lock descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                bail!("activation renewal is already in progress");
            }
            return Err(error).context("failed to lock activation renewal");
        }
        Ok(Self(file))
    }
}

impl Drop for RenewalLock {
    fn drop(&mut self) {
        // SAFETY: this unlocks only the descriptor owned by the guard.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

struct RuntimeBoundaryResult {
    nonce: String,
    report: crate::canary_protocol::RuntimeCanaryReport,
}

async fn run_runtime_boundary_canary(
    candidate: &VerifiedActivation,
) -> Result<RuntimeBoundaryResult> {
    let nonce = random_nonce()?;
    wait_for_unix_listener_live(
        Path::new(LAUNCHER_SOCKET_PATH),
        "launcher socket",
        DEPENDENCY_SOCKET_READY_TIMEOUT,
    )
    .await?;
    wait_for_unix_listener_live(
        Path::new(CONFIG_ACTION_SOCKET),
        "config worker socket",
        DEPENDENCY_SOCKET_READY_TIMEOUT,
    )
    .await?;
    let mut fixtures = HostFixtureSet::create(&nonce)?;

    let pending = stage_runtime_canary_workspace(&nonce, &fixtures.workspace_root).await?;
    let launch = RuntimeCanaryLaunchRequest {
        nonce: nonce.clone(),
        forbidden_tcp: fixtures.forbidden.bound_endpoint().to_string(),
        bot_tcp: fixtures.bot.bound_endpoint().to_string(),
        host_unix: fixtures.unix.bound_path().to_string_lossy().into_owned(),
        host_protected_path: fixtures.protected.path().to_string_lossy().into_owned(),
    };
    let cancellation = ExecutionCancellation::new();
    let execution = execute_runtime_canary(launch.clone(), candidate.clone(), &cancellation).await;
    let cleanup = pending.cleanup().await;
    let output = match (execution, cleanup) {
        (Ok(output), Ok(())) => output,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error).context("failed to clean canary input"),
        (Err(execution_error), Err(cleanup_error)) => {
            return Err(anyhow!(
                "{execution_error:#}; failed to clean canary input: {cleanup_error:#}"
            ));
        }
    };

    let runtime = parse_runtime_evidence(&output, &launch)?;
    fixtures.protected.verify_path_identity_unchanged()?;
    fixtures.protected.verify_contents_unchanged()?;
    fixtures.workspace.verify_path_identity_unchanged()?;
    fixtures.workspace.verify_contents_unchanged()?;

    let launcher_live_after = unix_listener_live(Path::new(LAUNCHER_SOCKET_PATH))?;
    let config_live_after = unix_listener_live(Path::new(CONFIG_ACTION_SOCKET))?;
    let host_evidence = RuntimeCanaryHostEvidence {
        nonce: nonce.clone(),
        fixture_binding: runtime.fixture_binding.clone(),
        protected_path_regular_file_before: true,
        protected_path_regular_file_after: true,
        protected_path_identity_unchanged: true,
        protected_path_contents_unchanged: true,
        credential_path_regular_file_before: runtime.credential_path_regular_file_before,
        credential_path_regular_file_after: runtime.credential_path_regular_file_after,
        credential_path_identity_unchanged: runtime.credential_path_identity_unchanged,
        credential_path_contents_unchanged: runtime.credential_path_contents_unchanged,
        main_home_fixture_regular_file_before: runtime.main_home_fixture_regular_file_before,
        main_home_fixture_regular_file_after: runtime.main_home_fixture_regular_file_after,
        main_home_fixture_identity_unchanged: runtime.main_home_fixture_identity_unchanged,
        main_home_fixture_contents_unchanged: runtime.main_home_fixture_contents_unchanged,
        codex_home_fixture_regular_file_before: runtime.codex_home_fixture_regular_file_before,
        codex_home_fixture_regular_file_after: runtime.codex_home_fixture_regular_file_after,
        codex_home_fixture_identity_unchanged: runtime.codex_home_fixture_identity_unchanged,
        codex_home_fixture_contents_unchanged: runtime.codex_home_fixture_contents_unchanged,
        final_output_fixture_regular_file_before: runtime.final_output_fixture_regular_file_before,
        final_output_fixture_regular_file_after: runtime.final_output_fixture_regular_file_after,
        final_output_fixture_identity_unchanged: runtime.final_output_fixture_identity_unchanged,
        final_output_fixture_contents_unchanged: runtime.final_output_fixture_contents_unchanged,
        workspace_fixture_regular_file_before: runtime.workspace_fixture_regular_file_before,
        workspace_fixture_regular_file_after: runtime.workspace_fixture_regular_file_after,
        workspace_fixture_identity_unchanged: runtime.workspace_fixture_identity_unchanged,
        workspace_fixture_contents_unchanged: runtime.workspace_fixture_contents_unchanged,
        host_unix_listener_live_before: true,
        host_unix_listener_live_after: fixtures.unix.is_live(),
        host_unix_accept_count: fixtures.unix.accept_count(),
        forbidden_tcp_listener_live_before: true,
        forbidden_tcp_listener_live_after: fixtures.forbidden.is_live(),
        forbidden_tcp_accept_count: fixtures.forbidden.accept_count(),
        bot_tcp_listener_live_before: true,
        bot_tcp_listener_live_after: fixtures.bot.is_live(),
        bot_tcp_accept_count: fixtures.bot.accept_count(),
        config_worker_socket_live_before: true,
        config_worker_socket_live_after: config_live_after,
        launcher_socket_live_before: true,
        launcher_socket_live_after: launcher_live_after,
    };
    runtime
        .report
        .ensure_success(&nonce, &runtime.fixture_binding, &host_evidence)?;
    fixtures.shutdown_listeners()?;
    fixtures.cleanup_files()?;
    Ok(RuntimeBoundaryResult {
        nonce,
        report: runtime.report,
    })
}

fn parse_runtime_evidence(
    output: &str,
    launch: &RuntimeCanaryLaunchRequest,
) -> Result<RuntimeCanaryRuntimeEvidence> {
    if output.is_empty() || !output.ends_with('\n') || output[..output.len() - 1].contains('\n') {
        bail!("runtime canary evidence framing is invalid");
    }
    let preliminary: RuntimeCanaryRuntimeEvidence =
        serde_json::from_slice(&output.as_bytes()[..output.len() - 1])
            .context("runtime canary evidence is invalid JSON")?;
    let inputs = RuntimeCanaryFixtureInputs {
        main_pid: preliminary.main_pid,
        fd_secret_sha256: preliminary.fd_secret_sha256.clone(),
        forbidden_tcp: launch.forbidden_tcp.clone(),
        bot_tcp: launch.bot_tcp.clone(),
        host_unix: launch.host_unix.clone(),
        host_protected_path: launch.host_protected_path.clone(),
    };
    let binding = runtime_canary_fixture_binding(&launch.nonce, &inputs)?;
    parse_runtime_canary_runtime_evidence(output.as_bytes(), &launch.nonce, &binding, &inputs)
}

fn passing_receipt_canaries(runtime: &RuntimeBoundaryResult) -> BTreeMap<String, bool> {
    debug_assert!(runtime.report.checks.values().all(|passed| *passed));
    let mut canaries = BTreeMap::new();
    for name in REQUIRED_CANARIES {
        canaries.insert((*name).to_owned(), true);
    }
    canaries
}

struct HostFixtureSet {
    protected: BoundedRegularFileSnapshot,
    workspace: BoundedRegularFileSnapshot,
    workspace_root: PathBuf,
    workspace_nonce_root: PathBuf,
    workspace_canary_root: PathBuf,
    unix: InstrumentedUnixListener,
    forbidden: InstrumentedTcpListener,
    bot: InstrumentedTcpListener,
    files_cleaned: bool,
}

impl HostFixtureSet {
    fn create(nonce: &str) -> Result<Self> {
        validate_runtime_canary_nonce(nonce)?;
        validate_root_directory(
            Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT),
            0o700,
            "runtime canary root",
        )?;
        validate_root_directory(
            Path::new(RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT),
            0o700,
            "protected canary root",
        )?;
        let mut setup = FixtureSetupGuard::new();
        let protected_path = Path::new(RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT).join(nonce);
        create_private_fixture(&protected_path, &random_fixture_contents()?)?;
        setup.track(&protected_path, FixtureSetupKind::File)?;
        let protected = BoundedRegularFileSnapshot::capture(&protected_path, FIXTURE_MAX_BYTES)?;

        let workspace_root =
            Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT).join(format!("{nonce}.workspace"));
        let workspace_canary_root = workspace_root.join(".webex-codex-canary");
        let workspace_nonce_root = workspace_canary_root.join(nonce);
        create_private_directory(&workspace_root)?;
        setup.track(&workspace_root, FixtureSetupKind::Directory)?;
        create_private_directory(&workspace_canary_root)?;
        setup.track(&workspace_canary_root, FixtureSetupKind::Directory)?;
        create_private_directory(&workspace_nonce_root)?;
        setup.track(&workspace_nonce_root, FixtureSetupKind::Directory)?;
        let workspace_path = workspace_nonce_root.join("probe.txt");
        create_private_fixture(&workspace_path, &workspace_probe_payload(nonce)?)?;
        setup.track(&workspace_path, FixtureSetupKind::File)?;
        let workspace = BoundedRegularFileSnapshot::capture(&workspace_path, FIXTURE_MAX_BYTES)?;

        let unix_path =
            Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT).join(format!("{nonce}.sock"));
        let unix = InstrumentedUnixListener::bind(unix_path)?;
        let forbidden = bind_assigned_non_loopback_listener()?;
        let bot = bind_loopback_bot_listener()?;
        let fixtures = Self {
            protected,
            workspace,
            workspace_root,
            workspace_nonce_root,
            workspace_canary_root,
            unix,
            forbidden,
            bot,
            files_cleaned: false,
        };
        setup.disarm();
        Ok(fixtures)
    }

    fn shutdown_listeners(&mut self) -> Result<()> {
        let unix = self.unix.shutdown_and_verify_zero_accepts();
        let forbidden = self.forbidden.shutdown_and_verify_zero_accepts();
        let bot = self.bot.shutdown_and_verify_zero_accepts();
        unix.and(forbidden).and(bot)
    }

    fn cleanup_files(&mut self) -> Result<()> {
        self.protected.verify_path_identity_unchanged()?;
        self.workspace.verify_path_identity_unchanged()?;
        fs::remove_file(self.protected.path())?;
        fs::remove_file(self.workspace.path())?;
        fs::remove_dir(&self.workspace_nonce_root)?;
        fs::remove_dir(&self.workspace_canary_root)?;
        fs::remove_dir(&self.workspace_root)?;
        self.files_cleaned = true;
        Ok(())
    }
}

impl Drop for HostFixtureSet {
    fn drop(&mut self) {
        if !self.files_cleaned && self.cleanup_files().is_err() {
            tracing::error!(nonce = %self.protected.path().display(), "runtime canary fixtures require manual cleanup");
        }
    }
}

#[derive(Clone, Copy)]
enum FixtureSetupKind {
    File,
    Directory,
}

struct FixtureSetupEntry {
    path: PathBuf,
    device: u64,
    inode: u64,
    kind: FixtureSetupKind,
}

struct FixtureSetupGuard {
    entries: Vec<FixtureSetupEntry>,
    armed: bool,
}

impl FixtureSetupGuard {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            armed: true,
        }
    }

    fn track(&mut self, path: &Path, kind: FixtureSetupKind) -> Result<()> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to track canary fixture {}", path.display()))?;
        let expected_kind = match kind {
            FixtureSetupKind::File => metadata.is_file(),
            FixtureSetupKind::Directory => metadata.is_dir(),
        };
        if metadata.file_type().is_symlink() || !expected_kind {
            bail!("created canary fixture type is invalid");
        }
        self.entries.push(FixtureSetupEntry {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            kind,
        });
        Ok(())
    }

    fn disarm(&mut self) {
        self.entries.clear();
        self.armed = false;
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        for entry in self.entries.drain(..).rev() {
            let result = (|| -> Result<()> {
                let metadata = match fs::symlink_metadata(&entry.path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => return Err(error.into()),
                };
                let expected_kind = match entry.kind {
                    FixtureSetupKind::File => metadata.is_file(),
                    FixtureSetupKind::Directory => metadata.is_dir(),
                };
                if metadata.file_type().is_symlink()
                    || !expected_kind
                    || metadata.dev() != entry.device
                    || metadata.ino() != entry.inode
                {
                    bail!("created canary fixture was replaced before rollback");
                }
                match entry.kind {
                    FixtureSetupKind::File => fs::remove_file(&entry.path)?,
                    FixtureSetupKind::Directory => fs::remove_dir(&entry.path)?,
                }
                Ok(())
            })();
            if let Err(error) = result {
                failures.push(format!("{}: {error:#}", entry.path.display()));
            }
        }
        self.armed = false;
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to roll back canary fixture setup: {}",
                failures.join("; ")
            )
        }
    }
}

impl Drop for FixtureSetupGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.cleanup() {
                tracing::error!(error = %error, "runtime canary setup requires manual cleanup");
            }
        }
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)
        .with_context(|| format!("failed to create canary directory {}", path.display()))?;
    let result = (|| -> Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o700
        {
            bail!("created canary directory metadata is invalid");
        }
        Ok(())
    })();
    if let Err(error) = result {
        return Err(failed_creation_error(
            path,
            FixtureSetupKind::Directory,
            error,
        ));
    }
    Ok(())
}

fn create_private_fixture(path: &Path, contents: &[u8]) -> Result<()> {
    create_private_fixture_with_owner(path, contents, ROOT_FILE_OWNER)
}

fn create_private_fixture_with_owner(
    path: &Path,
    contents: &[u8],
    owner: PrivateFileOwner,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to create canary fixture {}", path.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        validate_private_file(&file.metadata()?, "canary fixture", owner)
    })();
    drop(file);
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(failed_creation_error(path, FixtureSetupKind::File, error)),
    }
}

fn failed_creation_error(
    path: &Path,
    kind: FixtureSetupKind,
    error: anyhow::Error,
) -> anyhow::Error {
    let cleanup = match kind {
        FixtureSetupKind::File => fs::remove_file(path),
        FixtureSetupKind::Directory => fs::remove_dir(path),
    };
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => anyhow!(
            "{error:#}; failed to roll back canary fixture {}: {cleanup_error}",
            path.display()
        ),
    }
}

fn validate_private_root_file(metadata: &fs::Metadata, description: &str) -> Result<()> {
    validate_private_file(metadata, description, ROOT_FILE_OWNER)
}

fn validate_private_file(
    metadata: &fs::Metadata,
    description: &str,
    owner: PrivateFileOwner,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner.uid
        || metadata.gid() != owner.gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        bail!("{description} metadata is invalid");
    }
    Ok(())
}

fn validate_root_directory(path: &Path, mode: u32, description: &str) -> Result<()> {
    validate_directory_owner(path, mode, description, ROOT_FILE_OWNER)
}

fn validate_directory_owner(
    path: &Path,
    mode: u32,
    description: &str,
    owner: PrivateFileOwner,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{description} is unavailable: {}", path.display()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner.uid
        || metadata.gid() != owner.gid
        || metadata.mode() & 0o7777 != mode
    {
        bail!("{description} metadata is invalid");
    }
    Ok(())
}

fn random_fixture_contents() -> Result<Vec<u8>> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("failed to obtain canary fixture randomness"))?;
    Ok(format!("webex-runtime-canary-v1:{}\n", hex(&bytes)).into_bytes())
}

fn workspace_probe_payload(nonce: &str) -> Result<Vec<u8>> {
    validate_runtime_canary_nonce(nonce)?;
    Ok(nonce.as_bytes().to_vec())
}

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("failed to obtain runtime canary nonce"))?;
    Ok(hex(&bytes))
}

fn unix_listener_live(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() {
        return Ok(false);
    }
    let table = fs::read_to_string("/proc/net/unix")?;
    if table.len() > 1024 * 1024 {
        bail!("Unix socket table is oversized");
    }
    let expected = path
        .to_str()
        .ok_or_else(|| anyhow!("fixed Unix socket path is not UTF-8"))?;
    for line in table.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() >= 8 && fields[7] == expected {
            let flags = u32::from_str_radix(fields[3], 16)
                .context("Unix socket table contains invalid flags")?;
            return Ok(flags & 0x0001_0000 != 0 && fields[5] == "01");
        }
    }
    Ok(false)
}

async fn wait_for_unix_listener_live(
    path: &Path,
    description: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if unix_listener_live(path)? {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("{description} did not become live before the runtime canary");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn run_timeout_cleanup_canary(nonce: &str) -> Result<()> {
    let unit = lifecycle_unit_name("timeout", nonce);
    let mut args = vec![
        "--quiet".into(),
        "--service-type=exec".into(),
        format!("--unit={unit}"),
    ];
    args.extend(activation_owner_properties());
    args.extend([
        "--property=RuntimeMaxSec=2s".into(),
        "--property=TimeoutStopSec=5s".into(),
        "--property=KillMode=control-group".into(),
        SHELL_PATH.into(),
        "-c".into(),
        "exec sleep 30".into(),
    ]);
    let result = async {
        let start = run_command(SYSTEMD_RUN_PATH, &args, COMMAND_TIMEOUT).await?;
        ensure!(start.success(), "timeout canary failed to start");
        wait_for_unit_active(&unit).await?;
        wait_for_unit_inactive(&unit).await?;
        verify_timeout_unit_result(&unit).await
    }
    .await;
    let cleanup = cleanup_lifecycle_unit(&unit).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(anyhow!(
            "{error:#}; failed to clean timeout canary unit: {cleanup_error:#}"
        )),
    }
}

async fn run_owner_crash_cleanup_canary(nonce: &str, owner: &str) -> Result<()> {
    let anchor = lifecycle_unit_name(&format!("{owner}-anchor"), nonce);
    let child = lifecycle_unit_name(&format!("{owner}-child"), nonce);
    let mut anchor_may_exist = false;
    let mut child_may_exist = false;
    let result = async {
        anchor_may_exist = true;
        let start_anchor = run_command(
            SYSTEMD_RUN_PATH,
            &owner_anchor_args(&anchor),
            COMMAND_TIMEOUT,
        )
        .await?;
        ensure!(start_anchor.success(), "lifecycle anchor failed to start");

        child_may_exist = true;
        let start_child = run_command(
            SYSTEMD_RUN_PATH,
            &owner_child_args(&anchor, &child),
            COMMAND_TIMEOUT,
        )
        .await?;
        ensure!(start_child.success(), "lifecycle child failed to start");
        wait_for_unit_active(&child)
            .await
            .context("lifecycle child never became active")?;
        stop_unit(&anchor).await?;
        wait_for_unit_inactive(&child).await
    }
    .await;

    let cleanup =
        cleanup_owner_lifecycle_units(&anchor, anchor_may_exist, &child, child_may_exist).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(anyhow!(
            "{error:#}; failed to clean owner lifecycle canary units: {cleanup_error:#}"
        )),
    }
}

async fn run_bot_peer_exit_cleanup_canary(nonce: &str) -> Result<()> {
    let unit = crate::isolated_execution::bot_peer_exit_canary_unit_name(nonce)?;
    let mut peer_process = Command::new(SHELL_PATH);
    peer_process
        .args(["-c", "exec sleep 30"])
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut peer_process = peer_process
        .spawn()
        .context("failed to start bot peer-exit canary process")?;
    let peer_pid = peer_process
        .id()
        .ok_or_else(|| anyhow!("bot peer-exit canary process has no PID"))?;
    let cancellation = ExecutionCancellation::new();

    let execution = crate::isolated_execution::execute_bot_peer_exit_cleanup_canary(
        nonce,
        peer_pid,
        &cancellation,
    );
    let terminate_peer = async {
        let readiness = wait_for_unit_active(&unit).await;
        let termination = peer_process
            .start_kill()
            .context("failed to terminate bot peer-exit canary process");
        let reaped = peer_process
            .wait()
            .await
            .context("failed to reap bot peer-exit canary process");
        readiness?;
        termination?;
        reaped?;
        Ok::<(), anyhow::Error>(())
    };
    let (execution, termination) = tokio::join!(execution, terminate_peer);
    let result = async {
        execution?;
        termination?;
        wait_for_unit_inactive(&unit).await
    }
    .await;
    let cleanup = cleanup_lifecycle_unit(&unit).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(anyhow!(
            "{error:#}; failed to clean bot peer-exit canary unit: {cleanup_error:#}"
        )),
    }
}

fn owner_anchor_args(anchor: &str) -> Vec<String> {
    let mut args = vec![
        "--quiet".into(),
        "--service-type=exec".into(),
        format!("--unit={anchor}"),
    ];
    args.extend(activation_owner_properties());
    args.extend([SHELL_PATH.into(), "-c".into(), "exec sleep 30".into()]);
    args
}

fn owner_child_args(anchor: &str, child: &str) -> Vec<String> {
    vec![
        "--quiet".into(),
        "--service-type=exec".into(),
        format!("--unit={child}"),
        format!("--property=BindsTo={anchor}"),
        format!("--property=After={anchor}"),
        "--property=KillMode=control-group".into(),
        SHELL_PATH.into(),
        "-c".into(),
        "exec sleep 30".into(),
    ]
}

fn activation_owner_properties() -> [String; 1] {
    [format!("--property=BindsTo={ACTIVATION_RENEWAL_UNIT}")]
}

async fn run_command(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    tokio::time::timeout(timeout, command.status())
        .await
        .map_err(|_| anyhow!("fixed lifecycle command timed out"))?
        .with_context(|| format!("failed to run fixed lifecycle command {program}"))
}

async fn run_command_output(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<std::process::Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| anyhow!("fixed lifecycle command timed out"))?
        .with_context(|| format!("failed to run fixed lifecycle command {program}"))?;
    if output.stdout.len() > 128 {
        bail!("fixed lifecycle command output is oversized");
    }
    Ok(output)
}

async fn stop_unit(unit: &str) -> Result<()> {
    let status = run_command(
        SYSTEMCTL_PATH,
        &["--no-ask-password".into(), "stop".into(), unit.into()],
        COMMAND_TIMEOUT,
    )
    .await?;
    ensure!(status.success(), "failed to stop lifecycle canary unit");
    Ok(())
}

async fn cleanup_lifecycle_unit(unit: &str) -> Result<()> {
    let stop = stop_unit(unit).await;
    let reset = reset_failed_unit(unit).await;
    match (stop, reset) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(stop_error), Err(reset_error)) => Err(anyhow!(
            "{stop_error:#}; failed to reset lifecycle canary unit: {reset_error:#}"
        )),
    }
}

async fn cleanup_owner_lifecycle_units(
    anchor: &str,
    anchor_may_exist: bool,
    child: &str,
    child_may_exist: bool,
) -> Result<()> {
    let mut errors = Vec::new();
    if child_may_exist {
        if let Err(error) = cleanup_lifecycle_unit(child).await {
            errors.push(format!("child cleanup failed: {error:#}"));
        }
    }
    if anchor_may_exist {
        if let Err(error) = cleanup_lifecycle_unit(anchor).await {
            errors.push(format!("anchor cleanup failed: {error:#}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

async fn reset_failed_unit(unit: &str) -> Result<()> {
    let status = run_command(
        SYSTEMCTL_PATH,
        &[
            "--no-ask-password".into(),
            "reset-failed".into(),
            unit.into(),
        ],
        COMMAND_TIMEOUT,
    )
    .await?;
    ensure!(status.success(), "failed to reset lifecycle canary unit");
    Ok(())
}

async fn verify_timeout_unit_result(unit: &str) -> Result<()> {
    let output = run_command_output(
        SYSTEMCTL_PATH,
        &[
            "--no-pager".into(),
            "--no-ask-password".into(),
            "show".into(),
            "--property=Result".into(),
            "--value".into(),
            unit.into(),
        ],
        COMMAND_TIMEOUT,
    )
    .await?;
    ensure!(
        output.status.success(),
        "failed to inspect timeout canary result"
    );
    validate_timeout_unit_result(&output.stdout)
}

fn validate_timeout_unit_result(output: &[u8]) -> Result<()> {
    if output != b"timeout\n" {
        bail!("timeout canary unit did not finish because RuntimeMaxSec expired");
    }
    Ok(())
}

async fn wait_for_unit_inactive(unit: &str) -> Result<()> {
    wait_for_unit_state(unit, RequiredUnitState::Inactive).await
}

async fn wait_for_unit_active(unit: &str) -> Result<()> {
    wait_for_unit_state(unit, RequiredUnitState::Active).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequiredUnitState {
    Active,
    Inactive,
}

impl RequiredUnitState {
    fn reached(self, is_active: bool) -> bool {
        match self {
            Self::Active => is_active,
            Self::Inactive => !is_active,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }
}

async fn wait_for_unit_state(unit: &str, required: RequiredUnitState) -> Result<()> {
    let deadline = tokio::time::Instant::now() + UNIT_STATE_TIMEOUT;
    loop {
        let status = run_command(
            SYSTEMCTL_PATH,
            &["--quiet".into(), "is-active".into(), unit.into()],
            COMMAND_TIMEOUT,
        )
        .await?;
        if required.reached(status.success()) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "lifecycle canary unit did not become {}",
                required.description()
            );
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn lifecycle_unit_name(kind: &str, nonce: &str) -> String {
    format!("webex-codex-canary-{kind}-{}.service", &nonce[..16])
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RebootChallenge {
    version: u16,
    challenge_boot_id: String,
    marker_nonce: String,
    validated_boot_id: Option<String>,
    activation_binding: ActivationBindingReport,
}

#[derive(Debug)]
struct RebootChallengePaths {
    challenge: PathBuf,
    boot_id: PathBuf,
    marker_root: PathBuf,
    owner: PrivateFileOwner,
}

impl RebootChallengePaths {
    fn production() -> Self {
        Self {
            challenge: PathBuf::from(REBOOT_CHALLENGE_PATH),
            boot_id: PathBuf::from(BOOT_ID_PATH),
            marker_root: PathBuf::from(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT),
            owner: ROOT_FILE_OWNER,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRebootChallengeV1 {
    version: u16,
    challenge_boot_id: String,
    marker_nonce: String,
    validated_boot_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebootChallengeState {
    Absent,
    PendingCurrentBoot,
    ValidatedCurrentBoot,
    CrossedBootBoundary,
}

fn prepare_reboot_cleanup_challenge(
    apply: bool,
    expected_binding: &ActivationBindingReport,
) -> Result<(&'static str, u8, RebootChallengeReport)> {
    prepare_reboot_cleanup_challenge_with(
        &RebootChallengePaths::production(),
        apply,
        expected_binding,
    )
}

fn prepare_reboot_cleanup_challenge_with(
    paths: &RebootChallengePaths,
    apply: bool,
    expected_binding: &ActivationBindingReport,
) -> Result<(&'static str, u8, RebootChallengeReport)> {
    validate_reboot_marker_root(paths)?;
    let current_boot = read_boot_id_with(&paths.boot_id)?;
    let existing = read_reboot_challenge_with(paths)?;
    match classify_reboot_challenge(&current_boot, existing.as_ref(), expected_binding)? {
        RebootChallengeState::Absent if !apply => Ok((
            "ready",
            0,
            RebootChallengeReport {
                state: "absent",
                current_boot_matches: false,
                validated: false,
                marker_valid: false,
            },
        )),
        RebootChallengeState::Absent => {
            write_new_reboot_challenge_with(paths, &current_boot, None, expected_binding)?;
            let challenge = read_reboot_challenge_with(paths)?
                .ok_or_else(|| anyhow!("prepared reboot challenge is missing"))?;
            ensure!(
                classify_reboot_challenge(&current_boot, Some(&challenge), expected_binding)?
                    == RebootChallengeState::PendingCurrentBoot,
                "prepared reboot challenge is not pending for the current boot"
            );
            validate_reboot_marker_with(paths, &challenge.marker_nonce)?;
            Ok(("reboot_required", 2, pending_reboot_challenge_report()))
        }
        RebootChallengeState::PendingCurrentBoot => {
            let challenge = existing.expect("classified challenge must exist");
            validate_reboot_marker_with(paths, &challenge.marker_nonce)?;
            Ok(("reboot_required", 0, pending_reboot_challenge_report()))
        }
        RebootChallengeState::ValidatedCurrentBoot => {
            bail!("runtime activation reboot challenge is already validated for this boot")
        }
        RebootChallengeState::CrossedBootBoundary => {
            let challenge = existing.expect("classified challenge must exist");
            ensure!(
                path_is_absent(&reboot_marker_path_with(paths, &challenge.marker_nonce)?)?,
                "pre-reboot runtime marker survived the boot boundary"
            );
            bail!(
                "runtime activation reboot challenge has crossed a real boot; continue activation instead"
            )
        }
    }
}

fn classify_reboot_challenge(
    current_boot: &str,
    challenge: Option<&RebootChallenge>,
    expected_binding: &ActivationBindingReport,
) -> Result<RebootChallengeState> {
    let Some(challenge) = challenge else {
        return Ok(RebootChallengeState::Absent);
    };
    ensure!(
        &challenge.activation_binding == expected_binding,
        "reboot challenge does not match the active runtime binding"
    );
    if let Some(validated_boot) = challenge.validated_boot_id.as_deref() {
        if validated_boot != challenge.challenge_boot_id {
            bail!("reboot challenge validated boot ID is invalid");
        }
    }
    if challenge.challenge_boot_id != current_boot {
        return Ok(RebootChallengeState::CrossedBootBoundary);
    }
    if challenge.validated_boot_id.is_some() {
        Ok(RebootChallengeState::ValidatedCurrentBoot)
    } else {
        Ok(RebootChallengeState::PendingCurrentBoot)
    }
}

fn pending_reboot_challenge_report() -> RebootChallengeReport {
    RebootChallengeReport {
        state: "pending_current_boot",
        current_boot_matches: true,
        validated: false,
        marker_valid: true,
    }
}

fn verify_reboot_cleanup_challenge(binding: &VerifiedActivation) -> Result<()> {
    verify_reboot_cleanup_challenge_with(&RebootChallengePaths::production(), binding)
}

fn verify_reboot_cleanup_challenge_with(
    paths: &RebootChallengePaths,
    binding: &VerifiedActivation,
) -> Result<()> {
    validate_reboot_marker_root(paths)?;
    let current_boot = read_boot_id_with(&paths.boot_id)?;
    let challenge = read_reboot_challenge_with(paths)?;
    let expected_binding = ActivationBindingReport::from(binding);
    match challenge {
        None => {
            write_new_reboot_challenge_with(paths, &current_boot, None, &expected_binding)?;
            bail!("runtime activation requires one real reboot to validate cleanup");
        }
        Some(challenge) if challenge.challenge_boot_id == current_boot => {
            ensure!(
                challenge.activation_binding == expected_binding,
                "reboot challenge does not match the active runtime binding"
            );
            if challenge.validated_boot_id.as_deref() != Some(&current_boot) {
                bail!("runtime activation reboot challenge has not crossed a real boot");
            }
            validate_reboot_marker_with(paths, &challenge.marker_nonce)
        }
        Some(challenge) => {
            ensure!(
                challenge.activation_binding == expected_binding,
                "reboot challenge does not match the active runtime binding"
            );
            let marker = reboot_marker_path_with(paths, &challenge.marker_nonce)?;
            ensure!(
                path_is_absent(&marker)?,
                "pre-reboot runtime marker survived the boot boundary"
            );
            write_new_reboot_challenge_with(
                paths,
                &current_boot,
                Some(current_boot.clone()),
                &expected_binding,
            )
        }
    }
}

fn write_new_reboot_challenge_with(
    paths: &RebootChallengePaths,
    boot_id: &str,
    validated_boot_id: Option<String>,
    activation_binding: &ActivationBindingReport,
) -> Result<()> {
    let marker_nonce = random_nonce()?;
    let marker = reboot_marker_path_with(paths, &marker_nonce)?;
    create_private_fixture_with_owner(&marker, REBOOT_MARKER_CONTENTS, paths.owner)?;
    let challenge = RebootChallenge {
        version: REBOOT_CHALLENGE_VERSION,
        challenge_boot_id: boot_id.to_owned(),
        marker_nonce,
        validated_boot_id,
        activation_binding: activation_binding.clone(),
    };
    let mut payload = serde_json::to_vec(&challenge)?;
    payload.push(b'\n');
    ensure!(payload.len() as u64 <= CHALLENGE_MAX_BYTES);
    let result = atomic_write_private(&paths.challenge, &payload, paths.owner);
    if result.is_err() {
        let _ = remove_private_file(&marker, "reboot marker", paths.owner);
    }
    result
}

fn read_reboot_challenge_with(paths: &RebootChallengePaths) -> Result<Option<RebootChallenge>> {
    if path_is_absent(&paths.challenge)? {
        return Ok(None);
    }
    let payload = read_private_file(
        &paths.challenge,
        CHALLENGE_MAX_BYTES,
        "reboot challenge",
        paths.owner,
    )?;
    let challenge: RebootChallenge = match serde_json::from_slice(&payload) {
        Ok(challenge) => challenge,
        Err(error) => {
            if is_legacy_reboot_challenge_v1(&payload) {
                bail!("legacy reboot challenge schema version 1 requires operator recovery");
            }
            return Err(error.into());
        }
    };
    if challenge.version != REBOOT_CHALLENGE_VERSION
        || !activation::parse_boot_id(challenge.challenge_boot_id.as_bytes())
            .is_ok_and(|boot_id| boot_id == challenge.challenge_boot_id)
        || challenge
            .validated_boot_id
            .as_deref()
            .is_some_and(|validated_boot_id| {
                !activation::parse_boot_id(validated_boot_id.as_bytes())
                    .is_ok_and(|boot_id| boot_id == validated_boot_id)
            })
        || validate_runtime_canary_nonce(&challenge.marker_nonce).is_err()
    {
        bail!("reboot challenge is invalid");
    }
    Ok(Some(challenge))
}

fn is_legacy_reboot_challenge_v1(payload: &[u8]) -> bool {
    let Ok(challenge) = serde_json::from_slice::<LegacyRebootChallengeV1>(payload) else {
        return false;
    };
    challenge.version == 1
        && !challenge.challenge_boot_id.trim().is_empty()
        && validate_runtime_canary_nonce(&challenge.marker_nonce).is_ok()
        && challenge
            .validated_boot_id
            .as_deref()
            .is_none_or(|boot_id| !boot_id.trim().is_empty())
}

fn validate_reboot_marker_with(paths: &RebootChallengePaths, nonce: &str) -> Result<()> {
    let payload = read_private_file(
        &reboot_marker_path_with(paths, nonce)?,
        REBOOT_MARKER_CONTENTS.len() as u64,
        "current-boot reboot marker",
        paths.owner,
    )?;
    ensure!(
        payload == REBOOT_MARKER_CONTENTS,
        "current-boot reboot marker contents are invalid"
    );
    Ok(())
}

fn validate_reboot_marker_root(paths: &RebootChallengePaths) -> Result<()> {
    validate_directory_owner(&paths.marker_root, 0o700, "reboot marker root", paths.owner)
}

fn atomic_write_private(path: &Path, payload: &[u8], owner: PrivateFileOwner) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("private file has no parent"))?;
    validate_directory_owner(parent, 0o700, "private file parent", owner)?;
    if !path_is_absent(path)? {
        let metadata = fs::symlink_metadata(path)?;
        validate_private_file(&metadata, "existing private file", owner)?;
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        random_nonce()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(payload)?;
        file.sync_all()?;
        validate_private_file(&file.metadata()?, "temporary private file", owner)?;
        fs::rename(&temporary, path)?;
        ensure!(
            read_private_file(path, payload.len() as u64, "written private file", owner)?
                == payload,
            "written private file contents are invalid"
        );
        validate_directory_owner(parent, 0o700, "private file parent", owner)?;
        let directory = File::open(parent)?;
        directory.sync_all()?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateFileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
}

impl PrivateFileIdentity {
    fn capture(
        metadata: &fs::Metadata,
        max_bytes: u64,
        description: &str,
        owner: PrivateFileOwner,
    ) -> Result<Self> {
        validate_private_file(metadata, description, owner)?;
        ensure!(
            metadata.len() <= max_bytes,
            "{description} exceeds its size limit"
        );
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.len(),
        })
    }
}

fn read_private_file(
    path: &Path,
    max_bytes: u64,
    description: &str,
    owner: PrivateFileOwner,
) -> Result<Vec<u8>> {
    let expected =
        PrivateFileIdentity::capture(&fs::symlink_metadata(path)?, max_bytes, description, owner)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        PrivateFileIdentity::capture(&file.metadata()?, max_bytes, description, owner)? == expected,
        "{description} identity changed while opening"
    );
    let mut payload = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut payload)?;
    ensure!(payload.len() as u64 <= max_bytes);
    ensure!(
        payload.len() as u64 == expected.size,
        "{description} size changed while reading"
    );
    ensure!(
        PrivateFileIdentity::capture(&file.metadata()?, max_bytes, description, owner)? == expected,
        "{description} identity changed while reading"
    );
    ensure!(
        PrivateFileIdentity::capture(&fs::symlink_metadata(path)?, max_bytes, description, owner,)?
            == expected,
        "{description} path changed while reading"
    );
    Ok(payload)
}

fn remove_private_file(path: &Path, description: &str, owner: PrivateFileOwner) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_private_file(&metadata, description, owner)?;
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
fn reboot_marker_path(nonce: &str) -> Result<PathBuf> {
    reboot_marker_path_with(&RebootChallengePaths::production(), nonce)
}

fn reboot_marker_path_with(paths: &RebootChallengePaths, nonce: &str) -> Result<PathBuf> {
    validate_runtime_canary_nonce(nonce)?;
    Ok(paths.marker_root.join(format!("reboot-{nonce}.marker")))
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn read_boot_id_with(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)?;
    let value = value.trim();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23)
                    && byte.is_ascii_hexdigit()
                    && !byte.is_ascii_uppercase()
        })
    {
        bail!("kernel boot ID is invalid");
    }
    Ok(value.to_owned())
}

fn ensure_root() -> Result<()> {
    // SAFETY: geteuid has no arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        bail!("activation canary helper must run as root");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn verified_activation(boot_id: &str) -> VerifiedActivation {
        VerifiedActivation {
            schema_version: 1,
            boot_id: boot_id.to_owned(),
            active_manifest_sha256: "a".repeat(64),
            runtime_image_sha256: "b".repeat(64),
            bot_executable_sha256: "c".repeat(64),
            launcher_executable_sha256: "d".repeat(64),
            runtime_executable_sha256: "e".repeat(64),
            codex_version: "test".to_owned(),
            model: "test".to_owned(),
            canaries: REQUIRED_CANARIES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "webex-activation-canary-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
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

    struct RebootChallengeFixture {
        _root: TestDirectory,
        paths: RebootChallengePaths,
    }

    impl RebootChallengeFixture {
        fn new(boot_id: &str) -> Self {
            let root = TestDirectory::new("reboot-challenge");
            let challenge_root = root.join("persistent");
            let marker_root = root.join("run");
            for directory in [&challenge_root, &marker_root] {
                fs::create_dir(directory).unwrap();
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let boot_id_path = root.join("boot-id");
            fs::write(&boot_id_path, format!("{boot_id}\n")).unwrap();
            Self {
                _root: root,
                paths: RebootChallengePaths {
                    challenge: challenge_root.join("reboot-challenge.json"),
                    boot_id: boot_id_path,
                    marker_root,
                    owner: PrivateFileOwner {
                        // SAFETY: these calls have no arguments or side effects.
                        uid: unsafe { libc::geteuid() },
                        gid: unsafe { libc::getegid() },
                    },
                },
            }
        }

        fn set_boot_id(&self, boot_id: &str) {
            fs::write(&self.paths.boot_id, format!("{boot_id}\n")).unwrap();
        }

        fn challenge(&self) -> RebootChallenge {
            read_reboot_challenge_with(&self.paths)
                .unwrap()
                .expect("challenge is present")
        }

        fn marker(&self, nonce: &str) -> PathBuf {
            reboot_marker_path_with(&self.paths, nonce).unwrap()
        }
    }

    #[tokio::test]
    async fn ensure_reuses_a_valid_receipt_without_running_canaries() {
        let existing = verified_activation("existing");
        let renewal_called = Cell::new(false);

        let verified = ensure_activation_receipt_with(
            || Ok(existing.clone()),
            || async {
                renewal_called.set(true);
                Ok(verified_activation("renewed"))
            },
        )
        .await
        .unwrap();

        assert_eq!(verified, existing);
        assert!(!renewal_called.get());
    }

    #[tokio::test]
    async fn ensure_renews_a_missing_or_stale_receipt() {
        let renewed = verified_activation("renewed");
        let renewal_called = Cell::new(false);

        let verified = ensure_activation_receipt_with(
            || Err(anyhow!("missing receipt")),
            || async {
                renewal_called.set(true);
                Ok(renewed.clone())
            },
        )
        .await
        .unwrap();

        assert_eq!(verified, renewed);
        assert!(renewal_called.get());
    }

    #[test]
    fn lifecycle_unit_names_are_fixed_and_bounded() {
        let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let unit = lifecycle_unit_name("launcher-anchor", nonce);
        assert_eq!(
            unit,
            "webex-codex-canary-launcher-anchor-0123456789abcdef.service"
        );
        assert!(unit.len() < 128);
    }

    #[test]
    fn activation_owned_transients_bind_without_waiting_for_the_oneshot() {
        let properties = activation_owner_properties();
        assert_eq!(
            properties,
            [format!("--property=BindsTo={ACTIVATION_RENEWAL_UNIT}")]
        );
        assert!(
            properties
                .iter()
                .all(|property| !property.starts_with("--property=After="))
        );
    }

    #[test]
    fn owner_lifecycle_units_remain_loaded_until_explicit_cleanup() {
        let anchor = "webex-codex-canary-owner-anchor.service";
        let child = "webex-codex-canary-owner-child.service";
        let anchor_args = owner_anchor_args(anchor);
        let child_args = owner_child_args(anchor, child);

        assert!(!anchor_args.iter().any(|argument| argument == "--collect"));
        assert!(!child_args.iter().any(|argument| argument == "--collect"));
        assert!(
            anchor_args
                .iter()
                .any(|argument| argument
                    == "--property=BindsTo=webex-codex-activation-renew.service")
        );
        assert!(
            child_args
                .iter()
                .any(|argument| argument == &format!("--property=BindsTo={anchor}"))
        );
        assert!(
            child_args
                .iter()
                .any(|argument| argument == &format!("--property=After={anchor}"))
        );
    }

    #[test]
    fn lifecycle_state_targets_require_the_requested_state() {
        assert!(RequiredUnitState::Active.reached(true));
        assert!(!RequiredUnitState::Active.reached(false));
        assert!(RequiredUnitState::Inactive.reached(false));
        assert!(!RequiredUnitState::Inactive.reached(true));
    }

    #[test]
    fn timeout_canary_requires_the_exact_systemd_result() {
        validate_timeout_unit_result(b"timeout\n").unwrap();
        for invalid in [
            b"success\n".as_slice(),
            b"exit-code\n".as_slice(),
            b"timeout".as_slice(),
            b"timeout\nother\n".as_slice(),
        ] {
            assert!(validate_timeout_unit_result(invalid).is_err());
        }
    }

    #[test]
    fn receipt_canary_map_is_exact() {
        let report = RuntimeBoundaryResult {
            nonce: "0".repeat(64),
            report: crate::canary_protocol::RuntimeCanaryReport::new(
                "0".repeat(64),
                "1".repeat(64),
                crate::canary_protocol::RUNTIME_CANARY_CHECKS
                    .iter()
                    .map(|name| ((*name).to_owned(), true))
                    .collect(),
            )
            .unwrap(),
        };
        let canaries = passing_receipt_canaries(&report);
        assert_eq!(canaries.len(), REQUIRED_CANARIES.len());
        assert!(
            REQUIRED_CANARIES
                .iter()
                .all(|name| canaries.get(*name) == Some(&true))
        );
    }

    #[test]
    fn reboot_marker_path_is_derived_only_from_a_valid_nonce() {
        let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            reboot_marker_path(nonce).unwrap(),
            Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT).join(format!("reboot-{nonce}.marker"))
        );
        assert!(reboot_marker_path("../outside").is_err());
    }

    #[test]
    fn reboot_challenge_state_is_bound_to_boot_and_runtime() {
        let current_boot = "11111111-2222-3333-4444-555555555555";
        let previous_boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let binding = ActivationBindingReport::from(&verified_activation(current_boot));
        assert_eq!(
            classify_reboot_challenge(current_boot, None, &binding).unwrap(),
            RebootChallengeState::Absent
        );

        let mut challenge = RebootChallenge {
            version: REBOOT_CHALLENGE_VERSION,
            challenge_boot_id: current_boot.to_owned(),
            marker_nonce: "0".repeat(64),
            validated_boot_id: None,
            activation_binding: binding.clone(),
        };
        assert_eq!(
            classify_reboot_challenge(current_boot, Some(&challenge), &binding).unwrap(),
            RebootChallengeState::PendingCurrentBoot
        );
        challenge.validated_boot_id = Some(current_boot.to_owned());
        assert_eq!(
            classify_reboot_challenge(current_boot, Some(&challenge), &binding).unwrap(),
            RebootChallengeState::ValidatedCurrentBoot
        );
        challenge.challenge_boot_id = previous_boot.to_owned();
        challenge.validated_boot_id = None;
        assert_eq!(
            classify_reboot_challenge(current_boot, Some(&challenge), &binding).unwrap(),
            RebootChallengeState::CrossedBootBoundary
        );

        let mut other = binding.clone();
        other.runtime_image_sha256 = "f".repeat(64);
        assert!(classify_reboot_challenge(current_boot, Some(&challenge), &other).is_err());
        challenge.validated_boot_id = Some(current_boot.to_owned());
        assert!(classify_reboot_challenge(current_boot, Some(&challenge), &binding).is_err());
    }

    #[test]
    fn reboot_challenge_disk_state_arms_and_retries_without_changing_evidence() {
        let boot = "11111111-2222-3333-4444-555555555555";
        let fixture = RebootChallengeFixture::new(boot);
        let binding = ActivationBindingReport::from(&verified_activation(boot));

        let (status, writes, report) =
            prepare_reboot_cleanup_challenge_with(&fixture.paths, false, &binding).unwrap();
        assert_eq!(status, "ready");
        assert_eq!(writes, 0);
        assert_eq!(report.state, "absent");
        assert!(!fixture.paths.challenge.exists());

        let (status, writes, report) =
            prepare_reboot_cleanup_challenge_with(&fixture.paths, true, &binding).unwrap();
        assert_eq!(status, "reboot_required");
        assert_eq!(writes, 2);
        assert_eq!(report.state, "pending_current_boot");
        let challenge = fixture.challenge();
        let marker = fixture.marker(&challenge.marker_nonce);
        validate_reboot_marker_with(&fixture.paths, &challenge.marker_nonce).unwrap();
        assert_eq!(
            fs::symlink_metadata(&fixture.paths.challenge)
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::symlink_metadata(&marker).unwrap().mode() & 0o7777,
            0o600
        );

        let original_nonce = challenge.marker_nonce;
        let (_, writes, _) =
            prepare_reboot_cleanup_challenge_with(&fixture.paths, true, &binding).unwrap();
        assert_eq!(writes, 0);
        assert_eq!(fixture.challenge().marker_nonce, original_nonce);
    }

    #[test]
    fn reboot_challenge_disk_state_rejects_an_untrusted_marker_root() {
        let boot = "11111111-2222-3333-4444-555555555555";
        let fixture = RebootChallengeFixture::new(boot);
        let activation = verified_activation(boot);
        let binding = ActivationBindingReport::from(&activation);
        fs::set_permissions(
            &fixture.paths.marker_root,
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let error = prepare_reboot_cleanup_challenge_with(&fixture.paths, false, &binding)
            .expect_err("reject an unsafe marker root before challenge preparation");
        assert!(error.to_string().contains("reboot marker root metadata"));
        assert!(!fixture.paths.challenge.exists());

        let error = verify_reboot_cleanup_challenge_with(&fixture.paths, &activation)
            .expect_err("reject an unsafe marker root before activation renewal");
        assert!(error.to_string().contains("reboot marker root metadata"));
        assert!(!fixture.paths.challenge.exists());
    }

    #[test]
    fn reboot_challenge_disk_state_requires_marker_cleanup_across_a_real_boot() {
        let first_boot = "11111111-2222-3333-4444-555555555555";
        let next_boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let fixture = RebootChallengeFixture::new(first_boot);
        let activation = verified_activation(first_boot);
        let binding = ActivationBindingReport::from(&activation);
        prepare_reboot_cleanup_challenge_with(&fixture.paths, true, &binding).unwrap();
        let first = fixture.challenge();
        let first_marker = fixture.marker(&first.marker_nonce);

        fixture.set_boot_id(next_boot);
        let error = prepare_reboot_cleanup_challenge_with(&fixture.paths, false, &binding)
            .expect_err("reject a marker that survived the boot boundary");
        assert!(error.to_string().contains("marker survived"));

        fs::remove_file(&first_marker).unwrap();
        let error = prepare_reboot_cleanup_challenge_with(&fixture.paths, false, &binding)
            .expect_err("require the post-reboot activation path");
        assert!(error.to_string().contains("continue activation instead"));

        let mut drifted = activation.clone();
        drifted.runtime_image_sha256 = "f".repeat(64);
        let error = verify_reboot_cleanup_challenge_with(&fixture.paths, &drifted)
            .expect_err("reject runtime binding drift");
        assert!(error.to_string().contains("does not match"));
        assert_eq!(fixture.challenge().challenge_boot_id, first_boot);

        verify_reboot_cleanup_challenge_with(&fixture.paths, &activation).unwrap();
        let validated = fixture.challenge();
        assert_eq!(validated.challenge_boot_id, next_boot);
        assert_eq!(validated.validated_boot_id.as_deref(), Some(next_boot));
        assert_eq!(validated.activation_binding, binding);
        validate_reboot_marker_with(&fixture.paths, &validated.marker_nonce).unwrap();

        fs::remove_file(fixture.marker(&validated.marker_nonce)).unwrap();
        verify_reboot_cleanup_challenge_with(&fixture.paths, &activation)
            .expect_err("require current-boot marker evidence");
    }

    #[test]
    fn reboot_challenge_schema_rejects_legacy_and_unknown_fields() {
        let boot = "11111111-2222-3333-4444-555555555555";
        let challenge = RebootChallenge {
            version: REBOOT_CHALLENGE_VERSION,
            challenge_boot_id: boot.to_owned(),
            marker_nonce: "0".repeat(64),
            validated_boot_id: None,
            activation_binding: ActivationBindingReport::from(&verified_activation(boot)),
        };
        let mut value = serde_json::to_value(&challenge).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RebootChallenge>(value).is_err());

        let mut legacy = serde_json::to_value(&challenge).unwrap();
        legacy.as_object_mut().unwrap().remove("activation_binding");
        legacy["version"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RebootChallenge>(legacy.clone()).is_err());

        let fixture = RebootChallengeFixture::new(boot);
        let payload = serde_json::to_vec(&legacy).unwrap();
        create_private_fixture_with_owner(&fixture.paths.challenge, &payload, fixture.paths.owner)
            .unwrap();
        let error = read_reboot_challenge_with(&fixture.paths)
            .expect_err("identify an exact legacy challenge");
        assert!(
            error
                .to_string()
                .contains("legacy reboot challenge schema version 1")
        );
    }

    #[test]
    fn reboot_challenge_disk_state_rejects_noncanonical_boot_ids() {
        let boot = "11111111-2222-3333-4444-555555555555";
        for (challenge_boot_id, validated_boot_id) in [
            ("not-a-boot-id", None),
            (boot, Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")),
        ] {
            let fixture = RebootChallengeFixture::new(boot);
            let activation = verified_activation(boot);
            let challenge = RebootChallenge {
                version: REBOOT_CHALLENGE_VERSION,
                challenge_boot_id: challenge_boot_id.to_owned(),
                marker_nonce: "0".repeat(64),
                validated_boot_id: validated_boot_id.map(str::to_owned),
                activation_binding: ActivationBindingReport::from(&activation),
            };
            let payload = serde_json::to_vec(&challenge).unwrap();
            create_private_fixture_with_owner(
                &fixture.paths.challenge,
                &payload,
                fixture.paths.owner,
            )
            .unwrap();

            let error = verify_reboot_cleanup_challenge_with(&fixture.paths, &activation)
                .expect_err("reject a noncanonical persisted boot identifier");
            assert!(error.to_string().contains("reboot challenge is invalid"));
            assert_eq!(fs::read(&fixture.paths.challenge).unwrap(), payload);
        }
    }

    #[test]
    fn workspace_probe_payload_is_the_exact_nonce() {
        let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(workspace_probe_payload(nonce).unwrap(), nonce.as_bytes());
        assert!(workspace_probe_payload("not-a-nonce").is_err());
    }

    #[test]
    fn setup_guard_removes_tracked_fixtures_in_reverse_order() {
        let directory = TestDirectory::new("setup-rollback");
        let workspace = directory.join("workspace");
        let nested = workspace.join("nested");
        let fixture = nested.join("fixture");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(&fixture, b"fixture").unwrap();

        let mut setup = FixtureSetupGuard::new();
        setup
            .track(&workspace, FixtureSetupKind::Directory)
            .unwrap();
        setup.track(&nested, FixtureSetupKind::Directory).unwrap();
        setup.track(&fixture, FixtureSetupKind::File).unwrap();
        drop(setup);

        assert!(!workspace.exists());
    }

    #[test]
    fn setup_guard_preserves_replaced_paths() {
        let directory = TestDirectory::new("setup-replacement");
        let fixture = directory.join("fixture");
        let original = directory.join("original");
        fs::write(&fixture, b"original").unwrap();

        let mut setup = FixtureSetupGuard::new();
        setup.track(&fixture, FixtureSetupKind::File).unwrap();
        fs::rename(&fixture, &original).unwrap();
        fs::write(&fixture, b"replacement").unwrap();

        assert!(setup.cleanup().is_err());
        assert_eq!(fs::read(&fixture).unwrap(), b"replacement");
        assert_eq!(fs::read(&original).unwrap(), b"original");
    }

    #[test]
    fn proc_unix_probe_distinguishes_a_live_listener() {
        let directory = TestDirectory::new("proc-unix");
        let path = directory.join("listener.sock");
        assert!(!unix_listener_live(&path).unwrap());

        let listener = UnixListener::bind(&path).unwrap();
        assert!(unix_listener_live(&path).unwrap());

        drop(listener);
        assert!(!unix_listener_live(&path).unwrap());
    }

    #[tokio::test]
    async fn readiness_wait_accepts_live_and_rejects_missing_listeners() {
        let directory = TestDirectory::new("socket-ready");
        let path = directory.join("listener.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        wait_for_unix_listener_live(&path, "test listener", Duration::ZERO)
            .await
            .unwrap();

        assert!(
            wait_for_unix_listener_live(
                &directory.join("missing.sock"),
                "missing listener",
                Duration::ZERO,
            )
            .await
            .is_err()
        );
    }
}

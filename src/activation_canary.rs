#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
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
const REBOOT_CHALLENGE_VERSION: u16 = 1;
const REBOOT_MARKER_CONTENTS: &[u8] = b"webex-runtime-reboot-canary-v1\n";

pub async fn renew_activation_receipt() -> Result<VerifiedActivation> {
    ensure_root()?;
    let _lock = RenewalLock::acquire()?;
    let candidate = activation::begin_activation_renewal()?;
    let result = async {
        verify_reboot_cleanup_challenge()?;
        let runtime = run_runtime_boundary_canary(&candidate).await?;
        run_timeout_cleanup_canary(&runtime.nonce).await?;
        run_owner_crash_cleanup_canary(&runtime.nonce, "launcher").await?;
        run_owner_crash_cleanup_canary(&runtime.nonce, "bot").await?;
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
        if self.armed
            && let Err(error) = self.cleanup()
        {
            tracing::error!(error = %error, "runtime canary setup requires manual cleanup");
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
        validate_private_root_file(&file.metadata()?, "canary fixture")
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
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        bail!("{description} metadata is invalid");
    }
    Ok(())
}

fn validate_root_directory(path: &Path, mode: u32, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{description} is unavailable: {}", path.display()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
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
}

fn verify_reboot_cleanup_challenge() -> Result<()> {
    let current_boot = read_boot_id()?;
    let challenge = read_reboot_challenge()?;
    match challenge {
        None => {
            write_new_reboot_challenge(&current_boot, None)?;
            bail!("runtime activation requires one real reboot to validate cleanup");
        }
        Some(challenge) if challenge.challenge_boot_id == current_boot => {
            if challenge.validated_boot_id.as_deref() != Some(&current_boot) {
                bail!("runtime activation reboot challenge has not crossed a real boot");
            }
            validate_reboot_marker(&reboot_marker_path(&challenge.marker_nonce)?)
        }
        Some(challenge) => {
            let marker = reboot_marker_path(&challenge.marker_nonce)?;
            ensure!(
                path_is_absent(&marker)?,
                "pre-reboot runtime marker survived the boot boundary"
            );
            write_new_reboot_challenge(&current_boot, Some(current_boot.clone()))
        }
    }
}

fn write_new_reboot_challenge(boot_id: &str, validated_boot_id: Option<String>) -> Result<()> {
    let marker_nonce = random_nonce()?;
    let marker = reboot_marker_path(&marker_nonce)?;
    create_private_fixture(&marker, REBOOT_MARKER_CONTENTS)?;
    let challenge = RebootChallenge {
        version: REBOOT_CHALLENGE_VERSION,
        challenge_boot_id: boot_id.to_owned(),
        marker_nonce,
        validated_boot_id,
    };
    let mut payload = serde_json::to_vec(&challenge)?;
    payload.push(b'\n');
    ensure!(payload.len() as u64 <= CHALLENGE_MAX_BYTES);
    let result = atomic_write_private(Path::new(REBOOT_CHALLENGE_PATH), &payload);
    if result.is_err() {
        let _ = remove_private_root_file(&marker, "reboot marker");
    }
    result
}

fn read_reboot_challenge() -> Result<Option<RebootChallenge>> {
    let path = Path::new(REBOOT_CHALLENGE_PATH);
    if path_is_absent(path)? {
        return Ok(None);
    }
    let payload = read_private_root_file(path, CHALLENGE_MAX_BYTES, "reboot challenge")?;
    let challenge: RebootChallenge = serde_json::from_slice(&payload)?;
    if challenge.version != REBOOT_CHALLENGE_VERSION
        || challenge.challenge_boot_id.trim().is_empty()
        || validate_runtime_canary_nonce(&challenge.marker_nonce).is_err()
    {
        bail!("reboot challenge is invalid");
    }
    Ok(Some(challenge))
}

fn validate_reboot_marker(path: &Path) -> Result<()> {
    let payload = read_private_root_file(
        path,
        REBOOT_MARKER_CONTENTS.len() as u64,
        "current-boot reboot marker",
    )?;
    ensure!(
        payload == REBOOT_MARKER_CONTENTS,
        "current-boot reboot marker contents are invalid"
    );
    Ok(())
}

fn atomic_write_private(path: &Path, payload: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("private file has no parent"))?;
    validate_root_directory(parent, 0o700, "private file parent")?;
    if !path_is_absent(path)? {
        let metadata = fs::symlink_metadata(path)?;
        validate_private_root_file(&metadata, "existing private file")?;
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
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
        validate_private_root_file(&file.metadata()?, "temporary private file")?;
        fs::rename(&temporary, path)?;
        ensure!(
            read_private_root_file(path, payload.len() as u64, "written private file")? == payload,
            "written private file contents are invalid"
        );
        validate_root_directory(parent, 0o700, "private file parent")?;
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
    fn capture(metadata: &fs::Metadata, max_bytes: u64, description: &str) -> Result<Self> {
        validate_private_root_file(metadata, description)?;
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

fn read_private_root_file(path: &Path, max_bytes: u64, description: &str) -> Result<Vec<u8>> {
    let expected =
        PrivateFileIdentity::capture(&fs::symlink_metadata(path)?, max_bytes, description)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        PrivateFileIdentity::capture(&file.metadata()?, max_bytes, description)? == expected,
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
        PrivateFileIdentity::capture(&file.metadata()?, max_bytes, description)? == expected,
        "{description} identity changed while reading"
    );
    ensure!(
        PrivateFileIdentity::capture(&fs::symlink_metadata(path)?, max_bytes, description)?
            == expected,
        "{description} path changed while reading"
    );
    Ok(payload)
}

fn remove_private_root_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_private_root_file(&metadata, description)?;
    fs::remove_file(path)?;
    Ok(())
}

fn reboot_marker_path(nonce: &str) -> Result<PathBuf> {
    validate_runtime_canary_nonce(nonce)?;
    Ok(Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT).join(format!("reboot-{nonce}.marker")))
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn read_boot_id() -> Result<String> {
    let value = fs::read_to_string(BOOT_ID_PATH)?;
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
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "webex-activation-canary-{name}-{}-{sequence}",
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

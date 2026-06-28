#[cfg(target_os = "linux")]
use std::{
    fs,
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::anyhow;
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use tokio::{process::Command, time::timeout};

pub const LAUNCHER_SOCKET_PATH: &str = "/run/webex-codex-launcher/launcher.sock";
pub const BOT_SERVICE_UNIT: &str = "webex-generic-account-bot.service";
pub const BOT_EXECUTABLE_PATH: &str =
    "/opt/webex-generic-account-bot/bin/webex-generic-account-bot";
pub const LAUNCHER_EXECUTABLE_PATH: &str =
    "/opt/webex-generic-account-bot/bin/webex-codex-launcher";

#[cfg(target_os = "linux")]
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
#[cfg(target_os = "linux")]
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const SYSTEMCTL_MAIN_PID_ARGS: [&str; 5] = [
    "show",
    "--property=MainPID",
    "--value",
    "--no-pager",
    BOT_SERVICE_UNIT,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSnapshot {
    start_time_ticks: u64,
    executable: PathBuf,
    cgroup: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableMetadata {
    is_file: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct AuthorisedPeer {
    credentials: PeerCredentials,
    pidfd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl AuthorisedPeer {
    pub fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    pub fn ensure_alive(&self) -> Result<()> {
        pidfd_is_alive(self.pidfd.as_raw_fd())
    }
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
#[async_trait]
trait HostProbe: Send + Sync {
    async fn bot_main_pid(&self) -> Result<u32>;
    fn open_pidfd(&self, pid: u32) -> Result<OwnedFd>;
    fn process_snapshot(&self, pid: u32) -> Result<ProcessSnapshot>;
    fn executable_metadata(&self, path: &Path) -> Result<ExecutableMetadata>;
}

#[cfg(target_os = "linux")]
struct SystemHostProbe;

#[cfg(target_os = "linux")]
#[async_trait]
impl HostProbe for SystemHostProbe {
    async fn bot_main_pid(&self) -> Result<u32> {
        trusted_root_executable(Path::new(SYSTEMCTL_PATH))?;
        let mut command = Command::new(SYSTEMCTL_PATH);
        command
            .args(SYSTEMCTL_MAIN_PID_ARGS)
            .env_clear()
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let output = timeout(SYSTEMCTL_TIMEOUT, command.output())
            .await
            .map_err(|_| anyhow!("timed out while resolving the bot service MainPID"))??;
        if !output.status.success() || output.stdout.len() > 32 {
            return Err(anyhow!("failed to resolve the bot service MainPID"));
        }
        parse_main_pid(&output.stdout)
    }

    fn open_pidfd(&self, pid: u32) -> Result<OwnedFd> {
        open_pidfd(pid)
    }

    fn process_snapshot(&self, pid: u32) -> Result<ProcessSnapshot> {
        process_snapshot(pid)
    }

    fn executable_metadata(&self, path: &Path) -> Result<ExecutableMetadata> {
        trusted_root_executable(path)?;
        executable_metadata(path)
    }
}

#[cfg(target_os = "linux")]
pub fn socket_peer_credentials(fd: RawFd) -> Result<PeerCredentials> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length point to writable values of the expected sizes.
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error())
            .context("launcher connection peer credentials are unavailable");
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(anyhow!(
            "launcher connection peer credentials are unavailable"
        ));
    }
    if credentials.pid <= 1 {
        return Err(anyhow!("launcher connection peer process is invalid"));
    }
    Ok(PeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

#[cfg(target_os = "linux")]
pub async fn authorise_bot_peer(peer: PeerCredentials) -> Result<AuthorisedPeer> {
    authorise_bot_peer_with(peer, &SystemHostProbe).await
}

#[cfg(target_os = "linux")]
pub fn validate_launcher_process() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("Codex launcher must run as root"));
    }
    let executable = fs::read_link("/proc/self/exe")?;
    if executable != Path::new(LAUNCHER_EXECUTABLE_PATH) {
        return Err(anyhow!("Codex launcher executable path is invalid"));
    }
    trusted_root_executable(Path::new(LAUNCHER_EXECUTABLE_PATH))
}

#[cfg(target_os = "linux")]
pub fn validate_socket_stdio(stdin_fd: RawFd, stdout_fd: RawFd) -> Result<()> {
    let stdin = descriptor_metadata(stdin_fd)?;
    let stdout = descriptor_metadata(stdout_fd)?;
    if stdin != stdout || stdin.file_type != libc::S_IFSOCK {
        return Err(anyhow!(
            "Codex launcher stdin and stdout must be the same accepted socket"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn authorise_bot_peer_with(
    peer: PeerCredentials,
    probe: &dyn HostProbe,
) -> Result<AuthorisedPeer> {
    if peer.pid <= 1 || peer.uid == 0 {
        return Err(anyhow!("launcher caller is not authorised"));
    }

    let pidfd = probe
        .open_pidfd(peer.pid)
        .map_err(|_| anyhow!("launcher caller is not authorised"))?;
    let before = probe
        .process_snapshot(peer.pid)
        .map_err(|_| anyhow!("launcher caller is not authorised"))?;
    let main_pid = probe
        .bot_main_pid()
        .await
        .map_err(|_| anyhow!("launcher caller is not authorised"))?;
    if main_pid != peer.pid
        || before.executable != Path::new(BOT_EXECUTABLE_PATH)
        || !cgroup_contains_bot_service(&before.cgroup)
    {
        return Err(anyhow!("launcher caller is not authorised"));
    }

    let metadata = probe
        .executable_metadata(Path::new(BOT_EXECUTABLE_PATH))
        .map_err(|_| anyhow!("launcher caller is not authorised"))?;
    if !metadata_is_trusted(metadata) {
        return Err(anyhow!("launcher caller is not authorised"));
    }

    let after = probe
        .process_snapshot(peer.pid)
        .map_err(|_| anyhow!("launcher caller is not authorised"))?;
    if before != after {
        return Err(anyhow!("launcher caller is not authorised"));
    }

    Ok(AuthorisedPeer {
        credentials: peer,
        pidfd,
    })
}

#[cfg(target_os = "linux")]
fn parse_main_pid(output: &[u8]) -> Result<u32> {
    let value = std::str::from_utf8(output)
        .context("bot service MainPID is not UTF-8")?
        .trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(anyhow!("bot service MainPID is invalid"));
    }
    let pid = value.parse::<u32>()?;
    if pid <= 1 {
        return Err(anyhow!("bot service MainPID is not running"));
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn process_snapshot(pid: u32) -> Result<ProcessSnapshot> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read(proc.join("stat"))?;
    let cgroup = fs::read_to_string(proc.join("cgroup"))?;
    let executable = fs::read_link(proc.join("exe"))?;
    Ok(ProcessSnapshot {
        start_time_ticks: parse_proc_start_time(&stat)?,
        executable,
        cgroup,
    })
}

#[cfg(target_os = "linux")]
fn parse_proc_start_time(stat: &[u8]) -> Result<u64> {
    let stat = std::str::from_utf8(stat).context("process stat is not UTF-8")?;
    let command_end = stat
        .rfind(") ")
        .ok_or_else(|| anyhow!("process stat is invalid"))?;
    let fields = stat[command_end + 2..].split_ascii_whitespace();
    let start_time = fields
        .into_iter()
        .nth(19)
        .ok_or_else(|| anyhow!("process stat has no start time"))?;
    Ok(start_time.parse()?)
}

#[cfg(target_os = "linux")]
fn cgroup_contains_bot_service(cgroup: &str) -> bool {
    let expected = format!("/system.slice/{BOT_SERVICE_UNIT}");
    cgroup.lines().any(|line| {
        line.split_once("::")
            .is_some_and(|(hierarchy, path)| hierarchy == "0" && path == expected)
    })
}

#[cfg(target_os = "linux")]
fn executable_metadata(path: &Path) -> Result<ExecutableMetadata> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(ExecutableMetadata {
        is_file: metadata.is_file(),
        is_symlink: metadata.file_type().is_symlink(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

#[cfg(target_os = "linux")]
fn metadata_is_trusted(metadata: ExecutableMetadata) -> bool {
    metadata.is_file
        && !metadata.is_symlink
        && metadata.uid == 0
        && metadata.mode & 0o022 == 0
        && metadata.mode & 0o111 != 0
}

#[cfg(target_os = "linux")]
fn trusted_root_executable(path: &Path) -> Result<()> {
    if !path.is_absolute() || !metadata_is_trusted(executable_metadata(path)?) {
        return Err(anyhow!("trusted launcher dependency is invalid"));
    }
    let mut ancestor = path.parent();
    while let Some(path) = ancestor {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(anyhow!("trusted launcher dependency ancestor is invalid"));
        }
        ancestor = path.parent();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    // SAFETY: pidfd_open does not dereference userspace pointers.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: pidfd_open returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn pidfd_is_alive(pidfd: RawFd) -> Result<()> {
    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor points to one initialized pollfd and timeout zero never blocks.
    let status = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if status < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if status != 0 || descriptor.revents != 0 {
        return Err(anyhow!("launcher caller exited during request"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorMetadata {
    device: libc::dev_t,
    inode: libc::ino_t,
    file_type: libc::mode_t,
}

#[cfg(target_os = "linux")]
fn descriptor_metadata(fd: RawFd) -> Result<DescriptorMetadata> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: metadata points to enough writable storage for fstat.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: a successful fstat initialized the complete stat value.
    let metadata = unsafe { metadata.assume_init() };
    Ok(DescriptorMetadata {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        file_type: metadata.st_mode & libc::S_IFMT,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn unsupported_platform_error() -> anyhow::Error {
    anyhow!("the Codex launcher is supported only on Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::net::UnixStream,
        },
        sync::Mutex,
    };

    use super::*;

    struct FakeProbe {
        main_pid: u32,
        snapshots: Mutex<Vec<ProcessSnapshot>>,
        metadata: ExecutableMetadata,
    }

    #[async_trait]
    impl HostProbe for FakeProbe {
        async fn bot_main_pid(&self) -> Result<u32> {
            Ok(self.main_pid)
        }

        fn open_pidfd(&self, _pid: u32) -> Result<OwnedFd> {
            let file = fs::File::open("/dev/null")?;
            Ok(file.into())
        }

        fn process_snapshot(&self, _pid: u32) -> Result<ProcessSnapshot> {
            let mut snapshots = self.snapshots.lock().unwrap();
            if snapshots.len() > 1 {
                Ok(snapshots.remove(0))
            } else {
                Ok(snapshots[0].clone())
            }
        }

        fn executable_metadata(&self, _path: &Path) -> Result<ExecutableMetadata> {
            Ok(self.metadata)
        }
    }

    fn trusted_snapshot() -> ProcessSnapshot {
        ProcessSnapshot {
            start_time_ticks: 42,
            executable: PathBuf::from(BOT_EXECUTABLE_PATH),
            cgroup: format!("0::/system.slice/{BOT_SERVICE_UNIT}\n"),
        }
    }

    fn trusted_metadata() -> ExecutableMetadata {
        ExecutableMetadata {
            is_file: true,
            is_symlink: false,
            uid: 0,
            mode: 0o100755,
        }
    }

    #[tokio::test]
    async fn authorises_only_the_current_trusted_bot_main_process() {
        let peer = PeerCredentials {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };
        let probe = FakeProbe {
            main_pid: peer.pid,
            snapshots: Mutex::new(vec![trusted_snapshot()]),
            metadata: trusted_metadata(),
        };

        let authorised = authorise_bot_peer_with(peer, &probe).await.unwrap();

        assert_eq!(authorised.credentials(), peer);
    }

    #[tokio::test]
    async fn rejects_a_child_even_when_its_identity_matches_the_bot_user() {
        let peer = PeerCredentials {
            pid: 4243,
            uid: 1000,
            gid: 1000,
        };
        let probe = FakeProbe {
            main_pid: 4242,
            snapshots: Mutex::new(vec![trusted_snapshot()]),
            metadata: trusted_metadata(),
        };

        let error = authorise_bot_peer_with(peer, &probe).await.unwrap_err();

        assert_eq!(error.to_string(), "launcher caller is not authorised");
    }

    #[tokio::test]
    async fn rejects_pid_reuse_during_authorisation() {
        let peer = PeerCredentials {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };
        let mut changed = trusted_snapshot();
        changed.start_time_ticks += 1;
        let probe = FakeProbe {
            main_pid: peer.pid,
            snapshots: Mutex::new(vec![trusted_snapshot(), changed]),
            metadata: trusted_metadata(),
        };

        let error = authorise_bot_peer_with(peer, &probe).await.unwrap_err();

        assert_eq!(error.to_string(), "launcher caller is not authorised");
    }

    #[tokio::test]
    async fn rejects_untrusted_bot_executable_metadata() {
        let peer = PeerCredentials {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };
        let probe = FakeProbe {
            main_pid: peer.pid,
            snapshots: Mutex::new(vec![trusted_snapshot()]),
            metadata: ExecutableMetadata {
                mode: 0o100775,
                ..trusted_metadata()
            },
        };

        let error = authorise_bot_peer_with(peer, &probe).await.unwrap_err();

        assert_eq!(error.to_string(), "launcher caller is not authorised");
    }

    #[tokio::test]
    async fn rejects_root_wrong_executable_and_wrong_cgroup_callers() {
        let base_peer = PeerCredentials {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };
        let base_probe = || FakeProbe {
            main_pid: base_peer.pid,
            snapshots: Mutex::new(vec![trusted_snapshot()]),
            metadata: trusted_metadata(),
        };

        let root_error = authorise_bot_peer_with(
            PeerCredentials {
                uid: 0,
                ..base_peer
            },
            &base_probe(),
        )
        .await
        .unwrap_err();
        assert_eq!(root_error.to_string(), "launcher caller is not authorised");

        let mut wrong_executable = trusted_snapshot();
        wrong_executable.executable = PathBuf::from("/usr/bin/false");
        let executable_probe = FakeProbe {
            snapshots: Mutex::new(vec![wrong_executable]),
            ..base_probe()
        };
        assert!(
            authorise_bot_peer_with(base_peer, &executable_probe)
                .await
                .is_err()
        );

        let mut wrong_cgroup = trusted_snapshot();
        wrong_cgroup.cgroup = "0::/system.slice/other.service\n".to_owned();
        let cgroup_probe = FakeProbe {
            snapshots: Mutex::new(vec![wrong_cgroup]),
            ..base_probe()
        };
        assert!(
            authorise_bot_peer_with(base_peer, &cgroup_probe)
                .await
                .is_err()
        );
    }

    #[test]
    fn reads_unix_socket_peer_credentials() {
        let (left, _right) = UnixStream::pair().unwrap();

        let credentials = match socket_peer_credentials(left.as_raw_fd()) {
            Ok(credentials) => credentials,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.raw_os_error() == Some(libc::EPERM)) =>
            {
                // Some test sandboxes block SO_PEERCRED. Runtime remains fail closed.
                return;
            }
            Err(error) => panic!("failed to read peer credentials: {error:#}"),
        };

        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.uid, unsafe { libc::geteuid() });
        assert_eq!(credentials.gid, unsafe { libc::getegid() });
    }

    #[test]
    fn accepted_socket_must_back_both_standard_streams() {
        let (left, _right) = UnixStream::pair().unwrap();
        let duplicate = unsafe { libc::dup(left.as_raw_fd()) };
        assert!(duplicate >= 0);
        // SAFETY: dup returned a new descriptor owned by this test.
        let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };

        validate_socket_stdio(left.as_raw_fd(), duplicate.as_raw_fd()).unwrap();

        let file = fs::File::open("/dev/null").unwrap();
        assert!(validate_socket_stdio(left.as_raw_fd(), file.as_raw_fd()).is_err());
    }

    #[test]
    fn rejects_non_socket_peer_credentials() {
        let file = fs::File::open("/dev/null").unwrap();

        assert!(socket_peer_credentials(file.as_raw_fd()).is_err());
    }

    #[test]
    fn parses_only_a_live_numeric_main_pid() {
        assert_eq!(parse_main_pid(b"42\n").unwrap(), 42);
        assert!(parse_main_pid(b"0\n").is_err());
        assert!(parse_main_pid(b"42 extra\n").is_err());
        assert!(parse_main_pid(b"-42\n").is_err());
    }

    #[test]
    fn systemd_main_pid_lookup_uses_only_fixed_argv() {
        assert_eq!(SYSTEMCTL_PATH, "/usr/bin/systemctl");
        assert_eq!(
            SYSTEMCTL_MAIN_PID_ARGS,
            [
                "show",
                "--property=MainPID",
                "--value",
                "--no-pager",
                "webex-generic-account-bot.service",
            ]
        );
    }

    #[test]
    fn parses_start_time_after_a_command_name_with_parentheses() {
        let mut fields = vec!["S"; 20];
        fields[19] = "987654";
        let stat = format!("123 (a tricky ) name) {}", fields.join(" "));

        assert_eq!(parse_proc_start_time(stat.as_bytes()).unwrap(), 987654);
    }

    #[test]
    fn requires_the_exact_systemd_cgroup() {
        assert!(cgroup_contains_bot_service(&format!(
            "0::/system.slice/{BOT_SERVICE_UNIT}\n"
        )));
        assert!(!cgroup_contains_bot_service(&format!(
            "0::/system.slice/{BOT_SERVICE_UNIT}/child\n"
        )));
        assert!(!cgroup_contains_bot_service(&format!(
            "0::/user.slice/{BOT_SERVICE_UNIT}\n"
        )));
    }

    #[test]
    fn root_owned_non_writable_executable_is_required() {
        assert!(metadata_is_trusted(trusted_metadata()));
        assert!(!metadata_is_trusted(ExecutableMetadata {
            uid: 1000,
            ..trusted_metadata()
        }));
        assert!(!metadata_is_trusted(ExecutableMetadata {
            mode: 0o100775,
            ..trusted_metadata()
        }));
        assert!(!metadata_is_trusted(ExecutableMetadata {
            is_symlink: true,
            ..trusted_metadata()
        }));
    }

    #[test]
    fn pidfd_poll_reports_the_current_process_alive() {
        let pidfd = open_pidfd(std::process::id()).unwrap();

        pidfd_is_alive(pidfd.as_raw_fd()).unwrap();
    }
}

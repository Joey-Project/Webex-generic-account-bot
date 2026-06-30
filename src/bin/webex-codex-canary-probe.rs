#[cfg(target_os = "linux")]
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    net::{SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use ring::digest::{SHA256, digest};
#[cfg(target_os = "linux")]
use webex_generic_account_bot::{
    canary_protocol::{
        RUNTIME_CANARY_CHECKS, RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT,
        RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT, RUNTIME_CANARY_SUITE, RuntimeCanaryFixtureInputs,
        RuntimeCanaryReport, runtime_canary_codex_home_fixture_path,
        runtime_canary_credential_path, runtime_canary_fixture_binding,
        runtime_canary_main_home_fixture_path, runtime_canary_workspace_fixture_path,
        validate_runtime_canary_nonce,
    },
    codex_launcher::LAUNCHER_SOCKET_PATH,
};

#[cfg(target_os = "linux")]
const CONFIG_WORKER_SOCKET_PATH: &str = "/run/webex-config-pull/config-pull.sock";
#[cfg(target_os = "linux")]
const CREDENTIAL_ROOT: &str = "/run/credentials";
#[cfg(target_os = "linux")]
const MAIN_HOME: &str = "/tmp/webex-codex-main-home";
#[cfg(target_os = "linux")]
const CODEX_HOME: &str = "/tmp/webex-codex-main";
#[cfg(target_os = "linux")]
const CODEX_AUTH_PATH: &str = "/tmp/webex-codex-main/auth.json";
#[cfg(target_os = "linux")]
const FINAL_OUTPUT_PATH: &str = "/tmp/webex-codex-main/final-message.txt";
#[cfg(target_os = "linux")]
const TOOL_HOME: &str = "/tmp/webex-codex-tool-home";
#[cfg(target_os = "linux")]
const WORKSPACE_PATH: &str = "/workspace";
#[cfg(target_os = "linux")]
const NETWORK_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const FD_INSPECTION_LIMIT: usize = 256;
#[cfg(target_os = "linux")]
const FD_CONTENT_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const KCMP_FILE: libc::c_int = 0;

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
struct Cli {
    #[arg(value_parser = validate_suite)]
    suite: String,
    #[arg(long, value_parser = validate_nonce)]
    nonce: String,
    #[arg(long, value_parser = validate_main_pid)]
    main_pid: u32,
    #[arg(long, value_parser = validate_digest)]
    fd_secret_sha256: String,
    #[arg(long, value_parser = validate_loopback_address)]
    forbidden_tcp: SocketAddr,
    #[arg(long, value_parser = validate_loopback_address)]
    bot_tcp: SocketAddr,
    #[arg(long)]
    host_unix: PathBuf,
    #[arg(long)]
    host_protected_path: PathBuf,
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.forbidden_tcp == cli.bot_tcp {
        return Err(anyhow!("canary TCP endpoints must be distinct"));
    }
    validate_host_fixture_paths(&cli)?;
    let fixture_binding = fixture_binding(&cli)?;
    let report =
        RuntimeCanaryReport::new(cli.nonce.clone(), fixture_binding, collect_checks(&cli))?;
    use std::io::Write;
    std::io::stdout()
        .lock()
        .write_all(&report.to_json_line()?)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_checks(cli: &Cli) -> BTreeMap<String, bool> {
    let mut checks = BTreeMap::new();
    checks.insert(
        "bot_socket_denied".to_owned(),
        tcp_connection_denied(cli.bot_tcp),
    );
    checks.insert("capability_sets_empty".to_owned(), capability_sets_empty());
    checks.insert(
        "config_worker_socket_denied".to_owned(),
        unix_socket_denied(Path::new(CONFIG_WORKER_SOCKET_PATH)),
    );
    checks.insert(
        "credential_path_denied".to_owned(),
        credential_path_denied(&cli.nonce),
    );
    checks.insert(
        "final_output_denied".to_owned(),
        final_output_path_denied(Path::new(FINAL_OUTPUT_PATH)),
    );
    checks.insert(
        "forbidden_network_denied".to_owned(),
        tcp_connection_denied(cli.forbidden_tcp),
    );
    checks.insert(
        "host_protected_path_denied".to_owned(),
        file_access_denied(&cli.host_protected_path),
    );
    checks.insert(
        "host_unix_socket_denied".to_owned(),
        unix_socket_denied(&cli.host_unix),
    );
    checks.insert(
        "launcher_socket_denied".to_owned(),
        unix_socket_denied(Path::new(LAUNCHER_SOCKET_PATH)),
    );
    checks.insert("main_home_denied".to_owned(), main_home_denied(&cli.nonce));
    checks.insert(
        "main_process_inspection_denied".to_owned(),
        main_process_inspection_denied(cli.main_pid),
    );
    checks.insert("no_new_privileges".to_owned(), no_new_privileges());
    checks.insert(
        "privilege_escalation_denied".to_owned(),
        privilege_escalation_denied(),
    );
    checks.insert(
        "sensitive_descriptors_denied".to_owned(),
        sensitive_descriptors_denied(&cli.fd_secret_sha256),
    );
    checks.insert(
        "setid_and_file_capabilities_absent".to_owned(),
        setid_and_file_capabilities_absent(),
    );
    checks.insert(
        "tool_home_writable".to_owned(),
        tool_home_writable(&cli.nonce),
    );
    checks.insert(
        "workspace_read_only".to_owned(),
        workspace_read_only(&cli.nonce),
    );
    debug_assert_eq!(
        checks.keys().map(String::as_str).collect::<Vec<_>>(),
        RUNTIME_CANARY_CHECKS
    );
    checks
}

#[cfg(target_os = "linux")]
fn validate_suite(value: &str) -> std::result::Result<String, String> {
    (value == RUNTIME_CANARY_SUITE)
        .then(|| value.to_owned())
        .ok_or_else(|| "runtime canary suite is not supported".to_owned())
}

#[cfg(target_os = "linux")]
fn validate_nonce(value: &str) -> std::result::Result<String, String> {
    validate_runtime_canary_nonce(value)
        .map(|()| value.to_owned())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn validate_digest(value: &str) -> std::result::Result<String, String> {
    validate_nonce(value)
}

#[cfg(target_os = "linux")]
fn validate_main_pid(value: &str) -> std::result::Result<u32, String> {
    let pid = value
        .parse::<u32>()
        .map_err(|_| "main PID is invalid".to_owned())?;
    if !(2..=i32::MAX as u32).contains(&pid) {
        return Err("main PID must fit a positive Linux pid_t".to_owned());
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn validate_loopback_address(value: &str) -> std::result::Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "canary TCP endpoint is invalid".to_owned())?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("canary TCP endpoint must be a nonzero loopback address".to_owned());
    }
    Ok(address)
}

#[cfg(target_os = "linux")]
fn validate_host_fixture_paths(cli: &Cli) -> Result<()> {
    let expected_unix =
        Path::new(RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT).join(format!("{}.sock", cli.nonce));
    let expected_protected = Path::new(RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT).join(&cli.nonce);
    if cli.host_unix != expected_unix || cli.host_protected_path != expected_protected {
        return Err(anyhow!(
            "host canary fixture paths must be derived from the report nonce"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fixture_binding(cli: &Cli) -> Result<String> {
    let host_unix = cli
        .host_unix
        .to_str()
        .ok_or_else(|| anyhow!("host Unix fixture path must be UTF-8"))?;
    let host_protected_path = cli
        .host_protected_path
        .to_str()
        .ok_or_else(|| anyhow!("host protected fixture path must be UTF-8"))?;
    runtime_canary_fixture_binding(
        &cli.nonce,
        &RuntimeCanaryFixtureInputs {
            main_pid: cli.main_pid,
            fd_secret_sha256: cli.fd_secret_sha256.clone(),
            forbidden_tcp: cli.forbidden_tcp.to_string(),
            bot_tcp: cli.bot_tcp.to_string(),
            host_unix: host_unix.to_owned(),
            host_protected_path: host_protected_path.to_owned(),
        },
    )
}

#[cfg(target_os = "linux")]
fn path_denied(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::read_dir(path).is_err(),
        Ok(_) => File::open(path).is_err(),
        Err(error) => access_denial_error(&error),
    }
}

#[cfg(target_os = "linux")]
fn credential_path_denied(nonce: &str) -> bool {
    let Ok(path) = runtime_canary_credential_path(nonce) else {
        return false;
    };
    path_denied(Path::new(CREDENTIAL_ROOT)) && file_access_denied(Path::new(&path))
}

#[cfg(target_os = "linux")]
fn main_home_denied(nonce: &str) -> bool {
    let (Ok(main_fixture), Ok(codex_fixture)) = (
        runtime_canary_main_home_fixture_path(nonce),
        runtime_canary_codex_home_fixture_path(nonce),
    ) else {
        return false;
    };
    path_denied(Path::new(MAIN_HOME))
        && path_denied(Path::new(CODEX_HOME))
        && file_access_denied(Path::new(CODEX_AUTH_PATH))
        && file_access_denied(Path::new(&main_fixture))
        && file_access_denied(Path::new(&codex_fixture))
}

#[cfg(target_os = "linux")]
fn final_output_path_denied(path: &Path) -> bool {
    path_denied(path) && create_file_denied(path)
}

#[cfg(target_os = "linux")]
fn access_denial_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
    ) || matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EROFS))
}

#[cfg(target_os = "linux")]
fn unix_socket_denied(path: &Path) -> bool {
    // The child contains a blocking connect to a stale or backlog-saturated
    // socket. The parent always kills and reaps it at the fixed deadline.
    // SAFETY: the probe is single-threaded and the child exits without running
    // inherited Rust destructors.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        let denied = match UnixStream::connect(path) {
            Ok(_) => false,
            Err(error) => unix_connection_denial_error(&error),
        };
        // SAFETY: _exit terminates only the isolated connect child.
        unsafe { libc::_exit(i32::from(!denied)) };
    }
    match wait_child(child, NETWORK_TIMEOUT) {
        ChildWaitOutcome::Exited(0) => true,
        ChildWaitOutcome::Exited(_) | ChildWaitOutcome::TimedOut | ChildWaitOutcome::Failed => {
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn tcp_connection_denied(address: SocketAddr) -> bool {
    match TcpStream::connect_timeout(&address, NETWORK_TIMEOUT) {
        Ok(_) => false,
        Err(error) => tcp_connection_denial_error(&error),
    }
}

#[cfg(target_os = "linux")]
fn unix_connection_denial_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::ConnectionRefused
    ) || matches!(
        error.raw_os_error(),
        Some(libc::ENOENT) | Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ECONNREFUSED)
    )
}

#[cfg(target_os = "linux")]
fn tcp_connection_denial_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ConnectionRefused
    ) || matches!(
        error.raw_os_error(),
        Some(libc::EPERM)
            | Some(libc::EACCES)
            | Some(libc::ECONNREFUSED)
            | Some(libc::ENETUNREACH)
            | Some(libc::EHOSTUNREACH)
    )
}

#[cfg(target_os = "linux")]
fn proc_status() -> Option<String> {
    fs::read_to_string("/proc/self/status").ok()
}

#[cfg(target_os = "linux")]
fn no_new_privileges() -> bool {
    proc_status().is_some_and(|status| status.lines().any(|line| line == "NoNewPrivs:\t1"))
}

#[cfg(target_os = "linux")]
fn capability_sets_empty() -> bool {
    let Some(status) = proc_status() else {
        return false;
    };
    ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|name| {
            status.lines().any(|line| {
                line.strip_prefix(name)
                    .is_some_and(|value| value.trim().bytes().all(|byte| byte == b'0'))
            })
        })
}

#[cfg(target_os = "linux")]
fn privilege_escalation_denied() -> bool {
    // The child contains any identity change if the boundary is unexpectedly weak.
    // SAFETY: the probe is single-threaded and the child calls only libc syscalls
    // before _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        // SAFETY: these identity syscalls have no pointer arguments.
        let original_uid = unsafe { libc::geteuid() };
        // SAFETY: these identity syscalls have no pointer arguments.
        let original_gid = unsafe { libc::getegid() };
        // SAFETY: setgid and setuid take only numeric IDs.
        let denied = original_uid != 0
            && original_gid != 0
            && unsafe { libc::setgid(0) } != 0
            && unsafe { libc::setuid(0) } != 0
            && unsafe { libc::geteuid() } == original_uid
            && unsafe { libc::getegid() } == original_gid;
        // SAFETY: _exit terminates the isolated child without running inherited
        // Rust destructors or flushing buffered output.
        unsafe { libc::_exit(i32::from(!denied)) };
    }
    check_child_succeeded(child)
}

#[cfg(target_os = "linux")]
fn main_process_inspection_denied(pid: u32) -> bool {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let file_boundaries = ["mem", "environ"]
        .iter()
        .all(|name| path_denied(&root.join(name)));
    let fd_boundary = fs::read_dir(root.join("fd")).is_err();

    let ptrace_denied = ptrace_seize_denied(pid);
    // SAFETY: kcmp receives only process and descriptor numbers.
    let kcmp_denied =
        unsafe { libc::syscall(libc::SYS_kcmp, std::process::id(), pid, KCMP_FILE, 0, 0) } == -1
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM) | Some(libc::EACCES)
            );
    file_boundaries && fd_boundary && ptrace_denied && kcmp_denied && process_vm_access_denied(pid)
}

#[cfg(target_os = "linux")]
fn process_vm_access_denied(pid: u32) -> bool {
    process_vm_operation_denied(pid, false) && process_vm_operation_denied(pid, true)
}

#[cfg(target_os = "linux")]
fn process_vm_operation_denied(pid: u32, write: bool) -> bool {
    let mut local_byte = 0_u8;
    let local = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(local_byte).cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: std::ptr::dangling_mut::<libc::c_void>(),
        iov_len: 1,
    };
    // SAFETY: both iovec arrays are live for the syscall. The dangling remote
    // pointer makes an unexpectedly permitted operation fail with EFAULT
    // without touching useful target memory.
    let result = unsafe {
        if write {
            libc::process_vm_writev(pid as libc::pid_t, &local, 1, &remote, 1, 0)
        } else {
            libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0)
        }
    };
    syscall_permission_denied(result, std::io::Error::last_os_error().raw_os_error())
}

#[cfg(target_os = "linux")]
fn syscall_permission_denied(result: isize, error: Option<i32>) -> bool {
    result == -1 && matches!(error, Some(libc::EPERM) | Some(libc::EACCES))
}

#[cfg(target_os = "linux")]
fn ptrace_seize_denied(pid: u32) -> bool {
    // PTRACE_SEIZE does not stop the target. A successful, unexpected attachment
    // is confined to the child and is released automatically when it exits.
    // SAFETY: the probe is single-threaded and the child calls only libc syscalls
    // before _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        // SAFETY: ptrace is called without userspace pointers.
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                pid as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let denied = if result == 0 {
            false
        } else {
            // SAFETY: Linux libc exposes the calling thread's live errno pointer.
            matches!(
                unsafe { *libc::__errno_location() },
                libc::EPERM | libc::EACCES
            )
        };
        // SAFETY: _exit also drops any unexpected ptrace relationship owned by
        // this isolated child.
        unsafe { libc::_exit(i32::from(!denied)) };
    }
    check_child_succeeded(child)
}

#[cfg(target_os = "linux")]
fn check_child_succeeded(child: libc::pid_t) -> bool {
    let mut status = 0;
    loop {
        // SAFETY: child is a PID returned by fork and status is a live out-pointer.
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result == child {
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return false;
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum ChildWaitOutcome {
    Exited(i32),
    TimedOut,
    Failed,
}

#[cfg(target_os = "linux")]
fn wait_child(child: libc::pid_t, timeout: Duration) -> ChildWaitOutcome {
    let deadline = Instant::now() + timeout;
    let mut status = 0;
    loop {
        // SAFETY: child is a PID returned by fork, WNOHANG is nonblocking, and
        // status is a live out-pointer.
        let result = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if result == child {
            return if libc::WIFEXITED(status) {
                ChildWaitOutcome::Exited(libc::WEXITSTATUS(status))
            } else {
                ChildWaitOutcome::Failed
            };
        }
        if result < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return ChildWaitOutcome::Failed;
        }
        if Instant::now() >= deadline {
            // SAFETY: child is the still-running PID returned by fork.
            if unsafe { libc::kill(child, libc::SIGKILL) } != 0 {
                return ChildWaitOutcome::Failed;
            }
            let reaped = loop {
                // SAFETY: reap the same child after the kill attempt.
                let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
                if reaped == child {
                    break true;
                }
                if reaped < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                    continue;
                }
                break false;
            };
            return if reaped {
                ChildWaitOutcome::TimedOut
            } else {
                ChildWaitOutcome::Failed
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn sensitive_descriptors_denied(expected_digest: &str) -> bool {
    if !standard_input_sanitized(expected_digest) {
        return false;
    }
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return false;
    };
    let self_fd_directory = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let mut inspected = 0_usize;
    let mut targets = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        inspected += 1;
        if inspected > FD_INSPECTION_LIMIT {
            return false;
        }
        let path = entry.path();
        let Ok(target) = fs::read_link(&path) else {
            return false;
        };
        if open_fd_digest(&path).as_deref() == Some(expected_digest) {
            return false;
        }
        targets.push(target);
    }
    descriptor_targets_are_only_the_scan(&targets, &self_fd_directory)
}

#[cfg(target_os = "linux")]
fn descriptor_targets_are_only_the_scan(targets: &[PathBuf], self_fd_directory: &Path) -> bool {
    targets.len() == 1 && targets[0] == self_fd_directory
}

#[cfg(target_os = "linux")]
fn standard_input_sanitized(expected_digest: &str) -> bool {
    let path = Path::new("/proc/self/fd/0");
    let target = match fs::read_link(path) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !standard_input_target_allowed(&target) {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.file_type().is_char_device()
        && open_fd_digest(path).as_deref() != Some(expected_digest)
}

#[cfg(target_os = "linux")]
fn standard_input_target_allowed(target: &Path) -> bool {
    target == Path::new("/dev/null")
}

#[cfg(target_os = "linux")]
fn open_fd_digest(path: &Path) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(FD_CONTENT_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > FD_CONTENT_MAX_BYTES {
        return None;
    }
    Some(hex(digest(&SHA256, &bytes).as_ref()))
}

#[cfg(target_os = "linux")]
fn setid_and_file_capabilities_absent() -> bool {
    ["/bin/busybox", "/bin/webex-codex-canary-probe"]
        .iter()
        .all(|path| trusted_unprivileged_executable(Path::new(path)))
}

#[cfg(target_os = "linux")]
fn trusted_unprivileged_executable(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    metadata.is_file()
        && metadata.mode() & 0o6000 == 0
        && xattr_absent(&file, b"security.capability\0")
}

#[cfg(target_os = "linux")]
fn xattr_absent(file: &File, name: &[u8]) -> bool {
    // SAFETY: name is a fixed NUL-terminated byte string and the descriptor is live.
    let result = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    result < 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA) | Some(libc::ENOTSUP)
        )
}

#[cfg(target_os = "linux")]
fn tool_home_writable(nonce: &str) -> bool {
    if env::var_os("HOME").as_deref() != Some(std::ffi::OsStr::new(TOOL_HOME)) {
        return false;
    }
    let path = Path::new(TOOL_HOME).join(format!("canary-{nonce}"));
    let result = (|| -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(nonce.as_bytes())?;
        file.sync_all()?;
        let contents = fs::read_to_string(&path)?;
        if contents != nonce {
            return Err(anyhow!("tool-home canary contents changed"));
        }
        Ok(())
    })();
    let cleanup = fs::remove_file(path);
    result.is_ok() && cleanup.is_ok()
}

#[cfg(target_os = "linux")]
fn workspace_read_only(nonce: &str) -> bool {
    if fs::read_dir(WORKSPACE_PATH).is_err() {
        return false;
    }
    let Ok(fixture) = runtime_canary_workspace_fixture_path(nonce) else {
        return false;
    };
    let fixture = Path::new(&fixture);
    let Some(parent) = fixture.parent() else {
        return false;
    };
    if !fs::read(fixture).is_ok_and(|contents| contents == nonce.as_bytes()) {
        return false;
    }
    write_open_denied(fixture)
        && create_file_denied(&Path::new(WORKSPACE_PATH).join(format!("canary-write-{nonce}")))
        && create_file_denied(&parent.join(format!("canary-nested-write-{nonce}")))
}

#[cfg(target_os = "linux")]
fn write_open_denied(path: &Path) -> bool {
    match OpenOptions::new().write(true).open(path) {
        Ok(_) => false,
        Err(error) => write_denial_error(&error),
    }
}

#[cfg(target_os = "linux")]
fn file_access_denied(path: &Path) -> bool {
    path_denied(path) && write_open_denied(path)
}

#[cfg(target_os = "linux")]
fn create_file_denied(path: &Path) -> bool {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {
            let _ = fs::remove_file(path);
            false
        }
        Err(error) => write_denial_error(&error),
    }
}

#[cfg(target_os = "linux")]
fn write_denial_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    ) || matches!(
        error.raw_os_error(),
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS)
    )
}

#[cfg(target_os = "linux")]
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Err(anyhow!("the Codex canary probe is supported only on Linux"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn cli_accepts_only_the_fixed_suite_and_loopback_endpoints() {
        let cli = Cli::try_parse_from([
            "probe",
            RUNTIME_CANARY_SUITE,
            "--nonce",
            NONCE,
            "--main-pid",
            "42",
            "--fd-secret-sha256",
            NONCE,
            "--forbidden-tcp",
            "127.0.0.1:41001",
            "--bot-tcp",
            "127.0.0.1:41002",
            "--host-unix",
            "/run/webex-codex-canary/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sock",
            "--host-protected-path",
            "/var/lib/webex-generic-account-bot/canary-fixtures/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ])
        .unwrap();
        assert_eq!(cli.suite, RUNTIME_CANARY_SUITE);
        validate_host_fixture_paths(&cli).unwrap();
        assert_eq!(fixture_binding(&cli).unwrap().len(), 64);
        let mut mismatched = cli;
        mismatched.host_unix = PathBuf::from("/run/webex-codex-canary/other.sock");
        assert!(validate_host_fixture_paths(&mismatched).is_err());
        assert!(validate_loopback_address("0.0.0.0:1").is_err());
        assert!(validate_loopback_address("127.0.0.1:0").is_err());
        assert!(validate_suite("other").is_err());
        assert!(validate_digest("A").is_err());
        assert!(validate_main_pid("1").is_err());
        assert!(validate_main_pid("2147483648").is_err());
        assert!(unix_connection_denial_error(
            &std::io::Error::from_raw_os_error(libc::ENOENT)
        ));
        assert!(tcp_connection_denial_error(
            &std::io::Error::from_raw_os_error(libc::ENETUNREACH)
        ));
        assert!(!tcp_connection_denial_error(
            &std::io::Error::from_raw_os_error(libc::ETIMEDOUT)
        ));
        assert!(!tcp_connection_denial_error(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "inconclusive timeout"
        )));
        assert!(!unix_connection_denial_error(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
        assert!(!tcp_connection_denial_error(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
    }

    #[test]
    fn path_probe_distinguishes_existing_and_missing_paths() {
        let missing = std::env::temp_dir().join(format!(
            "webex-canary-missing-{}-{NONCE}",
            std::process::id()
        ));
        assert!(path_denied(&missing));
        assert!(!final_output_path_denied(&missing));
        assert!(!missing.exists());
        assert!(!path_denied(Path::new("/proc/self/status")));
    }

    #[test]
    fn report_uses_the_exact_contract_keys() {
        let checks = RUNTIME_CANARY_CHECKS
            .iter()
            .map(|name| ((*name).to_owned(), false))
            .collect();
        RuntimeCanaryReport::new(NONCE.to_owned(), "1".repeat(64), checks).unwrap();
    }

    #[test]
    fn descriptor_probe_rejects_non_null_stdin_and_unexpected_descriptors() {
        let self_fd_directory = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
        assert!(standard_input_target_allowed(Path::new("/dev/null")));
        assert!(!standard_input_target_allowed(Path::new("pipe:[123]")));
        assert!(descriptor_targets_are_only_the_scan(
            std::slice::from_ref(&self_fd_directory),
            &self_fd_directory
        ));
        assert!(!descriptor_targets_are_only_the_scan(
            &[self_fd_directory.clone(), self_fd_directory.clone()],
            &self_fd_directory
        ));
        assert!(!descriptor_targets_are_only_the_scan(
            &[self_fd_directory, PathBuf::from("socket:[123]")],
            Path::new(&format!("/proc/{}/fd", std::process::id()))
        ));

        let mut pipe_fds = [-1; 2];
        // SAFETY: pipe_fds is a live two-element out-buffer and the returned
        // descriptors are closed below.
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert!(!sensitive_descriptors_denied(NONCE));
        for fd in pipe_fds {
            // SAFETY: each descriptor was returned by the successful pipe2 call.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }

        let (_left, _right) = UnixStream::pair().unwrap();
        assert!(!sensitive_descriptors_denied(NONCE));
    }

    #[test]
    fn process_vm_probe_accepts_only_explicit_permission_denial() {
        assert!(syscall_permission_denied(-1, Some(libc::EPERM)));
        assert!(syscall_permission_denied(-1, Some(libc::EACCES)));
        assert!(!syscall_permission_denied(-1, Some(libc::EFAULT)));
        assert!(!syscall_permission_denied(-1, Some(libc::ESRCH)));
        assert!(!syscall_permission_denied(0, None));
    }

    #[test]
    fn child_wait_enforces_its_deadline_and_reaps() {
        // SAFETY: the child calls only pause and _exit; the parent reaps it in
        // wait_child.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            loop {
                // SAFETY: pause has no pointer arguments and the timeout path
                // terminates this child with SIGKILL.
                unsafe { libc::pause() };
            }
        }
        assert_eq!(
            wait_child(child, Duration::from_millis(20)),
            ChildWaitOutcome::TimedOut
        );

        // SAFETY: this child exits immediately with a fixed status and is reaped.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: terminate only this isolated test child.
            unsafe { libc::_exit(7) };
        }
        assert_eq!(
            wait_child(child, Duration::from_secs(1)),
            ChildWaitOutcome::Exited(7)
        );

        // SAFETY: this child waits for the parent to terminate and reap it.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            loop {
                // SAFETY: pause has no pointer arguments.
                unsafe { libc::pause() };
            }
        }
        // SAFETY: signal only this isolated test child.
        assert_eq!(unsafe { libc::kill(child, libc::SIGTERM) }, 0);
        assert_eq!(
            wait_child(child, Duration::from_secs(1)),
            ChildWaitOutcome::Failed
        );
    }
}

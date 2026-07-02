#[cfg(target_os = "linux")]
use std::{
    env,
    fs::{self, File},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::fs::MetadataExt,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, anyhow};

#[cfg(target_os = "linux")]
const NODE_FD_PATH: &str = "/proc/self/fd/3";
#[cfg(target_os = "linux")]
const NODE_FD: RawFd = 3;
#[cfg(target_os = "linux")]
const SOURCE_ROOT: &str = "/opt/webex-generic-account-bot/code/deploy/systemd";
#[cfg(target_os = "linux")]
const DEPLOYMENT_LOCK_FD: RawFd = 6;
#[cfg(target_os = "linux")]
const DEPLOYMENT_LOCK_PATH: &str = "/run/webex-config-deploy/deploy-config.lock";
#[cfg(target_os = "linux")]
const PARENT_PID_ENV: &str = "WEBEX_HOST_IDENTITY_LOCK_PARENT_PID";
#[cfg(target_os = "linux")]
const IDENTITY_LOCK_PATH: &str = "/etc/.pwd.lock";
#[cfg(target_os = "linux")]
const MAX_AUDITED_FDS: usize = 1024;
#[cfg(target_os = "linux")]
const FILE_CAPABILITY_XATTR: &[u8] = b"security.capability\0";
#[cfg(target_os = "linux")]
const IDENTITY_RECOVERY_BOOTSTRAP: &str = concat!(
    "const { readFileSync } = await import(\"node:fs\"); ",
    "const source = readFileSync(5).toString(\"base64\"); ",
    "const { runIdentityRecoveryChild } = await import(\"data:text/javascript;base64,\" + source); ",
    "process.exitCode = await runIdentityRecoveryChild();"
);

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn lckpwdf() -> libc::c_int;
    fn ulckpwdf() -> libc::c_int;
}

#[cfg(target_os = "linux")]
struct PasswordDatabaseLock {
    _fd: RawFd,
}

#[cfg(target_os = "linux")]
struct DeploymentLock {
    _file: File,
}

#[cfg(target_os = "linux")]
impl DeploymentLock {
    fn acquire() -> Result<Self> {
        Self::acquire_from(DEPLOYMENT_LOCK_FD, Path::new(DEPLOYMENT_LOCK_PATH), 0)
    }

    fn acquire_from(fd: RawFd, path: &Path, required_uid: u32) -> Result<Self> {
        // SAFETY: fcntl duplicates the inherited descriptor into an owned File.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 7) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to duplicate the inherited host provision lock");
        }
        // SAFETY: duplicate is a new descriptor owned by this File.
        let file = unsafe { File::from_raw_fd(duplicate) };
        let fd_metadata = file
            .metadata()
            .context("failed to inspect the inherited host provision lock")?;
        let path_metadata =
            fs::symlink_metadata(path).context("failed to inspect the host provision lock path")?;
        if !fd_metadata.is_file()
            || !path_metadata.is_file()
            || path_metadata.file_type().is_symlink()
            || fd_metadata.dev() != path_metadata.dev()
            || fd_metadata.ino() != path_metadata.ino()
            || fd_metadata.uid() != required_uid
            || fd_metadata.nlink() != 1
            || !matches!(fd_metadata.mode() & 0o7777, 0o600 | 0o660)
        {
            return Err(anyhow!("inherited host provision lock is not trusted"));
        }
        // This succeeds only for the same locked open-file-description. If the
        // descriptor was unexpectedly unlocked, it acquires the lock before
        // any identity inspection or mutation can begin.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("inherited host provision descriptor does not own the lock");
        }
        Ok(Self { _file: file })
    }
}

#[cfg(target_os = "linux")]
impl PasswordDatabaseLock {
    fn acquire() -> Result<Self> {
        // SAFETY: lckpwdf has no arguments and the process holds the lock until
        // this guard calls the matching libc release function.
        if unsafe { lckpwdf() } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to acquire the system identity database lock");
        }
        match retain_lock_descriptor_across_exec(Path::new(IDENTITY_LOCK_PATH), 0, 0) {
            Ok(fd) => Ok(Self { _fd: fd }),
            Err(error) => {
                unsafe {
                    ulckpwdf();
                }
                Err(error).context("failed to retain the system identity database lock")
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn retain_lock_descriptor_across_exec(
    path: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Result<RawFd> {
    let expected = fs::symlink_metadata(path).context("failed to inspect the lock path")?;
    if !expected.is_file()
        || expected.file_type().is_symlink()
        || expected.uid() != required_uid
        || expected.gid() != required_gid
        || expected.nlink() != 1
        || (expected.mode() & 0o077) != 0
    {
        return Err(anyhow!("lock path metadata is not trusted"));
    }
    let entries = fs::read_dir("/proc/self/fd").context("failed to inspect process descriptors")?;
    let mut matches = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_AUDITED_FDS {
            return Err(anyhow!(
                "process file descriptor table exceeds the audit limit"
            ));
        }
        let entry = entry.context("failed to inspect a process descriptor")?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<RawFd>().ok())
        else {
            continue;
        };
        if fd < 3 {
            continue;
        }
        let metadata = match fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("failed to inspect a process descriptor"),
        };
        if metadata.dev() == expected.dev() && metadata.ino() == expected.ino() {
            matches.push(fd);
        }
    }
    let [fd] = matches.as_slice() else {
        return Err(anyhow!("identity lock descriptor is missing or ambiguous"));
    };
    let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect identity lock descriptor flags");
    }
    if unsafe { libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to retain identity lock descriptor across exec");
    }
    Ok(*fd)
}

#[cfg(target_os = "linux")]
fn assert_no_file_capabilities(fd: RawFd) -> Result<()> {
    assert_xattr_absent(
        fd,
        FILE_CAPABILITY_XATTR,
        "Node executable has file capabilities that would clear the parent-death signal",
        "failed to inspect Node executable file capabilities",
    )
}

#[cfg(target_os = "linux")]
fn assert_xattr_absent(
    fd: RawFd,
    name: &[u8],
    present_error: &str,
    inspect_error: &str,
) -> Result<()> {
    if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return Err(anyhow!("invalid extended attribute name"));
    }
    // SAFETY: the name is a validated NUL-terminated byte string, fd is the
    // inspected executable, and a null value pointer requests only the size.
    let size = unsafe { libc::fgetxattr(fd, name.as_ptr().cast(), std::ptr::null_mut(), 0) };
    let error = (size < 0).then(|| std::io::Error::last_os_error().raw_os_error());
    assert_xattr_probe_absent(size, error.flatten(), present_error, inspect_error)
}

#[cfg(target_os = "linux")]
fn assert_xattr_probe_absent(
    size: libc::ssize_t,
    error: Option<libc::c_int>,
    present_error: &str,
    inspect_error: &str,
) -> Result<()> {
    if size >= 0 {
        return Err(anyhow!(present_error.to_owned()));
    }
    if error == Some(libc::ENODATA) {
        return Ok(());
    }
    Err(std::io::Error::from_raw_os_error(
        error.unwrap_or(libc::EIO),
    ))
    .context(inspect_error.to_owned())
}

#[cfg(target_os = "linux")]
impl Drop for PasswordDatabaseLock {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after a successful lckpwdf call.
        unsafe {
            ulckpwdf();
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<i32> {
    if env::args_os().len() != 1 {
        return Err(anyhow!("identity recovery helper accepts no arguments"));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("identity recovery helper requires root"));
    }
    let expected_parent = expected_parent_pid()?;
    arm_parent_death_signal(expected_parent)?;
    let _deployment_lock = DeploymentLock::acquire()?;
    let _lock = PasswordDatabaseLock::acquire()?;
    let lock_holder_pid = unsafe { libc::getpid() };
    let mut command = Command::new(NODE_FD_PATH);
    command
        .arg0("/usr/bin/node")
        .args([
            "--input-type=module",
            "--eval",
            IDENTITY_RECOVERY_BOOTSTRAP,
            "--",
        ])
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("WEBEX_HOST_PROVISION_LOCKED", "1")
        .env("WEBEX_HOST_PROVISION_PRIVATE_MOUNT_NS", "1")
        .env("WEBEX_HOST_PROVISION_SOURCE_ROOT", SOURCE_ROOT)
        .env("WEBEX_HOST_IDENTITY_RECOVERY_CHILD", "1")
        .env("WEBEX_HOST_IDENTITY_LOCK_PID", lock_holder_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    assert_no_file_capabilities(NODE_FD)?;
    let error = command.exec();
    Err(error).context("failed to exec the identity recovery process")
}

#[cfg(target_os = "linux")]
fn expected_parent_pid() -> Result<libc::pid_t> {
    let value = env::var(PARENT_PID_ENV).context("identity lock parent PID is missing")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(anyhow!("identity lock parent PID is invalid"));
    }
    let pid = value
        .parse::<libc::pid_t>()
        .context("identity lock parent PID is invalid")?;
    if pid <= 1 {
        return Err(anyhow!("identity lock parent PID is invalid"));
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn arm_parent_death_signal(expected_parent: libc::pid_t) -> Result<()> {
    // SAFETY: prctl and getppid have no pointer arguments here. Checking PPID
    // after arming closes the race where the parent exits before prctl.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to bind the identity recovery process to its parent");
        }
        if libc::getppid() != expected_parent {
            return Err(anyhow!(
                "host provisioner exited before identity lock supervision"
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("identity recovery process requires Linux");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const EXEC_LOCK_STAGE_ENV: &str = "WEBEX_TEST_IDENTITY_LOCK_EXEC_STAGE";
    const EXEC_LOCK_PATH_ENV: &str = "WEBEX_TEST_IDENTITY_LOCK_EXEC_PATH";
    const EXEC_LOCK_FD_ENV: &str = "WEBEX_TEST_IDENTITY_LOCK_EXEC_FD";
    const EXEC_LOCK_TEST_EXE_ENV: &str = "WEBEX_TEST_IDENTITY_LOCK_TEST_EXE";
    const NODE_LOCK_VERIFIER: &str = concat!(
        "const fs = require('node:fs'); ",
        "const { spawnSync } = require('node:child_process'); ",
        "fs.fstatSync(Number(process.env.WEBEX_TEST_IDENTITY_LOCK_EXEC_FD)); ",
        "const env = { ...process.env, WEBEX_TEST_IDENTITY_LOCK_EXEC_STAGE: 'contend' }; ",
        "const result = spawnSync(process.env.WEBEX_TEST_IDENTITY_LOCK_TEST_EXE, ",
        "['--exact', 'tests::password_lock_descriptor_survives_exec', '--nocapture'], ",
        "{ env, stdio: 'inherit' }); ",
        "process.exit(result.status ?? 1);"
    );

    #[test]
    fn child_contract_is_fixed_and_fd_bound() {
        assert_eq!(NODE_FD_PATH, "/proc/self/fd/3");
        assert_eq!(NODE_FD, 3);
        assert_eq!(DEPLOYMENT_LOCK_FD, 6);
        assert_eq!(
            SOURCE_ROOT,
            "/opt/webex-generic-account-bot/code/deploy/systemd"
        );
        assert!(IDENTITY_RECOVERY_BOOTSTRAP.contains("readFileSync(5)"));
        assert!(IDENTITY_RECOVERY_BOOTSTRAP.contains("runIdentityRecoveryChild"));
        assert!(!IDENTITY_RECOVERY_BOOTSTRAP.contains("runCli"));
    }

    #[test]
    fn node_exec_rejects_file_capability_transitions() {
        let executable = File::open(env::current_exe().expect("resolve test executable"))
            .expect("open test executable");
        assert_no_file_capabilities(executable.as_raw_fd())
            .expect("ordinary test executable has no file capabilities");

        let present = assert_xattr_probe_absent(
            20,
            None,
            "test executable capability is present",
            "failed to inspect test executable capability",
        )
        .expect_err("reject present executable capability");
        assert!(present.to_string().contains("capability is present"));
        let unreadable = assert_xattr_probe_absent(
            -1,
            Some(libc::EIO),
            "test executable capability is present",
            "failed to inspect test executable capability",
        )
        .expect_err("fail closed when capability state cannot be inspected");
        assert!(
            unreadable
                .to_string()
                .contains("failed to inspect test executable capability")
        );
    }

    #[test]
    fn inherited_deployment_lock_retains_the_same_open_file_description() {
        let path = env::temp_dir().join(format!(
            "webex-host-identity-lock-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create test lock");
        // SAFETY: original is a valid open descriptor.
        assert_eq!(
            unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        let retained =
            DeploymentLock::acquire_from(original.as_raw_fd(), &path, unsafe { libc::geteuid() })
                .expect("retain inherited lock");
        drop(original);

        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open contender");
        // SAFETY: contender is a valid open descriptor.
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1,
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        assert!(retained._file.metadata().is_ok());
        drop(retained);
        // SAFETY: contender remains valid and the retained OFD is now closed.
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
        );
        drop(contender);
        fs::remove_file(path).expect("remove test lock");
    }

    #[test]
    fn password_lock_descriptor_survives_exec() {
        if let Ok(stage) = env::var(EXEC_LOCK_STAGE_ENV) {
            run_exec_lock_stage(&stage);
            return;
        }
        let path = env::temp_dir().join(format!(
            "webex-password-lock-exec-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::write(&path, []).expect("create exec lock test file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set exec lock test mode");
        let status = Command::new(env::current_exe().expect("resolve test executable"))
            .args([
                "--exact",
                "tests::password_lock_descriptor_survives_exec",
                "--nocapture",
            ])
            .env(EXEC_LOCK_STAGE_ENV, "acquire")
            .env(EXEC_LOCK_PATH_ENV, &path)
            .status()
            .expect("start exec lock test process");
        assert!(status.success(), "exec lock test process failed: {status}");
        fs::remove_file(path).expect("remove exec lock test file");
    }

    #[test]
    fn parent_death_signal_rejects_the_wrong_parent() {
        let wrong_parent = unsafe { libc::getppid() }.saturating_add(1);
        let error = arm_parent_death_signal(wrong_parent).expect_err("reject wrong parent");
        assert!(
            error
                .to_string()
                .contains("exited before identity lock supervision")
        );
        // SAFETY: clear the test process setting before returning to the harness.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) }, 0);
    }

    #[test]
    fn parent_death_signal_kills_an_orphaned_recovery_process() {
        let ready = create_pipe();
        let worker_pid = create_pipe();
        let release = create_pipe();
        // SAFETY: each child uses only async-signal-safe libc operations before
        // exiting; the parent remains responsible for assertions and cleanup.
        let intermediate = unsafe { libc::fork() };
        assert!(intermediate >= 0, "fork intermediate process");
        if intermediate == 0 {
            close_fd(worker_pid[0]);
            close_fd(release[1]);
            let worker = unsafe { libc::fork() };
            if worker < 0 {
                unsafe { libc::_exit(20) };
            }
            if worker == 0 {
                close_fd(ready[0]);
                close_fd(worker_pid[1]);
                close_fd(release[0]);
                let parent = unsafe { libc::getppid() };
                if arm_parent_death_signal(parent).is_err() || write_all(ready[1], &[1_u8]).is_err()
                {
                    unsafe { libc::_exit(21) };
                }
                loop {
                    unsafe { libc::pause() };
                }
            }
            close_fd(ready[1]);
            if read_exact(ready[0], 1).is_err()
                || write_all(worker_pid[1], &worker.to_ne_bytes()).is_err()
                || read_exact(release[0], 1).is_err()
            {
                unsafe { libc::_exit(22) };
            }
            unsafe { libc::_exit(0) };
        }

        close_fd(ready[0]);
        close_fd(ready[1]);
        close_fd(worker_pid[1]);
        close_fd(release[0]);
        let pid_bytes =
            read_exact(worker_pid[0], std::mem::size_of::<libc::pid_t>()).expect("read worker PID");
        let orphan_pid = libc::pid_t::from_ne_bytes(pid_bytes.try_into().expect("PID byte width"));
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, orphan_pid, 0) as RawFd };
        assert!(
            pidfd >= 0,
            "open worker pidfd: {}",
            std::io::Error::last_os_error()
        );
        write_all(release[1], &[1_u8]).expect("release intermediate process");
        close_fd(release[1]);

        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(intermediate, &mut status, 0) },
            intermediate
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        let mut descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 3_000) }, 1);
        assert_ne!(descriptor.revents & libc::POLLIN, 0);
        close_fd(pidfd);
        close_fd(worker_pid[0]);
    }

    fn run_exec_lock_stage(stage: &str) {
        let path = std::path::PathBuf::from(
            env::var_os(EXEC_LOCK_PATH_ENV).expect("exec lock path is present"),
        );
        match stage {
            "acquire" => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .expect("open exec lock test file");
                assert_eq!(set_posix_write_lock(file.as_raw_fd()), 0);
                let fd =
                    retain_lock_descriptor_across_exec(&path, unsafe { libc::geteuid() }, unsafe {
                        libc::getegid()
                    })
                    .expect("retain POSIX lock descriptor");
                assert_eq!(fd, file.as_raw_fd());
                let mut command = Command::new("node");
                command
                    .args(["-e", NODE_LOCK_VERIFIER])
                    .env(EXEC_LOCK_PATH_ENV, &path)
                    .env(EXEC_LOCK_FD_ENV, fd.to_string())
                    .env(
                        EXEC_LOCK_TEST_EXE_ENV,
                        env::current_exe().expect("resolve test executable"),
                    );
                let error = command.exec();
                panic!("failed to exec Node lock verifier: {error}");
            }
            "contend" => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .expect("open competing lock descriptor");
                assert_eq!(set_posix_write_lock(file.as_raw_fd()), -1);
                assert!(matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EACCES) | Some(libc::EAGAIN)
                ));
            }
            _ => panic!("unexpected exec lock stage: {stage}"),
        }
    }

    fn set_posix_write_lock(fd: RawFd) -> libc::c_int {
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as libc::c_short;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) }
    }

    fn create_pipe() -> [RawFd; 2] {
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        descriptors
    }

    fn close_fd(fd: RawFd) {
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }

    fn write_all(fd: RawFd, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if written < 0 {
                return Err(std::io::Error::last_os_error());
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }

    fn read_exact(fd: RawFd, size: usize) -> std::io::Result<Vec<u8>> {
        let mut bytes = vec![0_u8; size];
        let mut offset = 0;
        while offset < size {
            let read =
                unsafe { libc::read(fd, bytes[offset..].as_mut_ptr().cast(), size - offset) };
            if read <= 0 {
                return Err(if read == 0 {
                    std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
                } else {
                    std::io::Error::last_os_error()
                });
            }
            offset += read as usize;
        }
        Ok(bytes)
    }
}

#[cfg(target_os = "linux")]
use std::{
    env,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, anyhow};

#[cfg(target_os = "linux")]
const NODE_FD_PATH: &str = "/proc/self/fd/3";
#[cfg(target_os = "linux")]
const SOURCE_ROOT: &str = "/opt/webex-generic-account-bot/code/deploy/systemd";
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
struct PasswordDatabaseLock;

#[cfg(target_os = "linux")]
impl PasswordDatabaseLock {
    fn acquire() -> Result<Self> {
        // SAFETY: lckpwdf has no arguments and the process holds the lock until
        // this guard calls the matching libc release function.
        if unsafe { lckpwdf() } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to acquire the system identity database lock");
        }
        Ok(Self)
    }
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
        return Err(anyhow!("identity lock supervisor accepts no arguments"));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("identity lock supervisor requires root"));
    }
    let _lock = PasswordDatabaseLock::acquire()?;
    let supervisor_pid = unsafe { libc::getpid() };
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
        .env("WEBEX_HOST_IDENTITY_LOCK_PID", supervisor_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: pre_exec performs only async-signal-safe libc calls and creates
    // no allocations. The parent PID check closes the parent-death race.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != supervisor_pid {
                return Err(std::io::Error::other(
                    "identity lock supervisor exited before child setup",
                ));
            }
            Ok(())
        });
    }
    let status = command
        .status()
        .context("failed to start the identity recovery child")?;
    status
        .code()
        .ok_or_else(|| anyhow!("identity recovery child terminated by signal"))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("identity lock supervisor requires Linux");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn child_contract_is_fixed_and_fd_bound() {
        assert_eq!(NODE_FD_PATH, "/proc/self/fd/3");
        assert_eq!(
            SOURCE_ROOT,
            "/opt/webex-generic-account-bot/code/deploy/systemd"
        );
        assert!(IDENTITY_RECOVERY_BOOTSTRAP.contains("readFileSync(5)"));
        assert!(IDENTITY_RECOVERY_BOOTSTRAP.contains("runIdentityRecoveryChild"));
        assert!(!IDENTITY_RECOVERY_BOOTSTRAP.contains("runCli"));
    }
}

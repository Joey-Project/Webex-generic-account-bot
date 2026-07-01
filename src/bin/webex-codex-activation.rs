#[cfg(target_os = "linux")]
use std::{fs, os::unix::fs::MetadataExt, path::Path};

use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use clap::{Parser, Subcommand};

#[cfg(target_os = "linux")]
const ACTIVATION_HELPER_PATH: &str = "/opt/webex-generic-account-bot/bin/webex-codex-activation";

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Subcommand)]
enum Command {
    Ensure,
    Renew,
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ensure_fixed_root_helper()?;
    match Cli::parse().command {
        Command::Ensure => {
            webex_generic_account_bot::activation_canary::ensure_activation_receipt().await?;
        }
        Command::Renew => {
            webex_generic_account_bot::activation_canary::renew_activation_receipt().await?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_fixed_root_helper() -> Result<()> {
    // SAFETY: geteuid has no arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("activation helper must run as root"));
    }
    let fixed = fs::symlink_metadata(ACTIVATION_HELPER_PATH)?;
    let current = fs::metadata("/proc/self/exe")?;
    if !fixed.is_file()
        || fixed.file_type().is_symlink()
        || fixed.uid() != 0
        || fixed.gid() != 0
        || fixed.nlink() != 1
        || !matches!(fixed.mode() & 0o7777, 0o555 | 0o755)
        || fixed.dev() != current.dev()
        || fixed.ino() != current.ino()
        || !Path::new(ACTIVATION_HELPER_PATH).is_absolute()
    {
        return Err(anyhow!(
            "activation helper is not the fixed root-owned executable"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Err(anyhow!(
        "the Codex activation helper is supported only on Linux"
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_fixed_activation_subcommands() {
        assert!(Cli::try_parse_from(["webex-codex-activation", "ensure"]).is_ok());
        assert!(Cli::try_parse_from(["webex-codex-activation", "renew"]).is_ok());
        assert!(Cli::try_parse_from(["webex-codex-activation", "mint"]).is_err());
        assert!(
            Cli::try_parse_from(["webex-codex-activation", "renew", "--path", "/tmp/x"]).is_err()
        );
    }
}

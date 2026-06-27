use std::{
    io::{self, ErrorKind},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use tokio::{fs, io::AsyncReadExt, task, time::timeout};

const DEPLOY_STATUS_FILE: &str = "/var/lib/webex-generic-account-bot/rendered/deploy-status.json";
const DEPLOY_TRANSACTION_FILE: &str =
    "/var/lib/webex-generic-account-bot/rendered/production.toml.transaction";
const STATUS_FILE_MAX_BYTES: u64 = 64 * 1024;
const STATUS_READ_TIMEOUT: Duration = Duration::from_secs(5);
const DEPLOYMENT_STATUSES: &[&str] = &[
    "deployed",
    "installed_without_restart",
    "failed_apply",
    "failed_restart_rollback_failed",
    "failed_restart_rollback_restart_failed",
    "failed_restart_rolled_back",
    "failed_after_commit",
    "failed_after_commit_cleanup",
    "failed_cleanup",
];
const TRANSACTION_PHASES: &[&str] = &[
    "prepared",
    "service_transition_started",
    "committed_pending_metadata",
];
const TRANSACTION_KEYS: &[&str] = &[
    "bot_code_dir",
    "committed_at",
    "config_ref",
    "config_repo",
    "config_revision",
    "had_previous",
    "metadata_file",
    "phase",
    "rendered_config",
    "service",
    "service_restart_required",
    "started_at",
    "version",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigStatusSnapshot {
    pub status: String,
    pub config_revision: Option<String>,
    pub service: Option<String>,
    pub transaction_phase: Option<String>,
}

impl ConfigStatusSnapshot {
    pub fn markdown(&self) -> String {
        let revision = self.config_revision.as_deref().unwrap_or("unknown");
        let service = self.service.as_deref().unwrap_or("unknown");
        let revision_label = match self.status.as_str() {
            "failed_after_commit" | "failed_after_commit_cleanup" => "Committed config revision",
            status if status.starts_with("failed_") => "Attempted config revision",
            "recovery_required" => "In-progress config revision",
            _ => "Config revision",
        };
        let transaction_phase = self
            .transaction_phase
            .as_deref()
            .map(|phase| format!("\n- Transaction phase: `{phase}`"))
            .unwrap_or_default();
        format!(
            "**Config deployment status**\n\n- State: `{}`\n- {revision_label}: `{revision}`{transaction_phase}\n- Service: `{service}`",
            self.status
        )
    }

    fn unknown() -> Self {
        Self {
            status: "unknown".to_owned(),
            config_revision: None,
            service: None,
            transaction_phase: None,
        }
    }

    fn recovery_required() -> Self {
        Self {
            status: "recovery_required".to_owned(),
            config_revision: None,
            service: Some("webex-generic-account-bot".to_owned()),
            transaction_phase: None,
        }
    }
}

#[async_trait]
pub trait ConfigStatusProvider: Send + Sync {
    async fn status(&self) -> Result<ConfigStatusSnapshot>;
}

pub struct FileConfigStatusProvider {
    status_file: PathBuf,
    transaction_file: PathBuf,
}

impl Default for FileConfigStatusProvider {
    fn default() -> Self {
        Self {
            status_file: PathBuf::from(DEPLOY_STATUS_FILE),
            transaction_file: PathBuf::from(DEPLOY_TRANSACTION_FILE),
        }
    }
}

#[async_trait]
impl ConfigStatusProvider for FileConfigStatusProvider {
    async fn status(&self) -> Result<ConfigStatusSnapshot> {
        match read_optional_bounded_file(&self.transaction_file).await {
            Ok(None) => {}
            Ok(Some(contents)) => {
                return Ok(parse_deployment_transaction(&contents)
                    .unwrap_or_else(|_| ConfigStatusSnapshot::recovery_required()));
            }
            Err(_) => return Ok(ConfigStatusSnapshot::recovery_required()),
        }
        let Some(contents) = read_optional_bounded_file(&self.status_file).await? else {
            return Ok(ConfigStatusSnapshot::unknown());
        };
        parse_deployment_status(&contents)
    }
}

async fn read_optional_bounded_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let open_path = path.to_path_buf();
    let file = match timeout(
        STATUS_READ_TIMEOUT,
        task::spawn_blocking(move || open_no_symlink_components(&open_path)),
    )
    .await
    {
        Ok(Ok(Ok(Some(file)))) => fs::File::from_std(file),
        Ok(Ok(Ok(None))) => return Ok(None),
        Ok(Ok(Err(error))) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
        Ok(Err(error)) => {
            return Err(anyhow!(error)).context("status file open task failed");
        }
        Err(_) => return Err(anyhow!("timed out opening {}", path.display())),
    };
    let metadata = timeout(STATUS_READ_TIMEOUT, file.metadata())
        .await
        .map_err(|_| anyhow!("timed out stating {}", path.display()))?
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("status input must be a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > STATUS_FILE_MAX_BYTES {
        return Err(anyhow!("status input size is invalid"));
    }
    let mut contents = Vec::new();
    timeout(
        STATUS_READ_TIMEOUT,
        file.take(STATUS_FILE_MAX_BYTES + 1)
            .read_to_end(&mut contents),
    )
    .await
    .map_err(|_| anyhow!("timed out reading {}", path.display()))?
    .with_context(|| format!("failed to read {}", path.display()))?;
    if contents.len() as u64 > STATUS_FILE_MAX_BYTES {
        return Err(anyhow!("status input exceeded the size limit"));
    }
    Ok(Some(contents))
}

#[cfg(unix)]
fn open_no_symlink_components(path: &Path) -> io::Result<Option<std::fs::File>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "status input path must be absolute",
        ));
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(component) => Some(Ok(component)),
            _ => Some(Err(io::Error::new(
                ErrorKind::InvalidInput,
                "status input path must contain only normal components",
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if components.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "status input path must name a file",
        ));
    }

    let mut root_options = std::fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let root = root_options.open("/")?;
    let mut directory = OwnedFd::from(root);

    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "status input contains a NUL byte")
        })?;
        let is_file = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if is_file { 0 } else { libc::O_DIRECTORY };
        // SAFETY: `directory` is an open directory fd and `name` is a live,
        // NUL-terminated component without path separators.
        let raw_fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if raw_fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: a successful `openat` returns a new fd owned by this process.
        let opened = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        if is_file {
            return Ok(Some(std::fs::File::from(opened)));
        }
        directory = opened;
    }

    unreachable!("non-empty path components always return from the loop")
}

#[cfg(not(unix))]
fn open_no_symlink_components(_path: &Path) -> io::Result<Option<std::fs::File>> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "secure config status file access requires Unix openat semantics",
    ))
}

fn parse_deployment_status(contents: &[u8]) -> Result<ConfigStatusSnapshot> {
    let value: Value =
        serde_json::from_slice(contents).context("invalid deployment status JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deployment status must be a JSON object"))?;
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| DEPLOYMENT_STATUSES.contains(status))
        .ok_or_else(|| anyhow!("deployment status contains an invalid state"))?;
    let config_revision = match object.get("config_revision") {
        Some(Value::Null) => None,
        Some(Value::String(revision)) if valid_revision(revision) => Some(revision.clone()),
        _ => return Err(anyhow!("deployment status contains an invalid revision")),
    };
    for field in [
        "config_repo",
        "config_ref",
        "bot_code_dir",
        "rendered_config",
        "deployed_at",
    ] {
        required_nonempty_string(object, field)?;
    }
    let service = required_nonempty_string(object, "service")?;
    if service != "webex-generic-account-bot" {
        return Err(anyhow!("deployment status contains an invalid service"));
    }
    let restart_skipped = object
        .get("service_restart_skipped")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("deployment status contains an invalid service_restart_skipped"))?;
    let valid_service_action = match (restart_skipped, object.get("service_action")) {
        (true, Some(Value::Null)) => true,
        (false, Some(Value::String(action))) if action == "restart" => true,
        _ => false,
    };
    if !valid_service_action {
        return Err(anyhow!(
            "deployment status contains an invalid service_action"
        ));
    }
    match status {
        "deployed" if restart_skipped || config_revision.is_none() => {
            return Err(anyhow!("deployed status metadata is inconsistent"));
        }
        "installed_without_restart" if !restart_skipped || config_revision.is_none() => {
            return Err(anyhow!(
                "installed_without_restart status metadata is inconsistent"
            ));
        }
        "failed_after_commit" | "failed_after_commit_cleanup" if config_revision.is_none() => {
            return Err(anyhow!(
                "post-commit failure status metadata requires a revision"
            ));
        }
        _ => {}
    }
    if status.starts_with("failed_") && !object.get("reason").is_some_and(Value::is_string) {
        return Err(anyhow!("failed deployment status must contain a reason"));
    }
    Ok(ConfigStatusSnapshot {
        status: status.to_owned(),
        config_revision,
        service: Some(service.to_owned()),
        transaction_phase: None,
    })
}

fn parse_deployment_transaction(contents: &[u8]) -> Result<ConfigStatusSnapshot> {
    let value: Value =
        serde_json::from_slice(contents).context("invalid deployment transaction JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deployment transaction must be a JSON object"))?;
    if object.len() != TRANSACTION_KEYS.len()
        || !TRANSACTION_KEYS
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(anyhow!("deployment transaction contains unexpected fields"));
    }
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(anyhow!("deployment transaction has an invalid version"));
    }
    let phase = required_nonempty_string(object, "phase")?;
    if !TRANSACTION_PHASES.contains(&phase) {
        return Err(anyhow!("deployment transaction has an invalid phase"));
    }
    let revision = required_nonempty_string(object, "config_revision")?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("deployment transaction has an invalid revision"));
    }
    let service = required_nonempty_string(object, "service")?;
    if service != "webex-generic-account-bot" {
        return Err(anyhow!("deployment transaction has an invalid service"));
    }
    let restart_required = object
        .get("service_restart_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("deployment transaction has an invalid restart requirement"))?;
    if phase == "service_transition_started" && !restart_required {
        return Err(anyhow!("deployment transaction phase is inconsistent"));
    }
    if !object.get("had_previous").is_some_and(Value::is_boolean) {
        return Err(anyhow!(
            "deployment transaction has an invalid backup state"
        ));
    }
    let config_repo = required_nonempty_string(object, "config_repo")?;
    if !valid_config_repo(config_repo) {
        return Err(anyhow!("deployment transaction has an invalid config_repo"));
    }
    let config_ref = required_nonempty_string(object, "config_ref")?;
    if !valid_config_ref(config_ref) {
        return Err(anyhow!("deployment transaction has an invalid config_ref"));
    }
    for field in ["bot_code_dir", "rendered_config", "metadata_file"] {
        let path = required_nonempty_string(object, field)?;
        if !is_normal_absolute_path(Path::new(path)) {
            return Err(anyhow!("deployment transaction has an invalid {field}"));
        }
    }
    let started_at = required_nonempty_string(object, "started_at")?;
    if DateTime::parse_from_rfc3339(started_at).is_err() {
        return Err(anyhow!("deployment transaction has an invalid start time"));
    }
    match (phase, object.get("committed_at")) {
        ("committed_pending_metadata", Some(Value::String(value)))
            if DateTime::parse_from_rfc3339(value).is_ok() => {}
        ("committed_pending_metadata", _) => {
            return Err(anyhow!("deployment transaction has an invalid commit time"));
        }
        (_, Some(Value::Null)) => {}
        _ => {
            return Err(anyhow!(
                "deployment transaction has an unexpected commit time"
            ));
        }
    }
    Ok(ConfigStatusSnapshot {
        status: "recovery_required".to_owned(),
        config_revision: Some(revision.to_ascii_lowercase()),
        service: Some(service.to_owned()),
        transaction_phase: Some(phase.to_owned()),
    })
}

fn required_nonempty_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("deployment status contains an invalid {field}"))
}

fn valid_revision(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_config_repo(value: &str) -> bool {
    let remainder = value
        .strip_prefix("git@github.com:")
        .or_else(|| value.strip_prefix("https://github.com/"));
    let Some(path) = remainder.and_then(|value| value.strip_suffix(".git")) else {
        return false;
    };
    let Some((owner, repository)) = path.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !repository.is_empty()
        && !repository.contains('/')
        && [owner, repository]
            .into_iter()
            .all(|part| part.bytes().all(is_repo_character))
}

fn is_repo_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn valid_config_ref(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && !value.starts_with(['/', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs as std_fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[cfg(unix)]
    #[tokio::test]
    async fn reads_allowlisted_status_fields() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "deployed",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();

        let snapshot = provider.status().await.unwrap();

        assert_eq!(snapshot.status, "deployed");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(snapshot.markdown().contains("Config revision:"));
        assert!(!snapshot.markdown().contains("Attempted config revision:"));
        assert!(!snapshot.markdown().contains("must not leak"));

        let mut installed_without_restart = deployment_metadata(
            "installed_without_restart",
            Some("0123456789abcdef0123456789abcdef01234567"),
        );
        installed_without_restart["service_restart_skipped"] = Value::Bool(true);
        installed_without_restart["service_action"] = Value::Null;
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&installed_without_restart).unwrap(),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "installed_without_restart");
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepts_complete_failure_metadata_without_exposing_reason() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "failed_apply",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();

        let snapshot = provider.status().await.unwrap();

        assert_eq!(snapshot.status, "failed_apply");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(snapshot.markdown().contains("Attempted config revision:"));
        assert!(!snapshot.markdown().contains("\n- Config revision:"));
        assert!(!snapshot.markdown().contains("must not leak"));

        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "failed_after_commit",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert!(snapshot.markdown().contains("Committed config revision:"));
        assert!(!snapshot.markdown().contains("Attempted config revision:"));
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn transaction_takes_precedence_without_exposing_contents() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(&provider.transaction_file, "secret transaction details").unwrap();

        let snapshot = provider.status().await.unwrap();

        assert_eq!(snapshot.status, "recovery_required");
        assert!(!snapshot.markdown().contains("secret"));
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_transaction_files_fail_closed_to_recovery_required() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);

        for contents in [
            Vec::new(),
            b"{not valid json".to_vec(),
            vec![b'x'; STATUS_FILE_MAX_BYTES as usize + 1],
        ] {
            std_fs::write(&provider.transaction_file, contents).unwrap();
            let snapshot = provider.status().await.unwrap();
            assert_eq!(snapshot.status, "recovery_required");
            assert_eq!(snapshot.config_revision, None);
            assert_eq!(snapshot.transaction_phase, None);
        }
        let mut invalid_repo = deployment_transaction();
        invalid_repo["config_repo"] = Value::String("https://example.com/config.git".to_owned());
        let mut invalid_ref = deployment_transaction();
        invalid_ref["config_ref"] = Value::String("../main".to_owned());
        let mut invalid_time = deployment_transaction();
        invalid_time["started_at"] = Value::String("not-a-timestamp".to_owned());
        for transaction in [invalid_repo, invalid_ref, invalid_time] {
            std_fs::write(
                &provider.transaction_file,
                serde_json::to_vec(&transaction).unwrap(),
            )
            .unwrap();
            let snapshot = provider.status().await.unwrap();
            assert_eq!(snapshot.status, "recovery_required");
            assert_eq!(snapshot.config_revision, None);
            assert_eq!(snapshot.transaction_phase, None);
        }

        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn valid_transaction_reports_phase_and_in_progress_revision() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(
            &provider.transaction_file,
            serde_json::to_vec(&deployment_transaction()).unwrap(),
        )
        .unwrap();

        let snapshot = provider.status().await.unwrap();

        assert_eq!(snapshot.status, "recovery_required");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef01")
        );
        assert_eq!(
            snapshot.transaction_phase.as_deref(),
            Some("service_transition_started")
        );
        assert!(snapshot.markdown().contains("In-progress config revision:"));
        assert!(
            snapshot
                .markdown()
                .contains("Transaction phase: `service_transition_started`")
        );
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_metadata_is_unknown() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let snapshot = provider_in(&root).status().await.unwrap();
        assert_eq!(snapshot.status, "unknown");
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_invalid_or_oversized_metadata() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(
            &provider.status_file,
            r#"{"status":"deployed","service":"webex-generic-account-bot"}"#,
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(&provider.status_file, r#"{"status":"unexpected"}"#).unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "deployed",
                Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01"),
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata("deployed", None)).unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata("failed_after_commit", None)).unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "failed_apply",
                Some("0123456789abcdef0123456789abcdef012345678"),
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        let mut skipped_deploy =
            deployment_metadata("deployed", Some("0123456789abcdef0123456789abcdef01234567"));
        skipped_deploy["service_restart_skipped"] = Value::Bool(true);
        skipped_deploy["service_action"] = Value::Null;
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&skipped_deploy).unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            serde_json::to_vec(&deployment_metadata(
                "installed_without_restart",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::write(
            &provider.status_file,
            vec![b'x'; STATUS_FILE_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(provider.status().await.is_err());
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_status_inputs() {
        use std::os::unix::fs::symlink;

        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        let target = root.join("target.json");
        std_fs::write(
            &target,
            serde_json::to_vec(&deployment_metadata(
                "deployed",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();
        symlink(target, &provider.status_file).unwrap();
        assert!(provider.status().await.is_err());
        std_fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_parent_components() {
        use std::os::unix::fs::symlink;

        let root = temp_root();
        let real_root = root.join("real");
        let linked_root = root.join("linked");
        std_fs::create_dir_all(&real_root).unwrap();
        std_fs::write(
            real_root.join("status.json"),
            serde_json::to_vec(&deployment_metadata(
                "deployed",
                Some("0123456789abcdef0123456789abcdef01234567"),
            ))
            .unwrap(),
        )
        .unwrap();
        symlink(&real_root, &linked_root).unwrap();
        let provider = FileConfigStatusProvider {
            status_file: linked_root.join("status.json"),
            transaction_file: linked_root.join("transaction.json"),
        };

        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "recovery_required");
        std_fs::remove_dir_all(root).unwrap();
    }

    fn provider_in(root: &std::path::Path) -> FileConfigStatusProvider {
        FileConfigStatusProvider {
            status_file: root.join("status.json"),
            transaction_file: root.join("transaction.json"),
        }
    }

    fn deployment_metadata(status: &str, config_revision: Option<&str>) -> Value {
        serde_json::json!({
            "status": status,
            "reason": "must not leak",
            "config_repo": "git@github.com:example/config.git",
            "config_ref": "main",
            "config_revision": config_revision,
            "bot_code_dir": "/opt/webex-generic-account-bot/code",
            "rendered_config": "/var/lib/webex-generic-account-bot/rendered/production.toml",
            "service": "webex-generic-account-bot",
            "service_action": "restart",
            "service_restart_skipped": false,
            "deployed_at": "2026-06-27T00:00:00.000Z"
        })
    }

    fn deployment_transaction() -> Value {
        serde_json::json!({
            "version": 1,
            "phase": "service_transition_started",
            "had_previous": true,
            "config_revision": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "service_restart_required": true,
            "service": "webex-generic-account-bot",
            "config_repo": "git@github.com:example/config.git",
            "config_ref": "main",
            "bot_code_dir": "/opt/webex-generic-account-bot/code",
            "rendered_config": "/var/lib/webex-generic-account-bot/rendered/production.toml",
            "metadata_file": "/var/lib/webex-generic-account-bot/rendered/deploy-status.json",
            "started_at": "2026-06-27T00:00:00.000Z",
            "committed_at": null
        })
    }

    fn temp_root() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std_fs::canonicalize(std::env::temp_dir()).unwrap();
        temp_dir.join(format!(
            "webex-config-status-test-{}-{counter}",
            std::process::id()
        ))
    }
}

#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    io::{self, ErrorKind},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use chrono::DateTime;
#[cfg(target_os = "linux")]
use serde_json::Value;
#[cfg(target_os = "linux")]
use tokio::{fs, io::AsyncReadExt, task, time::timeout};

#[cfg(target_os = "linux")]
const DEPLOY_STATUS_FILE: &str = "/var/lib/webex-generic-account-bot/rendered/deploy-status.json";
#[cfg(target_os = "linux")]
const DEPLOY_TRANSACTION_FILE: &str =
    "/var/lib/webex-generic-account-bot/rendered/production.toml.transaction";
#[cfg(target_os = "linux")]
const DEPLOY_TRANSACTION_OWNER_UID: u32 = 0;
#[cfg(target_os = "linux")]
const DEPLOY_TRANSACTION_MODE: u32 = 0o644;
#[cfg(target_os = "linux")]
const CONFIG_ACTION_STATUS_FILE: &str =
    "/var/lib/webex-generic-account-bot/config-actions/public-status.json";
#[cfg(target_os = "linux")]
const STATUS_FILE_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const TRANSACTION_FILE_MAX_BYTES: u64 = 16 * 1024;
#[cfg(target_os = "linux")]
const CONFIG_ACTION_STATUS_MAX_BYTES: u64 = 16 * 1024;
#[cfg(target_os = "linux")]
const STATUS_READ_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
const TRANSACTION_V1_PHASES: &[&str] = &[
    "prepared",
    "service_transition_started",
    "committed_pending_metadata",
];
#[cfg(target_os = "linux")]
const TRANSACTION_V2_PHASES: &[&str] = &[
    "prepared",
    "activation_renewal_started",
    "activation_renewed",
    "activation_files_installed",
    "service_transition_started",
    "committed_pending_metadata",
];
#[cfg(target_os = "linux")]
const TRANSACTION_V1_KEYS: &[&str] = &[
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
#[cfg(target_os = "linux")]
const RUNNER_ACTIVATION_KEYS: &[&str] = &[
    "activation_receipt",
    "activation_receipt_backup",
    "bot_service_drop_in",
    "bot_service_drop_in_backup",
    "permission_had_previous",
    "receipt_had_previous",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigStatusSnapshot {
    pub status: String,
    pub config_revision: Option<String>,
    pub service: Option<String>,
    pub transaction_phase: Option<String>,
    pub config_action: Option<ConfigActionStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigActionStatusSnapshot {
    pub action_id: String,
    pub state: String,
    pub config_revision: Option<String>,
}

impl ConfigStatusSnapshot {
    pub fn markdown(&self) -> String {
        let revision = self.config_revision.as_deref().unwrap_or("unknown");
        let service = self.service.as_deref().unwrap_or("unknown");
        let revision_label = match (self.status.as_str(), self.transaction_phase.as_deref()) {
            ("failed_after_commit" | "failed_after_commit_cleanup", _)
            | ("recovery_required", Some("committed_pending_metadata")) => {
                "Committed config revision"
            }
            (status, _) if status.starts_with("failed_") => "Attempted config revision",
            ("recovery_required", _) => "In-progress config revision",
            _ => "Config revision",
        };
        let transaction_phase = self
            .transaction_phase
            .as_deref()
            .map(|phase| format!("\n- Transaction phase: `{phase}`"))
            .unwrap_or_default();
        let config_action = self
            .config_action
            .as_ref()
            .map(ConfigActionStatusSnapshot::markdown)
            .unwrap_or_default();
        format!(
            "**Config deployment status**\n\n- State: `{}`\n- {revision_label}: `{revision}`{transaction_phase}\n- Service: `{service}`",
            self.status
        ) + &config_action
    }

    #[cfg(target_os = "linux")]
    fn unknown() -> Self {
        Self {
            status: "unknown".to_owned(),
            config_revision: None,
            service: None,
            transaction_phase: None,
            config_action: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn recovery_required() -> Self {
        Self {
            status: "recovery_required".to_owned(),
            config_revision: None,
            service: Some("webex-generic-account-bot".to_owned()),
            transaction_phase: None,
            config_action: None,
        }
    }
}

impl ConfigActionStatusSnapshot {
    fn markdown(&self) -> String {
        let revision = self
            .config_revision
            .as_deref()
            .map(|revision| format!("\n- Prepared config revision: `{revision}`"))
            .unwrap_or_default();
        format!(
            "\n\n**Latest configuration action**\n\n- Action: `pull`\n- State: `{}`\n- Action ID: `{}`{revision}",
            self.state, self.action_id
        )
    }
}

#[async_trait]
pub trait ConfigStatusProvider: Send + Sync {
    async fn status(&self) -> Result<ConfigStatusSnapshot>;
}

pub struct FileConfigStatusProvider {
    #[cfg(target_os = "linux")]
    status_file: PathBuf,
    #[cfg(target_os = "linux")]
    transaction_file: PathBuf,
    #[cfg(target_os = "linux")]
    transaction_owner_uid: u32,
    #[cfg(target_os = "linux")]
    action_status_file: PathBuf,
}

impl Default for FileConfigStatusProvider {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            status_file: PathBuf::from(DEPLOY_STATUS_FILE),
            #[cfg(target_os = "linux")]
            transaction_file: PathBuf::from(DEPLOY_TRANSACTION_FILE),
            #[cfg(target_os = "linux")]
            transaction_owner_uid: DEPLOY_TRANSACTION_OWNER_UID,
            #[cfg(target_os = "linux")]
            action_status_file: PathBuf::from(CONFIG_ACTION_STATUS_FILE),
        }
    }
}

#[async_trait]
impl ConfigStatusProvider for FileConfigStatusProvider {
    #[cfg(target_os = "linux")]
    async fn status(&self) -> Result<ConfigStatusSnapshot> {
        let mut snapshot = match read_optional_bounded_file(
            &self.transaction_file,
            TRANSACTION_FILE_MAX_BYTES,
            Some(DEPLOY_TRANSACTION_MODE),
            Some(self.transaction_owner_uid),
        )
        .await
        {
            Ok(Some(contents)) => parse_deployment_transaction(&contents)
                .unwrap_or_else(|_| ConfigStatusSnapshot::recovery_required()),
            Err(_) => ConfigStatusSnapshot::recovery_required(),
            Ok(None) => match read_optional_bounded_file(
                &self.status_file,
                STATUS_FILE_MAX_BYTES,
                None,
                None,
            )
            .await?
            {
                Some(contents) => parse_deployment_status(&contents)?,
                None => ConfigStatusSnapshot::unknown(),
            },
        };
        let config_action = read_optional_bounded_file(
            &self.action_status_file,
            CONFIG_ACTION_STATUS_MAX_BYTES,
            Some(0o644),
            None,
        )
        .await
        .and_then(|contents| {
            contents
                .map(|contents| parse_config_action_status(&contents))
                .transpose()
        });
        snapshot.config_action = match config_action {
            Ok(config_action) => config_action,
            Err(_) => {
                tracing::warn!("ignoring unavailable public config action status");
                None
            }
        };
        Ok(snapshot)
    }

    #[cfg(not(target_os = "linux"))]
    async fn status(&self) -> Result<ConfigStatusSnapshot> {
        Err(anyhow!(
            "secure config status file access is supported only on Linux"
        ))
    }
}

#[cfg(target_os = "linux")]
async fn read_optional_bounded_file(
    path: &Path,
    max_bytes: u64,
    required_mode: Option<u32>,
    expected_owner_uid: Option<u32>,
) -> Result<Option<Vec<u8>>> {
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
    if !file_metadata_matches_policy(
        metadata.uid(),
        metadata.mode(),
        required_mode,
        expected_owner_uid,
    ) {
        return Err(anyhow!("status input ownership or mode is not trusted"));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(anyhow!("status input size is invalid"));
    }
    let mut contents = Vec::new();
    timeout(
        STATUS_READ_TIMEOUT,
        file.take(max_bytes + 1).read_to_end(&mut contents),
    )
    .await
    .map_err(|_| anyhow!("timed out reading {}", path.display()))?
    .with_context(|| format!("failed to read {}", path.display()))?;
    if contents.len() as u64 > max_bytes {
        return Err(anyhow!("status input exceeded the size limit"));
    }
    Ok(Some(contents))
}

#[cfg(target_os = "linux")]
fn file_metadata_matches_policy(
    owner_uid: u32,
    mode: u32,
    required_mode: Option<u32>,
    expected_owner_uid: Option<u32>,
) -> bool {
    required_mode.is_none_or(|required| mode & 0o7777 == required)
        && expected_owner_uid.is_none_or(|expected| owner_uid == expected)
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
        config_action: None,
    })
}

#[cfg(target_os = "linux")]
fn parse_deployment_transaction(contents: &[u8]) -> Result<ConfigStatusSnapshot> {
    let value: Value =
        serde_json::from_slice(contents).context("invalid deployment transaction JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deployment transaction must be a JSON object"))?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .filter(|version| matches!(*version, 1 | 2))
        .ok_or_else(|| anyhow!("deployment transaction has an invalid version"))?;
    let expected_key_count = TRANSACTION_V1_KEYS.len() + usize::from(version == 2);
    if object.len() != expected_key_count
        || !TRANSACTION_V1_KEYS
            .iter()
            .all(|field| object.contains_key(*field))
        || (version == 2) != object.contains_key("runner_activation")
    {
        return Err(anyhow!("deployment transaction contains unexpected fields"));
    }
    let phase = required_nonempty_string(object, "phase")?;
    let allowed_phases = if version == 2 {
        TRANSACTION_V2_PHASES
    } else {
        TRANSACTION_V1_PHASES
    };
    if !allowed_phases.contains(&phase) {
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
    if version == 2 {
        if !restart_required {
            return Err(anyhow!(
                "runner activation transaction must require a service restart"
            ));
        }
        validate_runner_activation_transaction(
            object
                .get("runner_activation")
                .expect("v2 transaction key set includes runner_activation"),
        )?;
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
        config_action: None,
    })
}

#[cfg(target_os = "linux")]
fn validate_runner_activation_transaction(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deployment transaction has an invalid runner_activation"))?;
    if object.len() != RUNNER_ACTIVATION_KEYS.len()
        || !RUNNER_ACTIVATION_KEYS
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(anyhow!(
            "deployment transaction runner_activation contains unexpected fields"
        ));
    }
    for field in [
        "activation_receipt",
        "activation_receipt_backup",
        "bot_service_drop_in",
        "bot_service_drop_in_backup",
    ] {
        let path = object
            .get(field)
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                anyhow!("deployment transaction has an invalid runner_activation.{field}")
            })?;
        if !is_normal_absolute_path(Path::new(path)) {
            return Err(anyhow!(
                "deployment transaction has an invalid runner_activation.{field}"
            ));
        }
    }
    for field in ["permission_had_previous", "receipt_had_previous"] {
        if !object.get(field).is_some_and(Value::is_boolean) {
            return Err(anyhow!(
                "deployment transaction has an invalid runner_activation.{field}"
            ));
        }
    }
    if object
        .get("permission_had_previous")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(anyhow!(
            "deployment transaction runner_activation.permission_had_previous must be false"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_config_action_status(contents: &[u8]) -> Result<ConfigActionStatusSnapshot> {
    let value: Value =
        serde_json::from_slice(contents).context("invalid config action status JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("config action status must be a JSON object"))?;
    let expected = [
        "action",
        "action_id",
        "config_revision",
        "state",
        "updated_at",
        "version",
    ];
    if object.len() != expected.len() || !expected.iter().all(|field| object.contains_key(*field)) {
        return Err(anyhow!("config action status contains unexpected fields"));
    }
    if object.get("version").and_then(Value::as_u64) != Some(1)
        || object.get("action").and_then(Value::as_str) != Some("pull")
    {
        return Err(anyhow!("config action status identity is invalid"));
    }
    let action_id = object
        .get("action_id")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| anyhow!("config action status action ID is invalid"))?;
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "queued" | "running" | "succeeded" | "failed"))
        .ok_or_else(|| anyhow!("config action status state is invalid"))?;
    let config_revision = match object.get("config_revision") {
        Some(Value::Null) => None,
        Some(Value::String(revision)) if revision.len() == 40 && valid_revision(revision) => {
            Some(revision.clone())
        }
        _ => return Err(anyhow!("config action status revision is invalid")),
    };
    if (state == "succeeded") != config_revision.is_some() {
        return Err(anyhow!("config action status revision is inconsistent"));
    }
    let updated_at = object
        .get("updated_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("config action status timestamp is invalid"))?;
    if DateTime::parse_from_rfc3339(updated_at).is_err() {
        return Err(anyhow!("config action status timestamp is invalid"));
    }
    Ok(ConfigActionStatusSnapshot {
        action_id: action_id.to_owned(),
        state: state.to_owned(),
        config_revision,
    })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn valid_revision(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(target_os = "linux")]
fn is_normal_absolute_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let mut components = value.split('/');
    path.is_absolute()
        && components.next() == Some("")
        && components.all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn is_repo_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

#[cfg(target_os = "linux")]
fn valid_config_ref(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && !value.starts_with(['/', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs as std_fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn production_transaction_metadata_policy_ignores_gid_and_fails_closed() {
        let provider = FileConfigStatusProvider::default();
        let root_owned_with_nonzero_gid = (DEPLOY_TRANSACTION_OWNER_UID, 1234);

        assert_eq!(
            provider.transaction_file,
            PathBuf::from(DEPLOY_TRANSACTION_FILE)
        );
        assert_eq!(provider.transaction_owner_uid, DEPLOY_TRANSACTION_OWNER_UID);
        assert_ne!(root_owned_with_nonzero_gid.1, 0);
        assert!(file_metadata_matches_policy(
            root_owned_with_nonzero_gid.0,
            0o100644,
            Some(DEPLOY_TRANSACTION_MODE),
            Some(provider.transaction_owner_uid),
        ));
        assert!(!file_metadata_matches_policy(
            1,
            0o100644,
            Some(DEPLOY_TRANSACTION_MODE),
            Some(provider.transaction_owner_uid),
        ));
        assert!(!file_metadata_matches_policy(
            DEPLOY_TRANSACTION_OWNER_UID,
            0o100600,
            Some(DEPLOY_TRANSACTION_MODE),
            Some(provider.transaction_owner_uid),
        ));
    }

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
        write_transaction(
            &provider,
            b"secret transaction details",
            DEPLOY_TRANSACTION_MODE,
        );

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
            vec![b'x'; TRANSACTION_FILE_MAX_BYTES as usize + 1],
        ] {
            write_transaction(&provider, &contents, DEPLOY_TRANSACTION_MODE);
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
        let mut non_normal_path = deployment_transaction();
        non_normal_path["bot_code_dir"] =
            Value::String("/opt//webex-generic-account-bot/code".to_owned());
        for transaction in [invalid_repo, invalid_ref, invalid_time, non_normal_path] {
            write_transaction(
                &provider,
                &serde_json::to_vec(&transaction).unwrap(),
                DEPLOY_TRANSACTION_MODE,
            );
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
        let transaction = serde_json::to_vec(&deployment_transaction()).unwrap();
        write_transaction(&provider, &transaction, DEPLOY_TRANSACTION_MODE);

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

        let mut committed = deployment_transaction();
        committed["phase"] = Value::String("committed_pending_metadata".to_owned());
        committed["committed_at"] = Value::String("2026-06-27T00:01:00.000Z".to_owned());
        write_transaction(
            &provider,
            &serde_json::to_vec(&committed).unwrap(),
            DEPLOY_TRANSACTION_MODE,
        );
        let snapshot = provider.status().await.unwrap();
        assert!(snapshot.markdown().contains("Committed config revision:"));
        assert!(!snapshot.markdown().contains("In-progress config revision:"));
        std_fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_all_v2_transaction_phases_without_exposing_runner_activation() {
        for phase in TRANSACTION_V2_PHASES {
            let transaction = deployment_transaction_v2(phase);
            let snapshot =
                parse_deployment_transaction(&serde_json::to_vec(&transaction).unwrap()).unwrap();

            assert_eq!(snapshot.status, "recovery_required");
            assert_eq!(
                snapshot.config_revision.as_deref(),
                Some("abcdef0123456789abcdef0123456789abcdef01")
            );
            assert_eq!(
                snapshot.service.as_deref(),
                Some("webex-generic-account-bot")
            );
            assert_eq!(snapshot.transaction_phase.as_deref(), Some(*phase));
            assert!(!snapshot.markdown().contains("activation-receipt"));
            assert!(!snapshot.markdown().contains("systemd/system"));
        }
    }

    #[test]
    fn rejects_malformed_v2_runner_activation_schema() {
        let mut malformed = Vec::new();

        let mut missing_field = deployment_transaction_v2("prepared");
        missing_field["runner_activation"]
            .as_object_mut()
            .unwrap()
            .remove("activation_receipt");
        malformed.push(missing_field);

        let mut unexpected_field = deployment_transaction_v2("prepared");
        unexpected_field["runner_activation"]["unexpected"] = Value::Bool(true);
        malformed.push(unexpected_field);

        for value in [
            Value::Null,
            serde_json::json!([]),
            Value::String("invalid".into()),
        ] {
            let mut invalid_object = deployment_transaction_v2("prepared");
            invalid_object["runner_activation"] = value;
            malformed.push(invalid_object);
        }

        for field in [
            "activation_receipt",
            "activation_receipt_backup",
            "bot_service_drop_in",
            "bot_service_drop_in_backup",
        ] {
            for value in [
                Value::Bool(false),
                Value::String("relative/path".into()),
                Value::String("/var/lib/../invalid".into()),
            ] {
                let mut invalid_path = deployment_transaction_v2("prepared");
                invalid_path["runner_activation"][field] = value;
                malformed.push(invalid_path);
            }
        }

        for field in ["permission_had_previous", "receipt_had_previous"] {
            let mut invalid_boolean = deployment_transaction_v2("prepared");
            invalid_boolean["runner_activation"][field] = Value::String("true".into());
            malformed.push(invalid_boolean);
        }

        let mut previous_permission = deployment_transaction_v2("prepared");
        previous_permission["runner_activation"]["permission_had_previous"] = Value::Bool(true);
        malformed.push(previous_permission);

        let mut restart_not_required = deployment_transaction_v2("prepared");
        restart_not_required["service_restart_required"] = Value::Bool(false);
        malformed.push(restart_not_required);

        for transaction in malformed {
            assert!(
                parse_deployment_transaction(&serde_json::to_vec(&transaction).unwrap()).is_err()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn custom_provider_pins_current_euid_and_fails_closed() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let mut provider = provider_in(&root);
        let transaction = serde_json::to_vec(&deployment_transaction()).unwrap();
        write_transaction(&provider, &transaction, DEPLOY_TRANSACTION_MODE);

        assert_eq!(provider.transaction_owner_uid, current_test_euid());
        let snapshot = provider.status().await.unwrap();
        assert_eq!(
            snapshot.transaction_phase.as_deref(),
            Some("service_transition_started")
        );

        provider.transaction_owner_uid ^= 1;
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot, ConfigStatusSnapshot::recovery_required());

        provider.transaction_owner_uid = current_test_euid();
        std_fs::set_permissions(
            &provider.transaction_file,
            std_fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot, ConfigStatusSnapshot::recovery_required());
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

    #[tokio::test]
    async fn reads_allowlisted_public_config_action_status() {
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
        std_fs::write(
            &provider.action_status_file,
            serde_json::to_vec(&action_status("queued", None)).unwrap(),
        )
        .unwrap();
        std_fs::set_permissions(
            &provider.action_status_file,
            std_fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let snapshot = provider.status().await.unwrap();

        let action = snapshot.config_action.unwrap();
        assert_eq!(action.action_id, "a".repeat(64));
        assert_eq!(action.state, "queued");
        assert_eq!(action.config_revision, None);
        let markdown = provider.status().await.unwrap().markdown();
        assert!(markdown.contains("Latest configuration action"));
        assert!(markdown.contains("State: `queued`"));
        assert!(!markdown.contains("Prepared config revision"));
        std_fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn succeeded_config_action_requires_a_revision_when_present() {
        let root = temp_root();
        std_fs::create_dir_all(&root).unwrap();
        let provider = provider_in(&root);
        std_fs::write(
            &provider.action_status_file,
            serde_json::to_vec(&action_status(
                "succeeded",
                Some("abcdef0123456789abcdef0123456789abcdef01"),
            ))
            .unwrap(),
        )
        .unwrap();
        std_fs::set_permissions(
            &provider.action_status_file,
            std_fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let snapshot = provider.status().await.unwrap();

        assert_eq!(snapshot.status, "unknown");
        assert!(
            snapshot
                .markdown()
                .contains("Prepared config revision: `abcdef0123456789abcdef0123456789abcdef01`")
        );
        let mut invalid = action_status("succeeded", None);
        std_fs::write(
            &provider.action_status_file,
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "unknown");
        assert_eq!(snapshot.config_action, None);
        invalid["state"] = Value::String("failed".to_owned());
        invalid["config_revision"] =
            Value::String("abcdef0123456789abcdef0123456789abcdef01".to_owned());
        std_fs::write(
            &provider.action_status_file,
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "unknown");
        assert_eq!(snapshot.config_action, None);
        std_fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn invalid_public_config_action_status_preserves_deployment_metadata() {
        use std::os::unix::fs::symlink;

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
        std_fs::write(
            &provider.action_status_file,
            serde_json::to_vec(&action_status("running", None)).unwrap(),
        )
        .unwrap();
        std_fs::set_permissions(
            &provider.action_status_file,
            std_fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "deployed");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(snapshot.config_action, None);

        std_fs::set_permissions(
            &provider.action_status_file,
            std_fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std_fs::write(&provider.action_status_file, br#"{"version":1}"#).unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "deployed");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(snapshot.config_action, None);

        std_fs::remove_file(&provider.action_status_file).unwrap();
        let target = root.join("target.json");
        std_fs::write(
            &target,
            serde_json::to_vec(&action_status("running", None)).unwrap(),
        )
        .unwrap();
        symlink(target, &provider.action_status_file).unwrap();
        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "deployed");
        assert_eq!(
            snapshot.config_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(snapshot.config_action, None);
        std_fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn invalid_public_config_action_status_preserves_recovery_required_transaction() {
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
        write_transaction(
            &provider,
            &serde_json::to_vec(&deployment_transaction()).unwrap(),
            DEPLOY_TRANSACTION_MODE,
        );
        std_fs::write(&provider.action_status_file, br#"{"version":1}"#).unwrap();
        std_fs::set_permissions(
            &provider.action_status_file,
            std_fs::Permissions::from_mode(0o644),
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
        assert_eq!(snapshot.config_action, None);
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
            transaction_owner_uid: current_test_euid(),
            action_status_file: root.join("action-status.json"),
        };

        let snapshot = provider.status().await.unwrap();
        assert_eq!(snapshot.status, "recovery_required");
        std_fs::remove_dir_all(root).unwrap();
    }

    fn provider_in(root: &std::path::Path) -> FileConfigStatusProvider {
        FileConfigStatusProvider {
            status_file: root.join("status.json"),
            transaction_file: root.join("transaction.json"),
            transaction_owner_uid: current_test_euid(),
            action_status_file: root.join("action-status.json"),
        }
    }

    fn current_test_euid() -> u32 {
        // SAFETY: this libc call takes no pointers and returns the process credential.
        unsafe { libc::geteuid() }
    }

    fn write_transaction(provider: &FileConfigStatusProvider, contents: &[u8], mode: u32) {
        std_fs::write(&provider.transaction_file, contents).unwrap();
        std_fs::set_permissions(
            &provider.transaction_file,
            std_fs::Permissions::from_mode(mode),
        )
        .unwrap();
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

    fn action_status(state: &str, config_revision: Option<&str>) -> Value {
        serde_json::json!({
            "version": 1,
            "action": "pull",
            "action_id": "a".repeat(64),
            "state": state,
            "config_revision": config_revision,
            "updated_at": "2026-06-27T00:00:00.000Z",
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

    fn deployment_transaction_v2(phase: &str) -> Value {
        let mut transaction = deployment_transaction();
        transaction["version"] = Value::from(2);
        transaction["phase"] = Value::String(phase.to_owned());
        transaction["committed_at"] = if phase == "committed_pending_metadata" {
            Value::String("2026-06-27T00:01:00.000Z".to_owned())
        } else {
            Value::Null
        };
        transaction["runner_activation"] = serde_json::json!({
            "activation_receipt": "/var/lib/webex-generic-account-bot/activation-receipt.json",
            "activation_receipt_backup": "/var/lib/webex-generic-account-bot/activation-receipt.json.backup",
            "bot_service_drop_in": "/etc/systemd/system/webex-generic-account-bot.service.d/runner-activation.conf",
            "bot_service_drop_in_backup": "/etc/systemd/system/webex-generic-account-bot.service.d/runner-activation.conf.backup",
            "permission_had_previous": false,
            "receipt_had_previous": false,
        });
        transaction
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

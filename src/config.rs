use std::{
    collections::HashSet,
    env, fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

const WEBEX_REQUEST_TIMEOUT_SECS: u64 = 30;
const WEBEX_REQUESTS_PER_ATTEMPT: u64 = 4;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BotConfig {
    pub server: ServerConfig,
    pub webex: WebexAuthConfig,
    pub state_file: PathBuf,
    pub self_person_id: Option<String>,
    pub codex: CodexConfig,
    pub rooms: Vec<RoomPolicy>,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            webex: WebexAuthConfig::default(),
            state_file: PathBuf::from(".codex-tmp/generic-account-bot/state.jsonl"),
            self_person_id: None,
            codex: CodexConfig::default(),
            rooms: Vec::new(),
        }
    }
}

impl BotConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        validate_http_path("server.event_path", &self.server.event_path)?;
        validate_http_path("server.health_path", &self.server.health_path)?;
        self.server.validate()?;
        if self.server.event_path == self.server.health_path {
            return Err(anyhow!(
                "server.event_path must differ from server.health_path"
            ));
        }
        if self.rooms.is_empty() {
            return Err(anyhow!("at least one [[rooms]] policy is required"));
        }
        if self
            .self_person_id
            .as_deref()
            .is_some_and(|person_id| person_id.trim().is_empty())
        {
            return Err(anyhow!("self_person_id must not be empty when set"));
        }
        self.validate_room_ids()?;
        for room in &self.rooms {
            room.validate()?;
        }
        for (name, codex) in self.codex_configs() {
            codex
                .validate()
                .map_err(|error| anyhow!("invalid {name}: {error}"))?;
        }
        self.validate_attempt_lease()?;
        self.validate_secret_boundaries()?;
        Ok(())
    }

    pub fn policy_for_room(&self, room_id: &str) -> Option<&RoomPolicy> {
        self.rooms.iter().find(|policy| policy.room_id == room_id)
    }

    pub fn codex_for_policy(&self, policy: &RoomPolicy) -> CodexConfig {
        policy
            .codex
            .as_ref()
            .map(|patch| patch.apply_to(&self.codex))
            .unwrap_or_else(|| self.codex.clone())
    }

    fn validate_room_ids(&self) -> Result<()> {
        let mut seen = HashSet::new();
        for room in &self.rooms {
            if !seen.insert(room.room_id.as_str()) {
                return Err(anyhow!("duplicate rooms.room_id {}", room.room_id));
            }
        }
        Ok(())
    }

    fn validate_secret_boundaries(&self) -> Result<()> {
        if let Some(token_file) = self.webex.runtime_access_token_file() {
            for (name, codex) in self.codex_configs() {
                if path_is_inside(&token_file, &codex.cwd) {
                    return Err(anyhow!(
                        "webex access token file {} must not be inside codex cwd {} ({name})",
                        token_file.display(),
                        codex.cwd.display()
                    ));
                }
            }
        }
        for (name, codex) in self.codex_configs() {
            if path_is_inside(&codex.codex_home, &codex.cwd) {
                return Err(anyhow!(
                    "codex.codex_home {} must not be inside codex cwd {} ({name})",
                    codex.codex_home.display(),
                    codex.cwd.display()
                ));
            }
        }
        Ok(())
    }

    fn validate_attempt_lease(&self) -> Result<()> {
        for (name, codex) in self.codex_configs() {
            let minimum_lease = codex.timeout_secs.saturating_add(
                WEBEX_REQUEST_TIMEOUT_SECS.saturating_mul(WEBEX_REQUESTS_PER_ATTEMPT),
            );
            if minimum_lease >= self.server.attempt_lease_secs {
                return Err(anyhow!(
                    "server.attempt_lease_secs must be greater than codex.timeout_secs plus Webex request timeout margin for {name}"
                ));
            }
        }
        Ok(())
    }

    fn codex_configs(&self) -> Vec<(String, CodexConfig)> {
        let mut configs = vec![("global codex".to_owned(), self.codex.clone())];
        for room in &self.rooms {
            if room.codex.is_some() {
                configs.push((
                    format!("room {}", room.room_id),
                    self.codex_for_policy(room),
                ));
            }
        }
        configs
    }
}

impl WebexAuthConfig {
    pub fn runtime_access_token_file(&self) -> Option<PathBuf> {
        if let Some(path) = &self.access_token_file {
            return Some(path.clone());
        }
        if let Ok(path) = env::var(&self.access_token_file_env) {
            if !path.trim().is_empty() {
                return Some(PathBuf::from(path));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: String,
    pub event_path: String,
    pub health_path: String,
    pub sidecar_token_env: String,
    pub allow_unauthenticated: bool,
    pub max_concurrent_requests: usize,
    pub attempt_lease_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8787".to_owned(),
            event_path: "/webex/events".to_owned(),
            health_path: "/healthz".to_owned(),
            sidecar_token_env: "WEBEX_SIDECAR_TOKEN".to_owned(),
            allow_unauthenticated: false,
            max_concurrent_requests: 4,
            attempt_lease_secs: 900,
        }
    }
}

impl ServerConfig {
    pub fn attempt_lease(&self) -> Duration {
        Duration::from_secs(self.attempt_lease_secs.max(1))
    }

    fn validate(&self) -> Result<()> {
        let bind = self
            .bind
            .parse::<SocketAddr>()
            .map_err(|error| anyhow!("server.bind must be a socket address: {error}"))?;
        if self.allow_unauthenticated && !bind.ip().is_loopback() {
            return Err(anyhow!(
                "server.allow_unauthenticated requires a loopback server.bind"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebexAuthConfig {
    pub access_token_env: String,
    pub access_token_file_env: String,
    pub access_token_file: Option<PathBuf>,
}

impl Default for WebexAuthConfig {
    fn default() -> Self {
        Self {
            access_token_env: "WEBEX_ACCESS_TOKEN".to_owned(),
            access_token_file_env: "WEBEX_ACCESS_TOKEN_FILE".to_owned(),
            access_token_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodexConfig {
    pub bin: String,
    pub cwd: PathBuf,
    pub codex_home: PathBuf,
    pub profile: Option<String>,
    pub model: Option<String>,
    pub model_reasoning_effort: Option<String>,
    pub sandbox: String,
    pub approval_policy: String,
    pub timeout_secs: u64,
    pub output_limit_chars: usize,
    pub skip_git_repo_check: bool,
    pub ephemeral: bool,
    pub isolation: IsolationConfig,
}

impl Default for CodexConfig {
    fn default() -> Self {
        Self {
            bin: "codex".to_owned(),
            cwd: PathBuf::from("."),
            codex_home: PathBuf::from("/var/lib/webex-generic-account-bot/codex-home"),
            profile: None,
            model: None,
            model_reasoning_effort: None,
            sandbox: "read-only".to_owned(),
            approval_policy: "never".to_owned(),
            timeout_secs: 600,
            output_limit_chars: 6_000,
            skip_git_repo_check: false,
            ephemeral: true,
            isolation: IsolationConfig::default(),
        }
    }
}

impl CodexConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.bin.trim().is_empty() {
            return Err(anyhow!("codex.bin must not be empty"));
        }
        if self.output_limit_chars == 0 {
            return Err(anyhow!(
                "codex.output_limit_chars must be greater than zero"
            ));
        }
        if self.timeout_secs == 0 {
            return Err(anyhow!("codex.timeout_secs must be greater than zero"));
        }
        if self.sandbox != "read-only" {
            return Err(anyhow!("codex.sandbox must be \"read-only\" in this MVP"));
        }
        if self.approval_policy != "never" {
            return Err(anyhow!(
                "codex.approval_policy must be \"never\" in this MVP"
            ));
        }
        if self
            .model_reasoning_effort
            .as_deref()
            .is_some_and(|effort| !valid_reasoning_effort(effort))
        {
            return Err(anyhow!(
                "codex.model_reasoning_effort must be one of minimal, low, medium, high, or xhigh"
            ));
        }
        if self.codex_home.as_os_str().is_empty() {
            return Err(anyhow!("codex.codex_home must not be empty"));
        }
        self.isolation.validate()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodexConfigPatch {
    pub bin: Option<String>,
    pub cwd: Option<PathBuf>,
    pub codex_home: Option<PathBuf>,
    pub profile: Option<String>,
    pub model: Option<String>,
    pub model_reasoning_effort: Option<String>,
    pub sandbox: Option<String>,
    pub approval_policy: Option<String>,
    pub timeout_secs: Option<u64>,
    pub output_limit_chars: Option<usize>,
    pub skip_git_repo_check: Option<bool>,
    pub ephemeral: Option<bool>,
    pub isolation: Option<IsolationConfig>,
}

impl CodexConfigPatch {
    fn apply_to(&self, base: &CodexConfig) -> CodexConfig {
        let mut config = base.clone();
        if let Some(value) = &self.bin {
            config.bin = value.clone();
        }
        if let Some(value) = &self.cwd {
            config.cwd = value.clone();
        }
        if let Some(value) = &self.codex_home {
            config.codex_home = value.clone();
        }
        if let Some(value) = &self.profile {
            config.profile = Some(value.clone());
        }
        if let Some(value) = &self.model {
            config.model = Some(value.clone());
        }
        if let Some(value) = &self.model_reasoning_effort {
            config.model_reasoning_effort = Some(value.clone());
        }
        if let Some(value) = &self.sandbox {
            config.sandbox = value.clone();
        }
        if let Some(value) = &self.approval_policy {
            config.approval_policy = value.clone();
        }
        if let Some(value) = self.timeout_secs {
            config.timeout_secs = value;
        }
        if let Some(value) = self.output_limit_chars {
            config.output_limit_chars = value;
        }
        if let Some(value) = self.skip_git_repo_check {
            config.skip_git_repo_check = value;
        }
        if let Some(value) = self.ephemeral {
            config.ephemeral = value;
        }
        if let Some(value) = &self.isolation {
            config.isolation = value.clone();
        }
        config
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct IsolationConfig {
    pub mode: IsolationMode,
    pub trusted_prompt_authors: bool,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            mode: IsolationMode::CurrentUser,
            trusted_prompt_authors: true,
        }
    }
}

impl IsolationConfig {
    fn validate(&self) -> Result<()> {
        match self.mode {
            IsolationMode::CurrentUser if self.trusted_prompt_authors => Ok(()),
            IsolationMode::CurrentUser => Err(anyhow!(
                "codex.isolation.trusted_prompt_authors must be true for current-user mode"
            )),
            IsolationMode::EphemeralLinuxUser => Err(anyhow!(
                "codex.isolation.mode = \"ephemeral-linux-user\" is planned but not implemented in this MVP"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationMode {
    #[default]
    CurrentUser,
    EphemeralLinuxUser,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoomPolicy {
    pub room_id: String,
    pub name: Option<String>,
    pub trigger: TriggerMode,
    pub prefixes: Vec<String>,
    pub allow_all_senders: bool,
    pub allowed_person_ids: Vec<String>,
    pub allowed_person_emails: Vec<String>,
    pub prompt_template: String,
    pub codex: Option<CodexConfigPatch>,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            room_id: String::new(),
            name: None,
            trigger: TriggerMode::Mention,
            prefixes: Vec::new(),
            allow_all_senders: false,
            allowed_person_ids: Vec::new(),
            allowed_person_emails: Vec::new(),
            prompt_template: DEFAULT_PROMPT_TEMPLATE.to_owned(),
            codex: None,
        }
    }
}

impl RoomPolicy {
    fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(anyhow!("rooms.room_id must not be empty"));
        }
        if !self.allow_all_senders
            && self.allowed_person_ids.is_empty()
            && self.allowed_person_emails.is_empty()
        {
            return Err(anyhow!(
                "rooms[{}] must configure allowed_person_ids, allowed_person_emails, or allow_all_senders = true",
                self.room_id
            ));
        }
        if matches!(self.trigger, TriggerMode::Prefix) {
            if self.prefixes.is_empty() {
                return Err(anyhow!(
                    "rooms[{}].prefixes is required when trigger = \"prefix\"",
                    self.room_id
                ));
            }
            if self
                .prefixes
                .iter()
                .any(|prefix| prefix.trim().is_empty() || prefix.trim() != prefix)
            {
                return Err(anyhow!(
                    "rooms[{}].prefixes must be non-empty without surrounding whitespace",
                    self.room_id
                ));
            }
        }
        if self.prompt_template.trim().is_empty() {
            return Err(anyhow!(
                "rooms[{}].prompt_template must not be empty",
                self.room_id
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TriggerMode {
    #[default]
    Mention,
    Prefix,
    Always,
    Never,
}

const DEFAULT_PROMPT_TEMPLATE: &str = r#"You are responding to a Webex message.

Room: {room_id}
Message ID: {message_id}
Sender: {person_email}

Message:
{body}
"#;

fn validate_http_path(name: &str, path: &str) -> Result<()> {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') || path.trim() != path {
        return Err(anyhow!("{name} must be an absolute HTTP path"));
    }
    Ok(())
}

fn valid_reasoning_effort(value: &str) -> bool {
    matches!(value, "minimal" | "low" | "medium" | "high" | "xhigh")
}

fn path_is_inside(path: &Path, root: &Path) -> bool {
    let lexical_path = absolute_lexical(path);
    let lexical_root = absolute_lexical(root);
    if path_starts_with(&lexical_path, &lexical_root) {
        return true;
    }

    let real_path = path.canonicalize().ok();
    let real_root = root.canonicalize().ok();
    match (real_path, real_root) {
        (Some(path), Some(root)) => path_starts_with(&path, &root),
        (Some(path), None) => path_starts_with(&path, &lexical_root),
        (None, Some(root)) => path_starts_with(&lexical_path, &root),
        (None, None) => false,
    }
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn absolute_lexical(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    normalize_lexical(&joined)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:8787");
        assert_eq!(
            config.codex.codex_home,
            Path::new("/var/lib/webex-generic-account-bot/codex-home")
        );
        assert_eq!(config.rooms[0].trigger, TriggerMode::Mention);
    }

    #[test]
    fn rejects_ephemeral_user_until_runner_support_exists() {
        let config: BotConfig = toml::from_str(
            r#"
[codex.isolation]
mode = "ephemeral-linux-user"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("not implemented"));
    }

    #[test]
    fn current_user_mode_requires_trusted_prompt_authors() {
        let config: BotConfig = toml::from_str(
            r#"
[codex.isolation]
mode = "current-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("trusted_prompt_authors"));
    }

    #[test]
    fn prefix_trigger_requires_prefixes() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
trigger = "prefix"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("prefixes")
        );
    }

    #[test]
    fn prefix_trigger_rejects_blank_prefixes() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
trigger = "prefix"
prefixes = [""]
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("non-empty")
        );
    }

    #[test]
    fn parses_codex_reasoning_effort() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
model = "gpt-5.5"
model_reasoning_effort = "xhigh"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.codex.model.as_deref(), Some("gpt-5.5"));
        assert_eq!(
            config.codex.model_reasoning_effort.as_deref(),
            Some("xhigh")
        );
    }

    #[test]
    fn rejects_invalid_codex_reasoning_effort() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
model_reasoning_effort = "xhigh\""

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("model_reasoning_effort")
        );
    }

    #[test]
    fn rejects_codex_timeout_that_exceeds_attempt_lease() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 10

[codex]
timeout_secs = 10

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("attempt_lease_secs")
        );
    }

    #[test]
    fn rejects_codex_timeout_without_webex_attempt_margin() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 101

[codex]
timeout_secs = 100

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("Webex request timeout margin")
        );
    }

    #[test]
    fn rejects_blank_self_person_id() {
        let config: BotConfig = toml::from_str(
            r#"
self_person_id = " "

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("self_person_id")
        );
    }

    #[test]
    fn rejects_unsafe_codex_runtime_modes() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
sandbox = "danger-full-access"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
    }

    #[test]
    fn rejects_access_token_file_inside_codex_cwd() {
        let config: BotConfig = toml::from_str(
            r#"
[webex]
access_token_file = ".codex-tmp/token"

[codex]
cwd = ".codex-tmp"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must not be inside codex cwd")
        );
    }

    #[cfg(unix)]
    #[test]
    fn token_boundary_resolves_symlinked_codex_cwd() {
        use std::os::unix::fs::symlink;
        use std::time::SystemTime;

        let root = env::temp_dir().join(format!(
            "webex-bot-config-test-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real_cwd = root.join("real-cwd");
        let link_cwd = root.join("link-cwd");
        let token = real_cwd.join("token");
        fs::create_dir_all(&real_cwd).unwrap();
        fs::write(&token, "token").unwrap();
        symlink(&real_cwd, &link_cwd).unwrap();

        assert!(path_is_inside(&token, &link_cwd));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn token_boundary_rejects_symlink_path_inside_codex_cwd() {
        use std::os::unix::fs::symlink;
        use std::time::SystemTime;

        let root = env::temp_dir().join(format!(
            "webex-bot-config-test-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let codex_cwd = root.join("codex-cwd");
        let token_dir = root.join("token-dir");
        let real_token = token_dir.join("token");
        let link_token = codex_cwd.join("token-link");
        fs::create_dir_all(&codex_cwd).unwrap();
        fs::create_dir_all(&token_dir).unwrap();
        fs::write(&real_token, "token").unwrap();
        symlink(&real_token, &link_token).unwrap();

        assert!(path_is_inside(&link_token, &codex_cwd));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_token_file_takes_priority_over_env_token_file() {
        unsafe {
            env::set_var(
                "WEBEX_BOT_TEST_TOKEN_FILE_PRIORITY",
                ".codex-tmp/stale-token",
            );
        }
        let config: BotConfig = toml::from_str(
            r#"
[webex]
access_token_file = "/var/lib/webex/access-token"
access_token_file_env = "WEBEX_BOT_TEST_TOKEN_FILE_PRIORITY"

[codex]
cwd = ".codex-tmp"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(config.validate().is_ok());
        unsafe {
            env::remove_var("WEBEX_BOT_TEST_TOKEN_FILE_PRIORITY");
        }
    }

    #[test]
    fn rooms_require_sender_allowlist_by_default() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allowed_person")
        );
    }

    #[test]
    fn duplicate_room_ids_are_rejected() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate rooms.room_id")
        );
    }

    #[test]
    fn invalid_server_bind_is_rejected() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
bind = "localhost:8787"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("server.bind")
        );
    }

    #[test]
    fn unauthenticated_server_requires_loopback_bind() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
bind = "0.0.0.0:8787"
allow_unauthenticated = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allow_unauthenticated")
        );
    }

    #[test]
    fn rejects_codex_home_inside_codex_cwd() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
cwd = "."
codex_home = ".codex"

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("codex.codex_home")
        );
    }

    #[test]
    fn room_codex_override_inherits_global_config() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
cwd = "/srv/webex-bot/workspace"
codex_home = "/srv/webex-bot/codex-home"
model = "gpt-5.5"
timeout_secs = 123
skip_git_repo_check = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.codex]
model = "gpt-5.5-mini"
"#,
        )
        .unwrap();

        let policy = config.policy_for_room("room-1").unwrap();
        let codex = config.codex_for_policy(policy);

        assert_eq!(codex.cwd, PathBuf::from("/srv/webex-bot/workspace"));
        assert_eq!(codex.codex_home, Path::new("/srv/webex-bot/codex-home"));
        assert_eq!(codex.model.as_deref(), Some("gpt-5.5-mini"));
        assert_eq!(codex.timeout_secs, 123);
        assert!(codex.skip_git_repo_check);
    }
}

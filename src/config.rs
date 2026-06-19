use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

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
        if self.server.event_path == self.server.health_path {
            return Err(anyhow!(
                "server.event_path must differ from server.health_path"
            ));
        }
        if self.rooms.is_empty() {
            return Err(anyhow!("at least one [[rooms]] policy is required"));
        }
        for room in &self.rooms {
            room.validate()?;
        }
        self.codex.validate()?;
        Ok(())
    }

    pub fn policy_for_room(&self, room_id: &str) -> Option<&RoomPolicy> {
        self.rooms.iter().find(|policy| policy.room_id == room_id)
    }

    pub fn codex_for_policy<'a>(&'a self, policy: &'a RoomPolicy) -> &'a CodexConfig {
        policy.codex.as_ref().unwrap_or(&self.codex)
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
        if self
            .model_reasoning_effort
            .as_deref()
            .is_some_and(|effort| effort.trim().is_empty() || effort.trim() != effort)
        {
            return Err(anyhow!(
                "codex.model_reasoning_effort must be non-empty without surrounding whitespace"
            ));
        }
        self.isolation.validate()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct IsolationConfig {
    pub mode: IsolationMode,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            mode: IsolationMode::CurrentUser,
        }
    }
}

impl IsolationConfig {
    fn validate(&self) -> Result<()> {
        match self.mode {
            IsolationMode::CurrentUser => Ok(()),
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
    pub allowed_person_ids: Vec<String>,
    pub allowed_person_emails: Vec<String>,
    pub prompt_template: String,
    pub codex: Option<CodexConfig>,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            room_id: String::new(),
            name: None,
            trigger: TriggerMode::Mention,
            prefixes: Vec::new(),
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
        if matches!(self.trigger, TriggerMode::Prefix) && self.prefixes.is_empty() {
            return Err(anyhow!(
                "rooms[{}].prefixes is required when trigger = \"prefix\"",
                self.room_id
            ));
        }
        if self.prompt_template.trim().is_empty() {
            return Err(anyhow!(
                "rooms[{}].prompt_template must not be empty",
                self.room_id
            ));
        }
        if let Some(codex) = &self.codex {
            codex.validate()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:8787");
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
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("not implemented"));
    }

    #[test]
    fn prefix_trigger_requires_prefixes() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
trigger = "prefix"
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
    fn parses_codex_reasoning_effort() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
model = "gpt-5.5"
model_reasoning_effort = "xhigh"

[[rooms]]
room_id = "room-1"
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
}

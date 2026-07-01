use std::{
    collections::HashSet,
    env, fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::{
    config_commands::{ConfigCommand, ConfigCommandsConfig},
    launcher_protocol::{
        EPHEMERAL_RUNNER_WALL_OVERHEAD_SECONDS, LAUNCHER_MAX_CONNECTIONS, OUTPUT_CHAR_LIMIT_MAX,
        TIMEOUT_SECONDS_MAX,
    },
};

const WEBEX_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const EVENT_HYDRATION_NOT_FOUND_RETRY_SECS: u64 = 5;
pub const DIRECT_REPLY_MARKER_SEARCH_MAX_PAGES: usize = 3;
const DIRECT_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT: u64 = 3;
const WEBEX_REQUESTS_PER_ATTEMPT: u64 =
    DIRECT_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT + (DIRECT_REPLY_MARKER_SEARCH_MAX_PAGES as u64 * 2);
const FOLLOWUP_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT: u64 = 3;
pub const WEBEX_LIST_PAGE_SIZE: usize = 100;
pub const FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES: usize = WEBEX_LIST_PAGE_SIZE;
pub const FOLLOWUP_REPLY_MARKER_SEARCH_MIN_MESSAGES: usize = WEBEX_LIST_PAGE_SIZE * 3;
const STAGING_SOURCE_MARKER_SEARCH_PAGES: u64 = 3;
const STAGING_WEBEX_REQUESTS_PER_ATTEMPT: u64 =
    STAGING_SOURCE_MARKER_SEARCH_PAGES + 1 + STAGING_SOURCE_MARKER_SEARCH_PAGES;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BotConfig {
    pub server: ServerConfig,
    pub webex: WebexAuthConfig,
    pub state_file: PathBuf,
    pub self_person_id: Option<String>,
    pub codex: CodexConfig,
    pub rooms: Vec<RoomPolicy>,
    pub config_commands: Option<ConfigCommandsConfig>,
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
            config_commands: None,
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
        if let Some(config_commands) = &self.config_commands {
            config_commands
                .validate()
                .context("invalid config_commands")?;
            self.validate_config_commands_room(config_commands)?;
            if config_commands.command_allowed(ConfigCommand::Pull)
                && !self.uses_ephemeral_linux_user()
            {
                return Err(anyhow!(
                    "config_commands pull requires ephemeral-linux-user for every Codex runner"
                ));
            }
        }
        for (name, codex) in self.codex_configs() {
            codex
                .validate()
                .map_err(|error| anyhow!("invalid {name}: {error}"))?;
        }
        if self.uses_ephemeral_linux_user() {
            if let Some((name, _)) = self
                .codex_configs()
                .into_iter()
                .find(|(_, codex)| codex.isolation.mode == IsolationMode::CurrentUser)
            {
                return Err(anyhow!(
                    "ephemeral-linux-user cannot be mixed with current-user execution ({name})"
                ));
            }
            if self.server.max_concurrent_requests > LAUNCHER_MAX_CONNECTIONS {
                return Err(anyhow!(
                    "server.max_concurrent_requests must not exceed the fixed launcher connection limit ({LAUNCHER_MAX_CONNECTIONS}) when ephemeral-linux-user is enabled"
                ));
            }
        }
        self.validate_attempt_lease()?;
        self.validate_secret_boundaries()?;
        Ok(())
    }

    pub fn policy_for_room(&self, room_id: &str) -> Option<&RoomPolicy> {
        self.rooms.iter().find(|policy| policy.room_id == room_id)
    }

    pub fn followup_policies_for_event_room(&self, room_id: &str) -> Vec<&RoomPolicy> {
        self.rooms
            .iter()
            .filter(|policy| {
                policy.followup.enabled
                    && (policy.room_id == room_id
                        || policy.output_room_id.as_deref() == Some(room_id))
            })
            .collect()
    }

    pub fn room_is_read_only_source(&self, room_id: &str) -> bool {
        self.rooms
            .iter()
            .any(|policy| policy.read_only_source && policy.room_id == room_id)
    }

    pub fn codex_for_policy(&self, policy: &RoomPolicy) -> CodexConfig {
        policy
            .codex
            .as_ref()
            .map(|patch| patch.apply_to(&self.codex))
            .unwrap_or_else(|| self.codex.clone())
    }

    pub fn uses_ephemeral_linux_user(&self) -> bool {
        self.codex_configs()
            .into_iter()
            .any(|(_, codex)| codex.isolation.mode == IsolationMode::EphemeralLinuxUser)
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

    fn validate_config_commands_room(&self, config_commands: &ConfigCommandsConfig) -> Result<()> {
        for room in &self.rooms {
            if room.room_id == config_commands.room_id {
                return Err(anyhow!(
                    "config_commands.room_id must differ from rooms.room_id {}",
                    room.room_id
                ));
            }
            if room.output_room_id.as_deref() == Some(config_commands.room_id.as_str()) {
                return Err(anyhow!(
                    "config_commands.room_id must differ from rooms.output_room_id {}",
                    config_commands.room_id
                ));
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
            if path_is_inside(&codex.codex_home, &codex.cwd)
                || path_is_inside(&codex.cwd, &codex.codex_home)
            {
                return Err(anyhow!(
                    "codex.codex_home {} must not overlap codex cwd {} ({name})",
                    codex.codex_home.display(),
                    codex.cwd.display()
                ));
            }
        }
        for room in &self.rooms {
            let Some(jenkins_context) = room
                .jenkins_context
                .as_ref()
                .filter(|jenkins_context| jenkins_context.enabled)
            else {
                continue;
            };
            let codex = self.codex_for_policy(room);
            let name = format!("room {}", room.room_id);
            if path_is_inside(&jenkins_context.script, &codex.cwd) {
                return Err(anyhow!(
                    "rooms[{}].jenkins_context.script {} must not be inside codex cwd {} ({name})",
                    room.room_id,
                    jenkins_context.script.display(),
                    codex.cwd.display()
                ));
            }
            if path_is_inside(&jenkins_context.env_file, &codex.cwd) {
                return Err(anyhow!(
                    "rooms[{}].jenkins_context.env_file {} must not be inside codex cwd {} ({name})",
                    room.room_id,
                    jenkins_context.env_file.display(),
                    codex.cwd.display()
                ));
            }
        }
        Ok(())
    }

    fn validate_attempt_lease(&self) -> Result<()> {
        self.validate_attempt_lease_for(
            "global codex",
            &self.codex,
            0,
            WEBEX_REQUESTS_PER_ATTEMPT,
        )?;
        for room in &self.rooms {
            let codex = self.codex_for_policy(room);
            let jenkins_prefetch_secs = room
                .jenkins_context
                .as_ref()
                .filter(|context| context.enabled)
                .map(JenkinsContextConfig::max_prefetch_secs)
                .unwrap_or(0);
            let webex_requests = room.webex_requests_per_attempt();
            if room.codex.is_some()
                || jenkins_prefetch_secs > 0
                || webex_requests > WEBEX_REQUESTS_PER_ATTEMPT
            {
                self.validate_attempt_lease_for(
                    &format!("room {}", room.room_id),
                    &codex,
                    jenkins_prefetch_secs,
                    webex_requests,
                )?;
            }
        }
        Ok(())
    }

    fn validate_attempt_lease_for(
        &self,
        name: &str,
        codex: &CodexConfig,
        jenkins_prefetch_secs: u64,
        webex_requests: u64,
    ) -> Result<()> {
        let isolation_overhead = if codex.isolation.mode == IsolationMode::EphemeralLinuxUser {
            EPHEMERAL_RUNNER_WALL_OVERHEAD_SECONDS
        } else {
            0
        };
        let minimum_lease = codex
            .timeout_secs
            .saturating_add(isolation_overhead)
            .saturating_add(jenkins_prefetch_secs)
            .saturating_add(EVENT_HYDRATION_NOT_FOUND_RETRY_SECS)
            .saturating_add(WEBEX_REQUEST_TIMEOUT_SECS.saturating_mul(webex_requests));
        if minimum_lease >= self.server.attempt_lease_secs {
            return Err(anyhow!(
                "server.attempt_lease_secs must be greater than the Codex execution budget plus isolation overhead, Jenkins prefetch time, hydration retry delay, and Webex request timeout margin for {name}"
            ));
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
        self.isolation.validate()?;
        if self.isolation.mode == IsolationMode::EphemeralLinuxUser {
            if self.model.as_deref() != Some("gpt-5.5") {
                return Err(anyhow!(
                    "ephemeral-linux-user requires codex.model = \"gpt-5.5\""
                ));
            }
            if self.profile.is_some() {
                return Err(anyhow!(
                    "ephemeral-linux-user does not accept codex.profile"
                ));
            }
            if !self.skip_git_repo_check {
                return Err(anyhow!(
                    "ephemeral-linux-user requires codex.skip_git_repo_check = true"
                ));
            }
            if !self.ephemeral {
                return Err(anyhow!(
                    "ephemeral-linux-user requires codex.ephemeral = true"
                ));
            }
            if self.timeout_secs > TIMEOUT_SECONDS_MAX {
                return Err(anyhow!(
                    "ephemeral-linux-user codex.timeout_secs exceeds the launcher limit"
                ));
            }
            if self.output_limit_chars as u64 > OUTPUT_CHAR_LIMIT_MAX {
                return Err(anyhow!(
                    "ephemeral-linux-user codex.output_limit_chars exceeds the launcher limit"
                ));
            }
        }
        Ok(())
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
            IsolationMode::EphemeralLinuxUser if !self.trusted_prompt_authors => Ok(()),
            IsolationMode::EphemeralLinuxUser => Err(anyhow!(
                "codex.isolation.trusted_prompt_authors must be false for ephemeral-linux-user mode"
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
    pub output_room_id: Option<String>,
    pub forward_source_message: bool,
    pub read_only_source: bool,
    pub jenkins_context: Option<JenkinsContextConfig>,
    pub followup: FollowupConfig,
    pub reply_format: ReplyFormat,
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
            output_room_id: None,
            forward_source_message: false,
            read_only_source: false,
            jenkins_context: None,
            followup: FollowupConfig::default(),
            reply_format: ReplyFormat::Markdown,
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
        if let Some(output_room_id) = &self.output_room_id {
            if output_room_id.trim().is_empty() {
                return Err(anyhow!(
                    "rooms[{}].output_room_id must not be empty when set",
                    self.room_id
                ));
            }
            if output_room_id == &self.room_id {
                return Err(anyhow!(
                    "rooms[{}].output_room_id must differ from room_id",
                    self.room_id
                ));
            }
            if !self.forward_source_message {
                return Err(anyhow!(
                    "rooms[{}].forward_source_message = true is required when output_room_id is set",
                    self.room_id
                ));
            }
        }
        if self.read_only_source && self.output_room_id.is_none() {
            return Err(anyhow!(
                "rooms[{}].read_only_source requires output_room_id",
                self.room_id
            ));
        }
        if self.forward_source_message && self.output_room_id.is_none() {
            return Err(anyhow!(
                "rooms[{}].forward_source_message requires output_room_id",
                self.room_id
            ));
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
        if matches!(self.trigger, TriggerMode::Prefix) && self.prefixes.is_empty() {
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
        if self.prompt_template.trim().is_empty() {
            return Err(anyhow!(
                "rooms[{}].prompt_template must not be empty",
                self.room_id
            ));
        }
        if let Some(jenkins_context) = &self.jenkins_context {
            jenkins_context
                .validate()
                .with_context(|| format!("invalid jenkins_context for room {}", self.room_id))?;
        }
        self.followup
            .validate()
            .with_context(|| format!("invalid followup for room {}", self.room_id))?;
        Ok(())
    }

    fn webex_requests_per_attempt(&self) -> u64 {
        let mut requests = WEBEX_REQUESTS_PER_ATTEMPT;
        if self.output_room_id.is_some() {
            requests = requests.saturating_add(STAGING_WEBEX_REQUESTS_PER_ATTEMPT);
        }
        if self.followup.enabled {
            requests = requests.saturating_add(self.followup.webex_requests_per_attempt());
        }
        requests
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReplyFormat {
    #[default]
    Markdown,
    JenkinsDiagnosisJson,
    JenkinsFollowupJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FollowupConfig {
    pub enabled: bool,
    pub triggers: Vec<FollowupTrigger>,
    pub allow_all_senders: bool,
    pub allowed_person_ids: Vec<String>,
    pub allowed_person_emails: Vec<String>,
    pub max_thread_messages: usize,
    pub max_thread_context_chars: usize,
    pub reply_format: Option<ReplyFormat>,
    pub prompt_template: String,
}

impl Default for FollowupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            triggers: vec![FollowupTrigger::Mention],
            allow_all_senders: false,
            allowed_person_ids: Vec::new(),
            allowed_person_emails: Vec::new(),
            max_thread_messages: 30,
            max_thread_context_chars: 12_000,
            reply_format: None,
            prompt_template: DEFAULT_FOLLOWUP_PROMPT_TEMPLATE.to_owned(),
        }
    }
}

impl FollowupConfig {
    fn validate(&self) -> Result<()> {
        if self.enabled && self.triggers.is_empty() {
            return Err(anyhow!("triggers must not be empty when enabled = true"));
        }
        if self.max_thread_messages == 0 {
            return Err(anyhow!("max_thread_messages must be greater than zero"));
        }
        if self.max_thread_context_chars == 0 {
            return Err(anyhow!(
                "max_thread_context_chars must be greater than zero"
            ));
        }
        if self.prompt_template.trim().is_empty() {
            return Err(anyhow!("prompt_template must not be empty"));
        }
        Ok(())
    }

    fn webex_requests_per_attempt(&self) -> u64 {
        let thread_context_pages = webex_page_requests(
            self.max_thread_messages
                .max(FOLLOWUP_MARKER_SEARCH_MAX_MESSAGES),
        );
        let reply_marker_pages =
            followup_reply_marker_search_max_pages(self.max_thread_messages) as u64;
        FOLLOWUP_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT
            .saturating_add(thread_context_pages)
            .saturating_add(reply_marker_pages)
    }
}

pub fn followup_reply_marker_search_max_pages(max_thread_messages: usize) -> usize {
    let item_limit = max_thread_messages.max(FOLLOWUP_REPLY_MARKER_SEARCH_MIN_MESSAGES);
    item_limit.saturating_add(WEBEX_LIST_PAGE_SIZE - 1) / WEBEX_LIST_PAGE_SIZE
}

fn webex_page_requests(item_limit: usize) -> u64 {
    let pages = item_limit.saturating_add(WEBEX_LIST_PAGE_SIZE - 1) / WEBEX_LIST_PAGE_SIZE;
    pages.try_into().unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FollowupTrigger {
    Mention,
    QuotedBotReply,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JenkinsContextConfig {
    pub enabled: bool,
    pub node_bin: String,
    pub script: PathBuf,
    pub env_file: PathBuf,
    pub timeout_secs: u64,
    pub max_urls: usize,
    pub output_limit_chars: usize,
}

impl Default for JenkinsContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            node_bin: "node".to_owned(),
            script: PathBuf::new(),
            env_file: PathBuf::from("/etc/webex-generic-account-bot/jenkins.env"),
            timeout_secs: 30,
            max_urls: 3,
            output_limit_chars: 12_000,
        }
    }
}

impl JenkinsContextConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    pub fn max_prefetch_secs(&self) -> u64 {
        self.timeout_secs
            .max(1)
            .saturating_mul(self.max_urls as u64)
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.node_bin.trim().is_empty() {
            return Err(anyhow!("node_bin must not be empty"));
        }
        if self.script.as_os_str().is_empty() {
            return Err(anyhow!("script must not be empty"));
        }
        if !self.script.is_absolute() {
            return Err(anyhow!("script must be an absolute path"));
        }
        if self.env_file.as_os_str().is_empty() {
            return Err(anyhow!("env_file must not be empty"));
        }
        if !self.env_file.is_absolute() {
            return Err(anyhow!("env_file must be an absolute path"));
        }
        if self.timeout_secs == 0 {
            return Err(anyhow!("timeout_secs must be greater than zero"));
        }
        if self.max_urls == 0 {
            return Err(anyhow!("max_urls must be greater than zero"));
        }
        if self.output_limit_chars == 0 {
            return Err(anyhow!("output_limit_chars must be greater than zero"));
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

const DEFAULT_FOLLOWUP_PROMPT_TEMPLATE: &str = r#"You are responding to a follow-up in an existing Webex thread.

Reply concisely. Use the thread context only as background, and answer the current follow-up directly.

Original message:
{original_body}

Recent thread:
{thread_context}

Current follow-up:
Room: {room_id}
Message ID: {message_id}
Sender: {person_email}

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
    fn pull_config_requires_ephemeral_runner_isolation() {
        let current_user: BotConfig = toml::from_str(
            r#"
[config_commands]
room_id = "admin-room"
allowed_person_ids = []
allowed_person_emails = ["operator@example.com"]
allowed_commands = ["status", "pull"]

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = format!("{:#}", current_user.validate().unwrap_err());
        assert!(error.contains("pull requires ephemeral-linux-user"));

        let ephemeral: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 3600

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[config_commands]
room_id = "admin-room"
allowed_person_ids = []
allowed_person_emails = ["operator@example.com"]
allowed_commands = ["status", "pull"]

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        ephemeral.validate().unwrap();
    }

    #[test]
    fn config_commands_room_must_not_match_input_room() {
        let config: BotConfig = toml::from_str(
            r#"
[config_commands]
room_id = "room-1"
allowed_person_ids = ["person-1"]
allowed_person_emails = []
allowed_commands = ["status"]

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("rooms.room_id"));
    }

    #[test]
    fn config_commands_room_must_not_match_output_room() {
        let config: BotConfig = toml::from_str(
            r#"
[config_commands]
room_id = "output-room"
allowed_person_ids = ["person-1"]
allowed_person_emails = []
allowed_commands = ["status"]

[[rooms]]
room_id = "room-1"
output_room_id = "output-room"
forward_source_message = true
read_only_source = true
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("rooms.output_room_id"));
    }

    #[test]
    fn parses_room_reply_format() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true
reply_format = "jenkins-diagnosis-json"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.rooms[0].reply_format,
            ReplyFormat::JenkinsDiagnosisJson
        );
    }

    #[test]
    fn parses_room_followup_config() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.followup]
enabled = true
triggers = ["mention", "quoted-bot-reply"]
allowed_person_emails = ["operator@example.com"]
max_thread_messages = 12
max_thread_context_chars = 4096
reply_format = "jenkins-followup-json"
prompt_template = "Follow up on {original_message_id}: {body}"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.rooms[0].followup.enabled);
        assert_eq!(
            config.rooms[0].followup.triggers,
            vec![FollowupTrigger::Mention, FollowupTrigger::QuotedBotReply]
        );
        assert_eq!(
            config.rooms[0].followup.allowed_person_emails,
            vec!["operator@example.com"]
        );
        assert_eq!(config.rooms[0].followup.max_thread_messages, 12);
        assert_eq!(config.rooms[0].followup.max_thread_context_chars, 4096);
        assert_eq!(
            config.rooms[0].followup.reply_format,
            Some(ReplyFormat::JenkinsFollowupJson)
        );
    }

    #[test]
    fn accepts_ephemeral_user_policy() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 3600

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.uses_ephemeral_linux_user());
    }

    #[test]
    fn ephemeral_user_rejects_request_concurrency_above_launcher_capacity() {
        let mut config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 3600
max_concurrent_requests = 5

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

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
                .contains("fixed launcher connection limit")
        );
        config.server.max_concurrent_requests = LAUNCHER_MAX_CONNECTIONS;
        config.validate().unwrap();
    }

    #[test]
    fn rejects_room_ephemeral_user_with_global_current_user() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 3000

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false
"#,
        )
        .unwrap();

        assert_eq!(config.codex.isolation.mode, IsolationMode::CurrentUser);
        assert_eq!(
            config
                .codex_for_policy(config.policy_for_room("room-1").unwrap())
                .isolation
                .mode,
            IsolationMode::EphemeralLinuxUser
        );

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cannot be mixed with current-user")
        );
        assert!(config.uses_ephemeral_linux_user());
    }

    #[test]
    fn rejects_room_current_user_with_global_ephemeral_user() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 3000

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.codex.isolation]
mode = "current-user"
trusted_prompt_authors = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cannot be mixed with current-user")
        );
        assert!(config.uses_ephemeral_linux_user());
    }

    #[test]
    fn load_accepts_ephemeral_user_for_host_preflight() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "webex-bot-config-load-test-{}-{nanos}.toml",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"
[server]
attempt_lease_secs = 3600

[codex]
model = "gpt-5.5"
skip_git_repo_check = true
ephemeral = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let config = BotConfig::load(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert!(config.uses_ephemeral_linux_user());
    }

    #[test]
    fn ephemeral_user_rejects_runtime_policy_downgrades() {
        let base = CodexConfig {
            model: Some("gpt-5.5".to_owned()),
            skip_git_repo_check: true,
            ephemeral: true,
            isolation: IsolationConfig {
                mode: IsolationMode::EphemeralLinuxUser,
                trusted_prompt_authors: false,
            },
            ..CodexConfig::default()
        };
        base.validate().unwrap();

        let mut invalid = base.clone();
        invalid.model = Some("other".to_owned());
        assert!(invalid.validate().is_err());
        invalid = base.clone();
        invalid.profile = Some("profile".to_owned());
        assert!(invalid.validate().is_err());
        invalid = base.clone();
        invalid.skip_git_repo_check = false;
        assert!(invalid.validate().is_err());
        invalid = base.clone();
        invalid.ephemeral = false;
        assert!(invalid.validate().is_err());
        invalid = base.clone();
        invalid.timeout_secs = TIMEOUT_SECONDS_MAX + 1;
        assert!(invalid.validate().is_err());
        invalid = base.clone();
        invalid.output_limit_chars = OUTPUT_CHAR_LIMIT_MAX as usize + 1;
        assert!(invalid.validate().is_err());
        invalid = base;
        invalid.isolation.trusted_prompt_authors = true;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn current_user_remains_default_and_kebab_case_schema_name() {
        let default_config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();
        assert_eq!(
            default_config.codex.isolation.mode,
            IsolationMode::CurrentUser
        );
        assert!(default_config.codex.isolation.trusted_prompt_authors);

        let explicit_config: BotConfig = toml::from_str(
            r#"
[codex.isolation]
mode = "current-user"
trusted_prompt_authors = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();
        explicit_config.validate().unwrap();
        assert_eq!(
            explicit_config.codex.isolation.mode,
            IsolationMode::CurrentUser
        );
        assert!(explicit_config.codex.isolation.trusted_prompt_authors);
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
    fn followup_prefix_fallback_rejects_untrimmed_prefixes() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
prefixes = [" @miku.gen"]
allow_all_senders = true

[rooms.followup]
enabled = true
triggers = ["mention"]
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("without surrounding whitespace")
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
    fn rejects_ephemeral_attempt_lease_without_isolation_overhead() {
        let mut config: BotConfig = toml::from_str(
            r#"
[codex]
model = "gpt-5.5"
skip_git_repo_check = true

[codex.isolation]
mode = "ephemeral-linux-user"
trusted_prompt_authors = false

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();
        config.server.attempt_lease_secs = config
            .codex
            .timeout_secs
            .saturating_add(EPHEMERAL_RUNNER_WALL_OVERHEAD_SECONDS)
            .saturating_add(EVENT_HYDRATION_NOT_FOUND_RETRY_SECS)
            .saturating_add(WEBEX_REQUEST_TIMEOUT_SECS.saturating_mul(WEBEX_REQUESTS_PER_ATTEMPT));

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("isolation overhead"), "{error}");
    }

    #[test]
    fn rejects_attempt_lease_without_hydration_retry_budget() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 305

[codex]
timeout_secs = 30

[[rooms]]
room_id = "room-1"
allow_all_senders = true
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("hydration retry delay"));
    }

    #[test]
    fn rejects_jenkins_prefetch_budget_that_exceeds_attempt_lease() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 190

[codex]
timeout_secs = 100

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
timeout_secs = 30
max_urls = 3
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("Jenkins prefetch time")
        );
    }

    #[test]
    fn rejects_staging_webex_budget_that_exceeds_attempt_lease() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 400

[codex]
timeout_secs = 100

[[rooms]]
room_id = "production-room"
output_room_id = "staging-room"
forward_source_message = true
read_only_source = true
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
    fn rejects_followup_webex_budget_that_exceeds_attempt_lease() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 300

[codex]
timeout_secs = 100

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.followup]
enabled = true
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
    fn rejects_paged_followup_thread_budget_that_exceeds_attempt_lease() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 300

[codex]
timeout_secs = 20

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.followup]
enabled = true
max_thread_messages = 250
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
    fn followup_webex_budget_counts_marker_scan_pages() {
        let single_page: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.followup]
enabled = true
max_thread_messages = 30
"#,
        )
        .unwrap();
        let paged: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.followup]
enabled = true
max_thread_messages = 250
"#,
        )
        .unwrap();

        assert_eq!(
            single_page.rooms[0].followup.webex_requests_per_attempt(),
            FOLLOWUP_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT
                + 1
                + followup_reply_marker_search_max_pages(30) as u64
        );
        assert_eq!(
            paged.rooms[0].followup.webex_requests_per_attempt(),
            FOLLOWUP_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT
                + 3
                + followup_reply_marker_search_max_pages(250) as u64
        );
        assert_eq!(
            paged.rooms[0].webex_requests_per_attempt(),
            WEBEX_REQUESTS_PER_ATTEMPT
                + FOLLOWUP_NON_PAGED_WEBEX_REQUESTS_PER_ATTEMPT
                + 3
                + followup_reply_marker_search_max_pages(250) as u64
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
    fn output_room_requires_forward_source_message() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
output_room_id = "room-2"
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("forward_source_message")
        );
    }

    #[test]
    fn read_only_source_requires_output_room() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
read_only_source = true
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("read_only_source")
        );
    }

    #[test]
    fn output_room_must_differ_from_source_room() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
output_room_id = "room-1"
forward_source_message = true
allow_all_senders = true
"#,
        )
        .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must differ")
        );
    }

    #[test]
    fn parses_staging_output_room_policy() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[[rooms]]
room_id = "room-1"
output_room_id = "room-2"
forward_source_message = true
read_only_source = true
allow_all_senders = true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.room_is_read_only_source("room-1"));
        assert!(!config.room_is_read_only_source("room-2"));
        assert_eq!(config.rooms[0].output_room_id.as_deref(), Some("room-2"));
    }

    #[test]
    fn parses_jenkins_context_config() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
timeout_secs = 15
max_urls = 2
output_limit_chars = 2048
"#,
        )
        .unwrap();

        config.validate().unwrap();
        let jenkins_context = config.rooms[0].jenkins_context.as_ref().unwrap();
        assert!(jenkins_context.enabled);
        assert_eq!(jenkins_context.node_bin, "node");
        assert!(jenkins_context.script.is_absolute());
        assert_eq!(jenkins_context.timeout_secs, 15);
        assert_eq!(jenkins_context.max_urls, 2);
        assert_eq!(jenkins_context.output_limit_chars, 2048);
    }

    #[test]
    fn production_style_jenkins_context_keeps_helper_outside_codex_cwd() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[codex]
cwd = "/var/lib/webex-generic-account-bot/codex-workspace"
codex_home = "/var/lib/webex-generic-account-bot/codex-home"
skip_git_repo_check = true

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
"#,
        )
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn rejects_relative_jenkins_context_script() {
        let config: BotConfig = toml::from_str(
            r#"
[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "scripts/jenkins-readonly.mjs"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(format!("{error:#}").contains("script must be an absolute path"));
    }

    #[test]
    fn rejects_jenkins_script_inside_codex_cwd() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[codex]
cwd = "/srv/webex-bot/workspace"
codex_home = "/srv/webex-bot/codex-home"

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "/srv/webex-bot/workspace/scripts/jenkins-readonly.mjs"
env_file = "/etc/webex-generic-account-bot/jenkins.env"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(format!("{error:#}").contains("jenkins_context.script"));
    }

    #[test]
    fn rejects_jenkins_env_file_inside_codex_cwd() {
        let config: BotConfig = toml::from_str(
            r#"
[server]
attempt_lease_secs = 1200

[codex]
cwd = "/srv/webex-bot/workspace"
codex_home = "/srv/webex-bot/codex-home"

[[rooms]]
room_id = "room-1"
allow_all_senders = true

[rooms.jenkins_context]
script = "/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs"
env_file = "/srv/webex-bot/workspace/jenkins.env"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(format!("{error:#}").contains("jenkins_context.env_file"));
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
    fn rejects_codex_cwd_inside_codex_home() {
        let config: BotConfig = toml::from_str(
            r#"
[codex]
cwd = "/var/lib/webex-generic-account-bot/codex-home/workspace"
codex_home = "/var/lib/webex-generic-account-bot/codex-home"

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

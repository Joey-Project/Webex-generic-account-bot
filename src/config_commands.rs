use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use anyhow::{Result, anyhow};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ConfigCommand {
    Status,
    Pull,
    Reload,
    Sync,
}

impl FromStr for ConfigCommand {
    type Err = ParseConfigCommandError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_config_command(input).ok_or(ParseConfigCommandError)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseConfigCommandError;

impl Display for ParseConfigCommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid config command")
    }
}

impl Error for ParseConfigCommandError {}

pub fn parse_config_command(input: &str) -> Option<ConfigCommand> {
    match input.trim() {
        "/config status" => Some(ConfigCommand::Status),
        "/config pull" => Some(ConfigCommand::Pull),
        "/config reload" => Some(ConfigCommand::Reload),
        "/config sync" => Some(ConfigCommand::Sync),
        _ => None,
    }
}

pub fn is_config_command_namespace(input: &str) -> bool {
    let input = input.trim();
    input == "/config"
        || input
            .strip_prefix("/config")
            .and_then(|remainder| remainder.chars().next())
            .is_some_and(char::is_whitespace)
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigCommandsConfig {
    pub room_id: String,
    pub allowed_person_ids: Vec<String>,
    pub allowed_person_emails: Vec<String>,
    pub allowed_commands: Vec<ConfigCommand>,
}

impl ConfigCommandsConfig {
    pub fn validate(&self) -> Result<()> {
        validate_trimmed_value("config_commands.room_id", &self.room_id)?;
        validate_string_list(
            "config_commands.allowed_person_ids",
            &self.allowed_person_ids,
            false,
        )?;
        validate_string_list(
            "config_commands.allowed_person_emails",
            &self.allowed_person_emails,
            true,
        )?;

        if self.allowed_person_ids.is_empty() && self.allowed_person_emails.is_empty() {
            return Err(anyhow!(
                "config_commands must configure at least one allowed_person_id or allowed_person_email"
            ));
        }
        if self.allowed_commands.is_empty() {
            return Err(anyhow!(
                "config_commands.allowed_commands must not be empty"
            ));
        }

        let mut seen_commands = HashSet::new();
        for command in &self.allowed_commands {
            if !seen_commands.insert(*command) {
                return Err(anyhow!(
                    "config_commands.allowed_commands must not contain duplicates"
                ));
            }
        }
        if let Some(command) = self
            .allowed_commands
            .iter()
            .find(|command| matches!(command, ConfigCommand::Reload | ConfigCommand::Sync))
        {
            return Err(anyhow!(
                "config_commands command {command:?} is not implemented; only status and pull are supported"
            ));
        }

        Ok(())
    }

    pub fn sender_allowed(&self, person_id: Option<&str>, person_email: Option<&str>) -> bool {
        person_id.is_some_and(|person_id| {
            self.allowed_person_ids
                .iter()
                .any(|allowed| allowed == person_id)
        }) || person_email.is_some_and(|person_email| {
            self.allowed_person_emails
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(person_email))
        })
    }

    pub fn command_allowed(&self, command: ConfigCommand) -> bool {
        self.allowed_commands.contains(&command)
    }
}

fn validate_trimmed_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(anyhow!(
            "{name} must be non-empty without surrounding whitespace"
        ));
    }
    Ok(())
}

fn validate_string_list(name: &str, values: &[String], case_insensitive: bool) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        validate_trimmed_value(name, value)?;
        let deduplication_key = if case_insensitive {
            value.to_ascii_lowercase()
        } else {
            value.clone()
        };
        if !seen.insert(deduplication_key) {
            return Err(anyhow!("{name} must not contain duplicates"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> ConfigCommandsConfig {
        ConfigCommandsConfig {
            room_id: "admin-room".to_owned(),
            allowed_person_ids: vec!["person-1".to_owned()],
            allowed_person_emails: vec!["operator@example.com".to_owned()],
            allowed_commands: vec![ConfigCommand::Status],
        }
    }

    #[test]
    fn parses_only_exact_trimmed_commands() {
        for (input, expected) in [
            ("/config status", ConfigCommand::Status),
            ("/config pull", ConfigCommand::Pull),
            ("/config reload", ConfigCommand::Reload),
            ("/config sync", ConfigCommand::Sync),
            (" \n/config status\t", ConfigCommand::Status),
        ] {
            assert_eq!(parse_config_command(input), Some(expected));
            assert_eq!(input.parse::<ConfigCommand>(), Ok(expected));
        }
    }

    #[test]
    fn rejects_arguments_case_changes_and_non_exact_syntax() {
        for input in [
            "/config status now",
            "/config Status",
            "/Config status",
            "/config  status",
            "/config",
            "config status",
            "/config status\n/config pull",
        ] {
            assert_eq!(parse_config_command(input), None, "accepted {input:?}");
            assert!(
                input.parse::<ConfigCommand>().is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn recognises_the_reserved_config_namespace() {
        for input in [
            "/config",
            "/config status",
            "/config status now",
            "/config future-command",
            " \n/config help\t",
        ] {
            assert!(is_config_command_namespace(input), "missed {input:?}");
        }
        for input in ["config status", "/Config status", "/configuration status"] {
            assert!(!is_config_command_namespace(input), "accepted {input:?}");
        }
    }

    #[test]
    fn uses_exact_lowercase_serde_names() {
        let config = toml::from_str::<ConfigCommandsConfig>(
            r#"
room_id = "admin-room"
allowed_person_ids = ["person-1"]
allowed_person_emails = []
allowed_commands = ["status", "pull", "reload", "sync"]
"#,
        )
        .unwrap();

        assert_eq!(
            config.allowed_commands,
            vec![
                ConfigCommand::Status,
                ConfigCommand::Pull,
                ConfigCommand::Reload,
                ConfigCommand::Sync,
            ]
        );
        assert!(
            toml::from_str::<ConfigCommandsConfig>(
                r#"
room_id = "admin-room"
allowed_person_ids = ["person-1"]
allowed_person_emails = []
allowed_commands = ["Status"]
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn matches_senders_and_commands_exactly() {
        let config = valid_config();

        assert!(config.sender_allowed(Some("person-1"), None));
        assert!(config.sender_allowed(None, Some("operator@example.com")));
        assert!(config.sender_allowed(Some("person-1"), Some("other@example.com")));
        assert!(!config.sender_allowed(Some("PERSON-1"), None));
        assert!(config.sender_allowed(None, Some("Operator@example.com")));
        assert!(!config.sender_allowed(None, None));
        assert!(config.command_allowed(ConfigCommand::Status));
        assert!(!config.command_allowed(ConfigCommand::Pull));
    }

    #[test]
    fn requires_explicit_schema_fields() {
        let error = toml::from_str::<ConfigCommandsConfig>(
            r#"
room_id = "admin-room"
allowed_person_emails = ["operator@example.com"]
allowed_commands = ["status"]
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("allowed_person_ids"));
    }

    #[test]
    fn rejects_empty_or_duplicate_lists() {
        let mut cases = Vec::new();

        let mut empty_senders = valid_config();
        empty_senders.allowed_person_ids.clear();
        empty_senders.allowed_person_emails.clear();
        cases.push(empty_senders);

        let mut blank_sender = valid_config();
        blank_sender.allowed_person_ids = vec![" ".to_owned()];
        cases.push(blank_sender);

        let mut untrimmed_sender = valid_config();
        untrimmed_sender.allowed_person_emails = vec![" operator@example.com".to_owned()];
        cases.push(untrimmed_sender);

        let mut duplicate_sender = valid_config();
        duplicate_sender.allowed_person_ids = vec!["person-1".to_owned(), "person-1".to_owned()];
        cases.push(duplicate_sender);

        let mut duplicate_email = valid_config();
        duplicate_email.allowed_person_emails = vec![
            "operator@example.com".to_owned(),
            "Operator@example.com".to_owned(),
        ];
        cases.push(duplicate_email);

        let mut empty_commands = valid_config();
        empty_commands.allowed_commands.clear();
        cases.push(empty_commands);

        let mut duplicate_commands = valid_config();
        duplicate_commands.allowed_commands = vec![ConfigCommand::Status, ConfigCommand::Status];
        cases.push(duplicate_commands);

        for config in cases {
            assert!(config.validate().is_err(), "accepted {config:?}");
        }
    }

    #[test]
    fn rejects_untrimmed_or_empty_room_id() {
        for room_id in ["", " ", " admin-room", "admin-room "] {
            let mut config = valid_config();
            config.room_id = room_id.to_owned();
            assert!(config.validate().is_err(), "accepted {room_id:?}");
        }
    }

    #[test]
    fn allows_pull_but_rejects_activation_commands() {
        let mut pull = valid_config();
        pull.allowed_commands = vec![ConfigCommand::Status, ConfigCommand::Pull];
        pull.validate().unwrap();

        for command in [ConfigCommand::Reload, ConfigCommand::Sync] {
            let mut config = valid_config();
            config.allowed_commands = vec![command];
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("only status and pull are supported"));
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        for field in ["allow_all", "path", "executable"] {
            let input = format!(
                r#"
room_id = "admin-room"
allowed_person_ids = []
allowed_person_emails = ["operator@example.com"]
allowed_commands = ["status"]
{field} = "unexpected"
"#,
            );
            let error = toml::from_str::<ConfigCommandsConfig>(&input).unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`"))
            );
        }
    }
}

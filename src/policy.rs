use serde::Serialize;
use webex_headless_messenger::types::Message;

use crate::config::{RoomPolicy, TriggerMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerDecision {
    Matched,
    RoomDisabled,
    SenderNotAllowed,
    MissingSelfPersonId,
    NotMentioned,
    PrefixNotMatched,
}

#[derive(Debug, Clone)]
pub struct MessageContext {
    pub message_id: String,
    pub room_id: String,
    pub person_id: Option<String>,
    pub person_email: Option<String>,
    pub body: String,
}

impl MessageContext {
    pub fn from_message(message: &Message) -> Option<Self> {
        Some(Self {
            message_id: message.id.clone()?,
            room_id: message.room_id.clone()?,
            person_id: message.person_id.clone(),
            person_email: message.person_email.clone(),
            body: message_body(message),
        })
    }
}

pub fn should_trigger(
    policy: &RoomPolicy,
    message: &Message,
    self_person_id: Option<&str>,
) -> TriggerDecision {
    if matches!(policy.trigger, TriggerMode::Never) {
        return TriggerDecision::RoomDisabled;
    }
    if !sender_allowed(policy, message) {
        return TriggerDecision::SenderNotAllowed;
    }

    match policy.trigger {
        TriggerMode::Always => TriggerDecision::Matched,
        TriggerMode::Never => TriggerDecision::RoomDisabled,
        TriggerMode::Mention => {
            let Some(self_person_id) = self_person_id else {
                return TriggerDecision::MissingSelfPersonId;
            };
            if message
                .mentioned_people
                .iter()
                .any(|person_id| person_id == self_person_id)
            {
                TriggerDecision::Matched
            } else {
                TriggerDecision::NotMentioned
            }
        }
        TriggerMode::Prefix => {
            if message_matches_prefix(message, &policy.prefixes) {
                TriggerDecision::Matched
            } else {
                TriggerDecision::PrefixNotMatched
            }
        }
    }
}

pub fn render_prompt(template: &str, context: &MessageContext) -> String {
    template
        .replace("{room_id}", &context.room_id)
        .replace("{message_id}", &context.message_id)
        .replace("{person_id}", context.person_id.as_deref().unwrap_or(""))
        .replace(
            "{person_email}",
            context.person_email.as_deref().unwrap_or(""),
        )
        .replace("{body}", &context.body)
}

pub fn trim_to_chars(value: &str, max_chars: usize) -> String {
    let max_chars = max_chars.max(1);
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            output.push_str("\n[truncated]");
            return output;
        }
        output.push(ch);
    }
    output
}

pub fn message_matches_prefix(message: &Message, prefixes: &[String]) -> bool {
    let body = message_body(message);
    prefixes.iter().any(|prefix| prefix_matches(&body, prefix))
}

pub fn sender_allowed(policy: &RoomPolicy, message: &Message) -> bool {
    if policy.allow_all_senders {
        return true;
    }
    if policy.allowed_person_ids.is_empty() && policy.allowed_person_emails.is_empty() {
        return false;
    }

    let person_id_allowed = message
        .person_id
        .as_deref()
        .is_some_and(|person_id| policy.allowed_person_ids.iter().any(|id| id == person_id));
    let person_email_allowed = message.person_email.as_deref().is_some_and(|email| {
        policy
            .allowed_person_emails
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(email))
    });

    person_id_allowed || person_email_allowed
}

fn prefix_matches(body: &str, prefix: &str) -> bool {
    let body = body.trim_start();
    let Some(rest) = body.strip_prefix(prefix) else {
        return false;
    };
    rest.is_empty() || rest.starts_with(char::is_whitespace)
}

fn message_body(message: &Message) -> String {
    message
        .text
        .as_deref()
        .or(message.markdown.as_deref())
        .unwrap_or("")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use webex_headless_messenger::types::Message;

    use super::*;
    use crate::config::{RoomPolicy, TriggerMode};

    fn message() -> Message {
        Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            person_email: Some("Joey@example.com".to_owned()),
            text: Some("@bot run this".to_owned()),
            mentioned_people: vec!["bot-person".to_owned()],
            ..Message::default()
        }
    }

    #[test]
    fn mention_trigger_matches_self_person_id() {
        let policy = RoomPolicy {
            allow_all_senders: true,
            ..RoomPolicy::default()
        };

        assert_eq!(
            should_trigger(&policy, &message(), Some("bot-person")),
            TriggerDecision::Matched
        );
    }

    #[test]
    fn mention_trigger_requires_self_person_id() {
        let policy = RoomPolicy {
            allow_all_senders: true,
            ..RoomPolicy::default()
        };

        assert_eq!(
            should_trigger(&policy, &message(), None),
            TriggerDecision::MissingSelfPersonId
        );
    }

    #[test]
    fn prefix_trigger_checks_body() {
        let policy = RoomPolicy {
            trigger: TriggerMode::Prefix,
            prefixes: vec!["@codex".to_owned()],
            allow_all_senders: true,
            ..RoomPolicy::default()
        };
        let mut message = message();
        message.text = Some("@codex summarize".to_owned());
        message.mentioned_people.clear();

        assert_eq!(
            should_trigger(&policy, &message, None),
            TriggerDecision::Matched
        );
    }

    #[test]
    fn prefix_trigger_prefers_visible_text_over_markdown_formatting() {
        let policy = RoomPolicy {
            trigger: TriggerMode::Prefix,
            prefixes: vec!["@codex".to_owned()],
            allow_all_senders: true,
            ..RoomPolicy::default()
        };
        let mut message = message();
        message.text = Some("@codex summarize".to_owned());
        message.markdown = Some("<@person:bot-person> summarize".to_owned());
        message.mentioned_people.clear();

        assert_eq!(
            should_trigger(&policy, &message, None),
            TriggerDecision::Matched
        );
    }

    #[test]
    fn sender_allowlist_is_case_insensitive_for_email() {
        let policy = RoomPolicy {
            allowed_person_emails: vec!["joey@example.com".to_owned()],
            ..RoomPolicy::default()
        };

        assert_eq!(
            should_trigger(&policy, &message(), Some("bot-person")),
            TriggerDecision::Matched
        );
    }

    #[test]
    fn empty_sender_allowlist_denies_by_default() {
        let policy = RoomPolicy::default();

        assert_eq!(
            should_trigger(&policy, &message(), Some("bot-person")),
            TriggerDecision::SenderNotAllowed
        );
    }

    #[test]
    fn sender_allowlist_matches_any_configured_identifier() {
        let policy = RoomPolicy {
            allowed_person_ids: vec!["person-1".to_owned()],
            allowed_person_emails: vec!["someone-else@example.com".to_owned()],
            ..RoomPolicy::default()
        };

        assert_eq!(
            should_trigger(&policy, &message(), Some("bot-person")),
            TriggerDecision::Matched
        );
    }

    #[test]
    fn renders_prompt_placeholders() {
        let context = MessageContext::from_message(&message()).unwrap();
        let prompt = render_prompt("room={room_id} sender={person_email} body={body}", &context);

        assert_eq!(
            prompt,
            "room=room-1 sender=Joey@example.com body=@bot run this"
        );
    }

    #[test]
    fn prefix_trigger_requires_boundary_after_prefix() {
        let policy = RoomPolicy {
            trigger: TriggerMode::Prefix,
            prefixes: vec!["/codex".to_owned()],
            allow_all_senders: true,
            ..RoomPolicy::default()
        };
        let mut message = message();
        message.text = Some("/codexify this".to_owned());
        message.mentioned_people.clear();

        assert_eq!(
            should_trigger(&policy, &message, None),
            TriggerDecision::PrefixNotMatched
        );

        message.text = Some("/codex this".to_owned());
        assert_eq!(
            should_trigger(&policy, &message, None),
            TriggerDecision::Matched
        );
    }
}

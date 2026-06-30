use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

use crate::canary_protocol::{
    RUNTIME_CANARY_SUITE, RuntimeCanaryFixtureInputs, RuntimeCanaryReport,
    expected_runtime_canary_final_line, parse_runtime_canary_report,
    runtime_canary_fixture_binding,
};

pub const CODEX_EXEC_CANARY_JSONL_MAX_BYTES: usize = 256 * 1024;
pub const CODEX_EXEC_CANARY_JSONL_LINE_MAX_BYTES: usize = 64 * 1024;
pub const RUNTIME_CANARY_PROBE_PATH: &str = "/bin/webex-codex-canary-probe";
pub const RUNTIME_CANARY_SHELL_PATH: &str = "/bin/sh";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCanaryExecRender {
    pub fixture_binding: String,
    pub probe_argv: Vec<String>,
    pub shell_script: String,
    pub event_command: String,
    pub prompt: String,
}

pub fn render_runtime_canary_exec(
    nonce: &str,
    inputs: &RuntimeCanaryFixtureInputs,
) -> Result<RuntimeCanaryExecRender> {
    let fixture_binding = runtime_canary_fixture_binding(nonce, inputs)?;
    let probe_argv = vec![
        RUNTIME_CANARY_PROBE_PATH.to_owned(),
        RUNTIME_CANARY_SUITE.to_owned(),
        "--nonce".to_owned(),
        nonce.to_owned(),
        "--main-pid".to_owned(),
        inputs.main_pid.to_string(),
        "--fd-secret-sha256".to_owned(),
        inputs.fd_secret_sha256.clone(),
        "--forbidden-tcp".to_owned(),
        inputs.forbidden_tcp.clone(),
        "--bot-tcp".to_owned(),
        inputs.bot_tcp.clone(),
        "--host-unix".to_owned(),
        inputs.host_unix.clone(),
        "--host-protected-path".to_owned(),
        inputs.host_protected_path.clone(),
    ];

    // The protocol validators constrain every dynamic argument to text without
    // double quotes, dollar signs, backticks, backslashes, CR, or LF.
    if probe_argv.iter().any(|argument| {
        argument
            .bytes()
            .any(|byte| matches!(byte, b'"' | b'$' | b'`' | b'\\' | b'\r' | b'\n'))
    }) {
        return Err(anyhow!("runtime canary probe argument is not shell-safe"));
    }

    let quoted_argv = probe_argv
        .iter()
        .map(|argument| format!("\"{argument}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let shell_script = format!("exec {quoted_argv}");
    let event_command = format!("{RUNTIME_CANARY_SHELL_PATH} -c '{shell_script}'");
    let final_line = expected_runtime_canary_final_line(nonce, &fixture_binding);
    let prompt = format!(
        "Run this exact POSIX shell script once and run no other command:\n\
         {shell_script}\n\
         Then reply with exactly this line and nothing else:\n\
         {final_line}"
    );

    Ok(RuntimeCanaryExecRender {
        fixture_binding,
        probe_argv,
        shell_script,
        event_command,
        prompt,
    })
}

pub fn parse_runtime_canary_exec_jsonl(
    input: &[u8],
    nonce: &str,
    inputs: &RuntimeCanaryFixtureInputs,
) -> Result<RuntimeCanaryReport> {
    if input.is_empty() || input.len() > CODEX_EXEC_CANARY_JSONL_MAX_BYTES {
        return Err(anyhow!("Codex canary JSONL has an invalid total size"));
    }
    if !input.ends_with(b"\n") || input.contains(&b'\r') {
        return Err(anyhow!("Codex canary JSONL framing is invalid"));
    }

    let rendered = render_runtime_canary_exec(nonce, inputs)?;
    let expected_final_line = expected_runtime_canary_final_line(nonce, &rendered.fixture_binding);
    let mut state = EventState::ThreadStarted;
    let mut command_id = None;
    let mut seen_item_ids = BTreeSet::new();
    let mut report = None;

    for line in input[..input.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > CODEX_EXEC_CANARY_JSONL_LINE_MAX_BYTES {
            return Err(anyhow!("Codex canary JSONL line framing is invalid"));
        }
        reject_duplicate_json_keys(line)?;
        let value: Value = serde_json::from_slice(line)
            .map_err(|error| anyhow!("Codex canary event is malformed: {error}"))?;
        let event_type = object_string_field(&value, "type", "Codex canary event")?.to_owned();

        match event_type.as_str() {
            "thread.started" => {
                require_state(state, EventState::ThreadStarted, &event_type)?;
                let event: ThreadStartedEvent = decode_event(value)?;
                require_kind(&event.event_type, &event_type)?;
                validate_protocol_id(&event.thread_id, "thread")?;
                state = EventState::TurnStarted;
            }
            "turn.started" => {
                require_state(state, EventState::TurnStarted, &event_type)?;
                let event: TurnStartedEvent = decode_event(value)?;
                require_kind(&event.event_type, &event_type)?;
                state = EventState::CommandStarted;
            }
            "item.started" => {
                require_state(state, EventState::CommandStarted, &event_type)?;
                let item_type = nested_item_type(&value)?.to_owned();
                if item_type != "command_execution" {
                    return Err(anyhow!(
                        "Codex canary item.started variant `{item_type}` is not allowed"
                    ));
                }
                let event: CommandStartedEvent = decode_event(value)?;
                require_kind(&event.event_type, &event_type)?;
                require_kind(&event.item.item_type, &item_type)?;
                validate_protocol_id(&event.item.id, "item")?;
                if !seen_item_ids.insert(event.item.id.clone()) {
                    return Err(anyhow!("Codex canary item id is duplicated"));
                }
                if event.item.command != rendered.event_command
                    || event.item.status != "in_progress"
                {
                    return Err(anyhow!(
                        "Codex canary command start does not match the fixed command"
                    ));
                }
                command_id = Some(event.item.id);
                state = EventState::CommandCompleted;
            }
            "item.completed" => {
                let item_type = nested_item_type(&value)?.to_owned();
                match item_type.as_str() {
                    "command_execution" => {
                        require_state(state, EventState::CommandCompleted, &item_type)?;
                        let event: CommandCompletedEvent = decode_event(value)?;
                        require_kind(&event.event_type, &event_type)?;
                        require_kind(&event.item.item_type, &item_type)?;
                        let expected_id = command_id.as_deref().ok_or_else(|| {
                            anyhow!("Codex canary command completion has no start")
                        })?;
                        if event.item.id != expected_id
                            || event.item.command != rendered.event_command
                            || event.item.status != "completed"
                            || event.item.exit_code != 0
                        {
                            return Err(anyhow!(
                                "Codex canary command completion does not match its start"
                            ));
                        }
                        report = Some(parse_runtime_canary_report(
                            event.item.aggregated_output.as_bytes(),
                            nonce,
                            &rendered.fixture_binding,
                        )?);
                        state = EventState::AgentMessage;
                    }
                    "reasoning" => {
                        if !matches!(state, EventState::CommandStarted | EventState::AgentMessage) {
                            return Err(anyhow!(
                                "Codex canary reasoning item is outside its allowed state"
                            ));
                        }
                        let event: ReasoningCompletedEvent = decode_event(value)?;
                        require_kind(&event.event_type, &event_type)?;
                        require_kind(&event.item.item_type, &item_type)?;
                        record_completed_item_id(&mut seen_item_ids, &event.item.id)?;
                        let _ = event.item.text;
                    }
                    "agent_message" => {
                        require_state(state, EventState::AgentMessage, &item_type)?;
                        let event: AgentMessageCompletedEvent = decode_event(value)?;
                        require_kind(&event.event_type, &event_type)?;
                        require_kind(&event.item.item_type, &item_type)?;
                        record_completed_item_id(&mut seen_item_ids, &event.item.id)?;
                        if event.item.text != expected_final_line {
                            return Err(anyhow!(
                                "Codex canary final agent message does not match its binding"
                            ));
                        }
                        state = EventState::TurnCompleted;
                    }
                    _ => {
                        return Err(anyhow!(
                            "Codex canary item.completed variant `{item_type}` is not allowed"
                        ));
                    }
                }
            }
            "turn.completed" => {
                require_state(state, EventState::TurnCompleted, &event_type)?;
                let event: TurnCompletedEvent = decode_event(value)?;
                require_kind(&event.event_type, &event_type)?;
                if event.usage.is_empty() {
                    return Err(anyhow!("Codex canary turn usage is empty"));
                }
                state = EventState::Finished;
            }
            "turn.failed" | "error" => {
                return Err(anyhow!("Codex canary emitted failure event `{event_type}`"));
            }
            _ => return Err(anyhow!("unknown Codex canary event variant `{event_type}`")),
        }
    }

    if state != EventState::Finished {
        return Err(anyhow!("Codex canary event stream is incomplete"));
    }
    report.ok_or_else(|| anyhow!("Codex canary command report is missing"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventState {
    ThreadStarted,
    TurnStarted,
    CommandStarted,
    CommandCompleted,
    AgentMessage,
    TurnCompleted,
    Finished,
}

fn require_state(actual: EventState, expected: EventState, event: &str) -> Result<()> {
    if actual != expected {
        return Err(anyhow!("Codex canary event `{event}` is out of sequence"));
    }
    Ok(())
}

fn require_kind(actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        return Err(anyhow!("Codex canary event kind changed during decoding"));
    }
    Ok(())
}

fn validate_protocol_id(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(anyhow!("Codex canary {name} id is invalid"));
    }
    Ok(())
}

fn record_completed_item_id(seen: &mut BTreeSet<String>, id: &str) -> Result<()> {
    validate_protocol_id(id, "item")?;
    if !seen.insert(id.to_owned()) {
        return Err(anyhow!("Codex canary item id is duplicated"));
    }
    Ok(())
}

fn object_string_field<'a>(value: &'a Value, field: &str, name: &str) -> Result<&'a str> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{name} has no string `{field}` field"))
}

fn nested_item_type(value: &Value) -> Result<&str> {
    let item = value
        .as_object()
        .and_then(|object| object.get("item"))
        .ok_or_else(|| anyhow!("Codex canary item event has no item"))?;
    object_string_field(item, "type", "Codex canary item")
}

fn decode_event<T>(value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|error| anyhow!("Codex canary event shape is invalid: {error}"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadStartedEvent {
    #[serde(rename = "type")]
    event_type: String,
    thread_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnStartedEvent {
    #[serde(rename = "type")]
    event_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandStartedEvent {
    #[serde(rename = "type")]
    event_type: String,
    item: CommandStartedItem,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandStartedItem {
    id: String,
    #[serde(rename = "type")]
    item_type: String,
    command: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandCompletedEvent {
    #[serde(rename = "type")]
    event_type: String,
    item: CommandCompletedItem,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandCompletedItem {
    id: String,
    #[serde(rename = "type")]
    item_type: String,
    command: String,
    aggregated_output: String,
    exit_code: i32,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningCompletedEvent {
    #[serde(rename = "type")]
    event_type: String,
    item: ReasoningCompletedItem,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningCompletedItem {
    id: String,
    #[serde(rename = "type")]
    item_type: String,
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentMessageCompletedEvent {
    #[serde(rename = "type")]
    event_type: String,
    item: AgentMessageCompletedItem,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentMessageCompletedItem {
    id: String,
    #[serde(rename = "type")]
    item_type: String,
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnCompletedEvent {
    #[serde(rename = "type")]
    event_type: String,
    usage: BTreeMap<String, Value>,
}

fn reject_duplicate_json_keys(input: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    NoDuplicateJson::deserialize(&mut deserializer)
        .map_err(|error| anyhow!("Codex canary event JSON is invalid: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow!("Codex canary event JSON is invalid: {error}"))
}

struct NoDuplicateJson;

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)?;
        Ok(Self)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        NoDuplicateJson::deserialize(deserializer)?;
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key `{key}`"
                )));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::*;
    use crate::canary_protocol::{RUNTIME_CANARY_CHECKS, RuntimeCanaryReport};

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FD_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn fixture_inputs() -> RuntimeCanaryFixtureInputs {
        RuntimeCanaryFixtureInputs {
            main_pid: 42,
            fd_secret_sha256: FD_DIGEST.to_owned(),
            forbidden_tcp: "192.0.2.10:41001".to_owned(),
            bot_tcp: "127.0.0.1:41002".to_owned(),
            host_unix: format!("/run/webex-codex-canary/{NONCE}.sock"),
            host_protected_path: format!(
                "/var/lib/webex-generic-account-bot/canary-fixtures/{NONCE}"
            ),
        }
    }

    fn passing_report() -> RuntimeCanaryReport {
        let inputs = fixture_inputs();
        let binding = runtime_canary_fixture_binding(NONCE, &inputs).unwrap();
        let checks = RUNTIME_CANARY_CHECKS
            .iter()
            .map(|name| ((*name).to_owned(), true))
            .collect::<BTreeMap<_, _>>();
        RuntimeCanaryReport::new(NONCE.to_owned(), binding, checks).unwrap()
    }

    fn success_events() -> Vec<Value> {
        let rendered = render_runtime_canary_exec(NONCE, &fixture_inputs()).unwrap();
        let report_output = String::from_utf8(passing_report().to_json_line().unwrap()).unwrap();
        let final_line = expected_runtime_canary_final_line(NONCE, &rendered.fixture_binding);
        vec![
            json!({"type": "thread.started", "thread_id": "thread-1"}),
            json!({"type": "turn.started"}),
            json!({
                "type": "item.completed",
                "item": {"id": "item-0", "type": "reasoning", "text": "Use one command."}
            }),
            json!({
                "type": "item.started",
                "item": {
                    "id": "item-1",
                    "type": "command_execution",
                    "command": rendered.event_command,
                    "status": "in_progress"
                }
            }),
            json!({
                "type": "item.completed",
                "item": {
                    "id": "item-1",
                    "type": "command_execution",
                    "command": rendered.event_command,
                    "aggregated_output": report_output,
                    "exit_code": 0,
                    "status": "completed"
                }
            }),
            json!({
                "type": "item.completed",
                "item": {"id": "item-2", "type": "reasoning", "text": "The probe completed."}
            }),
            json!({
                "type": "item.completed",
                "item": {"id": "item-3", "type": "agent_message", "text": final_line}
            }),
            json!({
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 5,
                    "reasoning_output_tokens": 2
                }
            }),
        ]
    }

    fn encode(events: &[Value]) -> Vec<u8> {
        let mut output = Vec::new();
        for event in events {
            output.extend(serde_json::to_vec(event).unwrap());
            output.push(b'\n');
        }
        output
    }

    fn assert_rejected(events: &[Value]) {
        assert!(
            parse_runtime_canary_exec_jsonl(&encode(events), NONCE, &fixture_inputs()).is_err()
        );
    }

    fn item_mut(events: &mut [Value], index: usize) -> &mut serde_json::Map<String, Value> {
        events[index]["item"].as_object_mut().unwrap()
    }

    #[test]
    fn renders_the_exact_fixed_probe_command_and_prompt() {
        let rendered = render_runtime_canary_exec(NONCE, &fixture_inputs()).unwrap();
        assert_eq!(
            rendered.probe_argv,
            vec![
                RUNTIME_CANARY_PROBE_PATH,
                RUNTIME_CANARY_SUITE,
                "--nonce",
                NONCE,
                "--main-pid",
                "42",
                "--fd-secret-sha256",
                FD_DIGEST,
                "--forbidden-tcp",
                "192.0.2.10:41001",
                "--bot-tcp",
                "127.0.0.1:41002",
                "--host-unix",
                "/run/webex-codex-canary/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sock",
                "--host-protected-path",
                "/var/lib/webex-generic-account-bot/canary-fixtures/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ]
        );
        let expected_script = rendered
            .probe_argv
            .iter()
            .map(|argument| format!("\"{argument}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let expected_script = format!("exec {expected_script}");
        assert_eq!(rendered.shell_script, expected_script);
        assert_eq!(
            rendered.event_command,
            format!("/bin/sh -c '{expected_script}'")
        );
        assert_eq!(
            rendered.prompt,
            format!(
                "Run this exact POSIX shell script once and run no other command:\n\
                 {expected_script}\n\
                 Then reply with exactly this line and nothing else:\n{}",
                expected_runtime_canary_final_line(NONCE, &rendered.fixture_binding)
            )
        );
    }

    #[test]
    fn renderer_rejects_invalid_or_noncanonical_dynamic_arguments() {
        let mut inputs = fixture_inputs();
        inputs.host_unix.push('"');
        assert!(render_runtime_canary_exec(NONCE, &inputs).is_err());
        assert!(render_runtime_canary_exec("ABC", &fixture_inputs()).is_err());

        let mut inputs = fixture_inputs();
        inputs.forbidden_tcp = "[::ffff:127.0.0.1]:41001".to_owned();
        assert!(render_runtime_canary_exec(NONCE, &inputs).is_err());
    }

    #[test]
    fn parses_one_thread_turn_command_and_bound_final_message() {
        let parsed =
            parse_runtime_canary_exec_jsonl(&encode(&success_events()), NONCE, &fixture_inputs())
                .unwrap();
        assert_eq!(parsed, passing_report());
    }

    #[test]
    fn rejects_invalid_jsonl_framing_and_size_limits() {
        assert!(parse_runtime_canary_exec_jsonl(&[], NONCE, &fixture_inputs()).is_err());

        let mut missing_lf = encode(&success_events());
        missing_lf.pop();
        assert!(parse_runtime_canary_exec_jsonl(&missing_lf, NONCE, &fixture_inputs()).is_err());

        let mut with_cr = encode(&success_events());
        with_cr.insert(1, b'\r');
        assert!(parse_runtime_canary_exec_jsonl(&with_cr, NONCE, &fixture_inputs()).is_err());

        let mut empty_line = encode(&success_events());
        empty_line.splice(0..0, [b'\n']);
        assert!(parse_runtime_canary_exec_jsonl(&empty_line, NONCE, &fixture_inputs()).is_err());

        let long_line = format!(
            "{{\"type\":\"thread.started\",\"thread_id\":\"{}\"}}\n",
            "x".repeat(CODEX_EXEC_CANARY_JSONL_LINE_MAX_BYTES)
        );
        assert!(
            parse_runtime_canary_exec_jsonl(long_line.as_bytes(), NONCE, &fixture_inputs())
                .is_err()
        );

        let mut oversized = vec![b' '; CODEX_EXEC_CANARY_JSONL_MAX_BYTES + 1];
        *oversized.last_mut().unwrap() = b'\n';
        assert!(parse_runtime_canary_exec_jsonl(&oversized, NONCE, &fixture_inputs()).is_err());
    }

    #[test]
    fn rejects_malformed_duplicate_and_unknown_json_shapes() {
        for input in [
            b"{not-json}\n".as_slice(),
            b"{\"type\":\"thread.started\",\"type\":\"thread.started\",\"thread_id\":\"x\"}\n",
            b"{\"type\":\"item.started\",\"item\":{\"id\":\"x\",\"id\":\"y\",\"type\":\"command_execution\",\"command\":\"x\",\"status\":\"in_progress\"}}\n",
            b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"input_tokens\":2}}\n",
        ] {
            assert!(parse_runtime_canary_exec_jsonl(input, NONCE, &fixture_inputs()).is_err());
        }

        let mut events = success_events();
        events[0]["unknown"] = json!(true);
        assert_rejected(&events);

        let mut events = success_events();
        item_mut(&mut events, 3).insert("unknown".to_owned(), json!(true));
        assert_rejected(&events);

        let mut events = success_events();
        events.insert(2, json!({"type": "future.event"}));
        assert_rejected(&events);

        let mut events = success_events();
        events[2]["item"]["type"] = json!("file_change");
        assert_rejected(&events);
    }

    #[test]
    fn rejects_failure_events_and_incomplete_or_multiple_turns() {
        for failure in [
            json!({"type": "error", "message": "failed"}),
            json!({"type": "turn.failed", "error": {"message": "failed"}}),
        ] {
            let mut events = success_events();
            events.insert(2, failure);
            assert_rejected(&events);
        }

        let mut events = success_events();
        events.pop();
        assert_rejected(&events);

        let mut events = success_events();
        events.insert(
            1,
            json!({"type": "thread.started", "thread_id": "thread-2"}),
        );
        assert_rejected(&events);

        let mut events = success_events();
        events.insert(2, json!({"type": "turn.started"}));
        assert_rejected(&events);

        let mut events = success_events();
        events.push(json!({"type": "turn.started"}));
        assert_rejected(&events);

        let mut events = success_events();
        events.swap(0, 1);
        assert_rejected(&events);
    }

    #[test]
    fn rejects_command_start_mutations_and_extra_commands() {
        for (field, replacement) in [
            ("command", json!("true")),
            ("status", json!("completed")),
            ("id", json!("bad id")),
        ] {
            let mut events = success_events();
            item_mut(&mut events, 3).insert(field.to_owned(), replacement);
            assert_rejected(&events);
        }

        let mut events = success_events();
        events.insert(4, events[3].clone());
        assert_rejected(&events);

        let mut events = success_events();
        let extra = events[3].clone();
        events.insert(2, extra);
        assert_rejected(&events);

        let mut events = success_events();
        events.remove(3);
        assert_rejected(&events);
    }

    #[test]
    fn rejects_command_completion_mutations_and_extra_completions() {
        for (field, replacement) in [
            ("id", json!("item-other")),
            ("command", json!("true")),
            ("status", json!("failed")),
            ("exit_code", json!(1)),
            ("aggregated_output", json!("{}\n")),
            ("aggregated_output", json!("not-json\n")),
            ("aggregated_output", json!("{}")),
        ] {
            let mut events = success_events();
            item_mut(&mut events, 4).insert(field.to_owned(), replacement);
            assert_rejected(&events);
        }

        let mut events = success_events();
        events.insert(5, events[4].clone());
        assert_rejected(&events);

        let mut events = success_events();
        events.swap(3, 4);
        assert_rejected(&events);
    }

    #[test]
    fn accepts_reasoning_only_as_ignored_non_evidence() {
        let mut events = success_events();
        let report = String::from_utf8(passing_report().to_json_line().unwrap()).unwrap();
        events[2]["item"]["text"] = json!(report);
        item_mut(&mut events, 4).insert("aggregated_output".to_owned(), json!("{}\n"));
        assert_rejected(&events);

        let mut events = success_events();
        events[6]["item"]["text"] = events[4]["item"]["aggregated_output"].clone();
        item_mut(&mut events, 4).insert("aggregated_output".to_owned(), json!("{}\n"));
        assert_rejected(&events);

        let mut events = success_events();
        events.insert(
            4,
            json!({
                "type": "item.completed",
                "item": {"id": "reasoning-between", "type": "reasoning", "text": "ignored"}
            }),
        );
        assert_rejected(&events);
    }

    #[test]
    fn requires_one_exact_completed_agent_message() {
        let mut events = success_events();
        events[6]["item"]["text"] = json!("WEBEX_CODEX_CANARY_OK wrong");
        assert_rejected(&events);

        let mut events = success_events();
        events.remove(6);
        assert_rejected(&events);

        let mut events = success_events();
        events.insert(7, events[6].clone());
        assert_rejected(&events);

        let mut events = success_events();
        events[6]["item"]["id"] = json!("item-1");
        assert_rejected(&events);

        let mut events = success_events();
        events[6]["item"]["text"] = events[4]["item"]["aggregated_output"].clone();
        assert_rejected(&events);
    }

    #[test]
    fn rejects_duplicate_keys_inside_the_aggregated_report() {
        let mut events = success_events();
        let binding = render_runtime_canary_exec(NONCE, &fixture_inputs())
            .unwrap()
            .fixture_binding;
        let duplicate_report = format!(
            "{{\"schema_version\":1,\"schema_version\":1,\"suite\":\"{RUNTIME_CANARY_SUITE}\",\"nonce\":\"{NONCE}\",\"fixture_binding\":\"{binding}\",\"checks\":{{}},\"final_line\":\"x\"}}\n"
        );
        item_mut(&mut events, 4).insert("aggregated_output".to_owned(), json!(duplicate_report));
        assert_rejected(&events);
    }
}

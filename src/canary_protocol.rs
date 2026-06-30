use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::{Result, anyhow};
use ring::digest::{SHA256, digest};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor},
};

pub const RUNTIME_CANARY_SCHEMA_VERSION: u16 = 1;
pub const RUNTIME_CANARY_SUITE: &str = "runtime-boundary-v1";
pub const RUNTIME_CANARY_REPORT_MAX_BYTES: usize = 16 * 1024;
pub const RUNTIME_CANARY_FINAL_PREFIX: &str = "WEBEX_CODEX_CANARY_OK";
pub const RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT: &str = "/run/webex-codex-canary";
pub const RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT: &str =
    "/var/lib/webex-generic-account-bot/canary-fixtures";
pub const RUNTIME_CANARY_CHECKS: &[&str] = &[
    "bot_socket_denied",
    "capability_sets_empty",
    "config_worker_socket_denied",
    "credential_path_denied",
    "final_output_denied",
    "forbidden_network_denied",
    "host_protected_path_denied",
    "host_unix_socket_denied",
    "launcher_socket_denied",
    "main_home_denied",
    "main_process_inspection_denied",
    "no_new_privileges",
    "privilege_escalation_denied",
    "sensitive_descriptors_denied",
    "setid_and_file_capabilities_absent",
    "tool_home_writable",
    "workspace_read_only",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeCanaryFixtureInputs {
    pub main_pid: u32,
    pub fd_secret_sha256: String,
    pub forbidden_tcp: String,
    pub bot_tcp: String,
    pub host_unix: String,
    pub host_protected_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCanaryHostEvidence {
    pub nonce: String,
    pub fixture_binding: String,
    pub protected_path_present_before: bool,
    pub protected_path_present_after: bool,
    pub host_unix_listener_live_before: bool,
    pub host_unix_listener_live_after: bool,
    pub host_unix_accept_count: u64,
    pub forbidden_tcp_listener_live_before: bool,
    pub forbidden_tcp_listener_live_after: bool,
    pub forbidden_tcp_accept_count: u64,
    pub bot_tcp_listener_live_before: bool,
    pub bot_tcp_listener_live_after: bool,
    pub bot_tcp_accept_count: u64,
    pub config_worker_socket_live_before: bool,
    pub config_worker_socket_live_after: bool,
    pub launcher_socket_live_before: bool,
    pub launcher_socket_live_after: bool,
}

impl RuntimeCanaryHostEvidence {
    pub fn validate(&self, expected_nonce: &str, expected_fixture_binding: &str) -> Result<()> {
        validate_runtime_canary_nonce(expected_nonce)?;
        validate_runtime_canary_fixture_binding(expected_fixture_binding)?;
        if self.nonce != expected_nonce
            || self.fixture_binding != expected_fixture_binding
            || !self.protected_path_present_before
            || !self.protected_path_present_after
            || !self.host_unix_listener_live_before
            || !self.host_unix_listener_live_after
            || self.host_unix_accept_count != 0
            || !self.forbidden_tcp_listener_live_before
            || !self.forbidden_tcp_listener_live_after
            || self.forbidden_tcp_accept_count != 0
            || !self.bot_tcp_listener_live_before
            || !self.bot_tcp_listener_live_after
            || self.bot_tcp_accept_count != 0
            || !self.config_worker_socket_live_before
            || !self.config_worker_socket_live_after
            || !self.launcher_socket_live_before
            || !self.launcher_socket_live_after
        {
            return Err(anyhow!(
                "runtime canary host evidence is incomplete or reports fixture access"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCanaryReport {
    pub schema_version: u16,
    pub suite: String,
    pub nonce: String,
    pub fixture_binding: String,
    #[serde(deserialize_with = "deserialize_runtime_canary_checks")]
    pub checks: BTreeMap<String, bool>,
    pub final_line: String,
}

fn deserialize_runtime_canary_checks<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, bool>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RuntimeCanaryChecksVisitor;

    impl<'de> Visitor<'de> for RuntimeCanaryChecksVisitor {
        type Value = BTreeMap<String, bool>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("the exact runtime canary check map without duplicate keys")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut checks = BTreeMap::new();
            while let Some((name, passed)) = map.next_entry::<String, bool>()? {
                if checks.insert(name.clone(), passed).is_some() {
                    return Err(A::Error::custom(format!(
                        "runtime canary check `{name}` is duplicated"
                    )));
                }
            }
            Ok(checks)
        }
    }

    deserializer.deserialize_map(RuntimeCanaryChecksVisitor)
}

impl RuntimeCanaryReport {
    pub fn new(
        nonce: String,
        fixture_binding: String,
        checks: BTreeMap<String, bool>,
    ) -> Result<Self> {
        let report = Self {
            schema_version: RUNTIME_CANARY_SCHEMA_VERSION,
            suite: RUNTIME_CANARY_SUITE.to_owned(),
            final_line: expected_runtime_canary_final_line(&nonce, &fixture_binding),
            nonce,
            fixture_binding,
            checks,
        };
        report.validate_shape(&report.nonce, &report.fixture_binding)?;
        Ok(report)
    }

    pub fn validate_shape(
        &self,
        expected_nonce: &str,
        expected_fixture_binding: &str,
    ) -> Result<()> {
        validate_runtime_canary_nonce(expected_nonce)?;
        validate_runtime_canary_fixture_binding(expected_fixture_binding)?;
        if self.schema_version != RUNTIME_CANARY_SCHEMA_VERSION
            || self.suite != RUNTIME_CANARY_SUITE
            || self.nonce != expected_nonce
            || self.fixture_binding != expected_fixture_binding
            || self.final_line
                != expected_runtime_canary_final_line(expected_nonce, expected_fixture_binding)
            || self.checks.len() != RUNTIME_CANARY_CHECKS.len()
            || self
                .checks
                .keys()
                .any(|name| !RUNTIME_CANARY_CHECKS.contains(&name.as_str()))
            || RUNTIME_CANARY_CHECKS
                .iter()
                .any(|name| !self.checks.contains_key(*name))
        {
            return Err(anyhow!(
                "runtime canary report does not match its fixed contract"
            ));
        }
        Ok(())
    }

    pub fn ensure_success(
        &self,
        expected_nonce: &str,
        expected_fixture_binding: &str,
        host_evidence: &RuntimeCanaryHostEvidence,
    ) -> Result<()> {
        host_evidence.validate(expected_nonce, expected_fixture_binding)?;
        self.validate_shape(expected_nonce, expected_fixture_binding)?;
        if self.checks.values().any(|passed| !passed) {
            return Err(anyhow!("runtime canary report contains a failed check"));
        }
        Ok(())
    }

    pub fn to_json_line(&self) -> Result<Vec<u8>> {
        let mut output = serde_json::to_vec(self)?;
        output.push(b'\n');
        if output.len() > RUNTIME_CANARY_REPORT_MAX_BYTES {
            return Err(anyhow!("runtime canary report exceeds its byte limit"));
        }
        Ok(output)
    }
}

pub fn parse_runtime_canary_report(
    input: &[u8],
    expected_nonce: &str,
    expected_fixture_binding: &str,
) -> Result<RuntimeCanaryReport> {
    if input.is_empty()
        || input.len() > RUNTIME_CANARY_REPORT_MAX_BYTES
        || !input.ends_with(b"\n")
        || input[..input.len() - 1].contains(&b'\n')
        || input.contains(&b'\r')
    {
        return Err(anyhow!("runtime canary report framing is invalid"));
    }
    let report: RuntimeCanaryReport = serde_json::from_slice(&input[..input.len() - 1])?;
    report.validate_shape(expected_nonce, expected_fixture_binding)?;
    Ok(report)
}

pub fn runtime_canary_fixture_binding(
    nonce: &str,
    inputs: &RuntimeCanaryFixtureInputs,
) -> Result<String> {
    validate_runtime_canary_nonce(nonce)?;
    validate_runtime_canary_nonce(&inputs.fd_secret_sha256)?;
    let forbidden_tcp = inputs
        .forbidden_tcp
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("runtime canary forbidden TCP endpoint is invalid"))?;
    let bot_tcp = inputs
        .bot_tcp
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("runtime canary bot TCP endpoint is invalid"))?;
    let expected_host_unix = format!("{RUNTIME_CANARY_HOST_UNIX_FIXTURE_ROOT}/{nonce}.sock");
    let expected_host_protected = format!("{RUNTIME_CANARY_HOST_PROTECTED_FIXTURE_ROOT}/{nonce}");
    if !(2..=i32::MAX as u32).contains(&inputs.main_pid)
        || !forbidden_tcp.ip().is_loopback()
        || forbidden_tcp.port() == 0
        || inputs.forbidden_tcp != forbidden_tcp.to_string()
        || !bot_tcp.ip().is_loopback()
        || bot_tcp.port() == 0
        || inputs.bot_tcp != bot_tcp.to_string()
        || forbidden_tcp == bot_tcp
        || inputs.host_unix != expected_host_unix
        || inputs.host_protected_path != expected_host_protected
    {
        return Err(anyhow!("runtime canary fixture inputs are invalid"));
    }
    #[derive(Serialize)]
    struct CanonicalFixtureBinding<'a> {
        schema_version: u16,
        suite: &'static str,
        nonce: &'a str,
        inputs: &'a RuntimeCanaryFixtureInputs,
    }
    let encoded = serde_json::to_vec(&CanonicalFixtureBinding {
        schema_version: RUNTIME_CANARY_SCHEMA_VERSION,
        suite: RUNTIME_CANARY_SUITE,
        nonce,
        inputs,
    })?;
    Ok(hex(digest(&SHA256, &encoded).as_ref()))
}

pub fn validate_runtime_canary_nonce(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(anyhow!(
            "runtime canary nonce must be 32 lowercase hexadecimal bytes"
        ));
    }
    Ok(())
}

pub fn validate_runtime_canary_fixture_binding(value: &str) -> Result<()> {
    validate_runtime_canary_nonce(value)
        .map_err(|_| anyhow!("runtime canary fixture binding must be a SHA-256 digest"))
}

pub fn expected_runtime_canary_final_line(nonce: &str, fixture_binding: &str) -> String {
    format!("{RUNTIME_CANARY_FINAL_PREFIX} {nonce} {fixture_binding}")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn passing_checks() -> BTreeMap<String, bool> {
        RUNTIME_CANARY_CHECKS
            .iter()
            .map(|name| ((*name).to_owned(), true))
            .collect()
    }

    fn fixture_inputs() -> RuntimeCanaryFixtureInputs {
        RuntimeCanaryFixtureInputs {
            main_pid: 42,
            fd_secret_sha256: "1".repeat(64),
            forbidden_tcp: "127.0.0.1:41001".to_owned(),
            bot_tcp: "127.0.0.1:41002".to_owned(),
            host_unix: format!("/run/webex-codex-canary/{NONCE}.sock"),
            host_protected_path: format!(
                "/var/lib/webex-generic-account-bot/canary-fixtures/{NONCE}"
            ),
        }
    }

    fn fixture_binding() -> String {
        runtime_canary_fixture_binding(NONCE, &fixture_inputs()).unwrap()
    }

    fn passing_host_evidence() -> RuntimeCanaryHostEvidence {
        RuntimeCanaryHostEvidence {
            nonce: NONCE.to_owned(),
            fixture_binding: fixture_binding(),
            protected_path_present_before: true,
            protected_path_present_after: true,
            host_unix_listener_live_before: true,
            host_unix_listener_live_after: true,
            host_unix_accept_count: 0,
            forbidden_tcp_listener_live_before: true,
            forbidden_tcp_listener_live_after: true,
            forbidden_tcp_accept_count: 0,
            bot_tcp_listener_live_before: true,
            bot_tcp_listener_live_after: true,
            bot_tcp_accept_count: 0,
            config_worker_socket_live_before: true,
            config_worker_socket_live_after: true,
            launcher_socket_live_before: true,
            launcher_socket_live_after: true,
        }
    }

    #[test]
    fn round_trips_the_exact_success_contract() {
        let binding = fixture_binding();
        let evidence = passing_host_evidence();
        let report =
            RuntimeCanaryReport::new(NONCE.to_owned(), binding.clone(), passing_checks()).unwrap();
        let encoded = report.to_json_line().unwrap();
        let parsed = parse_runtime_canary_report(&encoded, NONCE, &binding).unwrap();

        assert_eq!(parsed, report);
        parsed.ensure_success(NONCE, &binding, &evidence).unwrap();
    }

    #[test]
    fn rejects_failed_missing_unknown_and_mismatched_reports() {
        let binding = fixture_binding();
        let evidence = passing_host_evidence();
        let mut failed =
            RuntimeCanaryReport::new(NONCE.to_owned(), binding.clone(), passing_checks()).unwrap();
        failed
            .checks
            .insert(RUNTIME_CANARY_CHECKS[0].to_owned(), false);
        failed
            .ensure_success(NONCE, &binding, &evidence)
            .unwrap_err();

        let mut missing = failed.clone();
        missing.checks.remove(RUNTIME_CANARY_CHECKS[0]);
        assert!(missing.validate_shape(NONCE, &binding).is_err());
        assert!(missing.ensure_success(NONCE, &binding, &evidence).is_err());

        let mut unknown = failed.clone();
        unknown.checks.remove(RUNTIME_CANARY_CHECKS[0]);
        unknown.checks.insert("unknown".to_owned(), true);
        assert!(unknown.validate_shape(NONCE, &binding).is_err());
        assert!(unknown.ensure_success(NONCE, &binding, &evidence).is_err());

        let mut empty = failed.clone();
        empty.checks.clear();
        assert!(empty.ensure_success(NONCE, &binding, &evidence).is_err());

        let mut wrong_final = failed;
        wrong_final.final_line = "other".to_owned();
        assert!(wrong_final.validate_shape(NONCE, &binding).is_err());
        assert!(
            wrong_final
                .validate_shape(&"a".repeat(64), &binding)
                .is_err()
        );
    }

    #[test]
    fn requires_nonce_bound_live_zero_accept_host_evidence() {
        let binding = fixture_binding();
        let report =
            RuntimeCanaryReport::new(NONCE.to_owned(), binding.clone(), passing_checks()).unwrap();

        let mut unhealthy = passing_host_evidence();
        unhealthy.host_unix_listener_live_after = false;
        assert!(report.ensure_success(NONCE, &binding, &unhealthy).is_err());

        let mut accepted = passing_host_evidence();
        accepted.forbidden_tcp_accept_count = 1;
        assert!(report.ensure_success(NONCE, &binding, &accepted).is_err());

        let mut wrong_binding = passing_host_evidence();
        wrong_binding.fixture_binding = "f".repeat(64);
        assert!(
            report
                .ensure_success(NONCE, &binding, &wrong_binding)
                .is_err()
        );

        let mut changed_inputs = fixture_inputs();
        changed_inputs.main_pid += 1;
        assert_ne!(
            fixture_binding(),
            runtime_canary_fixture_binding(NONCE, &changed_inputs).unwrap()
        );
    }

    #[test]
    fn fixture_binding_rejects_noncanonical_or_unbound_inputs() {
        let mut inputs = fixture_inputs();
        inputs.main_pid = i32::MAX as u32 + 1;
        assert!(runtime_canary_fixture_binding(NONCE, &inputs).is_err());

        let mut inputs = fixture_inputs();
        inputs.forbidden_tcp = "[0:0:0:0:0:0:0:1]:41001".to_owned();
        assert!(runtime_canary_fixture_binding(NONCE, &inputs).is_err());

        let mut inputs = fixture_inputs();
        inputs.bot_tcp = inputs.forbidden_tcp.clone();
        assert!(runtime_canary_fixture_binding(NONCE, &inputs).is_err());

        let mut inputs = fixture_inputs();
        inputs.host_unix = "/run/webex-codex-canary/other.sock".to_owned();
        assert!(runtime_canary_fixture_binding(NONCE, &inputs).is_err());

        let mut inputs = fixture_inputs();
        inputs.host_protected_path =
            "/var/lib/webex-generic-account-bot/canary-fixtures/other".to_owned();
        assert!(runtime_canary_fixture_binding(NONCE, &inputs).is_err());
    }

    #[test]
    fn rejects_invalid_framing_size_nonce_and_json_fields() {
        let binding = fixture_binding();
        let report =
            RuntimeCanaryReport::new(NONCE.to_owned(), binding.clone(), passing_checks()).unwrap();
        let mut encoded = report.to_json_line().unwrap();
        encoded.pop();
        assert!(parse_runtime_canary_report(&encoded, NONCE, &binding).is_err());

        let mut multiple = report.to_json_line().unwrap();
        multiple.extend_from_slice(b"{}\n");
        assert!(parse_runtime_canary_report(&multiple, NONCE, &binding).is_err());
        assert!(
            parse_runtime_canary_report(
                &vec![b'a'; RUNTIME_CANARY_REPORT_MAX_BYTES + 1],
                NONCE,
                &binding
            )
            .is_err()
        );
        assert!(validate_runtime_canary_nonce("A").is_err());

        let mut value = serde_json::to_value(&report).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        let mut unknown = serde_json::to_vec(&value).unwrap();
        unknown.push(b'\n');
        assert!(parse_runtime_canary_report(&unknown, NONCE, &binding).is_err());

        let encoded = String::from_utf8(report.to_json_line().unwrap()).unwrap();
        let first_check = r#""bot_socket_denied":true"#;
        let duplicated =
            encoded.replacen(first_check, &format!(r#"{first_check},{first_check}"#), 1);
        assert_ne!(duplicated, encoded);
        assert!(parse_runtime_canary_report(duplicated.as_bytes(), NONCE, &binding).is_err());
    }
}

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor},
};

pub const RUNTIME_CANARY_SCHEMA_VERSION: u16 = 1;
pub const RUNTIME_CANARY_SUITE: &str = "runtime-boundary-v1";
pub const RUNTIME_CANARY_REPORT_MAX_BYTES: usize = 16 * 1024;
pub const RUNTIME_CANARY_FINAL_PREFIX: &str = "WEBEX_CODEX_CANARY_OK";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCanaryReport {
    pub schema_version: u16,
    pub suite: String,
    pub nonce: String,
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
    pub fn new(nonce: String, checks: BTreeMap<String, bool>) -> Result<Self> {
        let report = Self {
            schema_version: RUNTIME_CANARY_SCHEMA_VERSION,
            suite: RUNTIME_CANARY_SUITE.to_owned(),
            final_line: expected_runtime_canary_final_line(&nonce),
            nonce,
            checks,
        };
        report.validate_shape(&report.nonce)?;
        Ok(report)
    }

    pub fn validate_shape(&self, expected_nonce: &str) -> Result<()> {
        validate_runtime_canary_nonce(expected_nonce)?;
        if self.schema_version != RUNTIME_CANARY_SCHEMA_VERSION
            || self.suite != RUNTIME_CANARY_SUITE
            || self.nonce != expected_nonce
            || self.final_line != expected_runtime_canary_final_line(expected_nonce)
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

    pub fn ensure_success(&self, expected_nonce: &str) -> Result<()> {
        self.validate_shape(expected_nonce)?;
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
    report.validate_shape(expected_nonce)?;
    Ok(report)
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

pub fn expected_runtime_canary_final_line(nonce: &str) -> String {
    format!("{RUNTIME_CANARY_FINAL_PREFIX} {nonce}")
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

    #[test]
    fn round_trips_the_exact_success_contract() {
        let report = RuntimeCanaryReport::new(NONCE.to_owned(), passing_checks()).unwrap();
        let encoded = report.to_json_line().unwrap();
        let parsed = parse_runtime_canary_report(&encoded, NONCE).unwrap();

        assert_eq!(parsed, report);
        parsed.ensure_success(NONCE).unwrap();
    }

    #[test]
    fn rejects_failed_missing_unknown_and_mismatched_reports() {
        let mut failed = RuntimeCanaryReport::new(NONCE.to_owned(), passing_checks()).unwrap();
        failed
            .checks
            .insert(RUNTIME_CANARY_CHECKS[0].to_owned(), false);
        failed.ensure_success(NONCE).unwrap_err();

        let mut missing = failed.clone();
        missing.checks.remove(RUNTIME_CANARY_CHECKS[0]);
        assert!(missing.validate_shape(NONCE).is_err());
        assert!(missing.ensure_success(NONCE).is_err());

        let mut unknown = failed.clone();
        unknown.checks.remove(RUNTIME_CANARY_CHECKS[0]);
        unknown.checks.insert("unknown".to_owned(), true);
        assert!(unknown.validate_shape(NONCE).is_err());
        assert!(unknown.ensure_success(NONCE).is_err());

        let mut empty = failed.clone();
        empty.checks.clear();
        assert!(empty.ensure_success(NONCE).is_err());

        let mut wrong_final = failed;
        wrong_final.final_line = "other".to_owned();
        assert!(wrong_final.validate_shape(NONCE).is_err());
        assert!(wrong_final.validate_shape(&"a".repeat(64)).is_err());
    }

    #[test]
    fn rejects_invalid_framing_size_nonce_and_json_fields() {
        let report = RuntimeCanaryReport::new(NONCE.to_owned(), passing_checks()).unwrap();
        let mut encoded = report.to_json_line().unwrap();
        encoded.pop();
        assert!(parse_runtime_canary_report(&encoded, NONCE).is_err());

        let mut multiple = report.to_json_line().unwrap();
        multiple.extend_from_slice(b"{}\n");
        assert!(parse_runtime_canary_report(&multiple, NONCE).is_err());
        assert!(
            parse_runtime_canary_report(&vec![b'a'; RUNTIME_CANARY_REPORT_MAX_BYTES + 1], NONCE)
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
        assert!(parse_runtime_canary_report(&unknown, NONCE).is_err());

        let encoded = String::from_utf8(report.to_json_line().unwrap()).unwrap();
        let first_check = r#""bot_socket_denied":true"#;
        let duplicated =
            encoded.replacen(first_check, &format!(r#"{first_check},{first_check}"#), 1);
        assert_ne!(duplicated, encoded);
        assert!(parse_runtime_canary_report(duplicated.as_bytes(), NONCE).is_err());
    }
}

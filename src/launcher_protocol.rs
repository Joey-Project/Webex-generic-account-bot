use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();
pub const REQUEST_MAX_BYTES: usize = 512 * 1024;
pub const RESPONSE_MAX_BYTES: usize = 1024 * 1024;

pub const RUN_ID_MAX_BYTES: usize = 64;
pub const MESSAGE_ID_MAX_BYTES: usize = 256;
pub const PROMPT_MAX_CHARS: usize = 64 * 1024;
pub const PROMPT_MAX_BYTES: usize = 256 * 1024;
pub const WORKSPACE_PATH_MAX_BYTES: usize = 4 * 1024;
pub const MODEL_MAX_BYTES: usize = 128;
pub const TIMEOUT_SECONDS_MIN: u64 = 1;
pub const TIMEOUT_SECONDS_MAX: u64 = 60 * 60;
pub const OUTPUT_CHAR_LIMIT_MIN: u64 = 1;
pub const OUTPUT_CHAR_LIMIT_MAX: u64 = 100_000;
pub const OUTPUT_MAX_BYTES: usize = 4 * OUTPUT_CHAR_LIMIT_MAX as usize;
pub const ERROR_MESSAGE_MAX_CHARS: usize = 1024;
pub const ERROR_MESSAGE_MAX_BYTES: usize = 4 * ERROR_MESSAGE_MAX_CHARS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherRequest {
    pub version: u16,
    pub request: LauncherRequestKind,
}

impl LauncherRequest {
    pub fn preflight() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request: LauncherRequestKind::Preflight(PreflightRequest {}),
        }
    }

    pub fn execute(request: ExecuteRequest) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request: LauncherRequestKind::Execute(request),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        match &self.request {
            LauncherRequestKind::Preflight(request) => request.validate(),
            LauncherRequestKind::Execute(request) => request.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LauncherRequestKind {
    Preflight(PreflightRequest),
    Execute(ExecuteRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreflightRequest {}

impl PreflightRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub run_id: String,
    pub message_id: String,
    pub prompt: String,
    pub workspace: PathBuf,
    pub model: Option<String>,
    pub reasoning_effort: Option<ReasoningEffort>,
    pub timeout_seconds: u64,
    pub output_char_limit: u64,
    pub skip_git_repo_check: bool,
}

impl ExecuteRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_run_id(&self.run_id)?;
        validate_message_id(&self.message_id)?;
        validate_prompt(&self.prompt)?;
        validate_workspace(&self.workspace)?;
        if let Some(model) = &self.model {
            validate_model(model)?;
        }
        if self.reasoning_effort == Some(ReasoningEffort::Unknown) {
            return Err(ProtocolError::InvalidReasoningEffort);
        }
        validate_timeout_seconds(self.timeout_seconds)?;
        validate_output_char_limit(self.output_char_limit)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    #[doc(hidden)]
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherResponse {
    pub version: u16,
    pub response: LauncherResponseKind,
}

impl LauncherResponse {
    pub fn ready(execution_available: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            response: LauncherResponseKind::Ready(ReadyResponse {
                execution_available,
            }),
        }
    }

    pub fn completed(response: CompletedResponse) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            response: LauncherResponseKind::Completed(response),
        }
    }

    pub fn rejected(response: RejectedResponse) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            response: LauncherResponseKind::Rejected(response),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        match &self.response {
            LauncherResponseKind::Ready(response) => response.validate(),
            LauncherResponseKind::Completed(response) => response.validate(),
            LauncherResponseKind::Rejected(response) => response.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LauncherResponseKind {
    Ready(ReadyResponse),
    Completed(CompletedResponse),
    Rejected(RejectedResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyResponse {
    pub execution_available: bool,
}

impl ReadyResponse {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompletedResponse {
    pub run_id: String,
    pub output: String,
    pub truncated: bool,
}

impl CompletedResponse {
    pub fn bounded(
        run_id: impl Into<String>,
        output: &str,
        output_char_limit: u64,
    ) -> Result<Self, ProtocolError> {
        validate_output_char_limit(output_char_limit)?;
        let run_id = run_id.into();
        validate_run_id(&run_id)?;
        let (output, truncated) = bound_output(output, output_char_limit)?;
        Ok(Self {
            run_id,
            output,
            truncated,
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_run_id(&self.run_id)?;
        if self.output.chars().count() > OUTPUT_CHAR_LIMIT_MAX as usize
            || self.output.len() > OUTPUT_MAX_BYTES
        {
            return Err(ProtocolError::InvalidOutput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RejectedResponse {
    pub run_id: Option<String>,
    pub code: RejectionCode,
    pub message: String,
}

impl RejectedResponse {
    pub fn bounded(
        run_id: Option<String>,
        code: RejectionCode,
        message: &str,
    ) -> Result<Self, ProtocolError> {
        if let Some(run_id) = &run_id {
            validate_run_id(run_id)?;
        }
        let response = Self {
            run_id,
            code,
            message: bound_error_message(message),
        };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if let Some(run_id) = &self.run_id {
            validate_run_id(run_id)?;
        }
        if self.message.is_empty()
            || self.message.chars().count() > ERROR_MESSAGE_MAX_CHARS
            || self.message.len() > ERROR_MESSAGE_MAX_BYTES
            || self.message.chars().any(char::is_control)
        {
            return Err(ProtocolError::InvalidErrorMessage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    UnsupportedVersion,
    MalformedRequest,
    RequestTooLarge,
    InvalidRunId,
    InvalidMessageId,
    InvalidPrompt,
    InvalidWorkspace,
    InvalidModel,
    InvalidReasoningEffort,
    InvalidTimeout,
    InvalidOutputLimit,
    ExecutionUnavailable,
    ExecutionTimedOut,
    ExecutionFailed,
    InternalError,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("protocol frame is shorter than its length prefix")]
    FrameTooShort,
    #[error("protocol frame has an empty JSON payload")]
    EmptyPayload,
    #[error("protocol frame length does not match its prefix")]
    FrameLengthMismatch,
    #[error("launcher request exceeds the protocol byte limit")]
    RequestTooLarge,
    #[error("launcher response exceeds the protocol byte limit")]
    ResponseTooLarge,
    #[error("launcher request JSON is invalid")]
    InvalidRequestJson,
    #[error("launcher response JSON is invalid")]
    InvalidResponseJson,
    #[error("launcher protocol version is unsupported")]
    UnsupportedVersion,
    #[error("launcher run ID is invalid")]
    InvalidRunId,
    #[error("launcher message ID is invalid")]
    InvalidMessageId,
    #[error("launcher prompt is invalid")]
    InvalidPrompt,
    #[error("launcher workspace path is invalid")]
    InvalidWorkspace,
    #[error("launcher model is invalid")]
    InvalidModel,
    #[error("launcher reasoning effort is invalid")]
    InvalidReasoningEffort,
    #[error("launcher timeout is outside the protocol limits")]
    InvalidTimeout,
    #[error("launcher output character limit is outside the protocol limits")]
    InvalidOutputLimit,
    #[error("launcher output exceeds the protocol limits")]
    InvalidOutput,
    #[error("launcher rejection message is invalid")]
    InvalidErrorMessage,
}

pub fn encode_request_frame(request: &LauncherRequest) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    encode_frame(
        request,
        REQUEST_MAX_BYTES,
        ProtocolError::RequestTooLarge,
        ProtocolError::InvalidRequestJson,
    )
}

pub fn decode_request_frame(frame: &[u8]) -> Result<LauncherRequest, ProtocolError> {
    let request: LauncherRequest = decode_frame(
        frame,
        REQUEST_MAX_BYTES,
        ProtocolError::RequestTooLarge,
        ProtocolError::InvalidRequestJson,
    )?;
    request.validate()?;
    Ok(request)
}

pub fn encode_response_frame(response: &LauncherResponse) -> Result<Vec<u8>, ProtocolError> {
    response.validate()?;
    encode_frame(
        response,
        RESPONSE_MAX_BYTES,
        ProtocolError::ResponseTooLarge,
        ProtocolError::InvalidResponseJson,
    )
}

pub fn decode_response_frame(frame: &[u8]) -> Result<LauncherResponse, ProtocolError> {
    let response: LauncherResponse = decode_frame(
        frame,
        RESPONSE_MAX_BYTES,
        ProtocolError::ResponseTooLarge,
        ProtocolError::InvalidResponseJson,
    )?;
    response.validate()?;
    Ok(response)
}

pub fn bound_output(output: &str, output_char_limit: u64) -> Result<(String, bool), ProtocolError> {
    validate_output_char_limit(output_char_limit)?;
    let limit = output_char_limit as usize;
    if output.chars().count() <= limit {
        return Ok((output.to_owned(), false));
    }
    Ok((output.chars().take(limit).collect(), true))
}

pub fn bound_error_message(message: &str) -> String {
    let sanitized: String = message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(ERROR_MESSAGE_MAX_CHARS)
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        "launcher request rejected".to_owned()
    } else {
        sanitized.to_owned()
    }
}

fn validate_version(version: u16) -> Result<(), ProtocolError> {
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(())
}

fn validate_run_id(run_id: &str) -> Result<(), ProtocolError> {
    let mut bytes = run_id.bytes();
    let first = bytes.next().ok_or(ProtocolError::InvalidRunId)?;
    if run_id.len() > RUN_ID_MAX_BYTES
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::InvalidRunId);
    }
    Ok(())
}

fn validate_message_id(message_id: &str) -> Result<(), ProtocolError> {
    if message_id.is_empty()
        || message_id.len() > MESSAGE_ID_MAX_BYTES
        || !message_id.is_ascii()
        || message_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProtocolError::InvalidMessageId);
    }
    Ok(())
}

fn validate_prompt(prompt: &str) -> Result<(), ProtocolError> {
    if prompt.trim().is_empty()
        || prompt.len() > PROMPT_MAX_BYTES
        || prompt.chars().count() > PROMPT_MAX_CHARS
        || prompt.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(ProtocolError::InvalidPrompt);
    }
    Ok(())
}

fn validate_workspace(workspace: &Path) -> Result<(), ProtocolError> {
    let Some(workspace_text) = workspace.to_str() else {
        return Err(ProtocolError::InvalidWorkspace);
    };
    if !workspace.is_absolute()
        || workspace_text.len() > WORKSPACE_PATH_MAX_BYTES
        || workspace_text.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidWorkspace);
    }
    let Some(relative) = workspace_text.strip_prefix('/') else {
        return Err(ProtocolError::InvalidWorkspace);
    };
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(ProtocolError::InvalidWorkspace);
    }
    Ok(())
}

fn validate_model(model: &str) -> Result<(), ProtocolError> {
    if model.is_empty()
        || model.len() > MODEL_MAX_BYTES
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidModel);
    }
    Ok(())
}

fn validate_timeout_seconds(timeout_seconds: u64) -> Result<(), ProtocolError> {
    if !(TIMEOUT_SECONDS_MIN..=TIMEOUT_SECONDS_MAX).contains(&timeout_seconds) {
        return Err(ProtocolError::InvalidTimeout);
    }
    Ok(())
}

fn validate_output_char_limit(output_char_limit: u64) -> Result<(), ProtocolError> {
    if !(OUTPUT_CHAR_LIMIT_MIN..=OUTPUT_CHAR_LIMIT_MAX).contains(&output_char_limit) {
        return Err(ProtocolError::InvalidOutputLimit);
    }
    Ok(())
}

fn encode_frame<T: Serialize>(
    value: &T,
    max_bytes: usize,
    too_large: ProtocolError,
    invalid_json: ProtocolError,
) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(value).map_err(|_| invalid_json)?;
    if payload.is_empty() {
        return Err(ProtocolError::EmptyPayload);
    }
    if payload.len() > max_bytes || payload.len() > u32::MAX as usize {
        return Err(too_large);
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_frame<T: DeserializeOwned>(
    frame: &[u8],
    max_bytes: usize,
    too_large: ProtocolError,
    invalid_json: ProtocolError,
) -> Result<T, ProtocolError> {
    let header: [u8; FRAME_HEADER_BYTES] = frame
        .get(..FRAME_HEADER_BYTES)
        .ok_or(ProtocolError::FrameTooShort)?
        .try_into()
        .map_err(|_| ProtocolError::FrameTooShort)?;
    let payload_len = u32::from_be_bytes(header) as usize;
    if payload_len == 0 {
        return Err(ProtocolError::EmptyPayload);
    }
    if payload_len > max_bytes {
        return Err(too_large);
    }
    let expected_len = FRAME_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(ProtocolError::FrameLengthMismatch)?;
    if frame.len() != expected_len {
        return Err(ProtocolError::FrameLengthMismatch);
    }
    serde_json::from_slice(&frame[FRAME_HEADER_BYTES..]).map_err(|_| invalid_json)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn execute_request() -> ExecuteRequest {
        ExecuteRequest {
            run_id: "run_20260628-01".to_owned(),
            message_id: "message-123".to_owned(),
            prompt: "Inspect the workspace.\nReturn findings.".to_owned(),
            workspace: PathBuf::from("/srv/workspaces/repository"),
            model: Some("gpt-5.5-codex".to_owned()),
            reasoning_effort: Some(ReasoningEffort::High),
            timeout_seconds: 600,
            output_char_limit: 6_000,
            skip_git_repo_check: false,
        }
    }

    fn frame_json(value: Value) -> Vec<u8> {
        let payload = serde_json::to_vec(&value).unwrap();
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn request_variants_round_trip() {
        for request in [
            LauncherRequest::preflight(),
            LauncherRequest::execute(execute_request()),
        ] {
            let frame = encode_request_frame(&request).unwrap();
            assert_eq!(decode_request_frame(&frame).unwrap(), request);
        }
    }

    #[test]
    fn response_variants_round_trip_with_stable_rejection_code() {
        let responses = [
            LauncherResponse::ready(false),
            LauncherResponse::completed(CompletedResponse::bounded("run-1", "done", 100).unwrap()),
            LauncherResponse::rejected(
                RejectedResponse::bounded(
                    Some("run-1".to_owned()),
                    RejectionCode::ExecutionTimedOut,
                    "execution timed out",
                )
                .unwrap(),
            ),
        ];
        for response in responses {
            let frame = encode_response_frame(&response).unwrap();
            assert_eq!(decode_response_frame(&frame).unwrap(), response);
        }

        let encoded = encode_response_frame(&LauncherResponse::rejected(
            RejectedResponse::bounded(None, RejectionCode::InvalidWorkspace, "invalid workspace")
                .unwrap(),
        ))
        .unwrap();
        let json: Value = serde_json::from_slice(&encoded[FRAME_HEADER_BYTES..]).unwrap();
        assert_eq!(
            json["response"]["code"],
            Value::String("invalid_workspace".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_fields_at_every_request_level() {
        let unknown_envelope = frame_json(json!({
            "version": PROTOCOL_VERSION,
            "request": {"type": "preflight"},
            "extra": true
        }));
        assert_eq!(
            decode_request_frame(&unknown_envelope),
            Err(ProtocolError::InvalidRequestJson)
        );

        let unknown_preflight = frame_json(json!({
            "version": PROTOCOL_VERSION,
            "request": {"type": "preflight", "extra": true}
        }));
        assert_eq!(
            decode_request_frame(&unknown_preflight),
            Err(ProtocolError::InvalidRequestJson)
        );

        let mut execute =
            serde_json::to_value(LauncherRequest::execute(execute_request())).unwrap();
        execute["request"]["extra"] = json!(true);
        assert_eq!(
            decode_request_frame(&frame_json(execute)),
            Err(ProtocolError::InvalidRequestJson)
        );
    }

    #[test]
    fn rejects_dangerous_execute_fields() {
        for field in [
            "executable",
            "argv",
            "env",
            "credential",
            "credentials",
            "socket",
            "unit",
            "output_path",
            "sandbox",
            "approval",
            "approval_policy",
        ] {
            let mut value =
                serde_json::to_value(LauncherRequest::execute(execute_request())).unwrap();
            value["request"][field] = json!("attacker-controlled");
            assert_eq!(
                decode_request_frame(&frame_json(value)),
                Err(ProtocolError::InvalidRequestJson),
                "field {field} was accepted"
            );
        }
    }

    #[test]
    fn rejects_oversized_mismatched_and_trailing_frames() {
        let mut oversized = Vec::from(((REQUEST_MAX_BYTES + 1) as u32).to_be_bytes());
        oversized.extend_from_slice(b"{}");
        assert_eq!(
            decode_request_frame(&oversized),
            Err(ProtocolError::RequestTooLarge)
        );

        let mut trailing = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        trailing.push(0);
        assert_eq!(
            decode_request_frame(&trailing),
            Err(ProtocolError::FrameLengthMismatch)
        );

        let mut trailing_json = br#"{"version":1,"request":{"type":"preflight"}} true"#.to_vec();
        let mut frame = Vec::from((trailing_json.len() as u32).to_be_bytes());
        frame.append(&mut trailing_json);
        assert_eq!(
            decode_request_frame(&frame),
            Err(ProtocolError::InvalidRequestJson)
        );
    }

    #[test]
    fn rejects_invalid_ids_prompt_and_model() {
        for run_id in ["", "-leading", "has.dot", "has/slash"] {
            let mut request = execute_request();
            request.run_id = run_id.to_owned();
            assert_eq!(request.validate(), Err(ProtocolError::InvalidRunId));
        }
        let mut request = execute_request();
        request.run_id = "a".repeat(RUN_ID_MAX_BYTES + 1);
        assert_eq!(request.validate(), Err(ProtocolError::InvalidRunId));

        let mut request = execute_request();
        request.message_id = "m".repeat(MESSAGE_ID_MAX_BYTES + 1);
        assert_eq!(request.validate(), Err(ProtocolError::InvalidMessageId));

        for message_id in ["", "line\nbreak", "non-ascii-é"] {
            let mut request = execute_request();
            request.message_id = message_id.to_owned();
            assert_eq!(request.validate(), Err(ProtocolError::InvalidMessageId));
        }

        for prompt in ["", " \n\t", "contains\0nul"] {
            let mut request = execute_request();
            request.prompt = prompt.to_owned();
            assert_eq!(request.validate(), Err(ProtocolError::InvalidPrompt));
        }
        let mut request = execute_request();
        request.prompt = "p".repeat(PROMPT_MAX_CHARS + 1);
        assert_eq!(request.validate(), Err(ProtocolError::InvalidPrompt));

        for model in ["", "model/with/slash", "model with spaces"] {
            let mut request = execute_request();
            request.model = Some(model.to_owned());
            assert_eq!(request.validate(), Err(ProtocolError::InvalidModel));
        }

        let mut value = serde_json::to_value(LauncherRequest::execute(execute_request())).unwrap();
        value["request"]["reasoning_effort"] = json!("ultra");
        assert_eq!(
            decode_request_frame(&frame_json(value)),
            Err(ProtocolError::InvalidReasoningEffort)
        );
    }

    #[test]
    fn rejects_invalid_paths_and_limits() {
        for workspace in [
            "relative/path",
            "/",
            "/srv/../root",
            "/srv/./repo",
            "/srv//repo",
            "/srv/repo/",
        ] {
            let mut request = execute_request();
            request.workspace = PathBuf::from(workspace);
            assert_eq!(request.validate(), Err(ProtocolError::InvalidWorkspace));
        }
        let mut request = execute_request();
        request.workspace = PathBuf::from(format!("/{}", "w".repeat(WORKSPACE_PATH_MAX_BYTES)));
        assert_eq!(request.validate(), Err(ProtocolError::InvalidWorkspace));

        for timeout_seconds in [0, TIMEOUT_SECONDS_MAX + 1] {
            let mut request = execute_request();
            request.timeout_seconds = timeout_seconds;
            assert_eq!(request.validate(), Err(ProtocolError::InvalidTimeout));
        }

        for output_char_limit in [0, OUTPUT_CHAR_LIMIT_MAX + 1] {
            let mut request = execute_request();
            request.output_char_limit = output_char_limit;
            assert_eq!(request.validate(), Err(ProtocolError::InvalidOutputLimit));
        }
    }

    #[test]
    fn bounds_output_and_rejection_messages_by_characters() {
        let completed = CompletedResponse::bounded("run-1", "aé中z", 3).unwrap();
        assert_eq!(completed.output, "aé中");
        assert!(completed.truncated);
        completed.validate().unwrap();

        let oversized = CompletedResponse {
            run_id: "run-1".to_owned(),
            output: "x".repeat(OUTPUT_CHAR_LIMIT_MAX as usize + 1),
            truncated: false,
        };
        assert_eq!(oversized.validate(), Err(ProtocolError::InvalidOutput));

        let rejected = RejectedResponse::bounded(
            None,
            RejectionCode::InternalError,
            &("x".repeat(ERROR_MESSAGE_MAX_CHARS + 20) + "\nsecret"),
        )
        .unwrap();
        assert_eq!(rejected.message.chars().count(), ERROR_MESSAGE_MAX_CHARS);
        assert!(!rejected.message.chars().any(char::is_control));
    }

    #[test]
    fn rejects_unknown_response_fields_and_unsupported_versions() {
        let response = frame_json(json!({
            "version": PROTOCOL_VERSION,
            "response": {"type": "ready", "extra": true}
        }));
        assert_eq!(
            decode_response_frame(&response),
            Err(ProtocolError::InvalidResponseJson)
        );

        let unsupported = frame_json(json!({
            "version": PROTOCOL_VERSION + 1,
            "request": {"type": "preflight"}
        }));
        assert_eq!(
            decode_request_frame(&unsupported),
            Err(ProtocolError::UnsupportedVersion)
        );
    }
}

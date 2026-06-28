#[cfg(target_os = "linux")]
use std::os::{
    fd::{AsRawFd, FromRawFd, RawFd},
    unix::net::UnixStream as StdUnixStream,
};

use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};
#[cfg(target_os = "linux")]
use webex_generic_account_bot::{
    codex_launcher::{
        authorise_bot_peer, drop_peer_inspection_capability, socket_peer_credentials,
        validate_launcher_process, validate_socket_stdio,
    },
    launcher_protocol::{
        FRAME_HEADER_BYTES, LauncherRequestKind, LauncherResponse, REQUEST_MAX_BYTES,
        RejectedResponse, RejectionCode, decode_request_frame, encode_response_frame,
    },
};

#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    validate_launcher_process()?;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let stdout_fd = std::io::stdout().as_raw_fd();
    validate_socket_stdio(stdin_fd, stdout_fd)?;
    let mut socket = duplicate_launcher_socket(stdin_fd)?;

    let peer = socket_peer_credentials(stdin_fd)?;
    let peer = authorise_bot_peer(peer).await?;
    drop_peer_inspection_capability()?;
    peer.ensure_alive()?;

    let frame = timeout(IO_TIMEOUT, read_request_frame_from(&mut socket))
        .await
        .map_err(|_| anyhow!("launcher request read timed out"))??;
    peer.ensure_alive()?;
    let response = response_for_request(decode_request_frame(&frame))?;
    peer.ensure_alive()?;
    write_response(&mut socket, &response).await
}

#[cfg(target_os = "linux")]
fn response_for_request(
    request: Result<
        webex_generic_account_bot::launcher_protocol::LauncherRequest,
        webex_generic_account_bot::launcher_protocol::ProtocolError,
    >,
) -> Result<LauncherResponse> {
    Ok(match request {
        Ok(request) => match request.request {
            LauncherRequestKind::Preflight(_) => LauncherResponse::ready(false),
            LauncherRequestKind::Execute(request) => {
                LauncherResponse::rejected(RejectedResponse::bounded(
                    Some(request.run_id),
                    RejectionCode::ExecutionUnavailable,
                    "ephemeral Codex execution is not enabled",
                )?)
            }
        },
        Err(error) => LauncherResponse::rejected(RejectedResponse::bounded(
            None,
            protocol_rejection_code(error),
            "launcher request failed protocol validation",
        )?),
    })
}

#[cfg(target_os = "linux")]
fn duplicate_launcher_socket(fd: RawFd) -> Result<tokio::net::UnixStream> {
    // SAFETY: fcntl does not dereference userspace pointers for F_DUPFD_CLOEXEC.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this process.
    let socket = unsafe { StdUnixStream::from_raw_fd(duplicate) };
    socket.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(socket)?)
}

#[cfg(target_os = "linux")]
async fn read_request_frame_from<R>(input: &mut R) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    input.read_exact(&mut header).await?;
    let payload_len = u32::from_be_bytes(header) as usize;
    let mut frame =
        Vec::with_capacity(FRAME_HEADER_BYTES.saturating_add(payload_len.min(REQUEST_MAX_BYTES)));
    frame.extend_from_slice(&header);
    if payload_len == 0 || payload_len > REQUEST_MAX_BYTES {
        return Ok(frame);
    }

    let mut payload = vec![0_u8; payload_len];
    input.read_exact(&mut payload).await?;
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(target_os = "linux")]
async fn write_response<W>(output: &mut W, response: &LauncherResponse) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let frame = encode_response_frame(response)?;
    timeout(IO_TIMEOUT, async {
        output.write_all(&frame).await?;
        output.shutdown().await
    })
    .await
    .map_err(|_| anyhow!("launcher response write timed out"))??;
    Ok(())
}

#[cfg(target_os = "linux")]
fn protocol_rejection_code(
    error: webex_generic_account_bot::launcher_protocol::ProtocolError,
) -> RejectionCode {
    use webex_generic_account_bot::launcher_protocol::ProtocolError;

    match error {
        ProtocolError::UnsupportedVersion => RejectionCode::UnsupportedVersion,
        ProtocolError::RequestTooLarge => RejectionCode::RequestTooLarge,
        ProtocolError::InvalidRunId => RejectionCode::InvalidRunId,
        ProtocolError::InvalidMessageId => RejectionCode::InvalidMessageId,
        ProtocolError::InvalidPrompt => RejectionCode::InvalidPrompt,
        ProtocolError::InvalidWorkspace => RejectionCode::InvalidWorkspace,
        ProtocolError::InvalidModel => RejectionCode::InvalidModel,
        ProtocolError::InvalidReasoningEffort => RejectionCode::InvalidReasoningEffort,
        ProtocolError::InvalidTimeout => RejectionCode::InvalidTimeout,
        ProtocolError::InvalidOutputLimit => RejectionCode::InvalidOutputLimit,
        _ => RejectionCode::MalformedRequest,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Err(anyhow!("the Codex launcher is supported only on Linux"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::path::PathBuf;

    use webex_generic_account_bot::launcher_protocol::{
        ExecuteRequest, LauncherRequest, LauncherResponseKind, ProtocolError, encode_request_frame,
    };

    use super::*;

    #[test]
    fn preflight_reports_that_execution_is_unavailable() {
        let response = response_for_request(Ok(LauncherRequest::preflight())).unwrap();

        assert!(matches!(
            response.response,
            LauncherResponseKind::Ready(response) if !response.execution_available
        ));
    }

    #[test]
    fn execute_is_rejected_without_an_execution_backend() {
        let request = ExecuteRequest {
            run_id: "run-1".to_owned(),
            message_id: "message-1".to_owned(),
            prompt: "Inspect the workspace".to_owned(),
            workspace: PathBuf::from("/srv/workspaces/run-1"),
            model: None,
            reasoning_effort: None,
            timeout_seconds: 60,
            output_char_limit: 6_000,
            skip_git_repo_check: true,
        };

        let response = response_for_request(Ok(LauncherRequest::execute(request))).unwrap();

        assert!(matches!(
            response.response,
            LauncherResponseKind::Rejected(response)
                if response.run_id.as_deref() == Some("run-1")
                    && response.code == RejectionCode::ExecutionUnavailable
        ));
    }

    #[test]
    fn malformed_requests_receive_a_bounded_stable_rejection() {
        let response = response_for_request(Err(ProtocolError::InvalidRequestJson)).unwrap();

        assert!(matches!(
            response.response,
            LauncherResponseKind::Rejected(response)
                if response.run_id.is_none()
                    && response.code == RejectionCode::MalformedRequest
        ));
    }

    #[tokio::test]
    async fn length_prefixed_request_does_not_wait_for_eof() {
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(frame.len());
        writer.write_all(&frame).await.unwrap();

        let decoded = timeout(
            Duration::from_millis(100),
            read_request_frame_from(&mut reader),
        )
        .await
        .expect("reader must not wait for the writer to close")
        .unwrap();

        assert_eq!(decoded, frame);
        drop(writer);
    }
}

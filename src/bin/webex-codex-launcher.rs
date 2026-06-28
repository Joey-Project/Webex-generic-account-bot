#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use tokio::time::{Duration, timeout};
#[cfg(target_os = "linux")]
use webex_generic_account_bot::{
    codex_launcher::{
        AuthorisedPeer, authorise_bot_peer, drop_peer_inspection_capability,
        socket_peer_credentials, validate_launcher_process, validate_socket_stdio,
    },
    isolated_execution::{self, ExecutionCancellation, IsolatedExecutionError, IsolatedRunResult},
    launcher_protocol::{
        CompletedResponse, FRAME_HEADER_BYTES, LAUNCHER_CANCELLATION_DRAIN_SECONDS,
        LauncherRequestKind, LauncherResponse, REQUEST_MAX_BYTES, RejectedResponse, RejectionCode,
        decode_request_frame, encode_response_frame,
    },
};

#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const CONTROL_BUFFER_BYTES: usize = 128;
#[cfg(target_os = "linux")]
const STUCK_WORK_EXIT_CODE: i32 = 70;

#[cfg(target_os = "linux")]
struct ReceivedPacket {
    frame: Vec<u8>,
    sender: webex_generic_account_bot::codex_launcher::PeerCredentials,
    truncated: bool,
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct ControlBuffer([u8; CONTROL_BUFFER_BYTES]);

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    validate_launcher_process()?;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let stdout_fd = std::io::stdout().as_raw_fd();
    validate_socket_stdio(stdin_fd, stdout_fd)?;
    let socket = duplicate_launcher_socket(stdin_fd)?;

    let peer = socket_peer_credentials(stdin_fd)?;
    let peer = authorise_bot_peer(stdin_fd, peer).await?;
    drop_peer_inspection_capability()?;
    peer.ensure_alive()?;

    let packet = timeout(IO_TIMEOUT, receive_request_packet(&socket))
        .await
        .map_err(|_| anyhow!("launcher request read timed out"))??;
    if !request_writer_is_authorised(packet.sender, peer.credentials()) {
        return Err(anyhow!("launcher request writer is not authorised"));
    }
    peer.ensure_alive()?;
    let request = if packet.truncated {
        Err(webex_generic_account_bot::launcher_protocol::ProtocolError::RequestTooLarge)
    } else {
        decode_request_frame(&packet.frame)
    };
    let response = response_for_request(request, &peer, &socket).await?;
    peer.ensure_alive()?;
    write_response(&socket, &response).await
}

#[cfg(target_os = "linux")]
fn request_writer_is_authorised(
    sender: webex_generic_account_bot::codex_launcher::PeerCredentials,
    peer: webex_generic_account_bot::codex_launcher::PeerCredentials,
) -> bool {
    sender == peer
}

#[cfg(target_os = "linux")]
async fn response_for_request(
    request: Result<
        webex_generic_account_bot::launcher_protocol::LauncherRequest,
        webex_generic_account_bot::launcher_protocol::ProtocolError,
    >,
    peer: &AuthorisedPeer,
    socket: &AsyncFd<OwnedFd>,
) -> Result<LauncherResponse> {
    match request {
        Ok(request) => match request.request {
            LauncherRequestKind::Preflight(_) => match preflight_available(socket).await {
                Ok(available) => Ok(LauncherResponse::ready(available)),
                Err(_) => Ok(rejected(
                    None,
                    RejectionCode::MalformedRequest,
                    "launcher connection violated the one-packet protocol",
                )?),
            },
            LauncherRequestKind::Execute(request) => {
                let run_id = request.run_id.clone();
                let output_limit = request.output_char_limit;
                match execute_until_disconnect(&request, peer, socket).await {
                    Ok(result) => execution_response(run_id, output_limit, result),
                    Err(IsolatedExecutionError::Unavailable(_)) => Ok(rejected(
                        Some(run_id),
                        RejectionCode::ExecutionUnavailable,
                        "isolated Codex runtime is unavailable",
                    )?),
                    Err(IsolatedExecutionError::Failed(_)) => Ok(rejected(
                        Some(run_id),
                        RejectionCode::InternalError,
                        "isolated Codex execution failed internally",
                    )?),
                }
            }
        },
        Err(error) => Ok(rejected(
            None,
            protocol_rejection_code(error),
            "launcher request failed protocol validation",
        )?),
    }
}

#[cfg(target_os = "linux")]
async fn preflight_available(socket: &AsyncFd<OwnedFd>) -> std::io::Result<bool> {
    let cancellation = ExecutionCancellation::new();
    let preflight = isolated_execution::preflight_bounded(&cancellation);
    tokio::pin!(preflight);
    tokio::select! {
        result = &mut preflight => {
            inspect_client_socket(socket.get_ref().as_raw_fd())?;
            Ok(result.is_ok())
        },
        disconnect = wait_for_client_disconnect(socket) => {
            cancellation.cancel();
            let available = match timeout(
                Duration::from_secs(LAUNCHER_CANCELLATION_DRAIN_SECONDS),
                &mut preflight,
            )
            .await
            {
                Ok(result) => result.is_ok(),
                Err(_) => terminate_stuck_launcher("cancelled preflight did not drain"),
            };
            disconnect?;
            Ok(available)
        }
    }
}

#[cfg(target_os = "linux")]
async fn execute_until_disconnect(
    request: &webex_generic_account_bot::launcher_protocol::ExecuteRequest,
    peer: &AuthorisedPeer,
    socket: &AsyncFd<OwnedFd>,
) -> std::result::Result<IsolatedRunResult, IsolatedExecutionError> {
    let cancellation = ExecutionCancellation::new();
    let execution = isolated_execution::execute(request, peer, &cancellation);
    tokio::pin!(execution);
    tokio::select! {
        result = &mut execution => match inspect_client_socket(socket.get_ref().as_raw_fd()) {
            Ok(_) => result,
            Err(error) => Err(IsolatedExecutionError::Failed(anyhow!(
                "launcher connection violated the one-packet protocol: {error}"
            ))),
        },
        disconnect = wait_for_client_disconnect(socket) => {
            cancellation.cancel();
            let result = match timeout(
                Duration::from_secs(LAUNCHER_CANCELLATION_DRAIN_SECONDS),
                &mut execution,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => terminate_stuck_launcher("cancelled execution did not drain"),
            };
            match disconnect {
                Ok(()) => result,
                Err(error) => Err(IsolatedExecutionError::Failed(anyhow!(
                    "launcher connection violated the one-packet protocol: {error}"
                ))),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_stuck_launcher(reason: &'static str) -> ! {
    tracing::error!(reason, "terminating a launcher with stuck blocking work");
    std::process::exit(STUCK_WORK_EXIT_CODE)
}

#[cfg(target_os = "linux")]
async fn wait_for_client_disconnect(socket: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    loop {
        let mut guard = socket.readable().await?;
        match guard.try_io(
            |socket| match inspect_client_socket(socket.get_ref().as_raw_fd())? {
                ClientSocketState::Closed => Ok(()),
                ClientSocketState::Open => {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
            },
        ) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientSocketState {
    Open,
    Closed,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientReadSideState {
    Open,
    HalfClosed,
    Closed,
}

#[cfg(target_os = "linux")]
fn inspect_client_socket(socket_fd: RawFd) -> std::io::Result<ClientSocketState> {
    let mut byte = 0_u8;
    let mut control = ControlBuffer([0_u8; CONTROL_BUFFER_BYTES]);
    let mut iovec = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    // SAFETY: message references initialized byte, control, and iovec storage for this call.
    let received = unsafe {
        libc::recvmsg(
            socket_fd,
            &mut message,
            libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received == 0 {
        // A real zero-length packet still carries SCM_CREDENTIALS on this SO_PASSCRED
        // socket. EOF carries no packet metadata and must also report read-side HUP.
        // MSG_EOR is not reliable for distinguishing an empty SEQPACKET record.
        let has_packet_metadata = unsafe { !libc::CMSG_FIRSTHDR(&message).is_null() };
        if has_packet_metadata || message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launcher client sent an empty extra request packet",
            ));
        }
        return match client_read_side_state(socket_fd)? {
            ClientReadSideState::Closed => Ok(ClientSocketState::Closed),
            ClientReadSideState::HalfClosed => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launcher client half-closed the request stream",
            )),
            ClientReadSideState::Open => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launcher client sent an empty extra request packet",
            )),
        };
    }
    if received > 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "launcher client sent more than one request packet",
        ));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(ClientSocketState::Open)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn client_read_side_state(socket_fd: RawFd) -> std::io::Result<ClientReadSideState> {
    let mut descriptor = libc::pollfd {
        fd: socket_fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: descriptor points to one initialized pollfd for this nonblocking probe.
    let status = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if descriptor.revents & libc::POLLNVAL != 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    let hung_up = descriptor.revents & libc::POLLHUP != 0;
    let read_half_closed = descriptor.revents & libc::POLLRDHUP != 0;
    if descriptor.revents & libc::POLLERR != 0 && !hung_up {
        return Err(std::io::Error::other(
            "launcher client socket reported a read error",
        ));
    }
    Ok(if hung_up {
        ClientReadSideState::Closed
    } else if read_half_closed {
        ClientReadSideState::HalfClosed
    } else {
        ClientReadSideState::Open
    })
}

#[cfg(target_os = "linux")]
fn execution_response(
    run_id: String,
    output_char_limit: u64,
    result: IsolatedRunResult,
) -> Result<LauncherResponse> {
    Ok(match result {
        IsolatedRunResult::Completed { output, truncated } => {
            let mut completed = CompletedResponse::bounded(run_id, &output, output_char_limit)?;
            completed.truncated |= truncated;
            LauncherResponse::completed(completed)
        }
        IsolatedRunResult::TimedOut => rejected(
            Some(run_id),
            RejectionCode::ExecutionTimedOut,
            "isolated Codex execution timed out",
        )?,
        IsolatedRunResult::Failed => rejected(
            Some(run_id),
            RejectionCode::ExecutionFailed,
            "isolated Codex execution failed",
        )?,
    })
}

#[cfg(target_os = "linux")]
fn rejected(
    run_id: Option<String>,
    code: RejectionCode,
    message: &str,
) -> Result<LauncherResponse> {
    Ok(LauncherResponse::rejected(RejectedResponse::bounded(
        run_id, code, message,
    )?))
}

#[cfg(target_os = "linux")]
fn duplicate_launcher_socket(fd: RawFd) -> Result<AsyncFd<OwnedFd>> {
    // SAFETY: fcntl does not dereference userspace pointers for F_DUPFD_CLOEXEC.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this process.
    let socket = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(AsyncFd::new(socket)?)
}

#[cfg(target_os = "linux")]
async fn receive_request_packet(socket: &AsyncFd<OwnedFd>) -> Result<ReceivedPacket> {
    loop {
        let mut guard = socket.readable().await?;
        match guard.try_io(|socket| receive_request_packet_now(socket.get_ref().as_raw_fd())) {
            Ok(result) => return Ok(result?),
            Err(_) => continue,
        }
    }
}

#[cfg(target_os = "linux")]
fn receive_request_packet_now(fd: RawFd) -> std::io::Result<ReceivedPacket> {
    let mut frame = vec![0_u8; FRAME_HEADER_BYTES + REQUEST_MAX_BYTES + 1];
    let mut control = ControlBuffer([0_u8; CONTROL_BUFFER_BYTES]);
    let mut iovec = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();

    // SAFETY: message references initialized frame, control, and iovec storage for this call.
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sender = message_credentials(&message)?;
    frame.truncate(received as usize);
    Ok(ReceivedPacket {
        frame,
        sender,
        truncated: message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
    })
}

#[cfg(target_os = "linux")]
fn message_credentials(
    message: &libc::msghdr,
) -> std::io::Result<webex_generic_account_bot::codex_launcher::PeerCredentials> {
    let mut credentials = None;
    // SAFETY: message and its control buffer remain valid for the complete traversal.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR return headers within the validated control buffer.
        let control = unsafe { &*header };
        if control.cmsg_level == libc::SOL_SOCKET && control.cmsg_type == libc::SCM_CREDENTIALS {
            if control.cmsg_len
                < unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) } as usize
                || credentials.is_some()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "launcher packet credentials are invalid",
                ));
            }
            // SAFETY: the checked cmsg length contains one ucred; read_unaligned avoids alignment assumptions.
            let raw =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
            if raw.pid <= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "launcher packet sender is invalid",
                ));
            }
            credentials = Some(webex_generic_account_bot::codex_launcher::PeerCredentials {
                pid: raw.pid as u32,
                uid: raw.uid,
                gid: raw.gid,
            });
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launcher packet contains unexpected control data",
            ));
        }
        // SAFETY: message and header describe the same live control buffer.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    credentials.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "launcher packet credentials are unavailable",
        )
    })
}

#[cfg(target_os = "linux")]
async fn write_response(socket: &AsyncFd<OwnedFd>, response: &LauncherResponse) -> Result<()> {
    let frame = encode_response_frame(response)?;
    timeout(IO_TIMEOUT, async {
        loop {
            let mut guard = socket.writable().await?;
            match guard.try_io(|socket| {
                let fd = socket.get_ref().as_raw_fd();
                // SAFETY: frame is a valid immutable buffer for the duration of send.
                let sent = unsafe {
                    libc::send(fd, frame.as_ptr().cast(), frame.len(), libc::MSG_NOSIGNAL)
                };
                if sent < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if sent as usize != frame.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "launcher response packet was truncated",
                    ));
                }
                Ok(())
            }) {
                Ok(result) => break result,
                Err(_) => continue,
            }
        }
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
    use std::process::Command;

    use webex_generic_account_bot::launcher_protocol::{
        LauncherRequest, LauncherResponseKind, ProtocolError, encode_request_frame,
    };

    use super::*;

    #[test]
    fn execution_results_map_to_stable_protocol_responses() {
        let completed = execution_response(
            "run-1".to_owned(),
            100,
            IsolatedRunResult::Completed {
                output: "done".to_owned(),
                truncated: false,
            },
        )
        .unwrap();
        assert!(matches!(
            completed.response,
            LauncherResponseKind::Completed(response)
                if response.run_id == "run-1" && response.output == "done"
        ));

        for (result, code) in [
            (
                IsolatedRunResult::TimedOut,
                RejectionCode::ExecutionTimedOut,
            ),
            (IsolatedRunResult::Failed, RejectionCode::ExecutionFailed),
        ] {
            let response = execution_response("run-1".to_owned(), 100, result).unwrap();
            assert!(matches!(
                response.response,
                LauncherResponseKind::Rejected(response) if response.code == code
            ));
        }
    }

    #[test]
    fn malformed_requests_receive_a_bounded_stable_rejection() {
        let response = rejected(
            None,
            protocol_rejection_code(ProtocolError::InvalidRequestJson),
            "launcher request failed protocol validation",
        )
        .unwrap();

        assert!(matches!(
            response.response,
            LauncherResponseKind::Rejected(response)
                if response.run_id.is_none()
                    && response.code == RejectionCode::MalformedRequest
        ));
    }

    #[tokio::test]
    async fn credentialled_packet_does_not_wait_for_eof() {
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        send_packet(writer.as_raw_fd(), &frame);

        let packet = timeout(Duration::from_millis(100), receive_request_packet(&reader))
            .await
            .expect("receiver must not wait for the writer to close")
            .unwrap();

        assert_eq!(packet.frame, frame);
        assert!(!packet.truncated);
        assert_eq!(packet.sender.pid, std::process::id());
        assert_eq!(packet.sender.uid, unsafe { libc::geteuid() });
        assert_eq!(packet.sender.gid, unsafe { libc::getegid() });
    }

    #[tokio::test]
    async fn client_disconnect_is_detected_without_an_extra_packet() {
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        send_packet(writer.as_raw_fd(), &frame);
        receive_request_packet(&reader).await.unwrap();
        drop(writer);

        timeout(
            Duration::from_millis(100),
            wait_for_client_disconnect(&reader),
        )
        .await
        .expect("disconnect monitor must observe peer closure")
        .unwrap();
    }

    #[tokio::test]
    async fn a_second_packet_is_a_protocol_error_not_a_disconnect() {
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        send_packet(writer.as_raw_fd(), &frame);
        receive_request_packet(&reader).await.unwrap();
        send_packet(writer.as_raw_fd(), &frame);

        let error = wait_for_client_disconnect(&reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_empty_second_packet_is_a_protocol_error_not_a_disconnect() {
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        send_packet(writer.as_raw_fd(), &frame);
        receive_request_packet(&reader).await.unwrap();
        // SAFETY: the writer descriptor is live; a null pointer is valid for a zero-byte send.
        assert_eq!(
            unsafe { libc::send(writer.as_raw_fd(), std::ptr::null(), 0, libc::MSG_NOSIGNAL,) },
            0
        );
        drop(writer);

        let error = wait_for_client_disconnect(&reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_write_half_close_is_a_protocol_error_not_a_disconnect() {
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        send_packet(writer.as_raw_fd(), &frame);
        receive_request_packet(&reader).await.unwrap();
        // SAFETY: the writer descriptor is live and owned by this test.
        assert_eq!(
            unsafe { libc::shutdown(writer.as_raw_fd(), libc::SHUT_WR) },
            0
        );

        let error = wait_for_client_disconnect(&reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn partial_frame_packets_receive_stable_rejections() {
        for frame in [
            vec![0_u8; 2],
            [10_u32.to_be_bytes().as_slice(), b"{}"].concat(),
        ] {
            let Some((writer, reader)) = credentialled_packet_pair() else {
                return;
            };
            send_packet(writer.as_raw_fd(), &frame);
            let packet = receive_request_packet(&reader).await.unwrap();
            let error = decode_request_frame(&packet.frame).unwrap_err();
            let response = rejected(
                None,
                protocol_rejection_code(error),
                "launcher request failed protocol validation",
            )
            .unwrap();

            assert!(matches!(
                response.response,
                LauncherResponseKind::Rejected(response)
                    if response.code == RejectionCode::MalformedRequest
            ));
        }
    }

    #[tokio::test]
    async fn inherited_connection_packet_is_bound_to_the_child_writer() {
        let Some((writer, reader)) = credentialled_packet_pair() else {
            return;
        };
        let authorised_peer = socket_peer_credentials(reader.get_ref().as_raw_fd()).unwrap();
        make_fd_inheritable(writer.as_raw_fd());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::credentialled_packet_child_helper",
                "--nocapture",
            ])
            .env(
                "WEBEX_LAUNCHER_PACKET_TEST_FD",
                writer.as_raw_fd().to_string(),
            )
            .spawn()
            .unwrap();
        drop(writer);

        let packet = receive_request_packet(&reader).await.unwrap();
        assert_eq!(packet.sender.pid, child.id());
        assert!(!request_writer_is_authorised(
            packet.sender,
            authorised_peer
        ));
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn credentialled_packet_child_helper() {
        let Ok(fd) = std::env::var("WEBEX_LAUNCHER_PACKET_TEST_FD") else {
            return;
        };
        let frame = encode_request_frame(&LauncherRequest::preflight()).unwrap();
        send_packet(fd.parse().unwrap(), &frame);
    }

    #[test]
    fn request_writer_must_match_the_authorised_peer() {
        let peer = webex_generic_account_bot::codex_launcher::PeerCredentials {
            pid: 42,
            uid: 1000,
            gid: 1000,
        };
        assert!(request_writer_is_authorised(peer, peer));
        assert!(!request_writer_is_authorised(
            webex_generic_account_bot::codex_launcher::PeerCredentials { pid: 43, ..peer },
            peer
        ));
    }

    fn credentialled_packet_pair() -> Option<(OwnedFd, AsyncFd<OwnedFd>)> {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has storage for the two fds returned by socketpair.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    descriptors.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: socketpair returned two descriptors owned by this test.
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: socketpair returned two descriptors owned by this test.
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let enabled: libc::c_int = 1;
        // SAFETY: enabled points to one initialized c_int.
        let status = unsafe {
            libc::setsockopt(
                reader.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if status != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPERM) {
                // Some test sandboxes block SO_PASSCRED. Runtime remains fail closed.
                return None;
            }
            panic!("failed to enable SO_PASSCRED: {error}");
        }
        Some((writer, AsyncFd::new(reader).unwrap()))
    }

    fn send_packet(fd: RawFd, packet: &[u8]) {
        // SAFETY: packet is readable for the complete send call.
        let sent = unsafe { libc::send(fd, packet.as_ptr().cast(), packet.len(), 0) };
        assert_eq!(sent, packet.len() as isize);
    }

    fn make_fd_inheritable(fd: RawFd) {
        // SAFETY: fcntl does not dereference userspace pointers for these operations.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
    }
}

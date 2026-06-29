use std::{io, path::PathBuf, time::Duration};

use thiserror::Error;

use crate::{
    codex_launcher::LAUNCHER_SOCKET_PATH,
    launcher_protocol::{
        CompletedResponse, ExecuteRequest, LAUNCHER_EXECUTE_RESPONSE_OVERHEAD_SECONDS,
        LAUNCHER_IO_TIMEOUT_SECONDS, LAUNCHER_PREFLIGHT_RESPONSE_TIMEOUT_SECONDS, LauncherRequest,
        LauncherResponse, LauncherResponseKind, ProtocolError, RejectedResponse, RejectionCode,
        bound_error_message, encode_request_frame,
    },
};

const LAUNCHER_IO_TIMEOUT: Duration = Duration::from_secs(LAUNCHER_IO_TIMEOUT_SECONDS);
const PREFLIGHT_RESPONSE_TIMEOUT: Duration =
    Duration::from_secs(LAUNCHER_PREFLIGHT_RESPONSE_TIMEOUT_SECONDS);

type ClientResult<T> = Result<T, LauncherClientError>;

#[derive(Debug, Error)]
pub enum LauncherClientError {
    #[error("launcher request failed validation")]
    InvalidRequest(#[source] ProtocolError),
    #[error("launcher connection timed out")]
    ConnectionTimeout,
    #[error("failed to connect to the launcher socket")]
    ConnectionFailed(#[source] io::Error),
    #[error("launcher request write timed out")]
    WriteTimeout,
    #[error("failed to write the launcher request")]
    WriteFailed(#[source] io::Error),
    #[error("launcher response read timed out")]
    ReadTimeout,
    #[error("failed to read the launcher response")]
    ReadFailed(#[source] io::Error),
    #[error("launcher response packet was truncated")]
    TruncatedResponse,
    #[error("launcher response packet exceeds the protocol byte limit")]
    OversizedResponse,
    #[error("launcher response failed validation")]
    InvalidResponse(#[source] ProtocolError),
    #[error("launcher reported that execution is unavailable")]
    ExecutionUnavailable,
    #[error("launcher returned an unexpected response to a preflight request")]
    UnexpectedPreflightResponse,
    #[error("launcher returned an unexpected response to an execute request")]
    UnexpectedExecuteResponse,
    #[error("launcher response run ID does not match the request")]
    RunIdMismatch,
    #[error("launcher rejected the request ({code:?}): {message}")]
    Rejected {
        code: RejectionCode,
        message: String,
    },
    #[error("launcher socket trust policy is unavailable")]
    TrustPolicyUnavailable(#[source] anyhow::Error),
    #[error("launcher socket has no parent directory")]
    SocketParentMissing,
    #[error("launcher socket directory is unavailable")]
    SocketDirectoryUnavailable(#[source] io::Error),
    #[error("launcher socket is unavailable")]
    SocketUnavailable(#[source] io::Error),
    #[error("launcher socket directory metadata is invalid")]
    InvalidSocketDirectoryMetadata,
    #[error("launcher socket metadata is invalid")]
    InvalidSocketMetadata,
    #[error("the Codex launcher is supported only on Linux")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone)]
pub struct LauncherClient {
    socket_path: PathBuf,
    io_timeout: Duration,
    preflight_response_timeout: Duration,
}

impl LauncherClient {
    pub fn fixed() -> Self {
        Self {
            socket_path: PathBuf::from(LAUNCHER_SOCKET_PATH),
            io_timeout: LAUNCHER_IO_TIMEOUT,
            preflight_response_timeout: PREFLIGHT_RESPONSE_TIMEOUT,
        }
    }

    pub async fn preflight(&self) -> ClientResult<()> {
        let response = self
            .exchange(
                LauncherRequest::preflight(),
                self.preflight_response_timeout,
            )
            .await?;
        validate_preflight_response(response)
    }

    pub async fn execute(&self, request: ExecuteRequest) -> ClientResult<CompletedResponse> {
        let run_id = request.run_id.clone();
        let response_timeout = execute_response_timeout(request.timeout_seconds, self.io_timeout);
        let response = self
            .exchange(LauncherRequest::execute(request), response_timeout)
            .await?;
        validate_execute_response(response, &run_id)
    }

    async fn exchange(
        &self,
        request: LauncherRequest,
        response_timeout: Duration,
    ) -> ClientResult<LauncherResponse> {
        let frame = encode_request_frame(&request).map_err(LauncherClientError::InvalidRequest)?;

        #[cfg(target_os = "linux")]
        {
            linux::exchange(&self.socket_path, self.io_timeout, response_timeout, &frame).await
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (frame, response_timeout);
            Err(LauncherClientError::UnsupportedPlatform)
        }
    }

    #[cfg(test)]
    fn for_test(socket_path: PathBuf, io_timeout: Duration) -> Self {
        Self {
            socket_path,
            io_timeout,
            preflight_response_timeout: io_timeout,
        }
    }
}

impl Default for LauncherClient {
    fn default() -> Self {
        Self::fixed()
    }
}

pub fn verify_fixed_launcher_socket() -> ClientResult<()> {
    #[cfg(target_os = "linux")]
    {
        let groups = crate::isolated_execution::production_codex_group_ids()
            .map_err(LauncherClientError::TrustPolicyUnavailable)?;
        linux::verify_socket_metadata(std::path::Path::new(LAUNCHER_SOCKET_PATH), 0, groups.launch)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(LauncherClientError::UnsupportedPlatform)
    }
}

fn execute_response_timeout(timeout_seconds: u64, io_timeout: Duration) -> Duration {
    Duration::from_secs(timeout_seconds)
        .saturating_add(Duration::from_secs(
            LAUNCHER_EXECUTE_RESPONSE_OVERHEAD_SECONDS,
        ))
        .saturating_add(io_timeout.saturating_sub(LAUNCHER_IO_TIMEOUT))
}

fn validate_preflight_response(response: LauncherResponse) -> ClientResult<()> {
    match response.response {
        LauncherResponseKind::Ready(response) if response.execution_available => Ok(()),
        LauncherResponseKind::Ready(_) => Err(LauncherClientError::ExecutionUnavailable),
        LauncherResponseKind::Rejected(response) => Err(rejection_error(response)),
        LauncherResponseKind::Completed(_) => Err(LauncherClientError::UnexpectedPreflightResponse),
    }
}

fn validate_execute_response(
    response: LauncherResponse,
    expected_run_id: &str,
) -> ClientResult<CompletedResponse> {
    match response.response {
        LauncherResponseKind::Completed(response) => {
            ensure_run_id(expected_run_id, &response.run_id)?;
            Ok(response)
        }
        LauncherResponseKind::Rejected(response) => {
            if let Some(run_id) = &response.run_id {
                ensure_run_id(expected_run_id, run_id)?;
            }
            Err(rejection_error(response))
        }
        LauncherResponseKind::Ready(_) => Err(LauncherClientError::UnexpectedExecuteResponse),
    }
}

fn ensure_run_id(expected: &str, actual: &str) -> ClientResult<()> {
    if actual != expected {
        return Err(LauncherClientError::RunIdMismatch);
    }
    Ok(())
}

fn rejection_error(response: RejectedResponse) -> LauncherClientError {
    LauncherClientError::Rejected {
        code: response.code,
        message: bound_error_message(&response.message),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::OsStr,
        io,
        mem::{offset_of, size_of},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::ffi::OsStrExt,
            unix::fs::{FileTypeExt, MetadataExt},
        },
        path::Path,
        ptr,
        time::Duration,
    };

    use tokio::{
        io::unix::AsyncFd,
        time::{sleep, timeout},
    };

    use crate::launcher_protocol::{
        FRAME_HEADER_BYTES, LauncherResponse, REQUEST_MAX_BYTES, RESPONSE_MAX_BYTES,
        decode_response_frame,
    };

    use super::{ClientResult, LauncherClientError};

    const RESPONSE_FRAME_MAX_BYTES: usize = FRAME_HEADER_BYTES + RESPONSE_MAX_BYTES;
    const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(1);

    struct ReceivedPacket {
        frame: Vec<u8>,
        truncated: bool,
    }

    pub(super) fn verify_socket_metadata(
        socket_path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> ClientResult<()> {
        let parent = socket_path
            .parent()
            .ok_or(LauncherClientError::SocketParentMissing)?;
        let parent_metadata = std::fs::symlink_metadata(parent)
            .map_err(LauncherClientError::SocketDirectoryUnavailable)?;
        let socket_metadata = std::fs::symlink_metadata(socket_path)
            .map_err(LauncherClientError::SocketUnavailable)?;

        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != expected_uid
            || parent_metadata.gid() != expected_gid
            || parent_metadata.mode() & 0o7777 != 0o750
        {
            return Err(LauncherClientError::InvalidSocketDirectoryMetadata);
        }
        if !socket_metadata.file_type().is_socket()
            || socket_metadata.file_type().is_symlink()
            || socket_metadata.uid() != expected_uid
            || socket_metadata.gid() != expected_gid
            || socket_metadata.mode() & 0o7777 != 0o660
        {
            return Err(LauncherClientError::InvalidSocketMetadata);
        }
        Ok(())
    }

    pub(super) async fn exchange(
        socket_path: &Path,
        io_timeout: Duration,
        response_timeout: Duration,
        request_frame: &[u8],
    ) -> ClientResult<LauncherResponse> {
        let socket = connect_with_timeout(socket_path, io_timeout).await?;
        send_with_timeout(&socket, request_frame, io_timeout).await?;
        let packet = receive_with_timeout(&socket, response_timeout).await?;
        decode_received_response(packet)
    }

    async fn connect_with_timeout(
        socket_path: &Path,
        io_timeout: Duration,
    ) -> ClientResult<AsyncFd<OwnedFd>> {
        timeout(io_timeout, connect(socket_path))
            .await
            .map_err(|_| LauncherClientError::ConnectionTimeout)?
            .map_err(LauncherClientError::ConnectionFailed)
    }

    async fn send_with_timeout(
        socket: &AsyncFd<OwnedFd>,
        packet: &[u8],
        io_timeout: Duration,
    ) -> ClientResult<()> {
        timeout(io_timeout, send_packet(socket, packet))
            .await
            .map_err(|_| LauncherClientError::WriteTimeout)?
            .map_err(LauncherClientError::WriteFailed)
    }

    async fn receive_with_timeout(
        socket: &AsyncFd<OwnedFd>,
        io_timeout: Duration,
    ) -> ClientResult<ReceivedPacket> {
        timeout(io_timeout, receive_packet(socket, RESPONSE_FRAME_MAX_BYTES))
            .await
            .map_err(|_| LauncherClientError::ReadTimeout)?
            .map_err(LauncherClientError::ReadFailed)
    }

    fn decode_received_response(packet: ReceivedPacket) -> ClientResult<LauncherResponse> {
        if packet.truncated {
            return Err(LauncherClientError::TruncatedResponse);
        }
        if packet.frame.len() > RESPONSE_FRAME_MAX_BYTES {
            return Err(LauncherClientError::OversizedResponse);
        }
        decode_response_frame(&packet.frame).map_err(LauncherClientError::InvalidResponse)
    }

    async fn connect(socket_path: &Path) -> io::Result<AsyncFd<OwnedFd>> {
        let (address, address_len) = socket_address(socket_path)?;
        let socket = new_socket()?;

        loop {
            // SAFETY: address is a fully initialized sockaddr_un and address_len covers its path.
            let status = unsafe {
                libc::connect(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len,
                )
            };
            if status == 0 {
                return Ok(socket);
            }

            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EISCONN) => return Ok(socket),
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    sleep(CONNECT_RETRY_DELAY).await;
                }
                Some(libc::EINPROGRESS) | Some(libc::EALREADY) => {
                    let mut guard = socket.writable().await?;
                    guard.clear_ready();
                    match socket_error(socket.as_raw_fd())? {
                        None => return Ok(socket),
                        Some(error)
                            if matches!(
                                error.raw_os_error(),
                                Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EAGAIN)
                            ) => {}
                        Some(error) => return Err(error),
                    }
                }
                _ => return Err(error),
            }
        }
    }

    fn new_socket() -> io::Result<AsyncFd<OwnedFd>> {
        // SAFETY: socket has no pointer arguments and returns a newly owned descriptor.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new descriptor owned by this process.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        set_buffer_size(
            socket.as_raw_fd(),
            libc::SO_SNDBUF,
            FRAME_HEADER_BYTES + REQUEST_MAX_BYTES,
        )?;
        set_buffer_size(
            socket.as_raw_fd(),
            libc::SO_RCVBUF,
            RESPONSE_FRAME_MAX_BYTES,
        )?;
        AsyncFd::new(socket)
    }

    fn set_buffer_size(fd: RawFd, option: libc::c_int, size: usize) -> io::Result<()> {
        let size = libc::c_int::try_from(size).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "socket buffer is too large")
        })?;
        // SAFETY: size points to one initialized c_int for the duration of setsockopt.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&size as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn socket_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher socket path must be absolute",
            ));
        }
        let path = OsStr::as_bytes(path.as_os_str());
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        if path.is_empty() || path.contains(&0) || path.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher socket path is invalid",
            ));
        }

        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // SAFETY: path length was checked against sun_path and the destination is initialized.
        unsafe {
            ptr::copy_nonoverlapping(
                path.as_ptr(),
                address.sun_path.as_mut_ptr().cast::<u8>(),
                path.len(),
            );
        }
        let length = offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
        Ok((address, length as libc::socklen_t))
    }

    fn socket_error(fd: RawFd) -> io::Result<Option<io::Error>> {
        let mut error: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: error and length point to writable values of the expected sizes.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<libc::c_int>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "launcher socket returned an invalid connection status",
            ));
        }
        Ok((error != 0).then(|| io::Error::from_raw_os_error(error)))
    }

    async fn send_packet(socket: &AsyncFd<OwnedFd>, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = socket.writable().await?;
            match guard.try_io(|socket| {
                // SAFETY: packet remains readable for the duration of send.
                let sent = unsafe {
                    libc::send(
                        socket.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent < 0 {
                    return Err(io::Error::last_os_error());
                }
                if sent as usize != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "launcher packet was only partially written",
                    ));
                }
                Ok(())
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    async fn receive_packet(
        socket: &AsyncFd<OwnedFd>,
        max_frame_bytes: usize,
    ) -> io::Result<ReceivedPacket> {
        loop {
            let mut guard = socket.readable().await?;
            match guard
                .try_io(|socket| receive_packet_now(socket.get_ref().as_raw_fd(), max_frame_bytes))
            {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    fn receive_packet_now(fd: RawFd, max_frame_bytes: usize) -> io::Result<ReceivedPacket> {
        let mut frame = vec![0_u8; max_frame_bytes + 1];
        let mut iovec = libc::iovec {
            iov_base: frame.as_mut_ptr().cast(),
            iov_len: frame.len(),
        };
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;

        // SAFETY: message references initialized frame and iovec storage for this call.
        let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        frame.truncate(received as usize);
        Ok(ReceivedPacket {
            frame,
            truncated: message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
        })
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
            path::{Path, PathBuf},
            sync::atomic::{AtomicU64, Ordering},
            time::Duration,
        };

        use crate::{
            isolated_execution::CODEX_INPUT_ROOT,
            launcher_client::{
                LauncherClient, LauncherClientError, execute_response_timeout,
                validate_execute_response, validate_preflight_response,
            },
            launcher_protocol::{
                CompletedResponse, ExecuteRequest, FRAME_HEADER_BYTES,
                LAUNCHER_EXECUTE_RESPONSE_OVERHEAD_SECONDS,
                LAUNCHER_PREFLIGHT_RESPONSE_TIMEOUT_SECONDS, LauncherRequestKind, LauncherResponse,
                ReasoningEffort, RejectedResponse, RejectionCode, decode_request_frame,
                encode_response_frame,
            },
        };

        use super::*;

        static NEXT_PATH_ID: AtomicU64 = AtomicU64::new(1);

        #[tokio::test]
        async fn client_round_trips_real_seqpacket_requests() {
            let Some((client, server, _path)) = response_server(
                LauncherResponse::ready(true),
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_secs(1),
            ) else {
                return;
            };
            client.preflight().await.unwrap();
            assert!(matches!(
                server.await.unwrap(),
                LauncherRequestKind::Preflight(_)
            ));

            let completed = CompletedResponse::bounded("run-1", "done", 100).unwrap();
            let Some((client, server, _path)) = response_server(
                LauncherResponse::completed(completed.clone()),
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_secs(1),
            ) else {
                return;
            };
            let request = execute_request("run-1");
            let actual = client.execute(request.clone()).await.unwrap();
            assert_eq!(actual, completed);
            assert_eq!(server.await.unwrap(), LauncherRequestKind::Execute(request));
        }

        #[tokio::test]
        async fn response_is_one_packet_and_does_not_wait_for_eof() {
            let Some((client, server, _path)) = response_server(
                LauncherResponse::ready(true),
                Duration::ZERO,
                Duration::from_millis(80),
                Duration::from_millis(20),
            ) else {
                return;
            };

            client.preflight().await.unwrap();
            server.await.unwrap();
        }

        #[tokio::test]
        async fn each_request_uses_a_new_connection() {
            let path = TestSocketPath::new();
            let Some(listener) = available_or_skip(bind_listener(&path.0, 2)) else {
                return;
            };
            let listener = AsyncFd::new(listener).unwrap();
            let response = encode_response_frame(&LauncherResponse::ready(true)).unwrap();
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let socket = accept(&listener).await.unwrap();
                    let packet = receive_packet(
                        &socket,
                        FRAME_HEADER_BYTES + crate::launcher_protocol::REQUEST_MAX_BYTES,
                    )
                    .await
                    .unwrap();
                    assert!(matches!(
                        decode_request_frame(&packet.frame).unwrap().request,
                        LauncherRequestKind::Preflight(_)
                    ));
                    send_packet(&socket, &response).await.unwrap();
                }
            });
            let client = LauncherClient::for_test(path.0.clone(), Duration::from_secs(1));

            client.preflight().await.unwrap();
            client.preflight().await.unwrap();
            server.await.unwrap();
        }

        #[test]
        fn fixed_client_uses_only_the_production_endpoint() {
            let client = LauncherClient::fixed();
            assert_eq!(
                client.socket_path,
                PathBuf::from(crate::codex_launcher::LAUNCHER_SOCKET_PATH)
            );
            assert_eq!(client.io_timeout, super::super::LAUNCHER_IO_TIMEOUT);
            assert_eq!(
                client.preflight_response_timeout,
                Duration::from_secs(LAUNCHER_PREFLIGHT_RESPONSE_TIMEOUT_SECONDS)
            );
        }

        #[test]
        fn execute_timeout_includes_preparation_cleanup_and_io_grace() {
            let io_timeout = Duration::from_secs(5);
            assert_eq!(
                execute_response_timeout(600, io_timeout),
                Duration::from_secs(600 + LAUNCHER_EXECUTE_RESPONSE_OVERHEAD_SECONDS)
            );
        }

        #[test]
        fn semantic_response_validation_is_fail_closed() {
            assert!(matches!(
                validate_preflight_response(LauncherResponse::ready(false)),
                Err(LauncherClientError::ExecutionUnavailable)
            ));
            assert!(matches!(
                validate_preflight_response(LauncherResponse::completed(
                    CompletedResponse::bounded("run-1", "done", 100).unwrap()
                )),
                Err(LauncherClientError::UnexpectedPreflightResponse)
            ));
            assert!(matches!(
                validate_execute_response(LauncherResponse::ready(true), "run-1"),
                Err(LauncherClientError::UnexpectedExecuteResponse)
            ));

            let mismatched = LauncherResponse::completed(
                CompletedResponse::bounded("run-2", "done", 100).unwrap(),
            );
            assert!(matches!(
                validate_execute_response(mismatched, "run-1"),
                Err(LauncherClientError::RunIdMismatch)
            ));

            let rejection = LauncherResponse::rejected(
                RejectedResponse::bounded(
                    Some("run-1".to_owned()),
                    RejectionCode::ExecutionFailed,
                    &"remote failure ".repeat(200),
                )
                .unwrap(),
            );
            match validate_execute_response(rejection, "run-1").unwrap_err() {
                LauncherClientError::Rejected { code, message } => {
                    assert_eq!(code, RejectionCode::ExecutionFailed);
                    assert!(message.chars().count() <= 1024);
                }
                error => panic!("unexpected error: {error}"),
            }

            let mismatched_rejection = LauncherResponse::rejected(
                RejectedResponse::bounded(
                    Some("run-2".to_owned()),
                    RejectionCode::ExecutionFailed,
                    "execution failed",
                )
                .unwrap(),
            );
            assert!(matches!(
                validate_execute_response(mismatched_rejection, "run-1"),
                Err(LauncherClientError::RunIdMismatch)
            ));
        }

        #[test]
        fn malformed_oversized_and_truncated_packets_are_rejected() {
            let malformed_payload = b"{]";
            let mut malformed = Vec::from((malformed_payload.len() as u32).to_be_bytes());
            malformed.extend_from_slice(malformed_payload);

            for (packet, expected) in [
                (
                    ReceivedPacket {
                        frame: vec![0_u8; FRAME_HEADER_BYTES - 1],
                        truncated: false,
                    },
                    "validation",
                ),
                (
                    ReceivedPacket {
                        frame: malformed,
                        truncated: false,
                    },
                    "validation",
                ),
                (
                    ReceivedPacket {
                        frame: vec![0_u8; RESPONSE_FRAME_MAX_BYTES + 1],
                        truncated: false,
                    },
                    "byte limit",
                ),
                (
                    ReceivedPacket {
                        frame: encode_response_frame(&LauncherResponse::ready(true)).unwrap(),
                        truncated: true,
                    },
                    "truncated",
                ),
            ] {
                let error = decode_received_response(packet).unwrap_err();
                assert!(error.to_string().contains(expected), "{error}");
            }
        }

        #[tokio::test]
        async fn client_socket_is_unix_nonblocking_cloexec_seqpacket() {
            let Some(socket) = available_or_skip(new_socket()) else {
                return;
            };
            let fd = socket.as_raw_fd();
            // SAFETY: fcntl and getsockopt only inspect the live descriptor.
            let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_ne!(status_flags, -1);
            assert_ne!(descriptor_flags, -1);
            assert_ne!(status_flags & libc::O_NONBLOCK, 0);
            assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
            assert_eq!(
                socket_option(fd, libc::SO_TYPE).unwrap(),
                libc::SOCK_SEQPACKET
            );
            assert_eq!(socket_option(fd, libc::SO_DOMAIN).unwrap(), libc::AF_UNIX);
        }

        #[test]
        fn socket_metadata_requires_exact_owner_group_modes_and_no_symlinks() {
            let directory = TestDirectory::new();
            let real_parent = directory.0.join("real");
            fs::create_dir(&real_parent).unwrap();
            fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o750)).unwrap();
            let socket_path = real_parent.join("launcher.sock");
            let Some(listener) = available_or_skip(bind_listener(&socket_path, 1)) else {
                return;
            };
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).unwrap();
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };

            verify_socket_metadata(&socket_path, uid, gid).unwrap();
            assert!(matches!(
                verify_socket_metadata(&socket_path, uid.wrapping_add(1), gid),
                Err(LauncherClientError::InvalidSocketDirectoryMetadata)
            ));
            assert!(matches!(
                verify_socket_metadata(&socket_path, uid, gid.wrapping_add(1)),
                Err(LauncherClientError::InvalidSocketDirectoryMetadata)
            ));

            fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o1750)).unwrap();
            assert!(matches!(
                verify_socket_metadata(&socket_path, uid, gid),
                Err(LauncherClientError::InvalidSocketDirectoryMetadata)
            ));
            fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o750)).unwrap();

            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o1660)).unwrap();
            assert!(matches!(
                verify_socket_metadata(&socket_path, uid, gid),
                Err(LauncherClientError::InvalidSocketMetadata)
            ));
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).unwrap();

            let linked_parent = directory.0.join("linked");
            symlink(&real_parent, &linked_parent).unwrap();
            assert!(matches!(
                verify_socket_metadata(&linked_parent.join("launcher.sock"), uid, gid),
                Err(LauncherClientError::InvalidSocketDirectoryMetadata)
            ));

            let real_socket_path = real_parent.join("real.sock");
            fs::rename(&socket_path, &real_socket_path).unwrap();
            symlink(&real_socket_path, &socket_path).unwrap();
            assert!(matches!(
                verify_socket_metadata(&socket_path, uid, gid),
                Err(LauncherClientError::InvalidSocketMetadata)
            ));
            drop(listener);
        }

        #[tokio::test]
        async fn connection_timeout_is_reported() {
            let path = TestSocketPath::new();
            let Some(listener) = available_or_skip(bind_listener(&path.0, 1)) else {
                return;
            };
            let Some(_fillers) = available_or_skip(saturate_listener(&path.0)) else {
                return;
            };

            let error = connect_with_timeout(&path.0, Duration::from_millis(20))
                .await
                .unwrap_err();
            assert!(matches!(error, LauncherClientError::ConnectionTimeout));
            drop(listener);
        }

        #[tokio::test]
        async fn response_read_timeout_is_reported() {
            let path = TestSocketPath::new();
            let Some(_listener) = available_or_skip(bind_listener(&path.0, 1)) else {
                return;
            };
            let client = LauncherClient::for_test(path.0.clone(), Duration::from_millis(20));

            let error = client.preflight().await.unwrap_err();
            assert!(matches!(error, LauncherClientError::ReadTimeout));
        }

        #[tokio::test]
        async fn request_write_timeout_is_reported() {
            let Some((sender, _receiver)) = available_or_skip(nonblocking_socket_pair()) else {
                return;
            };
            let packet = vec![0_u8; 1024];
            loop {
                // SAFETY: packet remains readable for the duration of send.
                let sent = unsafe {
                    libc::send(
                        sender.as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        return;
                    }
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
                assert_eq!(sent as usize, packet.len());
            }
            let sender = AsyncFd::new(sender).unwrap();

            let error = send_with_timeout(&sender, &packet, Duration::from_millis(20))
                .await
                .unwrap_err();
            assert!(matches!(error, LauncherClientError::WriteTimeout));
        }

        fn response_server(
            response: LauncherResponse,
            response_delay: Duration,
            hold_open: Duration,
            client_io_timeout: Duration,
        ) -> Option<(
            LauncherClient,
            tokio::task::JoinHandle<LauncherRequestKind>,
            TestSocketPath,
        )> {
            let path = TestSocketPath::new();
            let listener = available_or_skip(bind_listener(&path.0, 1))?;
            let listener = AsyncFd::new(listener).unwrap();
            let response = encode_response_frame(&response).unwrap();
            let server = tokio::spawn(async move {
                let socket = accept(&listener).await.unwrap();
                let packet = receive_packet(
                    &socket,
                    FRAME_HEADER_BYTES + crate::launcher_protocol::REQUEST_MAX_BYTES,
                )
                .await
                .unwrap();
                assert!(!packet.truncated);
                let request = decode_request_frame(&packet.frame).unwrap().request;
                tokio::time::sleep(response_delay).await;
                send_packet(&socket, &response).await.unwrap();
                tokio::time::sleep(hold_open).await;
                request
            });
            let client = LauncherClient::for_test(path.0.clone(), client_io_timeout);
            Some((client, server, path))
        }

        async fn accept(listener: &AsyncFd<OwnedFd>) -> io::Result<AsyncFd<OwnedFd>> {
            loop {
                let mut guard = listener.readable().await?;
                match guard.try_io(|listener| {
                    // SAFETY: accept4 has no pointer outputs and returns a newly owned descriptor.
                    let fd = unsafe {
                        libc::accept4(
                            listener.get_ref().as_raw_fd(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // SAFETY: accept4 returned a new descriptor owned by this process.
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                }) {
                    Ok(result) => return AsyncFd::new(result?),
                    Err(_) => continue,
                }
            }
        }

        fn execute_request(run_id: &str) -> ExecuteRequest {
            ExecuteRequest {
                run_id: run_id.to_owned(),
                message_id: "message-1".to_owned(),
                prompt: "Run the isolated task.".to_owned(),
                workspace: Path::new(CODEX_INPUT_ROOT).join(run_id),
                model: Some("gpt-5.5".to_owned()),
                reasoning_effort: Some(ReasoningEffort::Xhigh),
                timeout_seconds: 60,
                output_char_limit: 100,
                skip_git_repo_check: true,
            }
        }

        struct TestSocketPath(PathBuf);

        impl TestSocketPath {
            fn new() -> Self {
                Self(PathBuf::from(format!(
                    "/tmp/webex-launcher-client-{}-{}.sock",
                    std::process::id(),
                    NEXT_PATH_ID.fetch_add(1, Ordering::Relaxed)
                )))
            }
        }

        impl Drop for TestSocketPath {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new() -> Self {
                let path = PathBuf::from(format!(
                    "/tmp/webex-launcher-metadata-{}-{}",
                    std::process::id(),
                    NEXT_PATH_ID.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir(&path).unwrap();
                Self(path)
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn bind_listener(path: &Path, backlog: libc::c_int) -> io::Result<OwnedFd> {
            let socket = blocking_socket()?;
            let (address, address_len) = socket_address(path)?;
            // SAFETY: address is initialized and address_len covers its filesystem path.
            if unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: socket is a bound SOCK_SEQPACKET descriptor.
            if unsafe { libc::listen(socket.as_raw_fd(), backlog) } != 0 {
                return Err(io::Error::last_os_error());
            }
            set_nonblocking(socket.as_raw_fd())?;
            Ok(socket)
        }

        fn blocking_socket() -> io::Result<OwnedFd> {
            // SAFETY: socket has no pointer arguments and returns a newly owned descriptor.
            let fd = unsafe {
                libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: socket returned a new descriptor owned by this process.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }

        fn connect_now(fd: RawFd, path: &Path) -> io::Result<()> {
            let (address, address_len) = socket_address(path)?;
            // SAFETY: address is initialized and address_len covers its filesystem path.
            if unsafe {
                libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn saturate_listener(path: &Path) -> io::Result<Vec<OwnedFd>> {
            let mut connections = Vec::new();
            for _ in 0..32 {
                let socket = blocking_socket()?;
                set_nonblocking(socket.as_raw_fd())?;
                match connect_now(socket.as_raw_fd(), path) {
                    Ok(()) => connections.push(socket),
                    Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                        return Ok(connections);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::other(
                "test listener backlog could not be saturated",
            ))
        }

        fn set_nonblocking(fd: RawFd) -> io::Result<()> {
            // SAFETY: fcntl does not dereference userspace pointers for these operations.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn nonblocking_socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
            let mut descriptors = [-1; 2];
            // SAFETY: descriptors has storage for the two returned descriptors.
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: socketpair returned two descriptors owned by this process.
            Ok(unsafe {
                (
                    OwnedFd::from_raw_fd(descriptors[0]),
                    OwnedFd::from_raw_fd(descriptors[1]),
                )
            })
        }

        fn socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
            let mut value = 0;
            let mut length = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: value and length point to writable values of the expected sizes.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if length as usize != size_of::<libc::c_int>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "socket option had an invalid size",
                ));
            }
            Ok(value)
        }

        fn available_or_skip<T>(result: io::Result<T>) -> Option<T> {
            match result {
                Ok(value) => Some(value),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => None,
                Err(error) => panic!("unexpected socket test error: {error}"),
            }
        }
    }
}

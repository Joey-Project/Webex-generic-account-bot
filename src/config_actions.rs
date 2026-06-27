use std::{path::PathBuf, time::Duration};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::{
    ffi::CString,
    mem::MaybeUninit,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    ptr,
};
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const CONFIG_ACTION_SOCKET: &str = "/run/webex-generic-account-bot/config-pull.sock";
#[cfg(unix)]
const CONFIG_ACTION_WORKER_USER: &str = "webex-config-deploy";
#[cfg(unix)]
const CONFIG_ACTION_SHARED_GROUP: &str = "webex-config-pull";
const CONFIG_ACTION_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIG_ACTION_RESPONSE_MAX_BYTES: usize = 4 * 1024;
const CONFIG_ACTION_MESSAGE_ID_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigAction {
    Pull,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigActionEnqueueStatus {
    Queued,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigActionReceipt {
    pub action_id: String,
    pub status: ConfigActionEnqueueStatus,
}

#[async_trait]
pub trait ConfigActionClient: Send + Sync {
    async fn enqueue(&self, message_id: &str, action: ConfigAction) -> Result<ConfigActionReceipt>;
}

pub struct UnixConfigActionClient {
    socket_path: PathBuf,
    timeout: Duration,
    max_response_bytes: usize,
}

impl Default for UnixConfigActionClient {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(CONFIG_ACTION_SOCKET),
            timeout: CONFIG_ACTION_TIMEOUT,
            max_response_bytes: CONFIG_ACTION_RESPONSE_MAX_BYTES,
        }
    }
}

#[derive(Serialize)]
struct EnqueueRequest<'a> {
    version: u8,
    message_id: &'a str,
    action: ConfigAction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnqueueResponse {
    version: u8,
    status: ConfigActionEnqueueStatus,
    action: ConfigAction,
    action_id: String,
}

#[async_trait]
impl ConfigActionClient for UnixConfigActionClient {
    #[cfg(unix)]
    async fn enqueue(&self, message_id: &str, action: ConfigAction) -> Result<ConfigActionReceipt> {
        validate_message_id(message_id)?;
        validate_socket_path(&self.socket_path)?;
        let encoded = encode_request(message_id, action)?;
        let socket_path = self.socket_path.clone();
        let max_response_bytes = self.max_response_bytes;
        let response = timeout(self.timeout, async move {
            let mut stream = UnixStream::connect(&socket_path).await?;
            stream.write_all(&encoded).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream
                .take((max_response_bytes + 1) as u64)
                .read_to_end(&mut response)
                .await?;
            Result::<Vec<u8>, std::io::Error>::Ok(response)
        })
        .await
        .map_err(|_| anyhow!("config action worker request timed out"))??;
        decode_response(&response, action, max_response_bytes)
    }

    #[cfg(not(unix))]
    async fn enqueue(
        &self,
        _message_id: &str,
        _action: ConfigAction,
    ) -> Result<ConfigActionReceipt> {
        Err(anyhow!(
            "config action worker sockets are supported only on Unix"
        ))
    }
}

fn encode_request(message_id: &str, action: ConfigAction) -> Result<Vec<u8>> {
    validate_message_id(message_id)?;
    let request = EnqueueRequest {
        version: 1,
        message_id,
        action,
    };
    let mut encoded = serde_json::to_vec(&request)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn decode_response(
    response: &[u8],
    action: ConfigAction,
    max_response_bytes: usize,
) -> Result<ConfigActionReceipt> {
    if response.is_empty() || response.len() > max_response_bytes {
        return Err(anyhow!("config action worker response size is invalid"));
    }
    let response: EnqueueResponse = serde_json::from_slice(response)
        .map_err(|_| anyhow!("config action worker returned an invalid response"))?;
    if response.version != 1
        || response.action != action
        || response.action_id.len() != 64
        || !response
            .action_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(anyhow!("config action worker response failed validation"));
    }
    Ok(ConfigActionReceipt {
        action_id: response.action_id,
        status: response.status,
    })
}

fn validate_message_id(message_id: &str) -> Result<()> {
    if message_id.is_empty()
        || message_id.len() > CONFIG_ACTION_MESSAGE_ID_MAX_BYTES
        || message_id
            .bytes()
            .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(anyhow!("config action message ID is invalid"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow!("config action socket path must be absolute"));
    }
    let socket = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow!("config action worker socket is unavailable"))?;
    let expected_uid = lookup_user_uid(CONFIG_ACTION_WORKER_USER)?;
    let expected_gid = lookup_group_gid(CONFIG_ACTION_SHARED_GROUP)?;
    if !socket.file_type().is_socket()
        || socket.uid() != expected_uid
        || socket.gid() != expected_gid
        || socket.mode() & 0o7777 != 0o660
    {
        return Err(anyhow!("config action worker socket metadata is invalid"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config action socket path has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| anyhow!("config action worker socket parent is unavailable"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.gid() != expected_gid
        || parent_metadata.mode() & 0o7777 != 0o750
    {
        return Err(anyhow!("config action worker socket parent is not trusted"));
    }
    Ok(())
}

#[cfg(unix)]
fn lookup_user_uid(name: &str) -> Result<u32> {
    let name = CString::new(name).map_err(|_| anyhow!("config action worker user is invalid"))?;
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::zeroed();
        let mut result = ptr::null_mut();
        // SAFETY: all pointers reference live writable buffers for the duration of the call.
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || result.is_null() {
            return Err(anyhow!("config action worker user is unavailable"));
        }
        // SAFETY: a non-null result from getpwnam_r points to the initialised entry.
        return Ok(unsafe { entry.assume_init() }.pw_uid);
    }
}

#[cfg(unix)]
fn lookup_group_gid(name: &str) -> Result<u32> {
    let name = CString::new(name).map_err(|_| anyhow!("config action worker group is invalid"))?;
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let mut entry = MaybeUninit::<libc::group>::zeroed();
        let mut result = ptr::null_mut();
        // SAFETY: all pointers reference live writable buffers for the duration of the call.
        let status = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || result.is_null() {
            return Err(anyhow!("config action worker group is unavailable"));
        }
        // SAFETY: a non-null result from getgrnam_r points to the initialised entry.
        return Ok(unsafe { entry.assume_init() }.gr_gid);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn encodes_exact_request_and_validates_response() {
        let request = encode_request("message-1", ConfigAction::Pull).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).unwrap(),
            serde_json::json!({
                "version": 1,
                "message_id": "message-1",
                "action": "pull"
            })
        );
        let response = format!(
            "{{\"version\":1,\"status\":\"queued\",\"action\":\"pull\",\"action_id\":\"{}\"}}\n",
            "a".repeat(64)
        );
        let receipt = decode_response(
            response.as_bytes(),
            ConfigAction::Pull,
            CONFIG_ACTION_RESPONSE_MAX_BYTES,
        )
        .unwrap();
        assert_eq!(receipt.action_id, "a".repeat(64));
        assert_eq!(receipt.status, ConfigActionEnqueueStatus::Queued);
    }

    #[test]
    fn rejects_oversized_or_schema_invalid_responses() {
        for response in [
            vec![b'x'; CONFIG_ACTION_RESPONSE_MAX_BYTES + 1],
            br#"{"version":1,"status":"queued","action":"pull","action_id":"bad","extra":true}"#
                .to_vec(),
        ] {
            let error = decode_response(
                &response,
                ConfigAction::Pull,
                CONFIG_ACTION_RESPONSE_MAX_BYTES,
            )
            .unwrap_err();
            assert!(error.to_string().contains("response"));
        }
    }

    #[test]
    fn rejects_invalid_message_ids_and_socket_metadata() {
        for message_id in ["", "line\nbreak"] {
            assert!(validate_message_id(message_id).is_err());
        }
        assert!(validate_message_id(&"x".repeat(257)).is_err());

        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = root.join("worker.sock");
        fs::write(&socket_path, "not a socket").unwrap();
        assert!(validate_socket_path(&socket_path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn temp_root() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "webex-config-action-client-test-{}-{counter}-{nanos}",
            std::process::id()
        ))
    }
}

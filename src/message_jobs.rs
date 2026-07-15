use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tokio::task;
use webex_headless_messenger::SidecarEvent;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

const MESSAGE_JOB_RECORD_VERSION: u8 = 1;
const MAX_MESSAGE_ID_BYTES: usize = 1024;
const MAX_MESSAGE_JOB_RECORD_BYTES: u64 = 512 * 1024;
const MESSAGE_JOB_DIRECTORY_SUFFIX: &str = ".jobs";
const MESSAGE_JOB_FILE_SUFFIX: &str = ".json";
const MESSAGE_JOB_CANDIDATE_PREFIX: &str = ".pending-";
pub const MAX_PENDING_MESSAGE_JOBS: usize = 4096;

static NEXT_CANDIDATE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageJobEnqueueStatus {
    Queued,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageJobRecord {
    version: u8,
    message_id: String,
    enqueued_at_unix_nanos: u64,
    event: SidecarEvent,
}

impl MessageJobRecord {
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    pub fn event(&self) -> &SidecarEvent {
        &self.event
    }

    pub fn into_event(self) -> SidecarEvent {
        self.event
    }
}

#[derive(Debug)]
pub struct DurableMessageJobs {
    root: PathBuf,
    max_pending: usize,
    operation_state: StdMutex<MessageJobIndex>,
    runtime_unhealthy: AtomicBool,
}

#[derive(Debug, Default)]
struct MessageJobIndex {
    entries: HashMap<String, u64>,
}

impl DurableMessageJobs {
    pub fn open(state_file: &Path) -> Result<Self> {
        Self::open_with_limit(state_file, MAX_PENDING_MESSAGE_JOBS)
    }

    fn open_with_limit(state_file: &Path, max_pending: usize) -> Result<Self> {
        let root = message_job_root(state_file)?;
        ensure_private_job_root(&root)?;
        recover_candidates(&root)?;
        let index = load_message_job_index(&root, max_pending)?;
        Ok(Self {
            root,
            max_pending,
            operation_state: StdMutex::new(index),
            runtime_unhealthy: AtomicBool::new(false),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_healthy(&self) -> bool {
        !self.runtime_unhealthy.load(Ordering::Acquire)
    }

    pub fn mark_unhealthy(&self) {
        self.runtime_unhealthy.store(true, Ordering::Release);
    }

    pub async fn enqueue(
        self: &std::sync::Arc<Self>,
        message_id: String,
        event: SidecarEvent,
    ) -> Result<MessageJobEnqueueStatus> {
        let jobs = std::sync::Arc::clone(self);
        task::spawn_blocking(move || jobs.enqueue_sync(&message_id, event))
            .await
            .context("message job enqueue worker panicked")
            .and_then(|result| result)
    }

    pub async fn load(
        self: &std::sync::Arc<Self>,
        message_id: String,
    ) -> Result<Option<MessageJobRecord>> {
        let jobs = std::sync::Arc::clone(self);
        let result = task::spawn_blocking(move || jobs.load_sync(&message_id))
            .await
            .context("message job load worker panicked")
            .and_then(|result| result);
        self.latch_error(result)
    }

    pub async fn remove(self: &std::sync::Arc<Self>, message_id: String) -> Result<bool> {
        let jobs = std::sync::Arc::clone(self);
        let result = task::spawn_blocking(move || jobs.remove_sync(&message_id))
            .await
            .context("message job removal worker panicked")
            .and_then(|result| result);
        self.latch_error(result)
    }

    pub async fn pending_message_ids(
        self: &std::sync::Arc<Self>,
        excluded_message_ids: HashSet<String>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let jobs = std::sync::Arc::clone(self);
        let result = task::spawn_blocking(move || {
            jobs.pending_message_ids_sync(&excluded_message_ids, limit)
        })
        .await
        .context("message job listing worker panicked")
        .and_then(|result| result);
        self.latch_error(result)
    }

    pub async fn pending_count(self: &std::sync::Arc<Self>) -> Result<usize> {
        let jobs = std::sync::Arc::clone(self);
        let result = task::spawn_blocking(move || jobs.pending_count_sync())
            .await
            .context("message job count worker panicked")
            .and_then(|result| result);
        self.latch_error(result)
    }

    fn latch_error<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.mark_unhealthy();
        }
        result
    }

    fn enqueue_sync(
        &self,
        message_id: &str,
        event: SidecarEvent,
    ) -> Result<MessageJobEnqueueStatus> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        validate_message_id(message_id)?;
        validate_message_event(message_id, &event)?;
        self.prepare_root_sync(&mut index)?;

        let final_path = self.job_path(message_id);
        if final_path.try_exists()? {
            let existing = read_job_file(&final_path)?;
            if existing.message_id != message_id {
                return Err(anyhow!(
                    "message job digest collision for {}",
                    final_path.display()
                ));
            }
            register_index_record(&mut index, &existing)?;
            return Ok(MessageJobEnqueueStatus::Existing);
        }
        if self.checked_job_files_sync(&index)?.len() >= self.max_pending {
            return Err(anyhow!(
                "message job backlog reached the fixed limit of {}",
                self.max_pending
            ));
        }

        let record = MessageJobRecord {
            version: MESSAGE_JOB_RECORD_VERSION,
            message_id: message_id.to_owned(),
            enqueued_at_unix_nanos: unix_nanos_now(),
            event,
        };
        validate_record(&record)?;
        let mut bytes = serde_json::to_vec(&record).context("failed to serialise message job")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_MESSAGE_JOB_RECORD_BYTES {
            return Err(anyhow!(
                "message job record exceeds the {} byte limit",
                MAX_MESSAGE_JOB_RECORD_BYTES
            ));
        }

        let candidate_path = self.candidate_path();
        let mut candidate = create_private_file(&candidate_path)?;
        candidate
            .write_all(&bytes)
            .with_context(|| format!("failed to write {}", candidate_path.display()))?;
        candidate
            .sync_all()
            .with_context(|| format!("failed to sync {}", candidate_path.display()))?;
        drop(candidate);

        match fs::hard_link(&candidate_path, &final_path) {
            Ok(()) => {
                sync_directory(&self.root)?;
                register_index_record(&mut index, &record)?;
                fs::remove_file(&candidate_path)
                    .with_context(|| format!("failed to remove {}", candidate_path.display()))?;
                sync_directory(&self.root)?;
                let published = read_job_file(&final_path)?;
                if published != record {
                    return Err(anyhow!(
                        "published message job changed at {}",
                        final_path.display()
                    ));
                }
                Ok(MessageJobEnqueueStatus::Queued)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                remove_candidate(&candidate_path, &self.root)?;
                let existing = read_job_file(&final_path)?;
                if existing.message_id != message_id {
                    return Err(anyhow!(
                        "message job digest collision for {}",
                        final_path.display()
                    ));
                }
                register_index_record(&mut index, &existing)?;
                Ok(MessageJobEnqueueStatus::Existing)
            }
            Err(error) => {
                let cleanup = remove_candidate(&candidate_path, &self.root);
                if let Err(cleanup_error) = cleanup {
                    return Err(anyhow!(
                        "failed to publish {}: {error}; failed to clean candidate: {cleanup_error:#}",
                        final_path.display()
                    ));
                }
                Err(error).with_context(|| format!("failed to publish {}", final_path.display()))
            }
        }
    }

    fn load_sync(&self, message_id: &str) -> Result<Option<MessageJobRecord>> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        validate_message_id(message_id)?;
        self.prepare_root_sync(&mut index)?;
        let path = self.job_path(message_id);
        match read_job_file(&path) {
            Ok(record) => {
                if record.message_id != message_id {
                    return Err(anyhow!(
                        "message job digest collision for {}",
                        path.display()
                    ));
                }
                Ok(Some(record))
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn remove_sync(&self, message_id: &str) -> Result<bool> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        validate_message_id(message_id)?;
        self.prepare_root_sync(&mut index)?;
        let path = self.job_path(message_id);
        match read_job_file(&path) {
            Ok(record) => {
                if record.message_id != message_id {
                    return Err(anyhow!(
                        "message job digest collision for {}",
                        path.display()
                    ));
                }
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove message job {}", path.display()))?;
        index.entries.remove(message_id);
        sync_directory(&self.root)?;
        Ok(true)
    }

    #[cfg(test)]
    fn list_sync(&self) -> Result<Vec<MessageJobRecord>> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        self.prepare_root_sync(&mut index)?;
        let mut jobs = Vec::new();
        for path in self.checked_job_files_sync(&index)? {
            let record = read_job_file(&path)?;
            if self.job_path(&record.message_id) != path {
                return Err(anyhow!(
                    "message job filename does not match its message ID at {}",
                    path.display()
                ));
            }
            jobs.push(record);
        }
        jobs.sort_by(|left, right| {
            left.enqueued_at_unix_nanos
                .cmp(&right.enqueued_at_unix_nanos)
                .then_with(|| left.message_id.cmp(&right.message_id))
        });
        Ok(jobs)
    }

    fn pending_message_ids_sync(
        &self,
        excluded_message_ids: &HashSet<String>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        self.prepare_root_sync(&mut index)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.checked_job_files_sync(&index)?;
        let mut pending = index
            .entries
            .iter()
            .filter(|(message_id, _)| !excluded_message_ids.contains(*message_id))
            .map(|(message_id, enqueued_at)| (*enqueued_at, message_id.clone()))
            .collect::<Vec<_>>();
        pending.sort();
        let message_ids = pending
            .into_iter()
            .take(limit)
            .map(|(_, message_id)| message_id)
            .collect();
        Ok(message_ids)
    }

    fn pending_count_sync(&self) -> Result<usize> {
        let mut index = self
            .operation_state
            .lock()
            .map_err(|_| anyhow!("message job operation lock is poisoned"))?;
        self.prepare_root_sync(&mut index)?;
        Ok(self.checked_job_files_sync(&index)?.len())
    }

    fn prepare_root_sync(&self, index: &mut MessageJobIndex) -> Result<()> {
        ensure_private_job_root(&self.root)?;
        for record in recover_candidates(&self.root)? {
            register_index_record(index, &record)?;
        }
        Ok(())
    }

    fn checked_job_files_sync(&self, index: &MessageJobIndex) -> Result<Vec<PathBuf>> {
        let paths = list_job_files(&self.root)?;
        if paths.len() > self.max_pending {
            return Err(anyhow!(
                "message job backlog exceeds the fixed limit of {}",
                self.max_pending
            ));
        }
        let expected = index
            .entries
            .keys()
            .map(|message_id| self.job_path(message_id))
            .collect::<HashSet<_>>();
        if paths.len() != expected.len() || paths.iter().any(|path| !expected.contains(path)) {
            return Err(anyhow!(
                "message job directory does not match the in-memory startup index"
            ));
        }
        Ok(paths)
    }

    fn job_path(&self, message_id: &str) -> PathBuf {
        message_job_path(&self.root, message_id)
    }

    fn candidate_path(&self) -> PathBuf {
        let candidate_id = NEXT_CANDIDATE_ID.fetch_add(1, Ordering::Relaxed);
        self.root.join(format!(
            "{MESSAGE_JOB_CANDIDATE_PREFIX}{}-{candidate_id}",
            std::process::id()
        ))
    }
}

fn message_job_root(state_file: &Path) -> Result<PathBuf> {
    let file_name = state_file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("state_file must end in a UTF-8 filename"))?;
    let parent = state_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{file_name}{MESSAGE_JOB_DIRECTORY_SUFFIX}")))
}

fn message_job_path(root: &Path, message_id: &str) -> PathBuf {
    root.join(format!(
        "{}{}",
        message_id_digest(message_id),
        MESSAGE_JOB_FILE_SUFFIX
    ))
}

fn load_message_job_index(root: &Path, max_pending: usize) -> Result<MessageJobIndex> {
    let paths = list_job_files(root)?;
    if paths.len() > max_pending {
        return Err(anyhow!(
            "message job backlog exceeds the fixed limit of {max_pending}"
        ));
    }
    let mut index = MessageJobIndex::default();
    for path in paths {
        let record = read_job_file(&path)?;
        if message_job_path(root, &record.message_id) != path {
            return Err(anyhow!(
                "message job filename does not match its message ID at {}",
                path.display()
            ));
        }
        register_index_record(&mut index, &record)?;
    }
    Ok(index)
}

fn register_index_record(index: &mut MessageJobIndex, record: &MessageJobRecord) -> Result<()> {
    match index.entries.entry(record.message_id.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(record.enqueued_at_unix_nanos);
            Ok(())
        }
        Entry::Occupied(entry) if *entry.get() == record.enqueued_at_unix_nanos => Ok(()),
        Entry::Occupied(_) => Err(anyhow!(
            "message job index contains conflicting records for message ID"
        )),
    }
}

pub fn validate_message_id(message_id: &str) -> Result<()> {
    if message_id.is_empty() || message_id.len() > MAX_MESSAGE_ID_BYTES {
        return Err(anyhow!(
            "message ID must contain 1..={MAX_MESSAGE_ID_BYTES} bytes"
        ));
    }
    if message_id.chars().any(char::is_control) {
        return Err(anyhow!("message ID must not contain control characters"));
    }
    Ok(())
}

fn validate_message_event(message_id: &str, event: &SidecarEvent) -> Result<()> {
    if event.version != 1 || event.resource != "messages" || event.event != "created" {
        return Err(anyhow!(
            "only version 1 message-created events may be queued"
        ));
    }
    if event.data.get("id").and_then(serde_json::Value::as_str) != Some(message_id) {
        return Err(anyhow!(
            "queued event message ID does not match the durable job ID"
        ));
    }
    Ok(())
}

fn validate_record(record: &MessageJobRecord) -> Result<()> {
    if record.version != MESSAGE_JOB_RECORD_VERSION {
        return Err(anyhow!(
            "unsupported message job record version {}",
            record.version
        ));
    }
    validate_message_id(&record.message_id)?;
    validate_message_event(&record.message_id, &record.event)
}

fn message_id_digest(message_id: &str) -> String {
    digest(&SHA256, message_id.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_nanos_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

fn ensure_private_job_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_job_root_metadata(root, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root
                .parent()
                .ok_or_else(|| anyhow!("message job root has no parent"))?;
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(root) {
                Ok(()) => sync_directory(parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create message job root {}", root.display())
                    });
                }
            }
            let metadata = fs::symlink_metadata(root)
                .with_context(|| format!("failed to stat {}", root.display()))?;
            validate_job_root_metadata(root, &metadata)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to stat message job root {}", root.display())),
    }
}

fn validate_job_root_metadata(root: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "message job root must be a real directory: {}",
            root.display()
        ));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(anyhow!(
                "message job root must be owned by the current effective user: {}",
                root.display()
            ));
        }
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(anyhow!(
                "message job root must have mode 0700: {}",
                root.display()
            ));
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))
}

fn open_job_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
        .open(path)
        .with_context(|| format!("failed to open message job {}", path.display()))
}

fn read_job_file(path: &Path) -> Result<MessageJobRecord> {
    let mut file = open_job_file(path)?;
    let before = file
        .metadata()
        .with_context(|| format!("failed to stat message job {}", path.display()))?;
    validate_job_file_metadata(path, &before, 1)?;
    if before.len() > MAX_MESSAGE_JOB_RECORD_BYTES {
        return Err(anyhow!(
            "message job exceeds the {} byte limit: {}",
            MAX_MESSAGE_JOB_RECORD_BYTES,
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_MESSAGE_JOB_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read message job {}", path.display()))?;
    if bytes.len() as u64 > MAX_MESSAGE_JOB_RECORD_BYTES {
        return Err(anyhow!(
            "message job exceeds the {} byte limit: {}",
            MAX_MESSAGE_JOB_RECORD_BYTES,
            path.display()
        ));
    }
    let after = file
        .metadata()
        .with_context(|| format!("failed to restat message job {}", path.display()))?;
    if !same_file_snapshot(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(anyhow!(
            "message job changed while it was read: {}",
            path.display()
        ));
    }
    let record: MessageJobRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid message job JSON at {}", path.display()))?;
    validate_record(&record)
        .with_context(|| format!("invalid message job at {}", path.display()))?;
    Ok(record)
}

fn validate_job_file_metadata(path: &Path, metadata: &fs::Metadata, links: u64) -> Result<()> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "message job must be a real regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != links
        {
            return Err(anyhow!(
                "message job must be current-user-owned mode 0600 with {links} link(s): {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    }
}

fn list_job_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read message job root {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root.display()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow!("message job filename is not UTF-8"))?;
        if is_job_filename(name) {
            let metadata = fs::symlink_metadata(entry.path()).with_context(|| {
                format!("failed to stat message job {}", entry.path().display())
            })?;
            validate_job_file_metadata(&entry.path(), &metadata, 1)?;
            files.push(entry.path());
            continue;
        }
        if name.starts_with(MESSAGE_JOB_CANDIDATE_PREFIX) {
            return Err(anyhow!(
                "unrecovered message job candidate remains at {}",
                entry.path().display()
            ));
        }
        return Err(anyhow!(
            "unexpected entry in message job root: {}",
            entry.path().display()
        ));
    }
    files.sort();
    Ok(files)
}

fn is_job_filename(name: &str) -> bool {
    let Some(digest) = name.strip_suffix(MESSAGE_JOB_FILE_SUFFIX) else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recover_candidates(root: &Path) -> Result<Vec<MessageJobRecord>> {
    let mut removed = false;
    let mut published = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read message job root {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(anyhow!("message job candidate filename is not UTF-8"));
        };
        if !name.starts_with(MESSAGE_JOB_CANDIDATE_PREFIX) {
            continue;
        }
        let candidate_path = entry.path();
        let metadata = fs::symlink_metadata(&candidate_path).with_context(|| {
            format!(
                "failed to stat message job candidate {}",
                candidate_path.display()
            )
        })?;
        #[cfg(unix)]
        let links = metadata.nlink();
        #[cfg(not(unix))]
        let links = 1;
        if links == 1 {
            validate_job_file_metadata(&candidate_path, &metadata, 1)?;
        } else if links == 2 {
            validate_job_file_metadata(&candidate_path, &metadata, 2)?;
            let record = read_candidate_file(&candidate_path, 2)?;
            let final_path = root.join(format!(
                "{}{}",
                message_id_digest(&record.message_id),
                MESSAGE_JOB_FILE_SUFFIX
            ));
            let final_metadata = fs::symlink_metadata(&final_path).with_context(|| {
                format!(
                    "published link for candidate {} is unavailable",
                    candidate_path.display()
                )
            })?;
            if !same_file_identity(&metadata, &final_metadata) {
                return Err(anyhow!(
                    "message job candidate has an unexpected second link: {}",
                    candidate_path.display()
                ));
            }
            published.push(record);
        } else {
            return Err(anyhow!(
                "message job candidate has an unexpected link count: {}",
                candidate_path.display()
            ));
        }
        fs::remove_file(&candidate_path).with_context(|| {
            format!(
                "failed to remove message job candidate {}",
                candidate_path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(published)
}

fn read_candidate_file(path: &Path, links: u64) -> Result<MessageJobRecord> {
    let mut file = open_job_file(path)?;
    let before = file.metadata()?;
    validate_job_file_metadata(path, &before, links)?;
    if before.len() > MAX_MESSAGE_JOB_RECORD_BYTES {
        return Err(anyhow!(
            "message job candidate is too large: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_MESSAGE_JOB_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MESSAGE_JOB_RECORD_BYTES {
        return Err(anyhow!(
            "message job candidate is too large: {}",
            path.display()
        ));
    }
    let after = file.metadata()?;
    if !same_file_snapshot(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(anyhow!(
            "message job candidate changed while it was read: {}",
            path.display()
        ));
    }
    let record: MessageJobRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid message job candidate JSON at {}", path.display()))?;
    validate_record(&record)?;
    Ok(record)
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn remove_candidate(candidate_path: &Path, root: &Path) -> Result<()> {
    match fs::remove_file(candidate_path) {
        Ok(()) => sync_directory(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove candidate {}", candidate_path.display())),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::*;

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn queued_job_survives_reopen_and_removal() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let event = message_event("message-1", "first body");

        assert_eq!(
            jobs.enqueue_sync("message-1", event.clone()).unwrap(),
            MessageJobEnqueueStatus::Queued
        );
        drop(jobs);

        let reopened = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let records = reopened.list_sync().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message_id(), "message-1");
        assert_eq!(records[0].event(), &event);
        assert!(reopened.remove_sync("message-1").unwrap());
        assert!(!reopened.remove_sync("message-1").unwrap());
        assert!(
            DurableMessageJobs::open(&fixture.state_file)
                .unwrap()
                .list_sync()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn duplicate_enqueue_preserves_the_first_event() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();

        assert_eq!(
            jobs.enqueue_sync("message-1", message_event("message-1", "first"))
                .unwrap(),
            MessageJobEnqueueStatus::Queued
        );
        assert_eq!(
            jobs.enqueue_sync("message-1", message_event("message-1", "second"))
                .unwrap(),
            MessageJobEnqueueStatus::Existing
        );

        let record = jobs.load_sync("message-1").unwrap().unwrap();
        assert_eq!(record.event.data["text"], "first");
    }

    #[test]
    fn fixed_backlog_limit_rejects_new_jobs_without_damaging_existing_jobs() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open_with_limit(&fixture.state_file, 1).unwrap();
        jobs.enqueue_sync("message-1", message_event("message-1", "first"))
            .unwrap();

        let error = jobs
            .enqueue_sync("message-2", message_event("message-2", "second"))
            .unwrap_err();

        assert!(error.to_string().contains("fixed limit of 1"));
        assert_eq!(jobs.list_sync().unwrap().len(), 1);
    }

    #[test]
    fn pending_ids_are_bounded_and_exclude_active_jobs() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        for message_id in ["message-1", "message-2", "message-3"] {
            jobs.enqueue_sync(message_id, message_event(message_id, "body"))
                .unwrap();
        }

        let excluded = HashSet::from(["message-1".to_owned()]);
        let pending = jobs.pending_message_ids_sync(&excluded, 1).unwrap();

        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0], "message-1");
        assert_eq!(jobs.pending_count_sync().unwrap(), 3);
        assert!(
            jobs.pending_message_ids_sync(&HashSet::new(), 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn startup_recovers_published_job_after_candidate_removal_crash() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let root = jobs.root().to_path_buf();
        let record = MessageJobRecord {
            version: MESSAGE_JOB_RECORD_VERSION,
            message_id: "message-published".to_owned(),
            enqueued_at_unix_nanos: 1,
            event: message_event("message-published", "body"),
        };
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        let candidate = root.join(".pending-crash-after-publish");
        fs::write(&candidate, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            &candidate,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let final_path = jobs.job_path("message-published");
        fs::hard_link(&candidate, &final_path).unwrap();
        drop(jobs);

        let reopened = DurableMessageJobs::open(&fixture.state_file).unwrap();

        assert!(!candidate.exists());
        assert_eq!(
            reopened.load_sync("message-published").unwrap().unwrap(),
            record
        );
    }

    #[test]
    fn startup_removes_unpublished_candidate_but_rejects_corrupt_published_job() {
        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let root = jobs.root().to_path_buf();
        drop(jobs);
        let candidate = root.join(".pending-test");
        fs::write(&candidate, b"partial").unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            &candidate,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        DurableMessageJobs::open(&fixture.state_file).unwrap();
        assert!(!candidate.exists());

        let corrupt = root.join(format!("{}{}", "a".repeat(64), MESSAGE_JOB_FILE_SUFFIX));
        fs::write(&corrupt, b"not-json\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            &corrupt,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let error = DurableMessageJobs::open(&fixture.state_file).unwrap_err();
        assert!(error.to_string().contains("invalid message job JSON"));
    }

    #[cfg(unix)]
    #[test]
    fn startup_rejects_symlinks_and_permissive_roots() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let root = jobs.root().to_path_buf();
        drop(jobs);
        let outside = fixture.root.join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(
            &outside,
            root.join(format!("{}{}", "b".repeat(64), MESSAGE_JOB_FILE_SUFFIX)),
        )
        .unwrap();
        assert!(DurableMessageJobs::open(&fixture.state_file).is_err());
        fs::remove_file(root.join(format!("{}{}", "b".repeat(64), MESSAGE_JOB_FILE_SUFFIX)))
            .unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let error = DurableMessageJobs::open(&fixture.state_file).unwrap_err();
        assert!(error.to_string().contains("mode 0700"));
    }

    #[cfg(unix)]
    #[test]
    fn startup_rejects_fifo_without_blocking_and_opens_jobs_nonblocking() {
        use std::{
            ffi::CString,
            os::{fd::AsRawFd as _, unix::ffi::OsStrExt as _},
        };

        let fixture = Fixture::new();
        let jobs = DurableMessageJobs::open(&fixture.state_file).unwrap();
        let root = jobs.root().to_path_buf();
        drop(jobs);
        let fifo = root.join(format!("{}{}", "c".repeat(64), MESSAGE_JOB_FILE_SUFFIX));
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let error = DurableMessageJobs::open(&fixture.state_file).unwrap_err();
        assert!(error.to_string().contains("real regular file"));
        fs::remove_file(&fifo).unwrap();

        let regular = root.join("nonblocking-check");
        fs::write(&regular, b"check").unwrap();
        let file = open_job_file(&regular).unwrap();
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    fn message_event(message_id: &str, text: &str) -> SidecarEvent {
        SidecarEvent::message_created(json!({
            "id": message_id,
            "roomId": "room-1",
            "text": text,
        }))
    }

    struct Fixture {
        root: PathBuf,
        state_file: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("webex-message-jobs-{}-{id}", std::process::id()));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&root).unwrap();
            let state_file = root.join("state.jsonl");
            Self { root, state_file }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

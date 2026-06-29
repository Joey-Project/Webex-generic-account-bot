#![cfg(target_os = "linux")]

use std::{
    collections::HashSet,
    ffi::{CStr, CString, OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path},
};

#[cfg(test)]
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use ring::{
    digest::{Context as DigestContext, SHA256},
    rand::{SecureRandom, SystemRandom},
};

use crate::{
    input_sealer::{CODEX_PENDING_INPUT_ROOT, ensure_posix_acl_absent},
    isolated_execution::production_codex_group_ids,
    launcher_protocol::{
        INPUT_STAGING_PROCESS_TIMEOUT_SECONDS, INPUT_STAGING_WORK_TIMEOUT_SECONDS,
        PENDING_WORKSPACE_CLEANUP_PROCESS_TIMEOUT_SECONDS,
        PENDING_WORKSPACE_CLEANUP_WORK_TIMEOUT_SECONDS,
    },
    work_budget::{WorkBudget, run_blocking_with_process_watchdog},
};

const PENDING_ROOT_MODE: u32 = 0o2730;
const PRIVATE_DIRECTORY_MODE: u32 = 0o2700;
const SOURCE_DIRECTORY_MODE: u32 = 0o2770;
const PRIVATE_FILE_MODE: u32 = 0o600;
const SOURCE_FILE_MODE: u32 = 0o640;
const WORKSPACE_ENTRY_MAX: usize = 8_192;
const WORKSPACE_DEPTH_MAX: usize = 32;
const WORKSPACE_TOTAL_BYTES_MAX: u64 = 2_112 * 1024 * 1024;
const RUN_ID_PREFIX: &str = "run-";
const RUN_ID_DIGEST_BYTES: usize = 30;
const RUN_ID_ATTEMPTS: usize = 128;

/// A pending workspace owned by this process until the launcher quarantines it.
#[derive(Debug)]
pub(crate) struct PendingWorkspace {
    run_id: String,
    #[cfg(test)]
    pending_path: PathBuf,
    pending_root: File,
    workspace: File,
    workspace_name: CString,
    workspace_identity: ObjectIdentity,
    cleanup_armed: bool,
}

impl PendingWorkspace {
    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    #[cfg(test)]
    fn pending_path(&self) -> &Path {
        &self.pending_path
    }

    pub(crate) async fn cleanup(mut self) -> Result<()> {
        let deadline = WorkBudget::after(std::time::Duration::from_secs(
            PENDING_WORKSPACE_CLEANUP_WORK_TIMEOUT_SECONDS,
        ));
        run_blocking_with_process_watchdog(
            "pending workspace cleanup",
            std::time::Duration::from_secs(PENDING_WORKSPACE_CLEANUP_PROCESS_TIMEOUT_SECONDS),
            move || self.cleanup_with_deadline(Some(&deadline)),
        )
        .await?
    }

    fn cleanup_with_deadline(&mut self, deadline: Option<&WorkBudget>) -> Result<()> {
        if !self.cleanup_armed {
            return Ok(());
        }
        let held_identity = stat_fd(self.workspace.as_raw_fd())?.identity();
        if held_identity != self.workspace_identity {
            bail!("refusing to clean a pending workspace whose held identity changed");
        }
        remove_owned_workspace(
            &self.pending_root,
            &self.workspace,
            &self.workspace_name,
            &self.workspace_identity,
            true,
            deadline,
        )?;
        self.cleanup_armed = false;
        Ok(())
    }
}

impl Drop for PendingWorkspace {
    fn drop(&mut self) {
        if self.cleanup_armed {
            tracing::warn!(
                run_id = %self.run_id,
                "pending workspace cleanup was deferred to tmpfiles"
            );
        }
    }
}

/// Copies only an explicitly supplied evidence tree into a fresh pending run.
/// `None` deliberately creates an empty workspace; the configured Codex cwd is
/// never an implicit input.
pub(crate) async fn stage_workspace(
    message_id: &str,
    evidence_root: Option<&Path>,
) -> Result<PendingWorkspace> {
    let message_id = message_id.to_owned();
    let evidence_root = evidence_root.map(Path::to_path_buf);
    let deadline = WorkBudget::after(std::time::Duration::from_secs(
        INPUT_STAGING_WORK_TIMEOUT_SECONDS,
    ));
    run_blocking_with_process_watchdog(
        "pending workspace staging",
        std::time::Duration::from_secs(INPUT_STAGING_PROCESS_TIMEOUT_SECONDS),
        move || {
            let groups = production_codex_group_ids()?;
            stage_workspace_at(
                Path::new(CODEX_PENDING_INPUT_ROOT),
                0,
                effective_uid(),
                groups.launch,
                &message_id,
                evidence_root.as_deref(),
                Limits {
                    deadline: Some(deadline),
                    ..Limits::default()
                },
            )
        },
    )
    .await?
}

#[derive(Clone)]
struct Limits {
    entries: usize,
    depth: usize,
    bytes: u64,
    deadline: Option<WorkBudget>,
    #[cfg(test)]
    mutation_hook: Option<FileMutationHook>,
    #[cfg(test)]
    post_copy_mutation_hook: Option<FileMutationHook>,
}

#[cfg(test)]
type FileMutationHook = fn(RawFd, &CStr) -> Result<()>;

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: WORKSPACE_ENTRY_MAX,
            depth: WORKSPACE_DEPTH_MAX,
            bytes: WORKSPACE_TOTAL_BYTES_MAX,
            deadline: None,
            #[cfg(test)]
            mutation_hook: None,
            #[cfg(test)]
            post_copy_mutation_hook: None,
        }
    }
}

struct CopyState {
    entries: usize,
    bytes: u64,
    source_uid: u32,
    launch_gid: u32,
    limits: Limits,
}

impl CopyState {
    fn check_deadline(&self) -> Result<()> {
        if let Some(deadline) = self.limits.deadline.as_ref() {
            deadline.check("pending workspace staging")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StatSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl StatSnapshot {
    fn from_stat(metadata: &libc::stat) -> Self {
        Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            links: metadata.st_nlink,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            size: metadata.st_size,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        }
    }

    fn file_type(&self) -> u32 {
        self.mode & libc::S_IFMT
    }

    fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }

    fn identity(&self) -> ObjectIdentity {
        ObjectIdentity {
            device: self.device,
            inode: self.inode,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[allow(clippy::too_many_arguments)]
fn stage_workspace_at(
    pending_root_path: &Path,
    expected_root_uid: u32,
    source_uid: u32,
    launch_gid: u32,
    message_id: &str,
    evidence_root: Option<&Path>,
    limits: Limits,
) -> Result<PendingWorkspace> {
    if let Some(deadline) = limits.deadline.as_ref() {
        deadline.check("pending workspace staging")?;
    }
    let pending_root = open_path_directory(pending_root_path, false)
        .context("failed to open the pending input root")?;
    validate_pending_root(
        &pending_root,
        expected_root_uid,
        launch_gid,
        "pending input root",
    )?;

    let source = evidence_root
        .map(|path| {
            open_path_directory(path, true)
                .with_context(|| format!("failed to open evidence root {}", path.display()))
        })
        .transpose()?;
    if let Some(source) = &source {
        let source_metadata = stat_fd(source.as_raw_fd())?;
        let pending_metadata = stat_fd(pending_root.as_raw_fd())?;
        if source_metadata.identity() == pending_metadata.identity() {
            bail!("evidence root must not be the pending input root");
        }
    }

    let (run_id, workspace_name, workspace, workspace_identity) =
        create_run_directory(&pending_root, message_id, source_uid, launch_gid)?;
    let result = (|| {
        if let Some(source) = &source {
            let mut state = CopyState {
                entries: 0,
                bytes: 0,
                source_uid,
                launch_gid,
                limits: limits.clone(),
            };
            copy_directory(source, &workspace, 0, &mut state)?;
        }

        if let Some(deadline) = limits.deadline.as_ref() {
            deadline.check("pending workspace publication")?;
        }

        set_mode(workspace.as_raw_fd(), SOURCE_DIRECTORY_MODE)?;
        validate_destination_directory(&workspace, source_uid, launch_gid, SOURCE_DIRECTORY_MODE)?;
        sync_checked(&workspace).context("failed to persist the pending workspace")?;

        let reopened = open_path_directory(pending_root_path, false)
            .context("failed to re-open the pending input root")?;
        validate_pending_root(
            &reopened,
            expected_root_uid,
            launch_gid,
            "pending input root",
        )?;
        if stat_fd(reopened.as_raw_fd())?.identity()
            != stat_fd(pending_root.as_raw_fd())?.identity()
        {
            bail!("pending input root path changed during workspace staging");
        }
        let published = stat_at(pending_root.as_raw_fd(), &workspace_name)?;
        if published.identity() != workspace_identity {
            bail!("pending workspace identity changed during staging");
        }
        validate_destination_directory_metadata(
            &published,
            source_uid,
            launch_gid,
            SOURCE_DIRECTORY_MODE,
        )?;
        sync_filesystem(&workspace)
            .context("failed to persist the pending workspace publication")?;
        Ok(())
    })();

    if let Err(error) = result {
        return match remove_owned_workspace(
            &pending_root,
            &workspace,
            &workspace_name,
            &workspace_identity,
            false,
            None,
        ) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow!(
                "{error:#}; failed to clean partial pending workspace: {cleanup_error:#}"
            )),
        };
    }

    Ok(PendingWorkspace {
        #[cfg(test)]
        pending_path: pending_root_path.join(&run_id),
        run_id,
        pending_root,
        workspace,
        workspace_name,
        workspace_identity,
        cleanup_armed: true,
    })
}

fn validate_pending_root(
    root: &File,
    expected_uid: u32,
    launch_gid: u32,
    description: &str,
) -> Result<()> {
    let metadata = stat_fd(root.as_raw_fd())?;
    if metadata.file_type() != libc::S_IFDIR
        || metadata.uid != expected_uid
        || metadata.gid != launch_gid
        || metadata.permissions() != PENDING_ROOT_MODE
    {
        bail!("{description} metadata is invalid");
    }
    Ok(())
}

fn create_run_directory(
    pending_root: &File,
    message_id: &str,
    source_uid: u32,
    launch_gid: u32,
) -> Result<(String, CString, File, ObjectIdentity)> {
    let random = SystemRandom::new();
    for _ in 0..RUN_ID_ATTEMPTS {
        let run_id = generate_run_id(message_id, &random)?;
        let name = CString::new(run_id.as_bytes()).expect("generated run id contains no NUL");
        // SAFETY: the held parent descriptor and generated component are valid.
        if unsafe {
            libc::mkdirat(
                pending_root.as_raw_fd(),
                name.as_ptr(),
                PRIVATE_DIRECTORY_MODE,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error).context("failed to create a pending workspace");
        }

        let setup = (|| {
            let workspace = open_directory_at(pending_root.as_raw_fd(), &name, true)?;
            set_mode(workspace.as_raw_fd(), PRIVATE_DIRECTORY_MODE)?;
            validate_destination_directory(
                &workspace,
                source_uid,
                launch_gid,
                PRIVATE_DIRECTORY_MODE,
            )?;
            let identity = stat_fd(workspace.as_raw_fd())?.identity();
            Ok((workspace, identity))
        })();
        return match setup {
            Ok((workspace, identity)) => Ok((run_id, name, workspace, identity)),
            Err(error) => {
                let cleanup = unlink_at(pending_root.as_raw_fd(), &name, libc::AT_REMOVEDIR);
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(anyhow!(
                        "{error:#}; failed to clean new pending workspace: {cleanup_error}"
                    )),
                }
            }
        };
    }
    bail!("failed to allocate a unique pending workspace")
}

fn generate_run_id(message_id: &str, random: &SystemRandom) -> Result<String> {
    let mut nonce = [0_u8; 32];
    random
        .fill(&mut nonce)
        .map_err(|_| anyhow!("failed to obtain run identifier randomness"))?;

    let mut digest = DigestContext::new(&SHA256);
    digest.update(b"webex-codex-pending-run-v1\0");
    digest.update(&(message_id.len() as u64).to_be_bytes());
    digest.update(message_id.as_bytes());
    digest.update(&nonce);
    let digest = digest.finish();

    let mut run_id = String::with_capacity(RUN_ID_PREFIX.len() + RUN_ID_DIGEST_BYTES * 2);
    run_id.push_str(RUN_ID_PREFIX);
    for byte in &digest.as_ref()[..RUN_ID_DIGEST_BYTES] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        run_id.push(HEX[(byte >> 4) as usize] as char);
        run_id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(run_id)
}

fn copy_directory(source: &File, target: &File, depth: usize, state: &mut CopyState) -> Result<()> {
    state.check_deadline()?;
    if depth > state.limits.depth {
        bail!("evidence workspace nesting exceeds its limit");
    }
    let before = stat_fd(source.as_raw_fd())?;
    if before.file_type() != libc::S_IFDIR {
        bail!("evidence workspace entry is not a directory");
    }
    let remaining_entries = state.limits.entries.saturating_sub(state.entries);
    let entries = list_directory(source.as_raw_fd(), remaining_entries)?;

    for name in entries {
        state.check_deadline()?;
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("evidence workspace entry count overflowed"))?;
        if state.entries > state.limits.entries {
            bail!("evidence workspace has too many entries");
        }
        if forbidden_name(&name) {
            bail!("evidence workspace contains a forbidden control name");
        }
        let c_name = c_string(&name)?;
        let entry = stat_at(source.as_raw_fd(), &c_name)?;
        match entry.file_type() {
            libc::S_IFDIR => {
                let source_child = open_directory_at(source.as_raw_fd(), &c_name, true)?;
                if stat_fd(source_child.as_raw_fd())? != entry {
                    bail!("evidence workspace directory changed before copy");
                }
                mkdir_at(target.as_raw_fd(), &c_name, PRIVATE_DIRECTORY_MODE)?;
                let target_child = open_directory_at(target.as_raw_fd(), &c_name, true)?;
                set_mode(target_child.as_raw_fd(), PRIVATE_DIRECTORY_MODE)?;
                validate_destination_directory(
                    &target_child,
                    state.source_uid,
                    state.launch_gid,
                    PRIVATE_DIRECTORY_MODE,
                )?;
                copy_directory(&source_child, &target_child, depth + 1, state)?;
                if stat_fd(source_child.as_raw_fd())? != entry {
                    bail!("evidence workspace directory changed during copy");
                }
                set_mode(target_child.as_raw_fd(), SOURCE_DIRECTORY_MODE)?;
                validate_destination_directory(
                    &target_child,
                    state.source_uid,
                    state.launch_gid,
                    SOURCE_DIRECTORY_MODE,
                )?;
                sync_checked(&target_child)
                    .context("failed to persist a pending workspace directory")?;
            }
            libc::S_IFREG => copy_file(source, target, &c_name, &entry, state)?,
            libc::S_IFLNK => bail!("evidence workspace contains a symbolic link"),
            _ => bail!("evidence workspace contains a special file"),
        }
    }

    if stat_fd(source.as_raw_fd())? != before {
        bail!("evidence workspace directory metadata changed during copy");
    }
    Ok(())
}

fn copy_file(
    source_directory: &File,
    target_directory: &File,
    name: &CStr,
    entry: &StatSnapshot,
    state: &mut CopyState,
) -> Result<()> {
    state.check_deadline()?;
    if entry.links != 1 {
        bail!("evidence workspace contains a hard-linked file");
    }
    let mut source = open_source_file(source_directory.as_raw_fd(), name)?;
    if stat_fd(source.as_raw_fd())? != *entry {
        bail!("evidence workspace file changed before copy");
    }
    #[cfg(test)]
    if let Some(hook) = state.limits.mutation_hook {
        hook(source_directory.as_raw_fd(), name)?;
    }

    let size = u64::try_from(entry.size)
        .map_err(|_| anyhow!("evidence workspace file size is invalid"))?;
    state.bytes = state
        .bytes
        .checked_add(size)
        .ok_or_else(|| anyhow!("evidence workspace size overflowed"))?;
    if state.bytes > state.limits.bytes {
        bail!("evidence workspace exceeds its size limit");
    }

    let mut target = create_target_file(target_directory.as_raw_fd(), name)?;
    validate_destination_file(
        &target,
        state.source_uid,
        state.launch_gid,
        PRIVATE_FILE_MODE,
        0,
    )?;
    let first_digest = copy_exact_with_digest(
        &mut source,
        &mut target,
        size,
        state.limits.deadline.clone(),
    )?;
    target.flush()?;
    #[cfg(test)]
    if let Some(hook) = state.limits.post_copy_mutation_hook {
        hook(source_directory.as_raw_fd(), name)?;
    }
    source.seek(SeekFrom::Start(0))?;
    let second_digest = hash_exact_source(&mut source, size, state.limits.deadline.clone())?;
    if first_digest.as_ref() != second_digest.as_ref() {
        bail!("evidence workspace file contents changed during copy");
    }
    if stat_fd(source.as_raw_fd())? != *entry
        || stat_at(source_directory.as_raw_fd(), name)? != *entry
    {
        bail!("evidence workspace file metadata changed during copy");
    }

    set_mode(target.as_raw_fd(), SOURCE_FILE_MODE)?;
    sync_checked(&target).context("failed to persist a pending workspace file")?;
    validate_destination_file(
        &target,
        state.source_uid,
        state.launch_gid,
        SOURCE_FILE_MODE,
        entry.size,
    )?;
    Ok(())
}

fn copy_exact_with_digest(
    source: &mut File,
    target: &mut File,
    size: u64,
    deadline: Option<WorkBudget>,
) -> Result<ring::digest::Digest> {
    let mut digest = DigestContext::new(&SHA256);
    let mut remaining = size;
    let mut buffer = [0_u8; 1024 * 1024];
    while remaining > 0 {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("pending workspace copy")?;
        }
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded copy chunk fits usize");
        let read = source.read(&mut buffer[..limit])?;
        if read == 0 {
            bail!("evidence workspace file size changed during copy");
        }
        target.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    reject_source_growth(source)?;
    Ok(digest.finish())
}

fn hash_exact_source(
    source: &mut File,
    size: u64,
    deadline: Option<WorkBudget>,
) -> Result<ring::digest::Digest> {
    let mut digest = DigestContext::new(&SHA256);
    let mut remaining = size;
    let mut buffer = [0_u8; 1024 * 1024];
    while remaining > 0 {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("pending workspace verification")?;
        }
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded hash chunk fits usize");
        let read = source.read(&mut buffer[..limit])?;
        if read == 0 {
            bail!("evidence workspace file size changed during verification");
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    reject_source_growth(source)?;
    Ok(digest.finish())
}

fn reject_source_growth(source: &mut File) -> Result<()> {
    let mut probe = [0_u8; 1];
    if source.read(&mut probe)? != 0 {
        bail!("evidence workspace file size changed during copy");
    }
    Ok(())
}

fn validate_destination_directory(
    directory: &File,
    source_uid: u32,
    launch_gid: u32,
    mode: u32,
) -> Result<()> {
    let metadata = stat_fd(directory.as_raw_fd())?;
    validate_destination_directory_metadata(&metadata, source_uid, launch_gid, mode)?;
    ensure_posix_acl_absent(directory, "pending workspace directory")?;
    Ok(())
}

fn validate_destination_directory_metadata(
    metadata: &StatSnapshot,
    source_uid: u32,
    launch_gid: u32,
    mode: u32,
) -> Result<()> {
    if metadata.file_type() != libc::S_IFDIR
        || metadata.uid != source_uid
        || metadata.gid != launch_gid
        || metadata.permissions() != mode
    {
        bail!("pending workspace directory owner, group, or mode is invalid");
    }
    Ok(())
}

fn validate_destination_file(
    file: &File,
    source_uid: u32,
    launch_gid: u32,
    mode: u32,
    size: i64,
) -> Result<()> {
    let metadata = stat_fd(file.as_raw_fd())?;
    if metadata.file_type() != libc::S_IFREG
        || metadata.uid != source_uid
        || metadata.gid != launch_gid
        || metadata.permissions() != mode
        || metadata.links != 1
        || metadata.size != size
    {
        bail!("pending workspace file owner, group, mode, or size is invalid");
    }
    ensure_posix_acl_absent(file, "pending workspace file")?;
    Ok(())
}

fn open_path_directory(path: &Path, readable: bool) -> Result<File> {
    let absolute = path.is_absolute();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if absolute => {}
            Component::CurDir => {}
            Component::Normal(component) => components.push(component),
            _ => bail!("directory path contains a path escape"),
        }
    }

    let anchor = if absolute {
        CString::new("/").expect("slash contains no NUL")
    } else {
        CString::new(".").expect("dot contains no NUL")
    };
    if components.is_empty() {
        return open_directory_at(libc::AT_FDCWD, &anchor, readable).map_err(Into::into);
    }

    let mut directory = open_directory_at(libc::AT_FDCWD, &anchor, false)?;
    for (index, component) in components.iter().enumerate() {
        let name = c_string(component)?;
        directory = open_directory_at(
            directory.as_raw_fd(),
            &name,
            readable && index + 1 == components.len(),
        )?;
    }
    Ok(directory)
}

fn open_directory_at(directory_fd: RawFd, name: &CStr, readable: bool) -> io::Result<File> {
    let access = if readable {
        libc::O_RDONLY
    } else {
        libc::O_PATH
    };
    let flags = access | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned here.
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_source_file(directory_fd: RawFd, name: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned here.
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn create_target_file(directory_fd: RawFd, name: &CStr) -> io::Result<File> {
    let flags = libc::O_RDWR
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned here.
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags, PRIVATE_FILE_MODE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn list_directory(directory_fd: RawFd, max_entries: usize) -> Result<Vec<OsString>> {
    let dot = CString::new(".").expect("dot contains no NUL");
    let duplicate = open_directory_at(directory_fd, &dot, true)?;
    let duplicate = duplicate.into_raw_fd();
    // SAFETY: `fdopendir` consumes `duplicate`; `closedir` below releases it.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed and did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(error).context("failed to enumerate an evidence directory");
    }

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    loop {
        // SAFETY: this module is Linux-only and errno is thread-local writable state.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains valid until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: this module is Linux-only and errno is thread-local readable state.
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                // SAFETY: `stream` is live and owned by this function.
                unsafe { libc::closedir(stream) };
                return Err(io::Error::from_raw_os_error(errno))
                    .context("failed while enumerating an evidence directory");
            }
            break;
        }
        // SAFETY: POSIX guarantees `d_name` is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if !seen.insert(name.to_vec()) {
            // SAFETY: `stream` is live and owned by this function.
            unsafe { libc::closedir(stream) };
            bail!("evidence workspace contains a duplicate directory entry");
        }
        if entries.len() >= max_entries {
            // SAFETY: `stream` is live and owned by this function.
            unsafe { libc::closedir(stream) };
            bail!("evidence workspace has too many entries");
        }
        entries.push(OsString::from_vec(name.to_vec()));
    }
    // SAFETY: `stream` is live and owned by this function.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to close a directory stream");
    }
    entries.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(entries)
}

fn remove_owned_workspace(
    pending_root: &File,
    workspace: &File,
    workspace_name: &CStr,
    expected: &ObjectIdentity,
    missing_ok: bool,
    deadline: Option<&WorkBudget>,
) -> Result<()> {
    if let Some(deadline) = deadline {
        deadline.check("pending workspace cleanup")?;
    }
    let current = match stat_at(pending_root.as_raw_fd(), workspace_name) {
        Ok(current) => current,
        Err(error) if missing_ok && error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => {
            return Err(error).context("failed to inspect pending workspace cleanup path");
        }
    };
    if &current.identity() != expected {
        bail!("refusing to clean a replaced pending workspace");
    }
    remove_tree_at(pending_root.as_raw_fd(), workspace_name, deadline)?;
    sync_filesystem(workspace).context("failed to persist pending workspace cleanup")
}

fn sync_filesystem(file: &File) -> Result<()> {
    // SAFETY: syncfs uses only the live descriptor to identify its filesystem.
    if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to sync workspace filesystem");
    }
    Ok(())
}

fn remove_tree_at(parent_fd: RawFd, name: &CStr, deadline: Option<&WorkBudget>) -> Result<()> {
    if let Some(deadline) = deadline {
        deadline.check("pending workspace cleanup")?;
    }
    let metadata = stat_at(parent_fd, name)?;
    if metadata.file_type() == libc::S_IFDIR {
        let directory = open_directory_at(parent_fd, name, true)?;
        if stat_fd(directory.as_raw_fd())?.identity() != metadata.identity() {
            bail!("cleanup directory changed before removal");
        }
        for child in list_directory(directory.as_raw_fd(), WORKSPACE_ENTRY_MAX)? {
            let child = c_string(&child)?;
            remove_tree_at(directory.as_raw_fd(), &child, deadline)?;
        }
        sync_checked(&directory)?;
        unlink_at(parent_fd, name, libc::AT_REMOVEDIR)?;
    } else {
        unlink_at(parent_fd, name, 0)?;
    }
    Ok(())
}

fn mkdir_at(directory_fd: RawFd, name: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: the parent descriptor and component are valid for `mkdirat`.
    if unsafe { libc::mkdirat(directory_fd, name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_at(directory_fd: RawFd, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: the parent descriptor and component are valid for `unlinkat`.
    if unsafe { libc::unlinkat(directory_fd, name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_mode(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: `fd` is live and `mode` contains only permission bits.
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sync_checked(file: &File) -> Result<()> {
    file.sync_all().map_err(Into::into)
}

fn stat_fd(fd: RawFd) -> io::Result<StatSnapshot> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `metadata` is valid writable storage and `fd` is live.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    Ok(StatSnapshot::from_stat(&metadata))
}

fn stat_at(directory_fd: RawFd, name: &CStr) -> io::Result<StatSnapshot> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: all pointers and descriptors are valid for `fstatat`.
    if unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    Ok(StatSnapshot::from_stat(&metadata))
}

fn forbidden_name(name: &OsStr) -> bool {
    matches!(
        name.as_bytes(),
        b".git" | b".codex" | b".agents" | b"AGENTS.md" | b"hooks.json"
    )
}

fn c_string(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| anyhow!("path component contains a NUL byte"))
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
fn effective_gid() -> u32 {
    // SAFETY: `getegid` has no preconditions.
    unsafe { libc::getegid() }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        base: PathBuf,
        pending: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow the Unix epoch")
                .as_nanos();
            let base = std::env::temp_dir().join(format!(
                "webex-runner-input-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            let pending = base.join("pending");
            fs::create_dir(&base).unwrap();
            fs::create_dir(&pending).unwrap();
            set_path_mode(&pending, PENDING_ROOT_MODE);
            Self {
                base,
                pending,
                uid: effective_uid(),
                gid: effective_gid(),
            }
        }

        fn evidence(&self, name: &str) -> PathBuf {
            let path = self.base.join(name);
            fs::create_dir(&path).unwrap();
            path
        }

        fn stage(&self, message_id: &str, evidence: Option<&Path>) -> Result<PendingWorkspace> {
            self.stage_with_limits(message_id, evidence, Limits::default())
        }

        fn stage_with_limits(
            &self,
            message_id: &str,
            evidence: Option<&Path>,
            limits: Limits,
        ) -> Result<PendingWorkspace> {
            stage_workspace_at(
                &self.pending,
                self.uid,
                self.uid,
                self.gid,
                message_id,
                evidence,
                limits,
            )
        }

        fn assert_pending_empty(&self) {
            assert_eq!(fs::read_dir(&self.pending).unwrap().count(), 0);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            make_tree_writable(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[tokio::test]
    async fn stages_empty_and_copied_workspaces_with_sealer_metadata() {
        let fixture = Fixture::new();
        let empty = fixture.stage("message-empty", None).unwrap();
        assert!(fs::read_dir(empty.pending_path()).unwrap().next().is_none());
        assert_directory_metadata(empty.pending_path(), fixture.uid, fixture.gid);
        let empty_path = empty.pending_path().to_owned();
        empty.cleanup().await.unwrap();
        assert!(!empty_path.exists());

        let evidence = fixture.evidence("evidence");
        let nested = evidence.join("logs");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("console.log"), b"deterministic evidence\n").unwrap();
        let staged = fixture.stage("message-copy", Some(&evidence)).unwrap();
        assert_eq!(
            fs::read(staged.pending_path().join("logs/console.log")).unwrap(),
            b"deterministic evidence\n"
        );
        assert_directory_metadata(staged.pending_path(), fixture.uid, fixture.gid);
        assert_directory_metadata(
            &staged.pending_path().join("logs"),
            fixture.uid,
            fixture.gid,
        );
        let file = fs::metadata(staged.pending_path().join("logs/console.log")).unwrap();
        assert_eq!(file.uid(), fixture.uid);
        assert_eq!(file.gid(), fixture.gid);
        assert_eq!(file.mode() & 0o7777, SOURCE_FILE_MODE);
        assert_eq!(file.nlink(), 1);
        let staged_path = staged.pending_path().to_owned();
        staged.cleanup().await.unwrap();
        assert!(!staged_path.exists());
    }

    #[test]
    fn allocates_unique_unpredictable_run_ids_for_the_same_message() {
        let fixture = Fixture::new();
        let first = fixture.stage("same-message", None).unwrap();
        let second = fixture.stage("same-message", None).unwrap();
        assert_ne!(first.run_id(), second.run_id());
        for run_id in [first.run_id(), second.run_id()] {
            assert!(run_id.starts_with(RUN_ID_PREFIX));
            assert_eq!(run_id.len(), RUN_ID_PREFIX.len() + RUN_ID_DIGEST_BYTES * 2);
            assert!(
                run_id[RUN_ID_PREFIX.len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            );
            assert!(!run_id.contains("same-message"));
        }
    }

    #[test]
    fn expired_work_budget_fails_before_publishing_a_workspace() {
        let fixture = Fixture::new();
        let evidence = fixture.evidence("expired-evidence");
        fs::write(evidence.join("console.log"), b"data").unwrap();

        let error = fixture
            .stage_with_limits(
                "expired-message",
                Some(&evidence),
                Limits {
                    deadline: Some(WorkBudget::after(std::time::Duration::ZERO)),
                    ..Limits::default()
                },
            )
            .unwrap_err();

        assert!(error.to_string().contains("work deadline"));
        fixture.assert_pending_empty();
    }

    #[test]
    fn rejects_control_names_links_and_special_files_without_partial_trees() {
        let fixture = Fixture::new();
        let control = fixture.evidence("control");
        fs::write(control.join(".git"), b"control").unwrap();
        assert_error_contains(
            fixture.stage("control", Some(&control)),
            "forbidden control name",
        );
        fixture.assert_pending_empty();

        let symlinks = fixture.evidence("symlinks");
        fs::write(symlinks.join("target"), b"data").unwrap();
        symlink("target", symlinks.join("link")).unwrap();
        assert_error_contains(fixture.stage("symlink", Some(&symlinks)), "symbolic link");
        fixture.assert_pending_empty();

        let hardlinks = fixture.evidence("hardlinks");
        fs::write(hardlinks.join("first"), b"data").unwrap();
        fs::hard_link(hardlinks.join("first"), hardlinks.join("second")).unwrap();
        assert_error_contains(fixture.stage("hardlink", Some(&hardlinks)), "hard-linked");
        fixture.assert_pending_empty();

        let special = fixture.evidence("special");
        let fifo = c_string(special.join("fifo").as_os_str()).unwrap();
        // SAFETY: `fifo` is a live NUL-terminated test path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_error_contains(fixture.stage("special", Some(&special)), "special file");
        fixture.assert_pending_empty();
    }

    #[test]
    fn enforces_depth_entry_and_byte_bounds() {
        let fixture = Fixture::new();
        let depth = fixture.evidence("depth");
        let one = depth.join("one");
        let two = one.join("two");
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        assert_error_contains(
            fixture.stage_with_limits(
                "depth",
                Some(&depth),
                Limits {
                    depth: 1,
                    ..Limits::default()
                },
            ),
            "nesting",
        );
        fixture.assert_pending_empty();

        let entries = fixture.evidence("entries");
        fs::write(entries.join("one"), b"1").unwrap();
        fs::write(entries.join("two"), b"2").unwrap();
        assert_error_contains(
            fixture.stage_with_limits(
                "entries",
                Some(&entries),
                Limits {
                    entries: 1,
                    ..Limits::default()
                },
            ),
            "too many entries",
        );
        fixture.assert_pending_empty();

        let bytes = fixture.evidence("bytes");
        fs::write(bytes.join("payload"), b"12345").unwrap();
        assert_error_contains(
            fixture.stage_with_limits(
                "bytes",
                Some(&bytes),
                Limits {
                    bytes: 4,
                    ..Limits::default()
                },
            ),
            "size limit",
        );
        fixture.assert_pending_empty();
    }

    #[tokio::test]
    async fn bounded_cleanup_removes_only_its_still_pending_tree() {
        let fixture = Fixture::new();
        let pending = fixture.stage("drop", None).unwrap();
        let pending_path = pending.pending_path().to_owned();
        pending.cleanup().await.unwrap();
        assert!(!pending_path.exists());

        let quarantined = fixture.stage("quarantine", None).unwrap();
        let quarantine_root = fixture.base.join("quarantine");
        fs::create_dir(&quarantine_root).unwrap();
        let moved = quarantine_root.join(quarantined.run_id());
        fs::rename(quarantined.pending_path(), &moved).unwrap();
        quarantined.cleanup().await.unwrap();
        assert!(moved.is_dir());
        fixture.assert_pending_empty();
    }

    #[test]
    fn drop_defers_pending_cleanup_to_tmpfiles() {
        let fixture = Fixture::new();
        let pending = fixture.stage("deferred", None).unwrap();
        let pending_path = pending.pending_path().to_owned();

        drop(pending);

        assert!(pending_path.is_dir());
    }

    #[test]
    fn rejects_metadata_and_same_size_content_changes() {
        let fixture = Fixture::new();
        let metadata = fixture.evidence("metadata-change");
        fs::write(metadata.join("payload"), b"original").unwrap();
        assert_error_contains(
            fixture.stage_with_limits(
                "metadata-change",
                Some(&metadata),
                Limits {
                    post_copy_mutation_hook: Some(change_source_mode),
                    ..Limits::default()
                },
            ),
            "metadata changed",
        );
        fixture.assert_pending_empty();

        let contents = fixture.evidence("content-change");
        fs::write(contents.join("payload"), b"original").unwrap();
        assert_error_contains(
            fixture.stage_with_limits(
                "content-change",
                Some(&contents),
                Limits {
                    post_copy_mutation_hook: Some(overwrite_source_same_size),
                    ..Limits::default()
                },
            ),
            "contents changed",
        );
        fixture.assert_pending_empty();
    }

    fn change_source_mode(directory_fd: RawFd, name: &CStr) -> Result<()> {
        let file = open_source_file(directory_fd, name)?;
        set_mode(file.as_raw_fd(), 0o600)?;
        Ok(())
    }

    fn overwrite_source_same_size(directory_fd: RawFd, name: &CStr) -> Result<()> {
        let flags = libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: the descriptor and name identify a test-owned regular file.
        let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: a successful `openat` returns a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(b"modified")?;
        file.sync_all()?;
        Ok(())
    }

    fn assert_directory_metadata(path: &Path, uid: u32, gid: u32) {
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
        assert_eq!(metadata.mode() & 0o7777, SOURCE_DIRECTORY_MODE);
    }

    fn assert_error_contains(result: Result<PendingWorkspace>, expected: &str) {
        let error = result.expect_err("workspace staging unexpectedly succeeded");
        assert!(
            format!("{error:#}").contains(expected),
            "error did not contain {expected:?}: {error:#}"
        );
    }

    fn set_path_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn make_tree_writable(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    make_tree_writable(&entry.path());
                }
            }
        } else if metadata.is_file() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

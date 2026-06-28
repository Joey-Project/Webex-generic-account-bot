#![cfg(target_os = "linux")]

use std::{
    collections::HashSet,
    ffi::{CStr, CString, OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
use ring::digest::{Context as DigestContext, SHA256};

use crate::isolated_execution::{CODEX_INPUT_ROOT, production_codex_group_ids};

pub const CODEX_PENDING_INPUT_ROOT: &str =
    "/var/lib/webex-generic-account-bot/codex-input-staging/pending";
pub const CODEX_SOURCE_CONSUMED_INPUT_ROOT: &str =
    "/var/lib/webex-generic-account-bot/codex-input-staging/consumed";

const STAGING_PREFIX: &str = ".seal-";
const SOURCE_DIRECTORY_MODE: u32 = 0o2770;
const SOURCE_FILE_MODE: u32 = 0o640;
const SEALED_DIRECTORY_MODE: u32 = 0o550;
const SEALED_FILE_MODE: u32 = 0o440;
const PENDING_ROOT_MODE: u32 = 0o2730;
const SHARED_ROOT_MODE: u32 = 0o1730;
const PRIVATE_ROOT_MODE: u32 = 0o700;
const WORKSPACE_ENTRY_MAX: usize = 8_192;
const WORKSPACE_DEPTH_MAX: usize = 32;
const WORKSPACE_TOTAL_MIB: u64 = 2_112;
const WORKSPACE_TOTAL_BYTES_MAX: u64 = WORKSPACE_TOTAL_MIB * 1024 * 1024;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPaths {
    pub pending_root: PathBuf,
    pub source_consumed_root: PathBuf,
    pub input_root: PathBuf,
}

impl SealPaths {
    pub fn new(
        pending_root: impl Into<PathBuf>,
        source_consumed_root: impl Into<PathBuf>,
        input_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            pending_root: pending_root.into(),
            source_consumed_root: source_consumed_root.into(),
            input_root: input_root.into(),
        }
    }

    pub fn production() -> Self {
        Self::new(
            CODEX_PENDING_INPUT_ROOT,
            CODEX_SOURCE_CONSUMED_INPUT_ROOT,
            CODEX_INPUT_ROOT,
        )
    }
}

impl Default for SealPaths {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    depth: usize,
    bytes: u64,
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
    limits: Limits,
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
}

pub fn seal_workspace(run_id: &str, source_uid: u32) -> Result<PathBuf> {
    let groups = production_codex_group_ids()?;
    seal_workspace_at(
        &SealPaths::production(),
        run_id,
        source_uid,
        groups.launch,
        groups.input,
    )
}

pub fn preflight() -> Result<()> {
    let groups = production_codex_group_ids()?;
    preflight_at(&SealPaths::production(), groups.launch, groups.input)
}

fn preflight_at(paths: &SealPaths, source_gid: u32, target_gid: u32) -> Result<()> {
    validate_root_layout(paths)?;
    let sealer_uid = required_sealer_uid()?;
    let pending_root = open_absolute_directory(&paths.pending_root)
        .context("failed to open the pending input root")?;
    let source_consumed_root = open_absolute_directory(&paths.source_consumed_root)
        .context("failed to open the source-consumed input root")?;
    let input_root = open_absolute_directory(&paths.input_root)
        .context("failed to open the sealed input root")?;
    validate_root(
        &pending_root,
        sealer_uid,
        Some(source_gid),
        PENDING_ROOT_MODE,
        "pending input root",
    )?;
    validate_root(
        &source_consumed_root,
        sealer_uid,
        None,
        PRIVATE_ROOT_MODE,
        "source-consumed input root",
    )?;
    validate_root(
        &input_root,
        sealer_uid,
        Some(target_gid),
        SHARED_ROOT_MODE,
        "sealed input root",
    )?;
    reject_same_root(&pending_root, &source_consumed_root)?;
    reject_same_root(&pending_root, &input_root)?;
    reject_same_root(&source_consumed_root, &input_root)?;
    ensure_root_path_unchanged(&paths.pending_root, &pending_root)?;
    ensure_root_path_unchanged(&paths.source_consumed_root, &source_consumed_root)?;
    ensure_root_path_unchanged(&paths.input_root, &input_root)?;
    Ok(())
}

fn seal_workspace_at(
    paths: &SealPaths,
    run_id: &str,
    source_uid: u32,
    source_gid: u32,
    target_gid: u32,
) -> Result<PathBuf> {
    seal_workspace_with_limits(
        paths,
        run_id,
        source_uid,
        source_gid,
        target_gid,
        Limits::default(),
    )
}

fn seal_workspace_with_limits(
    paths: &SealPaths,
    run_id: &str,
    source_uid: u32,
    source_gid: u32,
    target_gid: u32,
    limits: Limits,
) -> Result<PathBuf> {
    validate_run_id(run_id)?;
    validate_root_layout(paths)?;

    let sealer_uid = required_sealer_uid()?;
    let pending_root = open_absolute_directory(&paths.pending_root)
        .context("failed to open the pending input root")?;
    let source_consumed_root = open_absolute_directory(&paths.source_consumed_root)
        .context("failed to open the source-consumed input root")?;
    let input_root = open_absolute_directory(&paths.input_root)
        .context("failed to open the sealed input root")?;

    validate_root(
        &pending_root,
        sealer_uid,
        Some(source_gid),
        PENDING_ROOT_MODE,
        "pending input root",
    )?;
    validate_root(
        &source_consumed_root,
        sealer_uid,
        None,
        PRIVATE_ROOT_MODE,
        "source-consumed input root",
    )?;
    validate_root(
        &input_root,
        sealer_uid,
        Some(target_gid),
        SHARED_ROOT_MODE,
        "sealed input root",
    )?;
    reject_same_root(&pending_root, &source_consumed_root)?;
    reject_same_root(&pending_root, &input_root)?;
    reject_same_root(&source_consumed_root, &input_root)?;
    ensure_root_path_unchanged(&paths.pending_root, &pending_root)?;
    ensure_root_path_unchanged(&paths.source_consumed_root, &source_consumed_root)?;
    ensure_root_path_unchanged(&paths.input_root, &input_root)?;

    let run_name = c_string(OsStr::new(run_id))?;
    let source_identity = stat_at(pending_root.as_raw_fd(), &run_name)
        .context("failed to inspect the pending workspace")?;
    rename_noreplace(
        pending_root.as_raw_fd(),
        &run_name,
        source_consumed_root.as_raw_fd(),
        &run_name,
    )
    .context("failed to quarantine the pending workspace")?;

    let mut staging_name = None;
    let mut published_by_us = false;
    let mut published_identity = None;
    let result = (|| {
        source_consumed_root
            .sync_all()
            .context("failed to persist the quarantined workspace")?;
        pending_root
            .sync_all()
            .context("failed to persist removal of the pending workspace")?;
        let source = open_directory_at(source_consumed_root.as_raw_fd(), &run_name)
            .context("quarantined workspace is not a directory")?;
        let opened_source = stat_fd(source.as_raw_fd())?;
        if !same_object(&opened_source, &source_identity) {
            bail!("quarantined workspace identity changed");
        }
        validate_source_directory(&opened_source, source_uid, source_gid)
            .context("quarantined workspace root metadata is invalid")?;

        let generated_staging = create_staging_directory(&input_root, sealer_uid, target_gid)?;
        staging_name = Some(generated_staging.clone());
        let target = open_directory_at(input_root.as_raw_fd(), &generated_staging)?;
        let mut state = CopyState {
            entries: 0,
            bytes: 0,
            limits,
        };
        copy_directory(
            &source, &target, source_uid, source_gid, sealer_uid, target_gid, 0, &mut state,
        )?;
        validate_root(
            &target,
            sealer_uid,
            Some(target_gid),
            PRIVATE_ROOT_MODE,
            "workspace staging directory",
        )?;

        set_owner_and_mode(
            target.as_raw_fd(),
            sealer_uid,
            target_gid,
            SEALED_DIRECTORY_MODE,
        )?;
        validate_sealed_directory(&stat_fd(target.as_raw_fd())?, sealer_uid, target_gid)?;
        target
            .sync_all()
            .context("failed to persist the staged workspace")?;
        input_root
            .sync_all()
            .context("failed to persist the workspace staging entry")?;

        let staged_identity = stat_fd(target.as_raw_fd())?;
        published_identity = Some(staged_identity.clone());
        ensure_root_path_unchanged(&paths.input_root, &input_root)?;
        rename_noreplace(
            input_root.as_raw_fd(),
            &generated_staging,
            input_root.as_raw_fd(),
            &run_name,
        )
        .context("failed to publish the sealed workspace")?;
        published_by_us = true;
        input_root
            .sync_all()
            .context("failed to persist the published workspace")?;
        let published = stat_at(input_root.as_raw_fd(), &run_name)?;
        if !same_object(&published, &staged_identity) {
            bail!("published workspace identity changed during publication");
        }
        validate_sealed_directory(&published, sealer_uid, target_gid)?;
        ensure_root_path_unchanged(&paths.input_root, &input_root)?;
        Ok(paths.input_root.join(run_id))
    })();

    let cleanup_source = || {
        remove_owned_tree_at(
            &source_consumed_root,
            &run_name,
            source_identity.device,
            source_identity.inode,
        )
        .context("failed to clean the quarantined source workspace")
    };
    let cleanup_target = || -> Result<()> {
        if published_by_us {
            let expected = published_identity
                .as_ref()
                .ok_or_else(|| anyhow!("published workspace identity is unavailable"))?;
            remove_owned_tree_at(&input_root, &run_name, expected.device, expected.inode)
                .context("failed to clean the published workspace")
        } else if let Some(staging_name) = &staging_name {
            remove_tree_at(input_root.as_raw_fd(), staging_name)
                .map_err(::anyhow::Error::from)
                .context("failed to clean the staged workspace")
        } else {
            Ok(())
        }
    };

    match result {
        Ok(path) => match cleanup_source() {
            Ok(()) => Ok(path),
            Err(source_error) => match cleanup_target() {
                Ok(()) => Err(source_error),
                Err(target_error) => Err(anyhow!(
                    "{source_error:#}; failed to roll back sealed workspace: {target_error:#}"
                )),
            },
        },
        Err(error) => {
            let mut cleanup_errors = Vec::new();
            if let Err(cleanup_error) = cleanup_target() {
                cleanup_errors.push(format!("target cleanup failed: {cleanup_error:#}"));
            }
            if let Err(cleanup_error) = cleanup_source() {
                cleanup_errors.push(format!("source cleanup failed: {cleanup_error:#}"));
            }
            if cleanup_errors.is_empty() {
                Err(error)
            } else {
                Err(anyhow!("{error:#}; {}", cleanup_errors.join("; ")))
            }
        }
    }
}

fn validate_run_id(run_id: &str) -> Result<()> {
    let mut components = Path::new(run_id).components();
    if run_id.is_empty()
        || run_id.len() > 64
        || !run_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_'))
        })
        || !matches!(components.next(), Some(Component::Normal(component)) if component == run_id)
        || components.next().is_some()
        || run_id.as_bytes().contains(&0)
    {
        bail!("run identifier is not a single path component");
    }
    if forbidden_name(OsStr::new(run_id)) {
        bail!("run identifier uses a forbidden control name");
    }
    Ok(())
}

fn validate_root_layout(paths: &SealPaths) -> Result<()> {
    for path in [
        &paths.pending_root,
        &paths.source_consumed_root,
        &paths.input_root,
    ] {
        validate_absolute_normal_path(path)?;
    }
    let roots = [
        &paths.pending_root,
        &paths.source_consumed_root,
        &paths.input_root,
    ];
    for (index, left) in roots.iter().enumerate() {
        for right in roots.iter().skip(index + 1) {
            if left.starts_with(right) || right.starts_with(left) {
                bail!("input sealer roots must not overlap");
            }
        }
    }
    Ok(())
}

fn validate_absolute_normal_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path == Path::new("/") {
        bail!("input sealer root must be a non-root absolute path");
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("input sealer root contains a path escape");
    }
    Ok(())
}

fn open_absolute_directory(path: &Path) -> Result<File> {
    validate_absolute_normal_path(path)?;
    let slash = CString::new("/").expect("slash contains no NUL");
    let mut directory = open_directory(libc::AT_FDCWD, &slash)?;
    for component in path.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        let name = c_string(component)?;
        directory = open_directory_at(directory.as_raw_fd(), &name)?;
    }
    Ok(directory)
}

fn open_directory(directory_fd: RawFd, name: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned here.
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory_at(directory_fd: RawFd, name: &CStr) -> io::Result<File> {
    open_directory(directory_fd, name)
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
    let flags = libc::O_WRONLY
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned here.
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_root(
    directory: &File,
    uid: u32,
    gid: Option<u32>,
    mode: u32,
    description: &str,
) -> Result<()> {
    let metadata = stat_fd(directory.as_raw_fd())?;
    if metadata.file_type() != libc::S_IFDIR
        || metadata.uid != uid
        || gid.is_some_and(|gid| metadata.gid != gid)
        || metadata.permissions() != mode
    {
        bail!("{description} metadata is invalid");
    }
    ensure_posix_acl_absent(directory, description)?;
    Ok(())
}

fn reject_same_root(left: &File, right: &File) -> Result<()> {
    let left = stat_fd(left.as_raw_fd())?;
    let right = stat_fd(right.as_raw_fd())?;
    if left.device == right.device && left.inode == right.inode {
        bail!("input sealer roots resolve to the same directory");
    }
    Ok(())
}

fn same_object(left: &StatSnapshot, right: &StatSnapshot) -> bool {
    left.device == right.device && left.inode == right.inode
}

pub(crate) fn remove_owned_tree_at(
    parent: &File,
    name: &CStr,
    expected_device: u64,
    expected_inode: u64,
) -> Result<()> {
    let current = stat_at(parent.as_raw_fd(), name)?;
    if current.device != expected_device || current.inode != expected_inode {
        bail!("refusing to clean a replaced workspace");
    }
    remove_tree_at(parent.as_raw_fd(), name)?;
    Ok(())
}

fn ensure_root_path_unchanged(path: &Path, held: &File) -> Result<()> {
    let reopened = open_absolute_directory(path)?;
    let held = stat_fd(held.as_raw_fd())?;
    let reopened = stat_fd(reopened.as_raw_fd())?;
    if held.device != reopened.device || held.inode != reopened.inode {
        bail!("sealed input root path changed during publication");
    }
    Ok(())
}

fn create_staging_directory(staging: &File, sealer_uid: u32, target_gid: u32) -> Result<CString> {
    for _ in 0..128 {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!("{STAGING_PREFIX}{}-{sequence}", std::process::id()))
            .expect("generated staging name contains no NUL");
        // SAFETY: the parent descriptor and generated component are valid for `mkdirat`.
        if unsafe { libc::mkdirat(staging.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            let result = (|| {
                let directory = open_directory_at(staging.as_raw_fd(), &name)?;
                set_owner_and_mode(
                    directory.as_raw_fd(),
                    sealer_uid,
                    target_gid,
                    PRIVATE_ROOT_MODE,
                )?;
                Ok(name.clone())
            })();
            return match result {
                Ok(name) => Ok(name),
                Err(error) => match remove_tree_at(staging.as_raw_fd(), &name) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(anyhow!(
                        "{error:#}; failed to clean staging directory: {cleanup_error}"
                    )),
                },
            };
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).context("failed to create a workspace staging directory");
        }
    }
    bail!("failed to allocate a unique workspace staging directory")
}

#[allow(clippy::too_many_arguments)]
fn copy_directory(
    source: &File,
    target: &File,
    source_uid: u32,
    source_gid: u32,
    sealer_uid: u32,
    target_gid: u32,
    depth: usize,
    state: &mut CopyState,
) -> Result<()> {
    if depth > state.limits.depth {
        bail!("pending workspace nesting exceeds its limit");
    }
    let before = stat_fd(source.as_raw_fd())?;
    validate_source_directory(&before, source_uid, source_gid)?;
    ensure_posix_acl_absent(source, "pending workspace directory")?;
    let remaining_entries = state.limits.entries.saturating_sub(state.entries);
    let entries = list_directory(source.as_raw_fd(), remaining_entries)?;

    for name in entries {
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("pending workspace entry count overflowed"))?;
        if state.entries > state.limits.entries {
            bail!("pending workspace has too many entries");
        }
        if forbidden_name(&name) {
            bail!("pending workspace contains a forbidden control name");
        }
        let c_name = c_string(&name)?;
        let entry = stat_at(source.as_raw_fd(), &c_name)?;
        match entry.file_type() {
            libc::S_IFDIR => {
                validate_source_directory(&entry, source_uid, source_gid)?;
                let source_child = open_directory_at(source.as_raw_fd(), &c_name)?;
                let opened = stat_fd(source_child.as_raw_fd())?;
                if opened != entry {
                    bail!("pending workspace directory changed before copy");
                }
                mkdir_at(target.as_raw_fd(), &c_name, PRIVATE_ROOT_MODE)?;
                let target_child = open_directory_at(target.as_raw_fd(), &c_name)?;
                set_owner_and_mode(
                    target_child.as_raw_fd(),
                    sealer_uid,
                    target_gid,
                    PRIVATE_ROOT_MODE,
                )?;
                copy_directory(
                    &source_child,
                    &target_child,
                    source_uid,
                    source_gid,
                    sealer_uid,
                    target_gid,
                    depth + 1,
                    state,
                )?;
                set_owner_and_mode(
                    target_child.as_raw_fd(),
                    sealer_uid,
                    target_gid,
                    SEALED_DIRECTORY_MODE,
                )?;
                target_child.sync_all()?;
                validate_sealed_directory(
                    &stat_fd(target_child.as_raw_fd())?,
                    sealer_uid,
                    target_gid,
                )?;
                ensure_posix_acl_absent(&target_child, "sealed workspace directory")?;
                if stat_fd(source_child.as_raw_fd())? != entry {
                    bail!("pending workspace directory changed during copy");
                }
            }
            libc::S_IFREG => copy_file(
                source, target, &c_name, &entry, source_uid, source_gid, sealer_uid, target_gid,
                state,
            )?,
            libc::S_IFLNK => bail!("pending workspace contains a symbolic link"),
            _ => bail!("pending workspace contains a special file"),
        }
    }

    if stat_fd(source.as_raw_fd())? != before {
        bail!("pending workspace directory metadata changed during copy");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn copy_file(
    source_directory: &File,
    target_directory: &File,
    name: &CStr,
    entry: &StatSnapshot,
    source_uid: u32,
    source_gid: u32,
    sealer_uid: u32,
    target_gid: u32,
    state: &mut CopyState,
) -> Result<()> {
    validate_source_file(entry, source_uid, source_gid)?;
    let mut source = open_source_file(source_directory.as_raw_fd(), name)?;
    if stat_fd(source.as_raw_fd())? != *entry {
        bail!("pending workspace file changed before copy");
    }
    ensure_posix_acl_absent(&source, "pending workspace file")?;
    #[cfg(test)]
    if let Some(hook) = state.limits.mutation_hook {
        hook(source_directory.as_raw_fd(), name)?;
    }
    let size =
        u64::try_from(entry.size).map_err(|_| anyhow!("pending workspace file is invalid"))?;
    state.bytes = state
        .bytes
        .checked_add(size)
        .ok_or_else(|| anyhow!("pending workspace size overflowed"))?;
    if state.bytes > state.limits.bytes {
        bail!("pending workspace exceeds its size limit");
    }

    let mut target = create_target_file(target_directory.as_raw_fd(), name)?;
    set_owner_and_mode(target.as_raw_fd(), sealer_uid, target_gid, SOURCE_FILE_MODE)?;
    let first_digest = copy_exact_with_digest(&mut source, &mut target, size)?;
    target.flush()?;
    #[cfg(test)]
    if let Some(hook) = state.limits.post_copy_mutation_hook {
        hook(source_directory.as_raw_fd(), name)?;
    }
    source.seek(SeekFrom::Start(0))?;
    let second_digest = hash_exact_source(&mut source, size)?;
    if first_digest.as_ref() != second_digest.as_ref() {
        bail!("pending workspace file contents changed during copy");
    }
    if stat_fd(source.as_raw_fd())? != *entry
        || stat_at(source_directory.as_raw_fd(), name)? != *entry
    {
        bail!("pending workspace file metadata changed during copy");
    }
    set_owner_and_mode(target.as_raw_fd(), sealer_uid, target_gid, SEALED_FILE_MODE)?;
    target.sync_all()?;
    let sealed = stat_fd(target.as_raw_fd())?;
    if sealed.file_type() != libc::S_IFREG
        || sealed.uid != sealer_uid
        || sealed.gid != target_gid
        || sealed.permissions() != SEALED_FILE_MODE
        || sealed.links != 1
        || sealed.size != entry.size
    {
        bail!("sealed workspace file metadata is invalid");
    }
    ensure_posix_acl_absent(&target, "sealed workspace file")?;
    Ok(())
}

fn copy_exact_with_digest(
    source: &mut File,
    target: &mut File,
    size: u64,
) -> Result<ring::digest::Digest> {
    let mut digest = DigestContext::new(&SHA256);
    let mut remaining = size;
    let mut buffer = [0_u8; 1024 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded copy chunk fits usize");
        let read = source.read(&mut buffer[..limit])?;
        if read == 0 {
            bail!("pending workspace file size changed during copy");
        }
        target.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    reject_source_growth(source)?;
    Ok(digest.finish())
}

fn hash_exact_source(source: &mut File, size: u64) -> Result<ring::digest::Digest> {
    let mut digest = DigestContext::new(&SHA256);
    let mut remaining = size;
    let mut buffer = [0_u8; 1024 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded hash chunk fits usize");
        let read = source.read(&mut buffer[..limit])?;
        if read == 0 {
            bail!("pending workspace file size changed during verification");
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    reject_source_growth(source)?;
    Ok(digest.finish())
}

fn reject_source_growth(source: &mut File) -> Result<()> {
    let mut growth_probe = [0_u8; 1];
    if source.read(&mut growth_probe)? != 0 {
        bail!("pending workspace file size changed during copy");
    }
    Ok(())
}

pub(crate) fn ensure_posix_acl_absent(file: &File, description: &str) -> Result<()> {
    for name in [
        b"system.posix_acl_access\0".as_slice(),
        b"system.posix_acl_default\0".as_slice(),
    ] {
        // SAFETY: each name is a fixed NUL-terminated byte string, `file` owns a
        // live descriptor, and a null value pointer requests only the size.
        let size = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size >= 0 {
            bail!("{description} has an unexpected POSIX ACL");
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::ENOTSUP)
        ) {
            return Err(error).with_context(|| format!("failed to inspect {description} ACL"));
        }
    }
    Ok(())
}

fn validate_source_directory(
    metadata: &StatSnapshot,
    source_uid: u32,
    source_gid: u32,
) -> Result<()> {
    if metadata.file_type() != libc::S_IFDIR
        || metadata.uid != source_uid
        || metadata.gid != source_gid
        || metadata.permissions() != SOURCE_DIRECTORY_MODE
    {
        bail!("pending workspace directory owner or mode is invalid");
    }
    Ok(())
}

fn validate_source_file(metadata: &StatSnapshot, source_uid: u32, source_gid: u32) -> Result<()> {
    if metadata.file_type() != libc::S_IFREG
        || metadata.uid != source_uid
        || metadata.gid != source_gid
        || metadata.permissions() != SOURCE_FILE_MODE
    {
        bail!("pending workspace file owner or mode is invalid");
    }
    if metadata.links != 1 {
        bail!("pending workspace contains a hard-linked file");
    }
    Ok(())
}

fn validate_sealed_directory(metadata: &StatSnapshot, uid: u32, gid: u32) -> Result<()> {
    if metadata.file_type() != libc::S_IFDIR
        || metadata.uid != uid
        || metadata.gid != gid
        || metadata.permissions() != SEALED_DIRECTORY_MODE
    {
        bail!("sealed workspace directory metadata is invalid");
    }
    Ok(())
}

fn forbidden_name(name: &OsStr) -> bool {
    matches!(
        name.as_bytes(),
        b".git" | b".codex" | b".agents" | b"AGENTS.md" | b"hooks.json"
    )
}

fn list_directory(directory_fd: RawFd, max_entries: usize) -> Result<Vec<OsString>> {
    // SAFETY: `fcntl` duplicates a live descriptor and returns a new owned descriptor.
    let duplicate = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error()).context("failed to duplicate a directory handle");
    }
    // SAFETY: `fdopendir` consumes `duplicate`; `closedir` below releases it.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed and did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(error).context("failed to enumerate a workspace directory");
    }

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    loop {
        // SAFETY: this function is Linux-only and errno is thread-local writable state.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains valid until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: this function is Linux-only and errno is thread-local readable state.
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                // SAFETY: `stream` is live and owned by this function.
                unsafe { libc::closedir(stream) };
                return Err(io::Error::from_raw_os_error(errno))
                    .context("failed while enumerating a workspace directory");
            }
            break;
        }
        // SAFETY: POSIX guarantees `d_name` is NUL-terminated for a returned entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if !seen.insert(name.to_vec()) {
            // SAFETY: `stream` is live and owned by this function.
            unsafe { libc::closedir(stream) };
            bail!("pending workspace contains a duplicate directory entry");
        }
        if entries.len() >= max_entries {
            // SAFETY: `stream` is live and owned by this function.
            unsafe { libc::closedir(stream) };
            bail!("pending workspace has too many entries");
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

fn mkdir_at(directory_fd: RawFd, name: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: the parent descriptor and component are valid for `mkdirat`.
    if unsafe { libc::mkdirat(directory_fd, name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_owner_and_mode(fd: RawFd, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor; ownership is set before final permissions.
    if unsafe { libc::fchown(fd, uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a live descriptor and `mode` contains only permission bits.
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rename_noreplace(
    old_directory_fd: RawFd,
    old_name: &CStr,
    new_directory_fd: RawFd,
    new_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors and NUL-terminated names are live for the syscall.
    let status = unsafe {
        libc::renameat2(
            old_directory_fd,
            old_name.as_ptr(),
            new_directory_fd,
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

fn remove_tree_at(parent_fd: RawFd, name: &CStr) -> io::Result<()> {
    let metadata = stat_at(parent_fd, name)?;
    if metadata.file_type() == libc::S_IFDIR {
        let directory = open_directory_at(parent_fd, name)?;
        // Staging children may already have their final read-only mode.
        // SAFETY: `directory` is a live descriptor owned by this function.
        if unsafe { libc::fchmod(directory.as_raw_fd(), PRIVATE_ROOT_MODE) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM)
                || metadata.permissions() != SOURCE_DIRECTORY_MODE
            {
                return Err(error);
            }
        }
        for child in
            list_directory(directory.as_raw_fd(), WORKSPACE_ENTRY_MAX).map_err(io::Error::other)?
        {
            let child = c_string(&child).map_err(io::Error::other)?;
            remove_tree_at(directory.as_raw_fd(), &child)?;
        }
        sync_fd(directory.as_raw_fd())?;
        // SAFETY: the parent descriptor and child component are valid for `unlinkat`.
        if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(io::Error::last_os_error());
        }
    } else {
        // SAFETY: the parent descriptor and child component are valid for `unlinkat`.
        if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    sync_fd(parent_fd)
}

fn sync_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live file or directory descriptor owned by the caller.
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c_string(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| anyhow!("path component contains a NUL byte"))
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

fn required_sealer_uid() -> Result<u32> {
    let uid = effective_uid();
    #[cfg(not(test))]
    if uid != 0 {
        bail!("input sealer must run as root");
    }
    Ok(uid)
}

#[cfg(test)]
fn effective_gid() -> u32 {
    // SAFETY: `getegid` has no preconditions.
    unsafe { libc::getegid() }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoots {
        base: PathBuf,
        paths: SealPaths,
        uid: u32,
        gid: u32,
    }

    impl TestRoots {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow the Unix epoch")
                .as_nanos();
            let base = std::env::temp_dir().join(format!(
                "webex-input-sealer-{}-{suffix}-{sequence}",
                std::process::id(),
            ));
            let paths = SealPaths::new(
                base.join("pending"),
                base.join("source-consumed"),
                base.join("inputs"),
            );
            fs::create_dir(&base).unwrap();
            fs::create_dir(&paths.pending_root).unwrap();
            fs::create_dir(&paths.source_consumed_root).unwrap();
            fs::create_dir(&paths.input_root).unwrap();
            set_mode(&paths.pending_root, PENDING_ROOT_MODE);
            set_mode(&paths.source_consumed_root, PRIVATE_ROOT_MODE);
            set_mode(&paths.input_root, SHARED_ROOT_MODE);
            Self {
                base,
                paths,
                uid: effective_uid(),
                gid: effective_gid(),
            }
        }

        fn source(&self, run_id: &str) -> PathBuf {
            let source = self.paths.pending_root.join(run_id);
            fs::create_dir(&source).unwrap();
            set_mode(&source, SOURCE_DIRECTORY_MODE);
            source
        }

        fn write_file(&self, path: &Path, contents: &[u8]) {
            fs::write(path, contents).unwrap();
            set_mode(path, SOURCE_FILE_MODE);
        }

        fn seal(&self, run_id: &str) -> Result<PathBuf> {
            seal_workspace_at(&self.paths, run_id, self.uid, self.gid, self.gid)
        }

        fn seal_with_limits(&self, run_id: &str, limits: Limits) -> Result<PathBuf> {
            seal_workspace_with_limits(&self.paths, run_id, self.uid, self.gid, self.gid, limits)
        }
    }

    impl Drop for TestRoots {
        fn drop(&mut self) {
            make_tree_writable(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn publishes_fresh_read_only_inodes() {
        let roots = TestRoots::new();
        preflight_at(&roots.paths, roots.gid, roots.gid).unwrap();
        let source = roots.source("run-one");
        let nested = source.join("logs");
        fs::create_dir(&nested).unwrap();
        set_mode(&nested, SOURCE_DIRECTORY_MODE);
        let source_file = nested.join("console.log");
        roots.write_file(&source_file, b"original evidence\n");
        let mut retained = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_file)
            .unwrap();
        let source_inode = retained.metadata().unwrap().ino();

        let published = roots.seal("run-one").unwrap();
        let published_file = published.join("logs/console.log");
        let published_metadata = fs::metadata(&published_file).unwrap();
        assert_ne!(source_inode, published_metadata.ino());
        assert_eq!(published_metadata.mode() & 0o7777, SEALED_FILE_MODE);
        assert_eq!(published_metadata.nlink(), 1);
        assert_eq!(published_metadata.uid(), roots.uid);
        assert_eq!(published_metadata.gid(), roots.gid);
        let published_directory = fs::metadata(&published).unwrap();
        assert_eq!(published_directory.mode() & 0o7777, SEALED_DIRECTORY_MODE);

        retained.seek(SeekFrom::Start(0)).unwrap();
        retained.write_all(b"changed source!!\n").unwrap();
        retained.set_len(16).unwrap();
        let mut contents = Vec::new();
        File::open(published_file)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"original evidence\n");
        assert!(!roots.paths.pending_root.join("run-one").exists());
        assert!(!roots.paths.source_consumed_root.join("run-one").exists());
    }

    #[test]
    fn rejects_links_special_files_and_control_names() {
        let roots = TestRoots::new();
        let source = roots.source("symlink");
        roots.write_file(&source.join("target"), b"data");
        symlink("target", source.join("link")).unwrap();
        assert_error_contains(roots.seal("symlink"), "symbolic link");
        assert_rejected_workspace_cleaned(&roots, "symlink");

        let roots = TestRoots::new();
        let source = roots.source("hardlink");
        roots.write_file(&source.join("first"), b"data");
        fs::hard_link(source.join("first"), source.join("second")).unwrap();
        assert_error_contains(roots.seal("hardlink"), "hard-linked");
        assert_rejected_workspace_cleaned(&roots, "hardlink");

        let roots = TestRoots::new();
        let source = roots.source("special");
        let fifo = c_string(source.join("fifo").as_os_str()).unwrap();
        // SAFETY: `fifo` is a live NUL-terminated path.
        let status = unsafe { libc::mkfifo(fifo.as_ptr(), SOURCE_FILE_MODE) };
        if status == 0 {
            assert_error_contains(roots.seal("special"), "special file");
            assert_rejected_workspace_cleaned(&roots, "special");
        } else {
            let error = io::Error::last_os_error();
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::ENOTSUP)
            ));
        }

        for forbidden in [".git", ".codex", ".agents", "AGENTS.md", "hooks.json"] {
            let roots = TestRoots::new();
            let source = roots.source("control");
            roots.write_file(&source.join(forbidden), b"control");
            assert_error_contains(roots.seal("control"), "forbidden control name");
            assert_rejected_workspace_cleaned(&roots, "control");
        }
    }

    #[test]
    fn rejects_duplicate_publication_without_overwriting() {
        let roots = TestRoots::new();
        let source = roots.source("duplicate");
        roots.write_file(&source.join("new"), b"new data");
        let existing = roots.paths.input_root.join("duplicate");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("marker"), b"existing data").unwrap();

        assert_error_contains(roots.seal("duplicate"), "publish");
        assert_eq!(fs::read(existing.join("marker")).unwrap(), b"existing data");
        assert!(!existing.join("new").exists());
        assert_staging_empty(&roots);

        let roots = TestRoots::new();
        let source = roots.source("quarantine-duplicate");
        roots.write_file(&source.join("pending-marker"), b"pending data");
        let consumed = roots
            .paths
            .source_consumed_root
            .join("quarantine-duplicate");
        fs::create_dir(&consumed).unwrap();
        fs::write(consumed.join("existing-marker"), b"existing data").unwrap();
        assert_error_contains(roots.seal("quarantine-duplicate"), "quarantine");
        assert_eq!(
            fs::read(consumed.join("existing-marker")).unwrap(),
            b"existing data"
        );
        assert!(
            roots
                .paths
                .pending_root
                .join("quarantine-duplicate/pending-marker")
                .exists()
        );
        assert!(!roots.paths.input_root.join("quarantine-duplicate").exists());
    }

    #[test]
    fn rejects_owner_mode_mismatches_and_path_escapes() {
        let roots = TestRoots::new();
        let source = roots.source("bad-mode");
        roots.write_file(&source.join("mutable"), b"data");
        set_mode(&source.join("mutable"), 0o600);
        assert_error_contains(roots.seal("bad-mode"), "owner or mode");
        assert_rejected_workspace_cleaned(&roots, "bad-mode");

        let roots = TestRoots::new();
        let source = roots.source("bad-owner");
        roots.write_file(&source.join("owned"), b"data");
        let wrong_uid = roots.uid.checked_add(1).unwrap();
        assert_error_contains(
            seal_workspace_at(&roots.paths, "bad-owner", wrong_uid, roots.gid, roots.gid),
            "owner or mode",
        );
        assert_rejected_workspace_cleaned(&roots, "bad-owner");

        let roots = TestRoots::new();
        let source = roots.source("bad-group");
        roots.write_file(&source.join("owned"), b"data");
        let wrong_gid = roots.gid.checked_add(1).unwrap();
        assert_error_contains(
            seal_workspace_at(&roots.paths, "bad-group", roots.uid, wrong_gid, roots.gid),
            "pending input root metadata is invalid",
        );

        let roots = TestRoots::new();
        assert_error_contains(roots.seal("../escape"), "single path component");
        assert!(!roots.base.join("escape").exists());
    }

    #[test]
    fn rejects_invalid_overlapping_and_symlinked_root_layouts() {
        let roots = TestRoots::new();
        let relative = SealPaths::new(
            "relative-pending",
            &roots.paths.source_consumed_root,
            &roots.paths.input_root,
        );
        assert_error_contains(
            seal_workspace_at(&relative, "run", roots.uid, roots.gid, roots.gid),
            "non-root absolute path",
        );

        let root = SealPaths::new(
            Path::new("/"),
            &roots.paths.source_consumed_root,
            &roots.paths.input_root,
        );
        assert_error_contains(
            seal_workspace_at(&root, "run", roots.uid, roots.gid, roots.gid),
            "non-root absolute path",
        );

        let overlap = SealPaths::new(
            &roots.paths.pending_root,
            &roots.paths.pending_root,
            &roots.paths.input_root,
        );
        assert_error_contains(
            seal_workspace_at(&overlap, "run", roots.uid, roots.gid, roots.gid),
            "must not overlap",
        );

        let escaped = SealPaths::new(
            roots.paths.pending_root.join("../pending"),
            &roots.paths.source_consumed_root,
            &roots.paths.input_root,
        );
        assert_error_contains(
            seal_workspace_at(&escaped, "run", roots.uid, roots.gid, roots.gid),
            "path escape",
        );

        let pending_link = roots.base.join("pending-link");
        symlink(&roots.paths.pending_root, &pending_link).unwrap();
        let linked = SealPaths::new(
            pending_link,
            &roots.paths.source_consumed_root,
            &roots.paths.input_root,
        );
        assert_error_contains(
            seal_workspace_at(&linked, "run", roots.uid, roots.gid, roots.gid),
            "failed to open the pending input root",
        );
    }

    #[test]
    fn enforces_depth_entry_and_byte_bounds() {
        let roots = TestRoots::new();
        let source = roots.source("depth");
        let child = source.join("one");
        fs::create_dir(&child).unwrap();
        set_mode(&child, SOURCE_DIRECTORY_MODE);
        let grandchild = child.join("two");
        fs::create_dir(&grandchild).unwrap();
        set_mode(&grandchild, SOURCE_DIRECTORY_MODE);
        assert_error_contains(
            roots.seal_with_limits(
                "depth",
                Limits {
                    depth: 1,
                    ..Limits::default()
                },
            ),
            "nesting",
        );
        assert_rejected_workspace_cleaned(&roots, "depth");

        let roots = TestRoots::new();
        let source = roots.source("entries");
        roots.write_file(&source.join("one"), b"1");
        roots.write_file(&source.join("two"), b"2");
        assert_error_contains(
            roots.seal_with_limits(
                "entries",
                Limits {
                    entries: 1,
                    ..Limits::default()
                },
            ),
            "too many entries",
        );
        assert_rejected_workspace_cleaned(&roots, "entries");

        let roots = TestRoots::new();
        let source = roots.source("bytes");
        roots.write_file(&source.join("payload"), b"12345");
        assert_error_contains(
            roots.seal_with_limits(
                "bytes",
                Limits {
                    bytes: 4,
                    ..Limits::default()
                },
            ),
            "size limit",
        );
        assert_rejected_workspace_cleaned(&roots, "bytes");
    }

    #[test]
    fn rejects_source_file_growth_during_copy_without_publishing() {
        let roots = TestRoots::new();
        let source = roots.source("growth");
        roots.write_file(&source.join("payload"), b"original");

        assert_error_contains(
            roots.seal_with_limits(
                "growth",
                Limits {
                    mutation_hook: Some(append_source_byte),
                    ..Limits::default()
                },
            ),
            "size changed during copy",
        );
        assert_rejected_workspace_cleaned(&roots, "growth");
    }

    #[test]
    fn rejects_same_size_source_changes_between_copy_passes() {
        let roots = TestRoots::new();
        let source = roots.source("same-size-change");
        roots.write_file(&source.join("payload"), b"original");

        assert_error_contains(
            roots.seal_with_limits(
                "same-size-change",
                Limits {
                    post_copy_mutation_hook: Some(overwrite_source_same_size),
                    ..Limits::default()
                },
            ),
            "contents changed during copy",
        );
        assert_rejected_workspace_cleaned(&roots, "same-size-change");
    }

    #[test]
    fn rejects_posix_acls_on_roots_and_source_entries() {
        let roots = TestRoots::new();
        let source = roots.source("source-acl");
        let evidence = source.join("evidence");
        roots.write_file(&evidence, b"data");
        if install_test_acl(&evidence, b"system.posix_acl_access\0") {
            set_mode(&evidence, SOURCE_FILE_MODE);
            assert_error_contains(roots.seal("source-acl"), "POSIX ACL");
            assert_rejected_workspace_cleaned(&roots, "source-acl");
        }

        let roots = TestRoots::new();
        let source = roots.source("root-acl");
        roots.write_file(&source.join("evidence"), b"data");
        if install_test_acl(&roots.paths.input_root, b"system.posix_acl_default\0") {
            set_mode(&roots.paths.input_root, SHARED_ROOT_MODE);
            assert_error_contains(roots.seal("root-acl"), "POSIX ACL");
            assert!(roots.paths.pending_root.join("root-acl").exists());
            assert!(!roots.paths.input_root.join("root-acl").exists());
        }
    }

    fn append_source_byte(directory_fd: RawFd, name: &CStr) -> Result<()> {
        let flags =
            libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: `directory_fd` and `name` identify the test-owned regular file.
        let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: a successful `openat` returns a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(b"+")?;
        file.sync_all()?;
        Ok(())
    }

    fn overwrite_source_same_size(directory_fd: RawFd, name: &CStr) -> Result<()> {
        let flags = libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: `directory_fd` and `name` identify the test-owned regular file.
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

    fn install_test_acl(path: &Path, name: &[u8]) -> bool {
        let path = c_string(path.as_os_str()).unwrap();
        let mut acl = Vec::new();
        acl.extend_from_slice(&2_u32.to_le_bytes());
        for (tag, permissions, id) in [
            (0x01_u16, 0o6_u16, u32::MAX),
            (0x02_u16, 0o4_u16, effective_uid()),
            (0x04_u16, 0o4_u16, u32::MAX),
            (0x10_u16, 0o4_u16, u32::MAX),
            (0x20_u16, 0o0_u16, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let name = CStr::from_bytes_with_nul(name).unwrap();
        // SAFETY: the path and attribute name are NUL-terminated and `acl`
        // remains live for the duration of the syscall.
        if unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        } == 0
        {
            return true;
        }
        let error = io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::ENOTSUP)
            ),
            "failed to install test ACL: {error}"
        );
        false
    }

    fn assert_rejected_workspace_cleaned(roots: &TestRoots, run_id: &str) {
        assert!(!roots.paths.pending_root.join(run_id).exists());
        assert!(!roots.paths.source_consumed_root.join(run_id).exists());
        assert!(!roots.paths.input_root.join(run_id).exists());
        assert_staging_empty(roots);
    }

    fn assert_staging_empty(roots: &TestRoots) {
        assert!(fs::read_dir(&roots.paths.input_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(STAGING_PREFIX.as_bytes())
        }));
    }

    fn assert_error_contains(result: Result<PathBuf>, expected: &str) {
        let error = result.expect_err("workspace sealing unexpectedly succeeded");
        assert!(
            format!("{error:#}").contains(expected),
            "error did not contain {expected:?}: {error:#}"
        );
    }

    fn set_mode(path: &Path, mode: u32) {
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

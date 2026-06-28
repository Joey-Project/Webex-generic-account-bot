use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, anyhow};
use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};

use crate::work_budget::WorkBudget;

pub const ACTIVATION_RECEIPT_PATH: &str = "/run/webex-codex-activation/receipt.json";
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
pub const ACTIVE_RUNTIME_MANIFEST_PATH: &str = "/opt/webex-generic-account-bot/runtime/active.json";
pub const BOT_EXECUTABLE_PATH: &str =
    "/opt/webex-generic-account-bot/bin/webex-generic-account-bot";
pub const LAUNCHER_EXECUTABLE_PATH: &str =
    "/opt/webex-generic-account-bot/bin/webex-codex-launcher";
pub const RUNTIME_EXECUTABLE_PATH: &str = "/opt/webex-generic-account-bot/bin/webex-codex-runtime";

pub const ACTIVATION_SCHEMA_VERSION: u16 = 1;
pub const SUPPORTED_CODEX_VERSION: &str = "0.142.3";
pub const SUPPORTED_MODEL: &str = "gpt-5.5";

pub const REQUIRED_CANARIES: &[&str] = &[
    "bot_crash_cleanup",
    "bot_socket_denied",
    "codex_model_auth_access",
    "config_worker_socket_denied",
    "credential_channel_reuse_denied",
    "forbidden_network_denied",
    "host_reboot_cleanup",
    "launcher_crash_cleanup",
    "launcher_socket_denied",
    "main_process_inspection_denied",
    "timeout_cleanup",
    "tool_inherited_descriptors_denied",
];

const RECEIPT_MAX_BYTES: u64 = 64 * 1024;
const BOOT_ID_MAX_BYTES: u64 = 128;
const ACTIVE_MANIFEST_MAX_BYTES: u64 = 64 * 1024;
const EXECUTABLE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const RUNTIME_IMAGE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";
const SUPPORTED_CODEX_TARGET: &str = "x86_64-unknown-linux-musl";
const SUPPORTED_CODEX_LAYOUT_VERSION: u16 = 1;
const EXPECTED_MKSQUASHFS_ARGV_SHA256: &str =
    "700c3e735fb100cddedd05dec3e8a45866e330522b74d2f96389ea2300564bd5";

static TEMPORARY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceipt {
    pub schema_version: u16,
    pub boot_id: String,
    pub active_manifest_sha256: String,
    pub runtime_image_sha256: String,
    pub bot_executable_sha256: String,
    pub launcher_executable_sha256: String,
    pub runtime_executable_sha256: String,
    pub codex_version: String,
    pub model: String,
    pub canaries: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActivation {
    pub schema_version: u16,
    pub boot_id: String,
    pub active_manifest_sha256: String,
    pub runtime_image_sha256: String,
    pub bot_executable_sha256: String,
    pub launcher_executable_sha256: String,
    pub runtime_executable_sha256: String,
    pub codex_version: String,
    pub model: String,
    pub canaries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ActivationPaths {
    receipt: PathBuf,
    boot_id: PathBuf,
    active_manifest: PathBuf,
    bot_executable: PathBuf,
    launcher_executable: PathBuf,
    runtime_executable: PathBuf,
    trusted_root: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl ActivationPaths {
    pub fn new(
        receipt: impl Into<PathBuf>,
        boot_id: impl Into<PathBuf>,
        active_manifest: impl Into<PathBuf>,
        bot_executable: impl Into<PathBuf>,
        launcher_executable: impl Into<PathBuf>,
        runtime_executable: impl Into<PathBuf>,
    ) -> Self {
        Self {
            receipt: receipt.into(),
            boot_id: boot_id.into(),
            active_manifest: active_manifest.into(),
            bot_executable: bot_executable.into(),
            launcher_executable: launcher_executable.into(),
            runtime_executable: runtime_executable.into(),
            trusted_root: PathBuf::from("/"),
            expected_uid: 0,
            expected_gid: 0,
        }
    }

    pub fn production() -> Self {
        Self::production_with_boot_id(BOOT_ID_PATH)
    }

    pub fn production_with_boot_id(boot_id: impl Into<PathBuf>) -> Self {
        Self::new(
            ACTIVATION_RECEIPT_PATH,
            boot_id,
            ACTIVE_RUNTIME_MANIFEST_PATH,
            BOT_EXECUTABLE_PATH,
            LAUNCHER_EXECUTABLE_PATH,
            RUNTIME_EXECUTABLE_PATH,
        )
    }

    pub fn receipt(&self) -> &Path {
        &self.receipt
    }

    pub fn boot_id(&self) -> &Path {
        &self.boot_id
    }

    pub fn active_manifest(&self) -> &Path {
        &self.active_manifest
    }

    pub fn bot_executable(&self) -> &Path {
        &self.bot_executable
    }

    pub fn launcher_executable(&self) -> &Path {
        &self.launcher_executable
    }

    pub fn runtime_executable(&self) -> &Path {
        &self.runtime_executable
    }

    #[cfg(all(test, target_os = "linux"))]
    fn for_test(root: &Path) -> Self {
        let mut paths = Self::new(
            root.join("activation.json"),
            root.join("boot_id"),
            root.join("active.json"),
            root.join("webex-generic-account-bot"),
            root.join("webex-codex-launcher"),
            root.join("webex-codex-runtime"),
        );
        paths.trusted_root = root.to_path_buf();
        // SAFETY: these libc calls have no pointer arguments or side effects.
        paths.expected_uid = unsafe { libc::geteuid() };
        // SAFETY: these libc calls have no pointer arguments or side effects.
        paths.expected_gid = unsafe { libc::getegid() };
        paths
    }
}

impl Default for ActivationPaths {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRuntimeManifest {
    version: u16,
    builder_version: u16,
    codex_version: String,
    codex_target: String,
    codex_layout_version: u16,
    image: String,
    image_sha256: String,
    image_size: u64,
    source_manifest_sha256: String,
    mksquashfs_sha256: String,
    mksquashfs_argv_sha256: String,
}

#[derive(Debug)]
struct ActivationBinding {
    boot_id: String,
    active_manifest_sha256: String,
    runtime_image_sha256: String,
    bot_executable_sha256: String,
    launcher_executable_sha256: String,
    runtime_executable_sha256: String,
    identities: Vec<(PathBuf, FileIdentity)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    volatile_timestamps: bool,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            volatile_timestamps: false,
        }
    }

    fn from_file_metadata(metadata: &fs::Metadata, kind: TrustedFileKind) -> Self {
        let mut identity = Self::from_metadata(metadata);
        identity.volatile_timestamps = matches!(kind, TrustedFileKind::BootId);
        identity
    }

    fn matches(&self, actual: &Self) -> bool {
        self.device == actual.device
            && self.inode == actual.inode
            && self.mode == actual.mode
            && self.uid == actual.uid
            && self.gid == actual.gid
            && self.links == actual.links
            && self.length == actual.length
            && (self.volatile_timestamps
                || (self.modified_seconds == actual.modified_seconds
                    && self.modified_nanoseconds == actual.modified_nanoseconds
                    && self.changed_seconds == actual.changed_seconds
                    && self.changed_nanoseconds == actual.changed_nanoseconds))
    }
}

#[derive(Debug, Clone, Copy)]
enum TrustedFileKind {
    BootId,
    ReadOnlyData,
    Executable,
}

pub fn verify_activation() -> Result<VerifiedActivation> {
    verify_activation_with(&ActivationPaths::production())
}

pub fn verify_activation_with(paths: &ActivationPaths) -> Result<VerifiedActivation> {
    verify_activation_with_deadline(paths, None)
}

pub(crate) fn verify_activation_with_deadline(
    paths: &ActivationPaths,
    deadline: Option<WorkBudget>,
) -> Result<VerifiedActivation> {
    ensure_linux()?;
    let receipt_file = read_trusted_file(
        paths,
        &paths.receipt,
        TrustedFileKind::ReadOnlyData,
        RECEIPT_MAX_BYTES,
    )?;
    let receipt: ActivationReceipt = serde_json::from_slice(&receipt_file.bytes)
        .context("activation receipt is invalid JSON")?;
    let binding = load_activation_binding_with_deadline(paths, deadline)?;
    let verified = validate_receipt(&receipt, &binding)?;
    ensure_path_identity(paths, &paths.receipt, &receipt_file.identity)?;
    for (path, identity) in &binding.identities {
        ensure_path_identity(paths, path, identity)?;
    }
    Ok(verified)
}

pub fn build_activation_receipt(canaries: BTreeMap<String, bool>) -> Result<ActivationReceipt> {
    build_activation_receipt_with(&ActivationPaths::production(), canaries)
}

pub fn write_activation_receipt(receipt: &ActivationReceipt) -> Result<()> {
    ensure_linux()?;
    ensure_root(unsafe { libc::geteuid() })?;
    let paths = ActivationPaths::production();
    write_activation_receipt_with(&paths, receipt)?;
    verify_activation_with(&paths)?;
    Ok(())
}

fn build_activation_receipt_with(
    paths: &ActivationPaths,
    canaries: BTreeMap<String, bool>,
) -> Result<ActivationReceipt> {
    ensure_linux()?;
    validate_canaries(&canaries)?;
    let binding = load_activation_binding(paths)?;
    let receipt = ActivationReceipt {
        schema_version: ACTIVATION_SCHEMA_VERSION,
        boot_id: binding.boot_id.clone(),
        active_manifest_sha256: binding.active_manifest_sha256.clone(),
        runtime_image_sha256: binding.runtime_image_sha256.clone(),
        bot_executable_sha256: binding.bot_executable_sha256.clone(),
        launcher_executable_sha256: binding.launcher_executable_sha256.clone(),
        runtime_executable_sha256: binding.runtime_executable_sha256.clone(),
        codex_version: SUPPORTED_CODEX_VERSION.to_owned(),
        model: SUPPORTED_MODEL.to_owned(),
        canaries,
    };
    validate_receipt(&receipt, &binding)?;
    for (path, identity) in &binding.identities {
        ensure_path_identity(paths, path, identity)?;
    }
    Ok(receipt)
}

fn load_activation_binding(paths: &ActivationPaths) -> Result<ActivationBinding> {
    load_activation_binding_with_deadline(paths, None)
}

fn load_activation_binding_with_deadline(
    paths: &ActivationPaths,
    deadline: Option<WorkBudget>,
) -> Result<ActivationBinding> {
    if let Some(deadline) = deadline.as_ref() {
        deadline.check("activation verification")?;
    }
    let boot_id_file = read_trusted_file(
        paths,
        &paths.boot_id,
        TrustedFileKind::BootId,
        BOOT_ID_MAX_BYTES,
    )?;
    let boot_id = parse_boot_id(&boot_id_file.bytes)?;

    let manifest_file = read_trusted_file(
        paths,
        &paths.active_manifest,
        TrustedFileKind::ReadOnlyData,
        ACTIVE_MANIFEST_MAX_BYTES,
    )?;
    let manifest: ActiveRuntimeManifest = serde_json::from_slice(&manifest_file.bytes)
        .context("runtime active manifest is invalid JSON")?;
    validate_active_manifest(&manifest)?;

    let runtime_root = paths
        .active_manifest
        .parent()
        .ok_or_else(|| anyhow!("runtime active manifest path has no parent"))?;
    let runtime_image_path = runtime_root.join(&manifest.image);
    let runtime_image = hash_runtime_image(
        paths,
        &runtime_image_path,
        manifest.image_size,
        &manifest.image_sha256,
        deadline.clone(),
    )?;
    let bot = hash_trusted_file(paths, &paths.bot_executable, deadline.clone())?;
    let launcher = hash_trusted_file(paths, &paths.launcher_executable, deadline.clone())?;
    let runtime = hash_trusted_file(paths, &paths.runtime_executable, deadline)?;

    Ok(ActivationBinding {
        boot_id,
        active_manifest_sha256: sha256(&manifest_file.bytes),
        runtime_image_sha256: runtime_image.digest,
        bot_executable_sha256: bot.digest,
        launcher_executable_sha256: launcher.digest,
        runtime_executable_sha256: runtime.digest,
        identities: vec![
            (paths.boot_id.clone(), boot_id_file.identity),
            (paths.active_manifest.clone(), manifest_file.identity),
            (runtime_image_path, runtime_image.identity),
            (paths.bot_executable.clone(), bot.identity),
            (paths.launcher_executable.clone(), launcher.identity),
            (paths.runtime_executable.clone(), runtime.identity),
        ],
    })
}

fn validate_receipt(
    receipt: &ActivationReceipt,
    binding: &ActivationBinding,
) -> Result<VerifiedActivation> {
    if receipt.schema_version != ACTIVATION_SCHEMA_VERSION {
        return Err(anyhow!("activation receipt schema version is unsupported"));
    }
    if receipt.codex_version != SUPPORTED_CODEX_VERSION || receipt.model != SUPPORTED_MODEL {
        return Err(anyhow!("activation receipt runtime policy is unsupported"));
    }
    for digest in [
        &receipt.active_manifest_sha256,
        &receipt.runtime_image_sha256,
        &receipt.bot_executable_sha256,
        &receipt.launcher_executable_sha256,
        &receipt.runtime_executable_sha256,
    ] {
        if !valid_digest(digest) {
            return Err(anyhow!("activation receipt contains an invalid digest"));
        }
    }
    validate_canaries(&receipt.canaries)?;
    if receipt.boot_id != binding.boot_id {
        return Err(anyhow!("activation receipt is from a different boot"));
    }
    if receipt.active_manifest_sha256 != binding.active_manifest_sha256
        || receipt.runtime_image_sha256 != binding.runtime_image_sha256
        || receipt.bot_executable_sha256 != binding.bot_executable_sha256
        || receipt.launcher_executable_sha256 != binding.launcher_executable_sha256
        || receipt.runtime_executable_sha256 != binding.runtime_executable_sha256
    {
        return Err(anyhow!(
            "activation receipt does not match the active runtime"
        ));
    }
    Ok(VerifiedActivation {
        schema_version: receipt.schema_version,
        boot_id: receipt.boot_id.clone(),
        active_manifest_sha256: receipt.active_manifest_sha256.clone(),
        runtime_image_sha256: receipt.runtime_image_sha256.clone(),
        bot_executable_sha256: receipt.bot_executable_sha256.clone(),
        launcher_executable_sha256: receipt.launcher_executable_sha256.clone(),
        runtime_executable_sha256: receipt.runtime_executable_sha256.clone(),
        codex_version: receipt.codex_version.clone(),
        model: receipt.model.clone(),
        canaries: receipt.canaries.keys().cloned().collect(),
    })
}

fn validate_canaries(canaries: &BTreeMap<String, bool>) -> Result<()> {
    if canaries.len() != REQUIRED_CANARIES.len() {
        return Err(anyhow!("activation receipt has an incomplete canary set"));
    }
    if canaries
        .keys()
        .any(|name| !REQUIRED_CANARIES.contains(&name.as_str()))
    {
        return Err(anyhow!("activation receipt has an unknown canary"));
    }
    if REQUIRED_CANARIES
        .iter()
        .any(|name| canaries.get(*name) != Some(&true))
    {
        return Err(anyhow!("activation receipt has a failed or missing canary"));
    }
    Ok(())
}

fn validate_active_manifest(manifest: &ActiveRuntimeManifest) -> Result<()> {
    if manifest.version != 1
        || manifest.builder_version != 1
        || manifest.codex_version != SUPPORTED_CODEX_VERSION
        || manifest.codex_target != SUPPORTED_CODEX_TARGET
        || manifest.codex_layout_version != SUPPORTED_CODEX_LAYOUT_VERSION
        || !valid_digest(&manifest.image_sha256)
        || !valid_digest(&manifest.source_manifest_sha256)
        || !valid_digest(&manifest.mksquashfs_sha256)
        || manifest.mksquashfs_argv_sha256 != EXPECTED_MKSQUASHFS_ARGV_SHA256
        || manifest.image_size <= 4
        || manifest.image_size > RUNTIME_IMAGE_MAX_BYTES
    {
        return Err(anyhow!("runtime active manifest fields are invalid"));
    }
    if manifest.image != format!("images/{}.squashfs", manifest.image_sha256) {
        return Err(anyhow!(
            "runtime active manifest image is not content-addressed"
        ));
    }
    Ok(())
}

fn parse_boot_id(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes).context("kernel boot identifier is not UTF-8")?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte != b'-'
            } else {
                !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase()
            }
        })
    {
        return Err(anyhow!("kernel boot identifier is invalid"));
    }
    Ok(value.to_owned())
}

struct TrustedRead {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

struct TrustedDigest {
    digest: String,
    identity: FileIdentity,
}

fn read_trusted_file(
    paths: &ActivationPaths,
    path: &Path,
    kind: TrustedFileKind,
    max_bytes: u64,
) -> Result<TrustedRead> {
    let (mut file, identity) = open_trusted_file(paths, path, kind, max_bytes)?;
    let mut bytes = Vec::with_capacity(identity.length.min(max_bytes) as usize);
    read_bounded(&mut file, &mut bytes, max_bytes)?;
    if bytes.is_empty() {
        return Err(anyhow!("trusted activation file is empty"));
    }
    ensure_open_file_identity(&file, &identity)?;
    ensure_path_identity(paths, path, &identity)?;
    Ok(TrustedRead { bytes, identity })
}

fn hash_trusted_file(
    paths: &ActivationPaths,
    path: &Path,
    deadline: Option<WorkBudget>,
) -> Result<TrustedDigest> {
    let (mut file, identity) = open_trusted_file(
        paths,
        path,
        TrustedFileKind::Executable,
        EXECUTABLE_MAX_BYTES,
    )?;
    let mut context = DigestContext::new(&SHA256);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("activation executable hashing")?;
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("trusted executable size overflowed"))?;
        if total > EXECUTABLE_MAX_BYTES {
            return Err(anyhow!("trusted executable is oversized"));
        }
        context.update(&buffer[..read]);
    }
    if total == 0 {
        return Err(anyhow!("trusted executable is empty"));
    }
    ensure_open_file_identity(&file, &identity)?;
    ensure_path_identity(paths, path, &identity)?;
    Ok(TrustedDigest {
        digest: hex(context.finish().as_ref()),
        identity,
    })
}

fn hash_runtime_image(
    paths: &ActivationPaths,
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
    deadline: Option<WorkBudget>,
) -> Result<TrustedDigest> {
    let (mut file, identity) = open_trusted_file(
        paths,
        path,
        TrustedFileKind::ReadOnlyData,
        RUNTIME_IMAGE_MAX_BYTES,
    )?;
    if identity.length != expected_size {
        return Err(anyhow!("runtime image size does not match its manifest"));
    }

    let mut magic = [0_u8; SQUASHFS_MAGIC.len()];
    file.read_exact(&mut magic)?;
    if &magic != SQUASHFS_MAGIC {
        return Err(anyhow!("runtime image is not SquashFS"));
    }

    let mut context = DigestContext::new(&SHA256);
    context.update(&magic);
    let mut total = magic.len() as u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        if let Some(deadline) = deadline.as_ref() {
            deadline.check("activation runtime image hashing")?;
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("runtime image size overflowed"))?;
        if total > RUNTIME_IMAGE_MAX_BYTES {
            return Err(anyhow!("runtime image is oversized"));
        }
        context.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(anyhow!("runtime image size changed while hashing"));
    }
    let digest = hex(context.finish().as_ref());
    if digest != expected_digest {
        return Err(anyhow!("runtime image digest does not match its manifest"));
    }
    ensure_open_file_identity(&file, &identity)?;
    ensure_path_identity(paths, path, &identity)?;
    Ok(TrustedDigest { digest, identity })
}

fn open_trusted_file(
    paths: &ActivationPaths,
    path: &Path,
    kind: TrustedFileKind,
    max_bytes: u64,
) -> Result<(File, FileIdentity)> {
    validate_trusted_ancestors(paths, path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("trusted activation path is unavailable: {}", path.display()))?;
    validate_file_metadata(paths, &metadata, kind, max_bytes)?;
    let expected = FileIdentity::from_file_metadata(&metadata, kind);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open trusted activation path: {}", path.display()))?;
    ensure_open_file_identity(&file, &expected)?;
    if matches!(kind, TrustedFileKind::Executable) {
        ensure_xattr_absent(&file, b"security.capability\0", "file capability")?;
    }
    Ok((file, expected))
}

fn validate_file_metadata(
    paths: &ActivationPaths,
    metadata: &fs::Metadata,
    kind: TrustedFileKind,
    max_bytes: u64,
) -> Result<()> {
    let permissions = metadata.mode() & 0o7777;
    let valid_mode = match kind {
        TrustedFileKind::BootId => matches!(permissions, 0o400 | 0o444),
        TrustedFileKind::ReadOnlyData => permissions == 0o444,
        TrustedFileKind::Executable => matches!(permissions, 0o555 | 0o755),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != paths.expected_uid
        || metadata.gid() != paths.expected_gid
        || metadata.nlink() != 1
        || !valid_mode
        || metadata.len() > max_bytes
        || (!matches!(kind, TrustedFileKind::BootId) && metadata.len() == 0)
    {
        return Err(anyhow!("trusted activation file metadata is invalid"));
    }
    Ok(())
}

fn validate_trusted_ancestors(paths: &ActivationPaths, path: &Path) -> Result<()> {
    validate_absolute_normal_path(&paths.trusted_root)?;
    validate_absolute_normal_path(path)?;
    if !path.starts_with(&paths.trusted_root) || path == paths.trusted_root {
        return Err(anyhow!("trusted activation path is outside its trust root"));
    }
    let mut current = path
        .parent()
        .ok_or_else(|| anyhow!("trusted activation path has no parent"))?;
    loop {
        let metadata = fs::symlink_metadata(current).with_context(|| {
            format!(
                "trusted activation directory is unavailable: {}",
                current.display()
            )
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != paths.expected_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(anyhow!("trusted activation directory metadata is invalid"));
        }
        if current == paths.trusted_root {
            break;
        }
        current = current
            .parent()
            .ok_or_else(|| anyhow!("trusted activation path escaped its trust root"))?;
    }
    Ok(())
}

fn validate_absolute_normal_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(anyhow!(
            "trusted activation path is not absolute and normalized"
        ));
    }
    Ok(())
}

fn ensure_open_file_identity(file: &File, expected: &FileIdentity) -> Result<()> {
    let actual = FileIdentity::from_metadata(&file.metadata()?);
    if !expected.matches(&actual) {
        return Err(anyhow!("trusted activation file changed while open"));
    }
    Ok(())
}

fn ensure_path_identity(
    paths: &ActivationPaths,
    path: &Path,
    expected: &FileIdentity,
) -> Result<()> {
    validate_trusted_ancestors(paths, path)?;
    let actual = FileIdentity::from_metadata(&fs::symlink_metadata(path)?);
    if !expected.matches(&actual) {
        return Err(anyhow!(
            "trusted activation path changed during verification"
        ));
    }
    Ok(())
}

fn ensure_xattr_absent(file: &File, name: &[u8], description: &str) -> Result<()> {
    if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return Err(anyhow!("invalid extended attribute name"));
    }
    // SAFETY: name is checked to be a single NUL-terminated byte string, the
    // descriptor is owned for this call, and a null value pointer requests only
    // the attribute size.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size >= 0 {
        return Err(anyhow!(
            "trusted executable has an unexpected {description}"
        ));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(()),
        _ => Err(error).with_context(|| format!("failed to inspect executable {description}")),
    }
}

fn read_bounded(file: &mut File, output: &mut Vec<u8>, max_bytes: u64) -> Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("trusted activation file size overflowed"))?;
        if total > max_bytes {
            return Err(anyhow!("trusted activation file is oversized"));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn write_activation_receipt_with(
    paths: &ActivationPaths,
    receipt: &ActivationReceipt,
) -> Result<()> {
    let binding = load_activation_binding(paths)?;
    validate_receipt(receipt, &binding)?;
    let mut payload = serde_json::to_vec_pretty(receipt)?;
    payload.push(b'\n');
    if payload.len() as u64 > RECEIPT_MAX_BYTES {
        return Err(anyhow!("activation receipt is oversized"));
    }

    validate_trusted_ancestors(paths, &paths.receipt)?;
    match fs::symlink_metadata(&paths.receipt) {
        Ok(metadata) => validate_file_metadata(
            paths,
            &metadata,
            TrustedFileKind::ReadOnlyData,
            RECEIPT_MAX_BYTES,
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let parent = paths
        .receipt
        .parent()
        .ok_or_else(|| anyhow!("activation receipt path has no parent"))?;
    let base_name = paths
        .receipt
        .file_name()
        .ok_or_else(|| anyhow!("activation receipt path has no file name"))?
        .to_string_lossy();
    let (temporary_path, mut temporary) =
        create_temporary_file(parent, &base_name, paths.expected_uid, paths.expected_gid)?;

    let result = (|| -> Result<()> {
        temporary.write_all(&payload)?;
        temporary.set_permissions(fs::Permissions::from_mode(0o444))?;
        set_file_owner_if_needed(&temporary, paths.expected_uid, paths.expected_gid)?;
        temporary.sync_all()?;
        validate_file_metadata(
            paths,
            &temporary.metadata()?,
            TrustedFileKind::ReadOnlyData,
            RECEIPT_MAX_BYTES,
        )?;
        fs::rename(&temporary_path, &paths.receipt)?;
        sync_directory(paths, parent)?;
        let installed = fs::symlink_metadata(&paths.receipt)?;
        validate_file_metadata(
            paths,
            &installed,
            TrustedFileKind::ReadOnlyData,
            RECEIPT_MAX_BYTES,
        )?;
        Ok(())
    })();
    drop(temporary);
    if temporary_path.exists() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn create_temporary_file(
    parent: &Path,
    base_name: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(PathBuf, File)> {
    for _ in 0..32 {
        let sequence = TEMPORARY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".{base_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                if let Err(error) = set_file_owner_if_needed(&file, expected_uid, expected_gid) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!("failed to allocate a temporary activation receipt"))
}

fn set_file_owner_if_needed(file: &File, expected_uid: u32, expected_gid: u32) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() == expected_uid && metadata.gid() == expected_gid {
        return Ok(());
    }
    // SAFETY: fchown operates on an owned, open descriptor and has no pointer arguments.
    if unsafe { libc::fchown(file.as_raw_fd(), expected_uid, expected_gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set activation receipt ownership");
    }
    Ok(())
}

fn sync_directory(paths: &ActivationPaths, directory: &Path) -> Result<()> {
    let expected = FileIdentity::from_metadata(&fs::symlink_metadata(directory)?);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(directory)?;
    let actual = FileIdentity::from_metadata(&file.metadata()?);
    if actual != expected
        || actual.uid != paths.expected_uid
        || actual.mode & 0o022 != 0
        || actual.mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(anyhow!("activation receipt directory changed"));
    }
    file.sync_all()?;
    Ok(())
}

fn ensure_root(effective_uid: u32) -> Result<()> {
    if effective_uid != 0 {
        return Err(anyhow!("activation receipt writer must run as root"));
    }
    Ok(())
}

fn ensure_linux() -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(anyhow!("activation receipts are supported only on Linux"));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&SHA256, bytes).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::*;

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);
    const BOOT_ID: &str = "11111111-2222-3333-4444-555555555555";
    const RUNTIME_IMAGE: &[u8] = b"hsqstest runtime image\n";

    struct Fixture {
        root: PathBuf,
        paths: ActivationPaths,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "webex-activation-test-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            let paths = ActivationPaths::for_test(&root);
            let image_directory = root.join("images");
            fs::create_dir(&image_directory).unwrap();
            fs::set_permissions(&image_directory, fs::Permissions::from_mode(0o755)).unwrap();
            write_mode(&paths.boot_id, format!("{BOOT_ID}\n").as_bytes(), 0o444);
            write_mode(
                &paths.active_manifest,
                &serde_json::to_vec_pretty(&active_manifest()).unwrap(),
                0o444,
            );
            write_mode(&paths.bot_executable, b"bot executable\n", 0o555);
            write_mode(&paths.launcher_executable, b"launcher executable\n", 0o555);
            write_mode(&paths.runtime_executable, b"runtime executable\n", 0o555);
            write_mode(&runtime_image_path(&paths), RUNTIME_IMAGE, 0o444);
            Self { root, paths }
        }

        fn receipt(&self) -> ActivationReceipt {
            build_activation_receipt_with(&self.paths, passing_canaries()).unwrap()
        }

        fn install(&self, receipt: &ActivationReceipt) {
            write_activation_receipt_with(&self.paths, receipt).unwrap();
        }

        fn install_unchecked(&self, value: &serde_json::Value) {
            write_mode(
                &self.paths.receipt,
                &serde_json::to_vec_pretty(value).unwrap(),
                0o444,
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn active_manifest() -> serde_json::Value {
        let image_digest = sha256(RUNTIME_IMAGE);
        json!({
            "version": 1,
            "builder_version": 1,
            "codex_version": SUPPORTED_CODEX_VERSION,
            "codex_target": SUPPORTED_CODEX_TARGET,
            "codex_layout_version": SUPPORTED_CODEX_LAYOUT_VERSION,
            "image": format!("images/{image_digest}.squashfs"),
            "image_sha256": image_digest,
            "image_size": RUNTIME_IMAGE.len(),
            "source_manifest_sha256": "b".repeat(64),
            "mksquashfs_sha256": "c".repeat(64),
            "mksquashfs_argv_sha256": EXPECTED_MKSQUASHFS_ARGV_SHA256,
        })
    }

    fn runtime_image_path(paths: &ActivationPaths) -> PathBuf {
        paths
            .active_manifest
            .parent()
            .unwrap()
            .join(format!("images/{}.squashfs", sha256(RUNTIME_IMAGE)))
    }

    #[test]
    fn production_paths_can_use_a_systemd_boot_id_credential() {
        let boot_id = PathBuf::from("/run/credentials/webex-codex-launcher/activation-boot-id");
        let paths = ActivationPaths::production_with_boot_id(&boot_id);

        assert_eq!(paths.boot_id(), boot_id);
        assert_eq!(paths.receipt(), Path::new(ACTIVATION_RECEIPT_PATH));
        assert_eq!(
            paths.runtime_executable(),
            Path::new(RUNTIME_EXECUTABLE_PATH)
        );
    }

    #[test]
    fn virtual_boot_id_identity_ignores_only_timestamp_churn() {
        let fixture = Fixture::new();
        let metadata = fs::metadata(&fixture.paths.boot_id).unwrap();
        let expected = FileIdentity::from_file_metadata(&metadata, TrustedFileKind::BootId);
        let mut actual = FileIdentity::from_metadata(&metadata);

        actual.modified_seconds += 1;
        actual.changed_nanoseconds += 1;
        assert!(expected.matches(&actual));

        actual.length += 1;
        assert!(!expected.matches(&actual));

        let stable = FileIdentity::from_file_metadata(&metadata, TrustedFileKind::ReadOnlyData);
        let mut changed = FileIdentity::from_metadata(&metadata);
        changed.modified_seconds += 1;
        assert!(!stable.matches(&changed));
    }

    #[test]
    fn extended_attribute_probe_rejects_present_attributes() {
        let fixture = Fixture::new();
        fs::set_permissions(
            &fixture.paths.bot_executable,
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.paths.bot_executable)
            .unwrap();
        let name = b"user.webex-activation-test\0";
        // SAFETY: name and value are valid byte buffers for the duration of the call.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                b"present".as_ptr().cast(),
                b"present".len(),
                0,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ENOTSUP));
            return;
        }

        fs::set_permissions(
            &fixture.paths.bot_executable,
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(ensure_xattr_absent(&file, name, "test attribute").is_err());
    }

    fn passing_canaries() -> BTreeMap<String, bool> {
        REQUIRED_CANARIES
            .iter()
            .map(|name| ((*name).to_owned(), true))
            .collect()
    }

    fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.is_dir() {
                fs::remove_dir(path).unwrap();
            } else {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::remove_file(path).unwrap();
            }
        }
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn replace_read_only(path: &Path, bytes: &[u8], mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn writes_and_verifies_a_complete_boot_scoped_receipt() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        fixture.install(&receipt);

        let verified = verify_activation_with(&fixture.paths).unwrap();
        assert_eq!(verified.boot_id, BOOT_ID);
        assert_eq!(verified.codex_version, SUPPORTED_CODEX_VERSION);
        assert_eq!(verified.model, SUPPORTED_MODEL);
        assert_eq!(verified.runtime_image_sha256, sha256(RUNTIME_IMAGE));
        assert_eq!(verified.canaries.len(), REQUIRED_CANARIES.len());

        let metadata = fs::symlink_metadata(&fixture.paths.receipt).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o444);
        assert_eq!(metadata.uid(), fixture.paths.expected_uid);
        assert_eq!(metadata.gid(), fixture.paths.expected_gid);
        assert_eq!(metadata.nlink(), 1);
        assert!(fs::read_dir(&fixture.root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn rejects_stale_boot_and_modified_manifest_or_binaries() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        fixture.install(&receipt);

        replace_read_only(
            &fixture.paths.boot_id,
            b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n",
            0o444,
        );
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(
            &fixture.paths.boot_id,
            format!("{BOOT_ID}\n").as_bytes(),
            0o444,
        );

        let mut manifest = serde_json::to_vec_pretty(&active_manifest()).unwrap();
        manifest.push(b'\n');
        replace_read_only(&fixture.paths.active_manifest, &manifest, 0o444);
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(
            &fixture.paths.active_manifest,
            &serde_json::to_vec_pretty(&active_manifest()).unwrap(),
            0o444,
        );

        for path in [
            &fixture.paths.bot_executable,
            &fixture.paths.launcher_executable,
            &fixture.paths.runtime_executable,
        ] {
            let original = fs::read(path).unwrap();
            replace_read_only(path, b"modified executable\n", 0o555);
            assert!(verify_activation_with(&fixture.paths).is_err());
            replace_read_only(path, &original, 0o555);
        }

        let image = runtime_image_path(&fixture.paths);
        replace_read_only(&image, b"hsqsmodified runtime image\n", 0o444);
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(&image, RUNTIME_IMAGE, 0o444);
        verify_activation_with(&fixture.paths).unwrap();
    }

    #[test]
    fn rejects_missing_malformed_or_untrusted_runtime_image() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        fixture.install(&receipt);
        let image = runtime_image_path(&fixture.paths);

        fs::set_permissions(&image, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
        fs::set_permissions(&image, fs::Permissions::from_mode(0o444)).unwrap();

        replace_read_only(&image, b"not-a-squashfs-image\n", 0o444);
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(&image, RUNTIME_IMAGE, 0o444);

        fs::set_permissions(&image, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&image).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
    }

    #[test]
    fn rejects_missing_false_and_unknown_canaries() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();

        let mut missing = receipt.clone();
        missing.canaries.remove(REQUIRED_CANARIES[0]);
        assert!(build_activation_receipt_with(&fixture.paths, missing.canaries.clone()).is_err());
        fixture.install_unchecked(&serde_json::to_value(&missing).unwrap());
        assert!(verify_activation_with(&fixture.paths).is_err());

        let mut failed = receipt.clone();
        failed
            .canaries
            .insert(REQUIRED_CANARIES[0].to_owned(), false);
        fixture.install_unchecked(&serde_json::to_value(&failed).unwrap());
        assert!(verify_activation_with(&fixture.paths).is_err());

        let mut unknown = receipt;
        unknown.canaries.remove(REQUIRED_CANARIES[0]);
        unknown.canaries.insert("unknown_canary".to_owned(), true);
        fixture.install_unchecked(&serde_json::to_value(&unknown).unwrap());
        assert!(verify_activation_with(&fixture.paths).is_err());
    }

    #[test]
    fn receipt_json_denies_unknown_fields() {
        let fixture = Fixture::new();
        let mut value = serde_json::to_value(fixture.receipt()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        fixture.install_unchecked(&value);
        assert!(verify_activation_with(&fixture.paths).is_err());
    }

    #[test]
    fn rejects_owner_mode_symlink_hardlink_and_type_errors() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        fixture.install(&receipt);

        fs::set_permissions(&fixture.paths.receipt, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
        fs::set_permissions(&fixture.paths.receipt, fs::Permissions::from_mode(0o444)).unwrap();

        let hardlink = fixture.root.join("activation-hardlink.json");
        fs::hard_link(&fixture.paths.receipt, &hardlink).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
        fs::remove_file(hardlink).unwrap();

        let target = fixture.root.join("activation-target.json");
        fs::rename(&fixture.paths.receipt, &target).unwrap();
        symlink(&target, &fixture.paths.receipt).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
        fs::remove_file(&fixture.paths.receipt).unwrap();
        fs::rename(&target, &fixture.paths.receipt).unwrap();

        fs::remove_file(&fixture.paths.receipt).unwrap();
        fs::create_dir(&fixture.paths.receipt).unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
        fs::remove_dir(&fixture.paths.receipt).unwrap();
        fixture.install(&receipt);

        let mut wrong_owner = fixture.paths.clone();
        wrong_owner.expected_uid = fixture.paths.expected_uid.saturating_add(1);
        assert!(verify_activation_with(&wrong_owner).is_err());
    }

    #[test]
    fn rejects_oversized_receipt_manifest_boot_id_and_executable() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        fixture.install(&receipt);

        replace_read_only(
            &fixture.paths.receipt,
            &vec![b' '; RECEIPT_MAX_BYTES as usize + 1],
            0o444,
        );
        assert!(verify_activation_with(&fixture.paths).is_err());
        fixture.install_unchecked(&serde_json::to_value(&receipt).unwrap());

        replace_read_only(
            &fixture.paths.active_manifest,
            &vec![b' '; ACTIVE_MANIFEST_MAX_BYTES as usize + 1],
            0o444,
        );
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(
            &fixture.paths.active_manifest,
            &serde_json::to_vec_pretty(&active_manifest()).unwrap(),
            0o444,
        );

        replace_read_only(
            &fixture.paths.boot_id,
            &vec![b'a'; BOOT_ID_MAX_BYTES as usize + 1],
            0o444,
        );
        assert!(verify_activation_with(&fixture.paths).is_err());
        replace_read_only(
            &fixture.paths.boot_id,
            format!("{BOOT_ID}\n").as_bytes(),
            0o444,
        );

        fs::set_permissions(
            &fixture.paths.bot_executable,
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let file = OpenOptions::new()
            .write(true)
            .open(&fixture.paths.bot_executable)
            .unwrap();
        file.set_len(EXECUTABLE_MAX_BYTES + 1).unwrap();
        drop(file);
        fs::set_permissions(
            &fixture.paths.bot_executable,
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(verify_activation_with(&fixture.paths).is_err());
    }

    #[test]
    fn constructor_and_writer_fail_closed_on_invalid_inputs() {
        let fixture = Fixture::new();
        let mut receipt = fixture.receipt();
        receipt.model = "other-model".to_owned();
        assert!(write_activation_receipt_with(&fixture.paths, &receipt).is_err());
        assert!(!fixture.paths.receipt.exists());

        assert!(ensure_root(1).is_err());
        assert!(ensure_root(0).is_ok());

        let mut manifest = active_manifest();
        manifest
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), json!(true));
        replace_read_only(
            &fixture.paths.active_manifest,
            &serde_json::to_vec_pretty(&manifest).unwrap(),
            0o444,
        );
        assert!(build_activation_receipt_with(&fixture.paths, passing_canaries()).is_err());
    }
}

#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::digest::{Context as DigestContext, SHA256};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MONITOR_START_TIMEOUT: Duration = Duration::from_secs(2);
const FILE_HASH_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegularFileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) file_type: u32,
    pub(crate) mode: u32,
    pub(crate) links: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) size: u64,
}

impl RegularFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let raw_mode = metadata.mode();
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            file_type: raw_mode & libc::S_IFMT,
            mode: raw_mode & 0o7777,
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.len(),
        }
    }

    fn validate_regular_file(&self, max_bytes: u64) -> Result<()> {
        ensure!(
            self.file_type == libc::S_IFREG,
            "canary fixture is not a regular file"
        );
        ensure!(self.links == 1, "canary fixture has multiple hard links");
        ensure!(
            self.size <= max_bytes,
            "canary fixture exceeds its size limit"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedRegularFileSnapshot {
    path: PathBuf,
    pub(crate) identity: RegularFileIdentity,
    pub(crate) content_sha256: [u8; 32],
    max_bytes: u64,
}

impl BoundedRegularFileSnapshot {
    pub(crate) fn capture(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self> {
        let path = path.as_ref();
        let path_metadata = no_follow_metadata(path)?;
        let identity = RegularFileIdentity::from_metadata(&path_metadata);
        identity.validate_regular_file(max_bytes)?;

        let mut file = open_no_follow(path)?;
        verify_file_identity(&file, &identity, max_bytes)?;
        verify_current_path(path, &identity, max_bytes)?;

        let content_sha256 = hash_bounded_file(&mut file, identity.size, max_bytes)?;
        verify_file_identity(&file, &identity, max_bytes)?;
        verify_current_path(path, &identity, max_bytes)?;

        Ok(Self {
            path: path.to_path_buf(),
            identity,
            content_sha256,
            max_bytes,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify_path_identity_unchanged(&self) -> Result<()> {
        let file = self.open_verified_path()?;
        verify_file_identity(&file, &self.identity, self.max_bytes)?;
        verify_current_path(&self.path, &self.identity, self.max_bytes)
    }

    pub(crate) fn verify_contents_unchanged(&self) -> Result<()> {
        let mut file = self.open_verified_path()?;
        let actual_digest = hash_bounded_file(&mut file, self.identity.size, self.max_bytes)?;
        ensure!(
            actual_digest == self.content_sha256,
            "canary fixture contents changed"
        );
        verify_file_identity(&file, &self.identity, self.max_bytes)?;
        verify_current_path(&self.path, &self.identity, self.max_bytes)
    }

    fn open_verified_path(&self) -> Result<File> {
        verify_current_path(&self.path, &self.identity, self.max_bytes)?;
        let file = open_no_follow(&self.path)?;
        verify_file_identity(&file, &self.identity, self.max_bytes)?;
        verify_current_path(&self.path, &self.identity, self.max_bytes)?;
        Ok(file)
    }
}

fn no_follow_metadata(path: &Path) -> Result<fs::Metadata> {
    fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect canary fixture {}", path.display()))
}

fn open_no_follow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open canary fixture {}", path.display()))
}

fn verify_file_identity(file: &File, expected: &RegularFileIdentity, max_bytes: u64) -> Result<()> {
    let actual = RegularFileIdentity::from_metadata(
        &file
            .metadata()
            .context("failed to inspect an open canary fixture")?,
    );
    actual.validate_regular_file(max_bytes)?;
    ensure!(actual == *expected, "open canary fixture identity changed");
    Ok(())
}

fn verify_current_path(path: &Path, expected: &RegularFileIdentity, max_bytes: u64) -> Result<()> {
    let actual = RegularFileIdentity::from_metadata(&no_follow_metadata(path)?);
    actual.validate_regular_file(max_bytes)?;
    ensure!(actual == *expected, "canary fixture path identity changed");
    Ok(())
}

fn hash_bounded_file(file: &mut File, expected_size: u64, max_bytes: u64) -> Result<[u8; 32]> {
    let mut context = DigestContext::new(&SHA256);
    let mut buffer = [0_u8; FILE_HASH_BUFFER_BYTES];
    let mut total = 0_u64;

    loop {
        let read = file
            .read(&mut buffer)
            .context("failed to read canary fixture")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("canary fixture size overflowed"))?;
        ensure!(total <= max_bytes, "canary fixture exceeds its size limit");
        context.update(&buffer[..read]);
    }

    ensure!(
        total == expected_size,
        "canary fixture size changed while hashing"
    );
    context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("SHA-256 returned an unexpected digest length"))
}

#[derive(Debug)]
struct ListenerMonitorState {
    stop: AtomicBool,
    live: AtomicBool,
    failed: AtomicBool,
    accepts: AtomicU64,
}

impl ListenerMonitorState {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            live: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            accepts: AtomicU64::new(0),
        }
    }

    fn record_accept(&self) {
        let _ = self
            .accepts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(1))
            });
    }
}

struct LiveGuard<'a>(&'a AtomicBool);

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

enum ListenerKind {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl ListenerKind {
    fn accept_once(&self) -> io::Result<()> {
        match self {
            Self::Tcp(listener) => listener.accept().map(|_| ()),
            Self::Unix(listener) => listener.accept().map(|_| ()),
        }
    }
}

struct ListenerMonitor {
    state: Arc<ListenerMonitorState>,
    thread: Option<JoinHandle<()>>,
}

impl ListenerMonitor {
    fn spawn(listener: ListenerKind, thread_name: &str) -> Result<Self> {
        let state = Arc::new(ListenerMonitorState::new());
        let thread_state = Arc::clone(&state);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(thread_name.to_owned())
            .spawn(move || {
                thread_state.live.store(true, Ordering::SeqCst);
                let _live_guard = LiveGuard(&thread_state.live);
                let _ = ready_tx.send(());

                loop {
                    match listener.accept_once() {
                        Ok(()) => thread_state.record_accept(),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if thread_state.stop.load(Ordering::SeqCst) {
                                break;
                            }
                            thread::park_timeout(ACCEPT_POLL_INTERVAL);
                        }
                        Err(_) => {
                            thread_state.failed.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            })
            .context("failed to start canary listener monitor")?;

        if ready_rx.recv_timeout(MONITOR_START_TIMEOUT).is_err() {
            state.stop.store(true, Ordering::SeqCst);
            thread.thread().unpark();
            let _ = thread.join();
            bail!("canary listener monitor did not start");
        }

        Ok(Self {
            state,
            thread: Some(thread),
        })
    }

    fn is_live(&self) -> bool {
        self.state.live.load(Ordering::SeqCst) && !self.state.failed.load(Ordering::SeqCst)
    }

    fn accept_count(&self) -> u64 {
        self.state.accepts.load(Ordering::SeqCst)
    }

    fn is_shutdown(&self) -> bool {
        self.thread.is_none()
    }

    fn shutdown(&mut self) -> Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.state.stop.store(true, Ordering::SeqCst);
        thread.thread().unpark();
        thread
            .join()
            .map_err(|_| anyhow!("canary listener monitor panicked"))?;
        ensure!(
            !self.state.failed.load(Ordering::SeqCst),
            "canary listener monitor failed"
        );
        Ok(())
    }

    fn verify_zero_accepts(&self) -> Result<()> {
        ensure!(
            self.is_shutdown(),
            "listener must be shut down before final zero-accept verification"
        );
        ensure!(
            self.accept_count() == 0,
            "canary listener accepted a connection"
        );
        Ok(())
    }
}

impl Drop for ListenerMonitor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketPathIdentity {
    device: u64,
    inode: u64,
}

impl SocketPathIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Result<Self> {
        ensure!(
            metadata.file_type().is_socket(),
            "bound Unix canary path is not a socket"
        );
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
    }
}

pub(crate) struct InstrumentedUnixListener {
    bound_path: PathBuf,
    path_identity: SocketPathIdentity,
    monitor: ListenerMonitor,
    cleanup_pending: bool,
}

impl InstrumentedUnixListener {
    pub(crate) fn bind(path: impl AsRef<Path>) -> Result<Self> {
        let bound_path = canonical_socket_path(path.as_ref())?;
        match fs::symlink_metadata(&bound_path) {
            Ok(_) => bail!("Unix canary listener path already exists"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to inspect Unix canary listener path"),
        }

        let listener = UnixListener::bind(&bound_path).with_context(|| {
            format!(
                "failed to bind Unix canary listener {}",
                bound_path.display()
            )
        })?;
        let path_identity = fs::symlink_metadata(&bound_path)
            .context("failed to inspect bound Unix canary listener")
            .and_then(|metadata| SocketPathIdentity::from_metadata(&metadata))?;
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = remove_owned_socket_path(&bound_path, path_identity);
            return Err(error).context("failed to make Unix canary listener nonblocking");
        }
        let monitor = match ListenerMonitor::spawn(
            ListenerKind::Unix(listener),
            "webex-canary-unix-listener",
        ) {
            Ok(monitor) => monitor,
            Err(error) => {
                let _ = remove_owned_socket_path(&bound_path, path_identity);
                return Err(error);
            }
        };

        Ok(Self {
            bound_path,
            path_identity,
            monitor,
            cleanup_pending: true,
        })
    }

    pub(crate) fn bound_path(&self) -> &Path {
        &self.bound_path
    }

    pub(crate) fn is_live(&self) -> bool {
        self.monitor.is_live()
            && fs::symlink_metadata(&self.bound_path)
                .is_ok_and(|metadata| self.path_identity.matches(&metadata))
    }

    pub(crate) fn accept_count(&self) -> u64 {
        self.monitor.accept_count()
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        let monitor_result = self.monitor.shutdown();
        let cleanup_result = self.cleanup_path();
        monitor_result.and(cleanup_result)
    }

    pub(crate) fn shutdown_and_verify_zero_accepts(&mut self) -> Result<()> {
        self.shutdown()?;
        self.monitor.verify_zero_accepts()
    }

    #[cfg(test)]
    pub(crate) fn verify_zero_accepts(&self) -> Result<()> {
        self.monitor.verify_zero_accepts()
    }

    fn cleanup_path(&mut self) -> Result<()> {
        if !self.cleanup_pending {
            return Ok(());
        }
        self.cleanup_pending = false;
        remove_owned_socket_path(&self.bound_path, self.path_identity)
    }
}

impl Drop for InstrumentedUnixListener {
    fn drop(&mut self) {
        let _ = self.monitor.shutdown();
        let _ = self.cleanup_path();
    }
}

fn canonical_socket_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Unix canary listener path has no file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to canonicalize Unix canary listener parent {}",
            parent.display()
        )
    })?;
    Ok(canonical_parent.join(file_name))
}

fn remove_owned_socket_path(path: &Path, expected: SocketPathIdentity) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect Unix canary listener cleanup"),
    };
    ensure!(
        expected.matches(&metadata),
        "Unix canary listener path was replaced; refusing to remove it"
    );
    fs::remove_file(path).context("failed to remove Unix canary listener path")
}

pub(crate) struct InstrumentedTcpListener {
    bound_endpoint: SocketAddr,
    monitor: ListenerMonitor,
}

impl InstrumentedTcpListener {
    pub(crate) fn bind(endpoint: SocketAddr) -> Result<Self> {
        ensure_unicast_ip(endpoint.ip())?;
        let listener = TcpListener::bind(endpoint)
            .with_context(|| format!("failed to bind TCP canary listener {endpoint}"))?;
        listener
            .set_nonblocking(true)
            .context("failed to make TCP canary listener nonblocking")?;
        let bound_endpoint = listener
            .local_addr()
            .context("failed to read bound TCP canary endpoint")?;
        ensure!(
            bound_endpoint.ip() == endpoint.ip(),
            "TCP canary listener did not bind the requested IP address"
        );
        ensure!(
            endpoint.port() == 0 || bound_endpoint.port() == endpoint.port(),
            "TCP canary listener did not bind the requested port"
        );
        match (endpoint, bound_endpoint) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => {}
            (SocketAddr::V6(requested), SocketAddr::V6(bound)) => ensure!(
                requested.scope_id() == bound.scope_id(),
                "TCP canary listener did not bind the requested IPv6 scope"
            ),
            _ => bail!("TCP canary listener changed address family while binding"),
        }
        let monitor =
            ListenerMonitor::spawn(ListenerKind::Tcp(listener), "webex-canary-tcp-listener")?;
        Ok(Self {
            bound_endpoint,
            monitor,
        })
    }

    pub(crate) fn bound_endpoint(&self) -> SocketAddr {
        self.bound_endpoint
    }

    pub(crate) fn is_live(&self) -> bool {
        self.monitor.is_live()
    }

    pub(crate) fn accept_count(&self) -> u64 {
        self.monitor.accept_count()
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        self.monitor.shutdown()
    }

    pub(crate) fn shutdown_and_verify_zero_accepts(&mut self) -> Result<()> {
        self.shutdown()?;
        self.monitor.verify_zero_accepts()
    }

    #[cfg(test)]
    pub(crate) fn verify_zero_accepts(&self) -> Result<()> {
        self.monitor.verify_zero_accepts()
    }
}

pub(crate) fn assigned_non_loopback_socket_addresses() -> Result<Vec<SocketAddr>> {
    let mut interfaces = ptr::null_mut();
    // SAFETY: getifaddrs initializes `interfaces` on success; the guard frees that list once.
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to enumerate network interfaces");
    }
    let guard = IfAddrsGuard(interfaces);
    let mut addresses = BTreeSet::new();
    let mut current = guard.0;

    while !current.is_null() {
        // SAFETY: every non-null node is owned by the live getifaddrs list.
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null()
            && interface.ifa_flags & libc::IFF_UP as u32 != 0
            && interface.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
        {
            // SAFETY: sa_family is available on every non-null sockaddr.
            let family = unsafe { (*interface.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                // SAFETY: AF_INET identifies a sockaddr_in at ifa_addr.
                let socket_address = unsafe { &*(interface.ifa_addr.cast::<libc::sockaddr_in>()) };
                let address = Ipv4Addr::from(socket_address.sin_addr.s_addr.to_ne_bytes());
                if is_unicast_non_loopback_ipv4(address) {
                    addresses.insert(SocketAddr::V4(SocketAddrV4::new(address, 0)));
                }
            } else if family == libc::AF_INET6 {
                // SAFETY: AF_INET6 identifies a sockaddr_in6 at ifa_addr.
                let socket_address = unsafe { &*(interface.ifa_addr.cast::<libc::sockaddr_in6>()) };
                let address = Ipv6Addr::from(socket_address.sin6_addr.s6_addr);
                // The canary protocol uses the canonical SocketAddr text form, which
                // intentionally excludes interface-scoped IPv6 endpoints.
                if is_unicast_non_loopback_ipv6(address) && socket_address.sin6_scope_id == 0 {
                    addresses.insert(SocketAddr::V6(SocketAddrV6::new(address, 0, 0, 0)));
                }
            }
        }
        // SAFETY: ifa_next is either null or the next node in the same live list.
        current = unsafe { (*current).ifa_next };
    }

    Ok(addresses.into_iter().collect())
}

#[cfg(test)]
pub(crate) fn assigned_non_loopback_ipv4_addresses() -> Result<Vec<Ipv4Addr>> {
    Ok(assigned_non_loopback_socket_addresses()?
        .into_iter()
        .filter_map(|endpoint| match endpoint {
            SocketAddr::V4(endpoint) => Some(*endpoint.ip()),
            SocketAddr::V6(_) => None,
        })
        .collect())
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        // SAFETY: the pointer came from one successful getifaddrs call and is freed once here.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

#[cfg(test)]
pub(crate) fn select_assigned_non_loopback_ipv4() -> Result<Ipv4Addr> {
    assigned_non_loopback_ipv4_addresses()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no assigned non-loopback unicast IPv4 address is available"))
}

fn select_preferred_non_loopback_endpoint(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    let mut ipv6 = None;
    for address in addresses {
        match address {
            SocketAddr::V4(_) => return Some(address),
            SocketAddr::V6(_) if ipv6.is_none() => ipv6 = Some(address),
            SocketAddr::V6(_) => {}
        }
    }
    ipv6
}

pub(crate) fn select_assigned_non_loopback_endpoint() -> Result<SocketAddr> {
    select_preferred_non_loopback_endpoint(assigned_non_loopback_socket_addresses()?)
        .ok_or_else(|| anyhow!("no assigned non-loopback unicast IP address is available"))
}

#[cfg(test)]
pub(crate) fn bind_controlled_non_loopback_listener(
    address: Ipv4Addr,
) -> Result<InstrumentedTcpListener> {
    ensure!(
        is_unicast_non_loopback_ipv4(address),
        "controlled canary IPv4 address is not non-loopback unicast"
    );
    ensure!(
        assigned_non_loopback_ipv4_addresses()?.contains(&address),
        "controlled canary IPv4 address is not assigned to this host"
    );
    InstrumentedTcpListener::bind(SocketAddr::V4(SocketAddrV4::new(address, 0)))
}

pub(crate) fn bind_assigned_non_loopback_listener() -> Result<InstrumentedTcpListener> {
    InstrumentedTcpListener::bind(select_assigned_non_loopback_endpoint()?)
}

pub(crate) fn bind_loopback_bot_listener() -> Result<InstrumentedTcpListener> {
    InstrumentedTcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
}

fn ensure_unicast_ip(address: IpAddr) -> Result<()> {
    match address {
        IpAddr::V4(address) => ensure_unicast_ipv4(address)?,
        IpAddr::V6(address) => ensure!(
            !address.is_unspecified() && !address.is_multicast(),
            "TCP canary listener requires a concrete unicast IPv6 address"
        ),
    }
    Ok(())
}

fn ensure_unicast_ipv4(address: Ipv4Addr) -> Result<()> {
    ensure!(
        !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast(),
        "TCP canary listener requires a concrete unicast IPv4 address"
    );
    Ok(())
}

fn is_unicast_non_loopback_ipv4(address: Ipv4Addr) -> bool {
    ensure_unicast_ipv4(address).is_ok() && !address.is_loopback()
}

fn is_unicast_non_loopback_ipv6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_loopback()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        net::TcpStream,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "webex-canary-host-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_fixture(path: &Path, contents: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
    }

    fn wait_for_accept_count<F>(count: F, expected: u64)
    where
        F: Fn() -> u64,
    {
        let deadline = Instant::now() + TEST_TIMEOUT;
        while count() < expected && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(count(), expected);
    }

    #[test]
    fn regular_file_snapshot_records_and_verifies_identity_and_contents() {
        let directory = TestDirectory::new("snapshot-ok");
        let path = directory.join("fixture");
        write_fixture(&path, b"canary secret");

        let snapshot = BoundedRegularFileSnapshot::capture(&path, 1024).unwrap();

        assert_eq!(snapshot.path(), path);
        assert_eq!(snapshot.identity.file_type, libc::S_IFREG);
        assert_eq!(snapshot.identity.mode, 0o600);
        assert_eq!(snapshot.identity.links, 1);
        assert_eq!(snapshot.identity.size, 13);
        assert_ne!(snapshot.content_sha256, [0; 32]);
        snapshot.verify_path_identity_unchanged().unwrap();
        snapshot.verify_contents_unchanged().unwrap();
    }

    #[test]
    fn regular_file_snapshot_rejects_missing_symlink_hardlink_and_directory() {
        let directory = TestDirectory::new("snapshot-types");
        let missing = directory.join("missing");
        assert!(BoundedRegularFileSnapshot::capture(&missing, 1024).is_err());

        let target = directory.join("target");
        let link = directory.join("link");
        write_fixture(&target, b"target");
        symlink(&target, &link).unwrap();
        assert!(BoundedRegularFileSnapshot::capture(&link, 1024).is_err());

        let hardlink = directory.join("hardlink");
        fs::hard_link(&target, &hardlink).unwrap();
        assert!(BoundedRegularFileSnapshot::capture(&target, 1024).is_err());
        assert!(BoundedRegularFileSnapshot::capture(&hardlink, 1024).is_err());
        assert!(BoundedRegularFileSnapshot::capture(&directory.0, 1024).is_err());
    }

    #[test]
    fn regular_file_snapshot_rejects_oversized_input() {
        let directory = TestDirectory::new("snapshot-oversized");
        let path = directory.join("fixture");
        write_fixture(&path, b"too large");

        assert!(BoundedRegularFileSnapshot::capture(&path, 8).is_err());
    }

    #[test]
    fn regular_file_snapshot_detects_content_and_size_mutations() {
        let directory = TestDirectory::new("snapshot-content");
        let path = directory.join("fixture");
        write_fixture(&path, b"original");
        let snapshot = BoundedRegularFileSnapshot::capture(&path, 1024).unwrap();

        fs::write(&path, b"mutated!").unwrap();
        snapshot.verify_path_identity_unchanged().unwrap();
        assert!(snapshot.verify_contents_unchanged().is_err());

        fs::write(&path, b"longer mutation").unwrap();
        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());
    }

    #[test]
    fn regular_file_snapshot_detects_mode_and_hardlink_mutations() {
        let directory = TestDirectory::new("snapshot-metadata");
        let path = directory.join("fixture");
        write_fixture(&path, b"fixture");
        let snapshot = BoundedRegularFileSnapshot::capture(&path, 1024).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = directory.join("hardlink");
        fs::hard_link(&path, hardlink).unwrap();
        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());
    }

    #[test]
    fn regular_file_snapshot_detects_path_replacement() {
        let directory = TestDirectory::new("snapshot-replacement");
        let path = directory.join("fixture");
        let replacement = directory.join("replacement");
        write_fixture(&path, b"same bytes");
        write_fixture(&replacement, b"same bytes");
        let snapshot = BoundedRegularFileSnapshot::capture(&path, 1024).unwrap();

        fs::rename(&replacement, &path).unwrap();

        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());
    }

    #[test]
    fn regular_file_snapshot_detects_missing_and_symlink_replacement() {
        let directory = TestDirectory::new("snapshot-symlink-replacement");
        let path = directory.join("fixture");
        let target = directory.join("target");
        write_fixture(&path, b"same bytes");
        write_fixture(&target, b"same bytes");
        let snapshot = BoundedRegularFileSnapshot::capture(&path, 1024).unwrap();

        fs::remove_file(&path).unwrap();
        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());

        symlink(&target, &path).unwrap();
        assert!(snapshot.verify_path_identity_unchanged().is_err());
        assert!(snapshot.verify_contents_unchanged().is_err());
    }

    #[test]
    fn unix_listener_reports_liveness_and_verifies_zero_accepts_after_shutdown() {
        let directory = TestDirectory::new("unix-zero");
        let path = directory.join("listener.sock");
        let canonical_path = fs::canonicalize(&directory.0)
            .unwrap()
            .join("listener.sock");
        let mut listener = InstrumentedUnixListener::bind(&path).unwrap();

        assert_eq!(listener.bound_path(), canonical_path);
        assert!(listener.is_live());
        assert_eq!(listener.accept_count(), 0);
        assert!(listener.verify_zero_accepts().is_err());
        listener.shutdown_and_verify_zero_accepts().unwrap();
        assert!(!listener.is_live());
        assert!(!path.exists());
    }

    #[test]
    fn unix_listener_counts_connections_and_preserves_replacement_on_cleanup() {
        let directory = TestDirectory::new("unix-accept");
        let path = directory.join("listener.sock");
        let mut listener = InstrumentedUnixListener::bind(&path).unwrap();

        let connection = std::os::unix::net::UnixStream::connect(listener.bound_path()).unwrap();
        wait_for_accept_count(|| listener.accept_count(), 1);
        drop(connection);
        listener.shutdown().unwrap();
        assert!(listener.verify_zero_accepts().is_err());

        let mut replacement_test = InstrumentedUnixListener::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        write_fixture(&path, b"replacement");
        assert!(replacement_test.shutdown().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }

    #[test]
    fn loopback_tcp_listener_reports_liveness_and_verifies_zero_accepts() {
        let mut listener = bind_loopback_bot_listener().unwrap();
        let endpoint = listener.bound_endpoint();

        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(endpoint.port(), 0);
        assert!(listener.is_live());
        assert!(listener.verify_zero_accepts().is_err());
        listener.shutdown_and_verify_zero_accepts().unwrap();
        assert!(!listener.is_live());
    }

    #[test]
    fn tcp_listener_counts_connections_and_rejects_wildcard_binding() {
        assert!(
            InstrumentedTcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                0,
            )))
            .is_err()
        );
        let mut listener = bind_loopback_bot_listener().unwrap();
        let connection = TcpStream::connect(listener.bound_endpoint()).unwrap();
        wait_for_accept_count(|| listener.accept_count(), 1);
        drop(connection);

        listener.shutdown().unwrap();
        assert_eq!(listener.accept_count(), 1);
        assert!(listener.verify_zero_accepts().is_err());
    }

    #[test]
    fn assigned_ipv4_selection_never_returns_wildcard_loopback_or_multicast() {
        let addresses = assigned_non_loopback_ipv4_addresses().unwrap();
        for address in &addresses {
            assert!(is_unicast_non_loopback_ipv4(*address));
        }

        if let Some(address) = addresses.first().copied() {
            assert_eq!(select_assigned_non_loopback_ipv4().unwrap(), address);
            let mut listener = bind_controlled_non_loopback_listener(address).unwrap();
            assert_eq!(listener.bound_endpoint().ip(), IpAddr::V4(address));
            listener.shutdown_and_verify_zero_accepts().unwrap();
        } else {
            assert!(select_assigned_non_loopback_ipv4().is_err());
            assert!(bind_assigned_non_loopback_listener().is_err());
        }

        assert!(bind_controlled_non_loopback_listener(Ipv4Addr::LOCALHOST).is_err());
        assert!(bind_controlled_non_loopback_listener(Ipv4Addr::UNSPECIFIED).is_err());
    }

    #[test]
    fn endpoint_selection_prefers_ipv4_and_falls_back_to_ipv6() {
        let ipv4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 0));
        let ipv6 = SocketAddr::V6(SocketAddrV6::new("2001:db8::10".parse().unwrap(), 0, 0, 0));

        assert_eq!(select_preferred_non_loopback_endpoint([ipv6]), Some(ipv6));
        assert_eq!(
            select_preferred_non_loopback_endpoint([ipv6, ipv4]),
            Some(ipv4)
        );
        assert_eq!(select_preferred_non_loopback_endpoint([]), None);
    }

    #[test]
    fn tcp_listener_supports_ipv6() {
        let endpoint = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
        let mut listener = InstrumentedTcpListener::bind(endpoint).unwrap();

        assert_eq!(
            listener.bound_endpoint().ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_ne!(listener.bound_endpoint().port(), 0);
        listener.shutdown_and_verify_zero_accepts().unwrap();
    }
}

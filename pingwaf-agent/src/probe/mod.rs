//! Host probe: samples basic machine state on a fixed cadence.
//!
//! Samples are buffered locally and shipped with the next heartbeat, so a
//! control plane that was briefly unreachable still receives the window it
//! missed instead of a gap. Everything here reads `/proc`, `/sys` and `df`
//! directly: the agent ships as a single binary and does not pull in a
//! system-information crate for it.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::debug;

/// Sampling cadence. The control plane draws one point per sample.
pub const DEFAULT_INTERVAL_SECS: u64 = 5;

/// Samples kept while the control plane is unreachable — two minutes at the
/// default cadence. Older points are dropped rather than buffered forever.
const MAX_BUFFERED: usize = 24;

/// How often the interface list is re-read. Addresses change rarely, and the
/// lookup shells out to `ip`, so it is not worth doing every tick.
const ADDRESS_REFRESH: Duration = Duration::from_secs(3600);

/// Interface name prefixes that are virtual by construction: container and VM
/// bridges, veth pairs, and CNI-style overlays. A node's own address lives on
/// its physical interface, so these are skipped when looking for one. This is
/// what keeps `172.17.0.1` (docker0) out of the reported addresses.
const VIRTUAL_PREFIXES: [&str; 11] = [
    "br-", "cali", "cni", "docker", "flannel", "kube", "lxc", "lxdbr",
    "podman", "veth", "virbr",
];

/// One point of host state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostSample {
    /// Unix epoch milliseconds at which the sample was taken.
    pub ts_millis: i64,
    pub cpu_usage_percent: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    /// Cumulative bytes received on physical interfaces since boot.
    pub net_rx_bytes: u64,
    /// Cumulative bytes sent on physical interfaces since boot.
    pub net_tx_bytes: u64,
    /// Cumulative bytes read from physical block devices since boot.
    pub disk_read_bytes: u64,
    /// Cumulative bytes written to physical block devices since boot.
    pub disk_write_bytes: u64,
    pub process_count: u32,
    pub tcp_connections: u32,
    pub uptime_secs: u64,
}

/// Where a node is reachable, split the way operators think about it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostAddresses {
    /// Address the node is reachable at from the internet. Empty behind NAT or
    /// when the host has no route out.
    pub public_ip: String,
    /// Address the node is reachable at inside its own network, with container
    /// and loopback addresses excluded.
    pub private_ip: String,
}

// ─────────────────────────────────────────────────────────────
// Address classification
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Public,
    Private,
}

/// Classifies a candidate address, or `None` when it can never identify the
/// host: loopback, link-local, multicast, or the unspecified address.
fn scope_of(ip: IpAddr) -> Option<Scope> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 224
            {
                return None;
            }
            if v4.is_private() || is_cgnat(v4) {
                Some(Scope::Private)
            } else {
                Some(Scope::Public)
            }
        },
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return None;
            }
            let head = v6.segments()[0];
            // fc00::/7 unique-local, fe80::/10 link-local
            if (head & 0xfe00) == 0xfc00 || (head & 0xffc0) == 0xfe80 {
                Some(Scope::Private)
            } else {
                Some(Scope::Public)
            }
        },
    }
}

/// 100.64.0.0/10 — carrier-grade NAT. Not routable, so it counts as private.
fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (64..128).contains(&octets[1])
}

/// Address the kernel would use to leave the host.
///
/// A UDP `connect` sends nothing but makes the kernel pick a source address,
/// which is exactly the hint needed: on a NAT'd node this is the private
/// address it owns, not a public one it merely reaches the internet through.
fn egress_ip() -> Option<IpAddr> {
    for probe in ["8.8.8.8:80", "[2001:4860:4860::8888]:80"] {
        let bind = if probe.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let Ok(socket) = UdpSocket::bind(bind) else {
            continue;
        };
        if socket.connect(probe).is_err() {
            continue;
        }
        match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) => return Some(IpAddr::V4(*addr.ip())),
            Ok(SocketAddr::V6(addr)) => return Some(IpAddr::V6(*addr.ip())),
            Err(_) => continue,
        }
    }
    None
}

/// Physical interfaces and their addresses, in kernel order.
///
/// Uses `ip -j addr show`; on a host without iproute2, or off Linux, this
/// yields nothing and the egress probe above still finds the primary address.
fn interface_addresses() -> Vec<(String, IpAddr)> {
    let output = match std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&output.stdout)
    {
        Ok(parsed) => parsed,
        Err(err) => {
            debug!(error = %err, "could not parse `ip -j addr show`");
            return Vec::new();
        },
    };

    let mut addresses = Vec::new();
    let Some(links) = parsed.as_array() else {
        return addresses;
    };
    for link in links {
        let Some(name) = link.get("ifname").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(infos) = link.get("addr_info").and_then(|a| a.as_array())
        else {
            continue;
        };
        for info in infos {
            if info.get("family").and_then(|f| f.as_str()) != Some("inet") {
                continue;
            }
            let Some(local) = info.get("local").and_then(|l| l.as_str()) else {
                continue;
            };
            if let Ok(ip) = local.parse::<IpAddr>() {
                addresses.push((name.to_string(), ip));
            }
        }
    }
    addresses
}

/// Whether an interface is virtual: a container bridge, veth pair or overlay
/// device rather than the link the host is addressed on.
fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Finds the node's public and private address.
///
/// The egress address wins because it is the one that actually works; the
/// interface list is then scanned for a private address, skipping container
/// and loopback addresses.
pub fn classify_addresses() -> HostAddresses {
    let mut public: Option<IpAddr> = None;
    let mut private: Option<IpAddr> = None;

    if let Some(ip) = egress_ip() {
        match scope_of(ip) {
            Some(Scope::Public) => public = Some(ip),
            Some(Scope::Private) => private = Some(ip),
            None => {},
        }
    }

    for (name, ip) in interface_addresses() {
        if is_virtual_interface(&name) {
            continue;
        }
        match scope_of(ip) {
            Some(Scope::Public) => {
                public.get_or_insert(ip);
            },
            Some(Scope::Private) => {
                private.get_or_insert(ip);
            },
            None => {},
        }
    }

    HostAddresses {
        public_ip: public.map(|ip| ip.to_string()).unwrap_or_default(),
        private_ip: private.map(|ip| ip.to_string()).unwrap_or_default(),
    }
}

// ─────────────────────────────────────────────────────────────
// Sampling
// ─────────────────────────────────────────────────────────────

/// Cumulative kernel counters. Kept between samples so CPU usage is the
/// average over the interval rather than the average since boot.
#[derive(Debug, Clone, Copy, Default)]
struct Counters {
    cpu_total: u64,
    cpu_idle: u64,
    net_rx: u64,
    net_tx: u64,
    disk_read: u64,
    disk_write: u64,
}

/// Reads one point of host state. Holds the previous counters to derive CPU
/// usage and the disk path whose usage is reported.
pub struct Sampler {
    disk_path: String,
    previous: Option<Counters>,
}

impl Sampler {
    pub fn new(disk_path: impl Into<String>) -> Self {
        Self {
            disk_path: disk_path.into(),
            previous: None,
        }
    }

    /// Takes a sample. Never fails: fields the platform does not expose stay 0.
    pub fn sample(&mut self) -> HostSample {
        let counters = read_counters();
        let cpu_usage_percent = self
            .previous
            .and_then(|previous| cpu_percent(&previous, &counters))
            .unwrap_or(0.0);
        self.previous = Some(counters);

        let memory = read_memory();
        let (load1, load5, load15, process_count) = read_load();
        let (disk_total_bytes, disk_used_bytes) = disk_usage(&self.disk_path);

        HostSample {
            ts_millis: now_millis(),
            cpu_usage_percent,
            load1,
            load5,
            load15,
            memory_total_bytes: memory.total,
            memory_used_bytes: memory.used(),
            memory_available_bytes: memory.available,
            swap_total_bytes: memory.swap_total,
            swap_used_bytes: memory.swap_total.saturating_sub(memory.swap_free),
            disk_total_bytes,
            disk_used_bytes,
            net_rx_bytes: counters.net_rx,
            net_tx_bytes: counters.net_tx,
            disk_read_bytes: counters.disk_read,
            disk_write_bytes: counters.disk_write,
            process_count,
            tcp_connections: count_tcp_connections(),
            uptime_secs: read_uptime(),
        }
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as i64)
        .unwrap_or_default()
}

/// CPU usage between two counter snapshots, in percent.
fn cpu_percent(previous: &Counters, current: &Counters) -> Option<f64> {
    cpu_percent_between(jiffies(previous), jiffies(current))
}

/// `(busy, total)` of one sampler snapshot.
fn jiffies(counters: &Counters) -> (u64, u64) {
    (
        counters.cpu_total.saturating_sub(counters.cpu_idle),
        counters.cpu_total,
    )
}

/// CPU usage between two `(busy, total)` jiffy snapshots, in percent.
///
/// `None` when the interval holds no time or the counters moved backwards
/// (a reboot between the samples, a wrapped counter): the difference is then
/// meaningless, and a caller that holds a baseline re-establishes it instead
/// of subtracting into a wrapped `u64`. Busy above total — a torn read of
/// `/proc/stat` — clamps to 100 % rather than reporting a percentage nothing
/// can plot.
pub(crate) fn cpu_percent_between(
    previous: (u64, u64),
    current: (u64, u64),
) -> Option<f64> {
    let total = current.1.checked_sub(previous.1)?;
    if total == 0 {
        return None;
    }
    let busy = current.0.checked_sub(previous.0)?;
    Some((busy.min(total) as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
}

/// Busy share since boot, in percent: the only CPU figure available before
/// this process has taken two samples.
pub(crate) fn cpu_percent_since_boot((busy, total): (u64, u64)) -> Option<f64> {
    (total > 0).then(|| busy.min(total) as f64 / total as f64 * 100.0)
}

/// CPU usage since the previous call, in percent, with the baseline kept in
/// `previous` (`(busy, total)` jiffies from `/proc/stat`).
///
/// The heartbeat uses this so its figure is the average over the heartbeat
/// interval, the same measurement the probe ships, instead of the average since
/// boot (which is diluted by everything the machine did before the agent
/// started).
///
/// The first call has no baseline and reports the since-boot average: the
/// heartbeat has no "unknown" CPU, and a non-null first sample is what keeps
/// the field honest until the second heartbeat. A counter that moved backwards
/// (reboot, wrap, a reset `/proc`) re-baselines the same way instead of
/// producing a wrapped percentage.
///
/// `None` only when the platform exposes no machine-wide counters at all
/// (anything without `/proc/stat`); the caller falls back to its own platform
/// reading.
pub(crate) fn cpu_percent_since(
    previous: &mut Option<(u64, u64)>,
) -> Option<f64> {
    let current = cpu_counters()?;
    let percent = previous
        .and_then(|prev| cpu_percent_between(prev, current))
        .or_else(|| cpu_percent_since_boot(current));
    *previous = Some(current);
    percent
}

/// Machine-wide CPU jiffies from `/proc/stat`, as `(total, idle)`.
///
/// One parser for both readers: the probe's own sampler and the heartbeat's
/// interval figure ([`cpu_counters`]) must never disagree about what "busy"
/// means.
#[cfg(target_os = "linux")]
fn read_cpu_jiffies() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    // user nice system idle iowait irq softirq steal ...
    let fields: Vec<u64> = stat
        .lines()
        .next()?
        .split_whitespace()
        .skip(1)
        .filter_map(|field| field.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let total = fields.iter().sum();
    // iowait counts as idle: the CPU was not doing work.
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some((total, idle))
}

/// Machine-wide CPU counters as `(busy, total)` jiffies.
///
/// The heartbeat diffs this against its previous reading, so its
/// `cpu_usage_percent` covers the heartbeat interval rather than the time since
/// boot.
#[cfg(target_os = "linux")]
pub(crate) fn cpu_counters() -> Option<(u64, u64)> {
    let (total, idle) = read_cpu_jiffies()?;
    Some((total.saturating_sub(idle), total))
}

/// Platforms without `/proc/stat` expose no machine-wide counters here; the
/// heartbeat keeps its own platform reading.
#[cfg(not(target_os = "linux"))]
pub(crate) fn cpu_counters() -> Option<(u64, u64)> {
    None
}

/// Physical block devices: everything the kernel exports as a whole disk, so
/// partitions are not counted twice alongside their parent.
#[cfg(target_os = "linux")]
fn whole_disks() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[cfg(target_os = "linux")]
fn read_counters() -> Counters {
    let mut counters = Counters::default();

    if let Some((total, idle)) = read_cpu_jiffies() {
        counters.cpu_total = total;
        counters.cpu_idle = idle;
    }

    if let Ok(dev) = std::fs::read_to_string("/proc/net/dev") {
        for line in dev.lines().skip(2) {
            let Some((name, rest)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name == "lo" || is_virtual_interface(name) {
                continue;
            }
            let fields: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|field| field.parse().ok())
                .collect();
            if fields.len() >= 9 {
                counters.net_rx += fields[0];
                counters.net_tx += fields[8];
            }
        }
    }

    let disks = whole_disks();
    if let Ok(stats) = std::fs::read_to_string("/proc/diskstats") {
        for line in stats.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let name = fields[2];
            // Loopback and RAM disks are not real I/O; device mapper and MD
            // volumes would double count the disk underneath them.
            if name.starts_with("loop")
                || name.starts_with("ram")
                || name.starts_with("fd")
                || name.starts_with("dm-")
                || name.starts_with("md")
            {
                continue;
            }
            if !disks.is_empty() && !disks.iter().any(|disk| disk == name) {
                continue;
            }
            let sectors_read: u64 = fields[5].parse().unwrap_or_default();
            let sectors_written: u64 = fields[9].parse().unwrap_or_default();
            counters.disk_read += sectors_read * 512;
            counters.disk_write += sectors_written * 512;
        }
    }

    counters
}

#[cfg(not(target_os = "linux"))]
fn read_counters() -> Counters {
    Counters::default()
}

#[derive(Debug, Clone, Copy, Default)]
struct Memory {
    total: u64,
    available: u64,
    free: u64,
    swap_total: u64,
    swap_free: u64,
}

impl Memory {
    /// Memory applications actually hold: what is not available to them.
    fn used(&self) -> u64 {
        if self.available > 0 {
            self.total.saturating_sub(self.available)
        } else {
            self.total.saturating_sub(self.free)
        }
    }
}

#[cfg(target_os = "linux")]
fn read_memory() -> Memory {
    let mut memory = Memory::default();
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return memory;
    };
    for line in meminfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(kb) = value
            .split_whitespace()
            .next()
            .and_then(|field| field.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => memory.total = kb * 1024,
            "MemAvailable" => memory.available = kb * 1024,
            "MemFree" => memory.free = kb * 1024,
            "SwapTotal" => memory.swap_total = kb * 1024,
            "SwapFree" => memory.swap_free = kb * 1024,
            _ => {},
        }
    }
    memory
}

#[cfg(not(target_os = "linux"))]
fn read_memory() -> Memory {
    Memory::default()
}

#[cfg(target_os = "linux")]
fn read_load() -> (f64, f64, f64, u32) {
    let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") else {
        return (0.0, 0.0, 0.0, 0);
    };
    // 0.00 0.01 0.05 1/234 5678
    let fields: Vec<&str> = loadavg.split_whitespace().collect();
    let parse = |index: usize| {
        fields
            .get(index)
            .and_then(|field| field.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    let processes = fields
        .get(3)
        .and_then(|field| field.split('/').nth(1))
        .and_then(|total| total.parse::<u32>().ok())
        .unwrap_or(0);
    (parse(0), parse(1), parse(2), processes)
}

#[cfg(not(target_os = "linux"))]
fn read_load() -> (f64, f64, f64, u32) {
    (0.0, 0.0, 0.0, 0)
}

#[cfg(target_os = "linux")]
fn count_tcp_connections() -> u32 {
    let mut count = 0_u32;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(table) = std::fs::read_to_string(path) {
            count += table.lines().skip(1).count() as u32;
        }
    }
    count
}

#[cfg(not(target_os = "linux"))]
fn count_tcp_connections() -> u32 {
    0
}

#[cfg(target_os = "linux")]
fn read_uptime() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|uptime| {
            uptime
                .split_whitespace()
                .next()
                .and_then(|seconds| seconds.parse::<f64>().ok())
        })
        .unwrap_or_default() as u64
}

#[cfg(not(target_os = "linux"))]
fn read_uptime() -> u64 {
    0
}

/// Total and used bytes of the filesystem holding `path`.
fn disk_usage(path: &str) -> (u64, u64) {
    let output = match std::process::Command::new("df")
        .args(["-kP", path])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return (0, 0),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(line) = text.lines().nth(1) else {
        return (0, 0);
    };
    // Filesystem 1024-blocks Used Available Capacity Mounted on
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return (0, 0);
    }
    let total = fields[1].parse::<u64>().unwrap_or_default() * 1024;
    let used = fields[2].parse::<u64>().unwrap_or_default() * 1024;
    (total, used)
}

// ─────────────────────────────────────────────────────────────
// Buffer and background thread
// ─────────────────────────────────────────────────────────────

/// Rolling window of samples plus the host's current addresses.
///
/// Shared between the sampler thread and the heartbeat stream: the thread
/// pushes, the heartbeat drains. Nothing but the sampler touches it in
/// steady-state, so both locks are uncontended in practice.
#[derive(Debug, Default)]
pub struct ProbeBuffer {
    samples: Mutex<VecDeque<HostSample>>,
    addresses: RwLock<HostAddresses>,
}

impl ProbeBuffer {
    /// Classifies the host's addresses up front so registration can report them
    /// before the sampler has produced its first tick.
    pub fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            addresses: RwLock::new(classify_addresses()),
        }
    }

    pub fn push(&self, sample: HostSample) {
        let mut samples =
            self.samples.lock().unwrap_or_else(|e| e.into_inner());
        if samples.len() >= MAX_BUFFERED {
            samples.pop_front();
        }
        samples.push_back(sample);
    }

    /// Takes every buffered sample, oldest first.
    pub fn drain(&self) -> Vec<HostSample> {
        let mut samples =
            self.samples.lock().unwrap_or_else(|e| e.into_inner());
        samples.drain(..).collect()
    }

    /// Most recent sample, without removing it.
    pub fn latest(&self) -> Option<HostSample> {
        let samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        samples.back().cloned()
    }

    pub fn addresses(&self) -> HostAddresses {
        self.addresses
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_addresses(&self, addresses: HostAddresses) {
        *self.addresses.write().unwrap_or_else(|e| e.into_inner()) = addresses;
    }
}

/// Starts the sampler thread.
///
/// The thread stops when `shutdown` is set and is deliberately not joined: it
/// exists to feed the heartbeat, and a process that is exiting should not wait
/// out its sleep.
pub fn spawn(
    buffer: Arc<ProbeBuffer>,
    interval_secs: u64,
    disk_path: String,
    shutdown: Arc<AtomicBool>,
) {
    let interval = Duration::from_secs(interval_secs.max(1));
    let spawned = std::thread::Builder::new()
        .name("pingwaf-probe".to_string())
        .spawn(move || {
            let mut sampler = Sampler::new(disk_path);
            let mut refreshed: Option<Instant> = None;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                buffer.push(sampler.sample());
                if refreshed.is_none_or(|at| at.elapsed() >= ADDRESS_REFRESH) {
                    let addresses = classify_addresses();
                    debug!(
                        public_ip = %addresses.public_ip,
                        private_ip = %addresses.private_ip,
                        "host addresses refreshed"
                    );
                    buffer.set_addresses(addresses);
                    refreshed = Some(Instant::now());
                }
                std::thread::sleep(interval);
            }
        });
    if let Err(err) = spawned {
        debug!(error = %err, "could not start the probe thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn container_and_loopback_addresses_are_rejected() {
        // docker0, its veth peers and loopback must never be reported.
        assert_eq!(scope_of(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), None);
        assert_eq!(scope_of(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 4))), None);
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("br-9f2c1e"));
        assert!(is_virtual_interface("veth1a2b3c"));
        assert!(is_virtual_interface("cni0"));
        assert!(!is_virtual_interface("eth0"));
        assert!(!is_virtual_interface("ens5"));
    }

    #[test]
    fn addresses_are_split_into_public_and_private() {
        assert_eq!(
            scope_of(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some(Scope::Private)
        );
        assert_eq!(
            scope_of(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1))),
            Some(Scope::Private)
        );
        assert_eq!(
            scope_of(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            Some(Scope::Private)
        );
        assert_eq!(
            scope_of(IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1))),
            Some(Scope::Private)
        );
        assert_eq!(
            scope_of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            Some(Scope::Public)
        );
        assert_eq!(scope_of("fe80::1".parse().unwrap()), Some(Scope::Private));
        assert_eq!(scope_of("fd00::1".parse().unwrap()), Some(Scope::Private));
        assert_eq!(
            scope_of("2001:4860:4860::8888".parse().unwrap()),
            Some(Scope::Public)
        );
    }

    #[test]
    fn cpu_usage_is_the_delta_between_samples() {
        let previous = Counters {
            cpu_total: 1_000,
            cpu_idle: 800,
            ..Counters::default()
        };
        let current = Counters {
            cpu_total: 1_200,
            cpu_idle: 900,
            ..Counters::default()
        };
        // 200 jiffies elapsed, 100 of them idle => 50%.
        let percent = cpu_percent(&previous, &current).unwrap();
        assert!((percent - 50.0).abs() < 0.001, "got {percent}");

        assert_eq!(cpu_percent(&previous, &previous), None);
    }

    /// The first heartbeat after start has no baseline: it reports the
    /// since-boot average, never a missing value.
    #[test]
    fn first_cpu_sample_falls_back_to_the_since_boot_average() {
        assert_eq!(cpu_percent_since_boot((400, 1_000)), Some(40.0));
        // A machine that exposes no jiffies has no percentage to report.
        assert_eq!(cpu_percent_since_boot((0, 0)), None);
    }

    /// Two samples: the delta over the interval, not the since-boot average.
    #[test]
    fn consecutive_cpu_samples_are_the_interval_delta() {
        // 200 jiffies elapsed, 100 of them busy => 50 %, where the since-boot
        // average of the second reading would be 25 %.
        let percent = cpu_percent_between((200, 1_000), (300, 1_200)).unwrap();
        assert!((percent - 50.0).abs() < 0.001, "got {percent}");
        // An interval with no busy time is 0 %, not a missing value.
        assert_eq!(cpu_percent_between((200, 1_000), (200, 1_200)), Some(0.0));
        // A stalled counter (the same reading twice) has no interval at all.
        assert_eq!(cpu_percent_between((200, 1_000), (200, 1_000)), None);
    }

    /// A reboot, a wrap or a reset `/proc` moves the counters backwards: no
    /// subtraction may panic or wrap, and the fallback still answers.
    #[test]
    fn cpu_counters_that_restart_do_not_panic() {
        assert_eq!(cpu_percent_between((5_000, 6_000), (10, 20)), None);
        assert_eq!(cpu_percent_since_boot((10, 20)), Some(50.0));
        // A torn read (busy above total) clamps instead of reporting >100 %.
        assert_eq!(cpu_percent_between((0, 100), (200, 200)), Some(100.0));
    }

    /// The stateful wrapper the heartbeat uses: a value on the first call and a
    /// baseline kept for the next one. On a platform without `/proc/stat` it
    /// reports `None` — the heartbeat then keeps its own platform reading — and
    /// must not leave a bogus baseline behind.
    #[test]
    fn heartbeat_cpu_sampling_keeps_its_baseline() {
        let mut previous = None;
        match cpu_percent_since(&mut previous) {
            Some(first) => {
                assert!((0.0..=100.0).contains(&first), "got {first}");
                assert!(previous.is_some(), "the baseline is kept");
                let second =
                    cpu_percent_since(&mut previous).expect("interval delta");
                assert!((0.0..=100.0).contains(&second), "got {second}");
            },
            None => assert!(
                previous.is_none(),
                "no counters read means no baseline to keep"
            ),
        }
    }

    #[test]
    fn buffer_keeps_only_the_recent_window() {
        let buffer = ProbeBuffer::default();
        for index in 0..(MAX_BUFFERED + 5) {
            buffer.push(HostSample {
                ts_millis: index as i64,
                ..HostSample::default()
            });
        }
        let drained = buffer.drain();
        assert_eq!(drained.len(), MAX_BUFFERED);
        assert_eq!(drained.first().unwrap().ts_millis, 5);
        assert!(buffer.drain().is_empty());
    }
}

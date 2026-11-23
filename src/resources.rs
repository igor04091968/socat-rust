use serde::Deserialize;

const DEFAULT_RESERVED_FDS: usize = 32;
const DEFAULT_RESERVED_MEMORY: u64 = 64 * 1024 * 1024;
const DEFAULT_MEMORY_PER_CONNECTION: u64 = 1024 * 1024;
const DEFAULT_CPU_PRESSURE_HIGH_PERCENT: u8 = 20;

fn default_reserved_fds() -> usize {
    DEFAULT_RESERVED_FDS
}
fn default_reserved_memory() -> u64 {
    DEFAULT_RESERVED_MEMORY
}
fn default_memory_per_connection() -> u64 {
    DEFAULT_MEMORY_PER_CONNECTION
}
fn default_cpu_pressure_high_percent() -> u8 {
    DEFAULT_CPU_PRESSURE_HIGH_PERCENT
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_reserved_fds")]
    pub reserve_fds: usize,
    #[serde(default = "default_reserved_memory")]
    pub reserve_memory_bytes: u64,
    #[serde(default = "default_memory_per_connection")]
    pub memory_per_connection_bytes: u64,
    #[serde(default = "default_cpu_pressure_high_percent")]
    pub cpu_pressure_high_percent: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reserve_fds: DEFAULT_RESERVED_FDS,
            reserve_memory_bytes: DEFAULT_RESERVED_MEMORY,
            memory_per_connection_bytes: DEFAULT_MEMORY_PER_CONNECTION,
            cpu_pressure_high_percent: DEFAULT_CPU_PRESSURE_HIGH_PERCENT,
        }
    }
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.reserve_fds >= 4,
            "resources.reserve_fds должен быть не меньше 4"
        );
        anyhow::ensure!(
            (1024 * 1024..=1024 * 1024 * 1024).contains(&self.memory_per_connection_bytes),
            "resources.memory_per_connection_bytes должен быть 1 МиБ..1 ГиБ"
        );
        anyhow::ensure!(
            self.cpu_pressure_high_percent <= 100,
            "resources.cpu_pressure_high_percent должен быть 0..=100"
        );
        anyhow::ensure!(
            self.reserve_memory_bytes <= 1024_u64.pow(4),
            "resources.reserve_memory_bytes не должен превышать 1 ТиБ"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub fd_connections: usize,
    pub memory_connections: Option<usize>,
    pub effective_connections: usize,
}

pub fn snapshot(configured_max: usize, active_connections: usize, config: &Config) -> Snapshot {
    let fd_connections = fd_connection_capacity(config.reserve_fds, active_connections);
    let memory_connections = available_memory().map(|available| {
        memory_connection_capacity(
            available,
            config.reserve_memory_bytes,
            config.memory_per_connection_bytes,
            active_connections,
        )
    });
    let effective_connections =
        compute_effective(configured_max, fd_connections, memory_connections);
    Snapshot {
        fd_connections,
        memory_connections,
        effective_connections,
    }
}

pub fn compute_effective(
    configured_max: usize,
    fd_connections: usize,
    memory_connections: Option<usize>,
) -> usize {
    configured_max
        .min(fd_connections)
        .min(memory_connections.unwrap_or(usize::MAX))
}

pub fn runtime_workers(configured: usize) -> usize {
    if configured != 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, 2)
}

#[derive(Debug, Default)]
pub struct CpuPressureController {
    cap: Option<usize>,
    high_samples: u8,
    low_samples: u8,
    unknown_samples: u8,
}

impl CpuPressureController {
    pub fn apply(
        &mut self,
        base_cap: usize,
        pressure_percent: Option<f64>,
        high_percent: u8,
    ) -> usize {
        if high_percent == 0 {
            self.cap = Some(base_cap);
            self.high_samples = 0;
            self.low_samples = 0;
            self.unknown_samples = 0;
            return base_cap;
        }
        let mut cap = self.cap.unwrap_or(base_cap).min(base_cap);
        if base_cap == 0 {
            self.cap = Some(0);
            return 0;
        }
        match pressure_percent {
            Some(value) if value >= f64::from(high_percent) => {
                self.unknown_samples = 0;
                self.high_samples = self.high_samples.saturating_add(1);
                self.low_samples = 0;
                if self.high_samples >= 3 {
                    cap = cap.saturating_sub((cap / 4).max(1)).max(1);
                    self.high_samples = 0;
                }
            }
            Some(value) if value < f64::from(high_percent) * 0.5 => {
                self.unknown_samples = 0;
                self.low_samples = self.low_samples.saturating_add(1);
                self.high_samples = 0;
                if self.low_samples >= 5 {
                    cap = cap.saturating_add((base_cap / 8).max(1)).min(base_cap);
                    self.low_samples = 0;
                }
            }
            Some(_) => {
                self.unknown_samples = 0;
                self.high_samples = 0;
                self.low_samples = 0;
            }
            None => {
                self.high_samples = 0;
                self.low_samples = 0;
                self.unknown_samples = self.unknown_samples.saturating_add(1);
                if self.unknown_samples >= 30 {
                    cap = cap.saturating_add((base_cap / 8).max(1)).min(base_cap);
                    self.unknown_samples = 0;
                }
            }
        }
        self.cap = Some(cap);
        cap
    }
}

pub fn cpu_pressure_percent() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let groups = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        for line in groups.lines() {
            if let Some(path) = line.strip_prefix("0::") {
                let root = std::path::Path::new("/sys/fs/cgroup");
                let dir = root.join(path.trim_start_matches('/'));
                if let Some(value) = pressure_percent_in_ancestors(&dir, root, "cpu.pressure") {
                    return Some(value);
                }
            }
        }
        pressure_percent_file(std::path::Path::new("/proc/pressure/cpu"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn pressure_percent_in_ancestors(
    dir: &std::path::Path,
    root: &std::path::Path,
    file: &str,
) -> Option<f64> {
    if !dir.starts_with(root) {
        return None;
    }
    let mut current = dir;
    loop {
        if let Some(value) = pressure_percent_file(&current.join(file)) {
            return Some(value);
        }
        if current == root {
            break;
        }
        current = current.parent()?;
    }
    None
}

#[cfg(target_os = "linux")]
fn pressure_percent_file(path: &std::path::Path) -> Option<f64> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_pressure_percent(&text)
}

fn parse_pressure_percent(text: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        if !line.starts_with("some ") {
            return None;
        }
        line.split_whitespace()
            .find_map(|field| field.strip_prefix("avg10=")?.parse::<f64>().ok())
    })
}

#[cfg(unix)]
fn fd_connection_capacity(reserve_fds: usize, active_connections: usize) -> usize {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return 1;
    }
    let limit = unsafe { limit.assume_init() }.rlim_cur;
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let open = open_fd_count().unwrap_or(0);
    fd_connection_capacity_from_counts(limit, open, reserve_fds, active_connections)
}

fn fd_connection_capacity_from_counts(
    limit: usize,
    open: usize,
    reserve_fds: usize,
    active_connections: usize,
) -> usize {
    active_connections.saturating_add(limit.saturating_sub(open.saturating_add(reserve_fds)) / 2)
}

fn memory_connection_capacity(
    available: u64,
    reserve_memory: u64,
    bytes_per_connection: u64,
    active_connections: usize,
) -> usize {
    let additional = available
        .saturating_sub(reserve_memory)
        .checked_div(bytes_per_connection)
        .unwrap_or(0)
        .min(usize::MAX as u64) as usize;
    active_connections.saturating_add(additional)
}

#[cfg(not(unix))]
fn fd_connection_capacity(_reserve_fds: usize, _active_connections: usize) -> usize {
    usize::MAX
}

#[cfg(target_os = "linux")]
fn open_fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count())
}

#[cfg(not(target_os = "linux"))]
fn open_fd_count() -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn available_memory() -> Option<u64> {
    let host = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let rest = line.strip_prefix("MemAvailable:")?;
                rest.split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .map(|kib| kib.saturating_mul(1024))
            })
        });
    host.into_iter().chain(cgroup_available_memory()).min()
}

#[cfg(not(target_os = "linux"))]
fn available_memory() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_available_memory() -> Option<u64> {
    let groups = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mut minimum = None;
    for line in groups.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let root = std::path::Path::new("/sys/fs/cgroup");
            let dir = root.join(path.trim_start_matches('/'));
            minimum = min_optional(
                minimum,
                cgroup_path_available(&dir, root, "memory.max", "memory.current"),
            );
        }
        let mut fields = line.splitn(3, ':');
        let (Some(_hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if controllers.split(',').any(|name| name == "memory") {
            let root = std::path::Path::new("/sys/fs/cgroup/memory");
            let dir = root.join(path.trim_start_matches('/'));
            minimum = min_optional(
                minimum,
                cgroup_path_available(&dir, root, "memory.limit_in_bytes", "memory.usage_in_bytes"),
            );
        }
    }
    minimum
}

#[cfg(target_os = "linux")]
fn cgroup_path_available(
    dir: &std::path::Path,
    root: &std::path::Path,
    limit_file: &str,
    current_file: &str,
) -> Option<u64> {
    if !dir.starts_with(root) {
        return None;
    }
    let mut current_dir = dir;
    let mut minimum = None;
    loop {
        minimum = min_optional(
            minimum,
            read_limit_current(
                &current_dir.join(limit_file),
                &current_dir.join(current_file),
            ),
        );
        if current_dir == root {
            break;
        }
        current_dir = current_dir.parent()?;
    }
    minimum
}

fn min_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
fn read_limit_current(limit_path: &std::path::Path, current_path: &std::path::Path) -> Option<u64> {
    let limit = std::fs::read_to_string(limit_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    if limit >= i64::MAX as u64 {
        return None;
    }
    let current = std::fs::read_to_string(current_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(limit.saturating_sub(current))
}

#[cfg(test)]
mod tests {
    use super::{
        CpuPressureController, compute_effective, fd_connection_capacity_from_counts,
        memory_connection_capacity, parse_pressure_percent, runtime_workers,
    };

    #[test]
    fn configured_limit_is_always_a_hard_ceiling() {
        assert_eq!(compute_effective(100, 80, Some(60)), 60);
        assert_eq!(compute_effective(10, 80, Some(60)), 10);
    }

    #[test]
    fn unknown_memory_limit_does_not_disable_fd_protection() {
        assert_eq!(compute_effective(100, 24, None), 24);
    }

    #[test]
    fn active_sessions_are_counted_in_total_fd_and_memory_capacity() {
        assert_eq!(fd_connection_capacity_from_counts(48, 34, 8, 14), 17);
        assert_eq!(memory_connection_capacity(20, 4, 1, 14), 30);
    }

    #[test]
    fn worker_override_is_respected_and_auto_is_bounded() {
        assert_eq!(runtime_workers(3), 3);
        assert!((1..=2).contains(&runtime_workers(0)));
    }

    #[test]
    fn cpu_pressure_reduces_only_after_three_high_samples_and_recovers_slowly() {
        let mut controller = CpuPressureController::default();
        assert_eq!(controller.apply(16, Some(40.0), 20), 16);
        assert_eq!(controller.apply(16, Some(40.0), 20), 16);
        assert_eq!(controller.apply(16, Some(40.0), 20), 12);
        for _ in 0..4 {
            controller.apply(16, Some(2.0), 20);
        }
        assert_eq!(controller.apply(16, Some(2.0), 20), 14);
    }

    #[test]
    fn cpu_pressure_parser_uses_some_avg10_and_disable_flag_restores_base() {
        assert_eq!(
            parse_pressure_percent("some avg10=23.50 avg60=1.20 total=12\nfull avg10=99.00"),
            Some(23.5)
        );
        assert_eq!(parse_pressure_percent("full avg10=90.00"), None);
        let mut controller = CpuPressureController::default();
        for _ in 0..3 {
            controller.apply(8, Some(40.0), 20);
        }
        assert_eq!(controller.apply(8, Some(40.0), 0), 8);
    }

    #[test]
    fn cpu_pressure_unknown_does_not_change_capacity() {
        let mut controller = CpuPressureController::default();
        assert_eq!(controller.apply(8, None, 20), 8);
        assert_eq!(controller.apply(8, None, 20), 8);
        for _ in 0..3 {
            controller.apply(8, Some(40.0), 20);
        }
        assert_eq!(controller.apply(8, None, 20), 6);
        for _ in 0..29 {
            controller.apply(8, None, 20);
        }
        assert_eq!(controller.apply(8, None, 20), 7);
    }

    #[test]
    fn zero_headroom_pauses_new_connections() {
        assert_eq!(compute_effective(100, 24, Some(0)), 0);
    }
}

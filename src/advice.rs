//! Passive, bounded observations. Never changes sockets, TLS policy or application data.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tracing::info;

const CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Off,
    Recommend,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub period_seconds: u64,
    pub min_samples: usize,
    pub timeout_min_seconds: u64,
    pub timeout_max_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            period_seconds: 900,
            min_samples: 20,
            timeout_min_seconds: 3,
            timeout_max_seconds: 30,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=86400).contains(&self.period_seconds),
            "advice.period_seconds must be 1..86400"
        );
        ensure!(
            (1..=CAPACITY).contains(&self.min_samples),
            "advice.min_samples must be 1..512"
        );
        ensure!(
            self.timeout_min_seconds > 0
                && self.timeout_min_seconds <= self.timeout_max_seconds
                && self.timeout_max_seconds <= 120,
            "advice timeout bounds must satisfy 1 <= min <= max <= 120 seconds"
        );
        #[cfg(feature = "legacy-kernel")]
        ensure!(
            self.mode == Mode::Off,
            "connection advice requires the modern runtime"
        );
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Window {
    tcp_ms: VecDeque<u64>,
    tls_ms: VecDeque<u64>,
    tcp_ok: u64,
    tcp_errors: u64,
    tcp_timeouts: u64,
    tls_ok: u64,
    tls_errors: u64,
    sessions_ok: u64,
    sessions_errors: u64,
}

pub struct Monitor {
    config: Config,
    window: Mutex<Window>,
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    tcp_ok: u64,
    tcp_errors: u64,
    tcp_timeouts: u64,
    tls_ok: u64,
    tls_errors: u64,
    sessions_ok: u64,
    sessions_errors: u64,
    tcp_samples: usize,
    tls_samples: usize,
    tcp_p95_ms: Option<u64>,
    tls_p95_ms: Option<u64>,
    suggested_timeout_seconds: Option<u64>,
    degraded: bool,
}

fn millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u64::MAX as u128) as u64
}

fn sample(samples: &mut VecDeque<u64>, value: u64) {
    if samples.len() == CAPACITY {
        samples.pop_front();
    }
    samples.push_back(value);
}

fn p95(samples: &VecDeque<u64>) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut values: Vec<_> = samples.iter().copied().collect();
    values.sort_unstable();
    Some(values[(95 * values.len()).div_ceil(100) - 1])
}

impl Monitor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            window: Mutex::new(Window::default()),
        }
    }

    pub fn tcp(&self, elapsed: Duration, success: bool, timed_out: bool) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            w.tcp_ok = w.tcp_ok.saturating_add(1);
            sample(&mut w.tcp_ms, millis(elapsed));
        } else {
            w.tcp_errors = w.tcp_errors.saturating_add(1);
            if timed_out {
                w.tcp_timeouts = w.tcp_timeouts.saturating_add(1);
            }
        }
    }

    pub fn tls(&self, elapsed: Duration, success: bool) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            w.tls_ok = w.tls_ok.saturating_add(1);
            sample(&mut w.tls_ms, millis(elapsed));
        } else {
            w.tls_errors = w.tls_errors.saturating_add(1);
        }
    }

    pub fn session(&self, success: bool) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            w.sessions_ok = w.sessions_ok.saturating_add(1);
        } else {
            w.sessions_errors = w.sessions_errors.saturating_add(1);
        }
    }

    fn take_summary(&self) -> Summary {
        let w = std::mem::take(&mut *self.window.lock().unwrap_or_else(|e| e.into_inner()));
        let tcp_p95_ms = p95(&w.tcp_ms);
        let tcp_total = w.tcp_ok.saturating_add(w.tcp_errors);
        let tls_total = w.tls_ok.saturating_add(w.tls_errors);
        let degraded = (tcp_total >= self.config.min_samples as u64
            && w.tcp_errors as f64 / tcp_total as f64 >= 0.2)
            || (tls_total >= self.config.min_samples as u64
                && w.tls_errors as f64 / tls_total as f64 >= 0.2);
        let suggested_timeout_seconds =
            if w.tcp_ms.len() >= self.config.min_samples && w.tcp_timeouts == 0 && !degraded {
                // Four times successful TCP p95 plus 1s; never a TLS or transaction timeout.
                Some(
                    tcp_p95_ms
                        .unwrap()
                        .saturating_mul(4)
                        .saturating_add(1000)
                        .div_ceil(1000)
                        .clamp(
                            self.config.timeout_min_seconds,
                            self.config.timeout_max_seconds,
                        ),
                )
            } else {
                None
            };
        Summary {
            tcp_ok: w.tcp_ok,
            tcp_errors: w.tcp_errors,
            tcp_timeouts: w.tcp_timeouts,
            tls_ok: w.tls_ok,
            tls_errors: w.tls_errors,
            sessions_ok: w.sessions_ok,
            sessions_errors: w.sessions_errors,
            tcp_samples: w.tcp_ms.len(),
            tls_samples: w.tls_ms.len(),
            tcp_p95_ms,
            tls_p95_ms: p95(&w.tls_ms),
            suggested_timeout_seconds,
            degraded,
        }
    }

    pub fn report(&self, relay: &str, configured_timeout_seconds: u64) {
        if self.config.mode == Mode::Off {
            return;
        }
        let s = self.take_summary();
        info!(relay, period_seconds = self.config.period_seconds,
            tcp_ok = s.tcp_ok, tcp_errors = s.tcp_errors, tcp_timeouts = s.tcp_timeouts,
            tls_ok = s.tls_ok, tls_errors = s.tls_errors,
            sessions_ok = s.sessions_ok, sessions_errors = s.sessions_errors,
            tcp_samples = s.tcp_samples, tls_samples = s.tls_samples,
            tcp_p95_ms = ?s.tcp_p95_ms, tls_p95_ms = ?s.tls_p95_ms,
            configured_timeout_seconds, suggested_timeout_seconds = ?s.suggested_timeout_seconds,
            degraded = s.degraded, applied = false,
            "connection_advice: passive window; TCP timeout recommendation only");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn monitor() -> Monitor {
        Monitor::new(Config {
            mode: Mode::Recommend,
            min_samples: 5,
            ..Config::default()
        })
    }
    #[test]
    fn disabled_does_not_collect() {
        let m = Monitor::new(Config::default());
        m.tcp(Duration::from_secs(1), true, false);
        m.tls(Duration::ZERO, false);
        m.session(false);
        assert_eq!(m.take_summary().tcp_ok, 0);
        assert_eq!(m.take_summary().sessions_errors, 0);
    }
    #[test]
    fn bounds_samples_and_resets_window() {
        let m = monitor();
        for _ in 0..10000 {
            m.tcp(Duration::from_millis(100), true, false);
        }
        let s = m.take_summary();
        assert_eq!(s.tcp_ok, 10000);
        assert_eq!(s.tcp_samples, CAPACITY);
        assert_eq!(s.suggested_timeout_seconds, Some(3));
        assert_eq!(m.take_summary().suggested_timeout_seconds, None);
    }
    #[test]
    fn insufficient_data_and_failed_attempts_are_not_latency_samples() {
        let m = monitor();
        for _ in 0..5 {
            m.tcp(Duration::from_secs(10), false, true);
        }
        m.tcp(Duration::from_millis(10), true, false);
        let s = m.take_summary();
        assert_eq!(s.suggested_timeout_seconds, None);
        assert_eq!(s.tcp_timeouts, 5);
        assert_eq!(s.tcp_p95_ms, Some(10));
        assert!(s.degraded);
    }
    #[test]
    fn percentile_ceiling_clamp_and_tls_separation() {
        let m = monitor();
        for x in 1..=20 {
            m.tcp(Duration::from_millis(x * 1000), true, false);
        }
        m.tls(Duration::from_secs(99), true);
        m.tls(Duration::ZERO, false);
        m.session(true);
        m.session(false);
        let s = m.take_summary();
        assert_eq!(s.tcp_p95_ms, Some(19000));
        assert_eq!(s.suggested_timeout_seconds, Some(30));
        assert_eq!(s.tls_p95_ms, Some(99000));
        assert_eq!((s.sessions_ok, s.sessions_errors), (1, 1));
    }
    #[test]
    fn timeout_suppresses_advice_even_with_enough_successes() {
        let m = monitor();
        for _ in 0..20 {
            m.tcp(Duration::from_millis(10), true, false);
        }
        m.tcp(Duration::from_secs(10), false, true);
        let s = m.take_summary();
        assert!(!s.degraded);
        assert_eq!(s.suggested_timeout_seconds, None);
    }

    #[test]
    fn concurrent_observers_do_not_lose_counts() {
        let m = std::sync::Arc::new(monitor());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        m.tcp(Duration::from_millis(1), true, false);
                        m.tls(Duration::from_millis(2), true);
                        m.session(true);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let s = m.take_summary();
        assert_eq!((s.tcp_ok, s.tls_ok, s.sessions_ok), (4000, 4000, 4000));
        assert_eq!((s.tcp_samples, s.tls_samples), (CAPACITY, CAPACITY));
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        let mut c = Config::default();
        c.period_seconds = 0;
        assert!(c.validate().is_err());
        c.period_seconds = 900;
        c.min_samples = 513;
        assert!(c.validate().is_err());
        c.min_samples = 20;
        c.timeout_min_seconds = 31;
        assert!(c.validate().is_err());
        c.timeout_min_seconds = 3;
        assert!(c.validate().is_ok());
        assert!(toml::from_str::<Config>("mode = 'auto'").is_err());
        assert!(toml::from_str::<Config>("unknown = 1").is_err());
    }
}

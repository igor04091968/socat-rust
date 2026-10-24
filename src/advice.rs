//! Bounded observations and opt-in TCP connect timeout control. Never changes TLS policy or application data.
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
    Auto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub period_seconds: u64,
    pub min_samples: usize,
    pub timeout_min_seconds: u64,
    pub timeout_max_seconds: u64,
    pub stable_windows: u32,
    pub cooldown_windows: u32,
    pub max_step_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            period_seconds: 900,
            min_samples: 20,
            timeout_min_seconds: 3,
            timeout_max_seconds: 30,
            stable_windows: 3,
            cooldown_windows: 3,
            max_step_seconds: 2,
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
        ensure!(
            (1..=24).contains(&self.stable_windows),
            "advice.stable_windows must be 1..24"
        );
        ensure!(
            (1..=96).contains(&self.cooldown_windows),
            "advice.cooldown_windows must be 1..96"
        );
        ensure!(
            (1..=120).contains(&self.max_step_seconds),
            "advice.max_step_seconds must be 1..120"
        );
        #[cfg(feature = "legacy-kernel")]
        ensure!(
            self.mode == Mode::Off,
            "connection advice requires the modern runtime"
        );
        Ok(())
    }

    pub fn validate_initial_timeout(&self, initial: u64) -> Result<()> {
        if self.mode == Mode::Auto {
            ensure!(
                (self.timeout_min_seconds..=self.timeout_max_seconds).contains(&initial),
                "auto mode requires configured TCP connect timeout within advice min/max bounds"
            );
        }
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
    current_timeouts: u64,
    current_tcp_ok: u64,
    current_tcp_errors: u64,
    current_tls_ok: u64,
    current_tls_errors: u64,
    mixed_generation: bool,
    tls_ok: u64,
    tls_errors: u64,
    sessions_ok: u64,
    sessions_errors: u64,
}

struct State {
    window: Window,
    baseline: u64,
    effective: u64,
    generation: u64,
    stable: u32,
    cooldown: u32,
}

pub struct Monitor {
    config: Config,
    state: Mutex<State>,
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
    effective_timeout_seconds: u64,
    previous_timeout_seconds: u64,
    generation: u64,
    stable_windows: u32,
    cooldown_windows: u32,
    mixed_generation: bool,
    action: &'static str,
    applied: bool,
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
    #[cfg(test)]
    pub fn new(config: Config) -> Self {
        Self::with_timeout(config, 10)
    }

    pub fn with_timeout(config: Config, baseline: u64) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                window: Window::default(),
                baseline,
                effective: baseline,
                generation: 0,
                stable: 0,
                cooldown: 0,
            }),
        }
    }

    /// One immutable snapshot per attempt. An in-flight attempt keeps its deadline.
    pub fn timeout_policy(&self) -> (u64, u64) {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (s.effective, s.generation)
    }

    #[cfg(test)]
    pub fn tcp(&self, elapsed: Duration, success: bool, timed_out: bool) {
        self.tcp_attempt(elapsed, success, timed_out, self.timeout_policy().1);
    }

    pub fn tcp_attempt(&self, elapsed: Duration, success: bool, timed_out: bool, generation: u64) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = generation == s.generation;
        let w = &mut s.window;
        w.mixed_generation |= !current;
        if success {
            w.tcp_ok = w.tcp_ok.saturating_add(1);
            if current {
                w.current_tcp_ok = w.current_tcp_ok.saturating_add(1);
            }
            sample(&mut w.tcp_ms, millis(elapsed));
        } else {
            w.tcp_errors = w.tcp_errors.saturating_add(1);
            if current {
                w.current_tcp_errors = w.current_tcp_errors.saturating_add(1);
            }
            if timed_out {
                w.tcp_timeouts = w.tcp_timeouts.saturating_add(1);
                if current {
                    w.current_timeouts = w.current_timeouts.saturating_add(1);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn tls(&self, elapsed: Duration, success: bool) {
        self.tls_attempt(elapsed, success, self.timeout_policy().1);
    }

    #[cfg(any(feature = "tls", test))]
    pub fn tls_attempt(&self, elapsed: Duration, success: bool, generation: u64) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = generation == s.generation;
        let w = &mut s.window;
        w.mixed_generation |= !current;
        if success {
            w.tls_ok = w.tls_ok.saturating_add(1);
            if current {
                w.current_tls_ok = w.current_tls_ok.saturating_add(1);
            }
            sample(&mut w.tls_ms, millis(elapsed));
        } else {
            w.tls_errors = w.tls_errors.saturating_add(1);
            if current {
                w.current_tls_errors = w.current_tls_errors.saturating_add(1);
            }
        }
    }

    pub fn session(&self, success: bool) {
        if self.config.mode == Mode::Off {
            return;
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let w = &mut s.window;
        if success {
            w.sessions_ok = w.sessions_ok.saturating_add(1);
        } else {
            w.sessions_errors = w.sessions_errors.saturating_add(1);
        }
    }

    fn take_summary(&self) -> Summary {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let w = std::mem::take(&mut state.window);
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
        let previous = state.effective;
        let mut action = "observe";
        if self.config.mode == Mode::Auto {
            // Old in-flight completions must not hide degradation of the current policy.
            let current_tcp_total = w.current_tcp_ok.saturating_add(w.current_tcp_errors);
            let current_tls_total = w.current_tls_ok.saturating_add(w.current_tls_errors);
            let bad = w.current_timeouts > 0
                || (current_tcp_total >= self.config.min_samples as u64
                    && w.current_tcp_errors as f64 / current_tcp_total as f64 >= 0.2)
                || (current_tls_total >= self.config.min_samples as u64
                    && w.current_tls_errors as f64 / current_tls_total as f64 >= 0.2);
            if bad {
                state.effective = state.baseline;
                state.stable = 0;
                state.cooldown = self.config.cooldown_windows;
                action = if previous != state.baseline {
                    "rollback"
                } else {
                    "degraded"
                };
            } else if state.cooldown > 0 {
                state.cooldown -= 1;
                state.stable = 0;
                action = "cooldown";
            } else if !w.mixed_generation
                && w.tcp_errors == 0
                && w.tls_errors == 0
                && w.sessions_errors == 0
            {
                if let Some(candidate) = suggested_timeout_seconds {
                    state.stable = state.stable.saturating_add(1);
                    action = "collect";
                    if state.stable >= self.config.stable_windows {
                        state.effective = if candidate > previous {
                            candidate.min(previous.saturating_add(self.config.max_step_seconds))
                        } else {
                            candidate.max(previous.saturating_sub(self.config.max_step_seconds))
                        }
                        .clamp(
                            self.config.timeout_min_seconds,
                            self.config.timeout_max_seconds,
                        );
                        state.stable = 0;
                        action = if state.effective == previous {
                            "hold"
                        } else {
                            "apply"
                        };
                    }
                } else {
                    state.stable = 0;
                    action = "insufficient_data";
                }
            } else {
                state.stable = 0;
                action = "mixed_or_errors";
            }
        }
        let applied = state.effective != previous;
        if applied {
            state.generation = state.generation.saturating_add(1);
        }
        Summary {
            effective_timeout_seconds: state.effective,
            previous_timeout_seconds: previous,
            generation: state.generation,
            stable_windows: state.stable,
            cooldown_windows: state.cooldown,
            mixed_generation: w.mixed_generation,
            action,
            applied,
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
            degraded = s.degraded, applied = s.applied, action = %s.action,
            effective_timeout_seconds = s.effective_timeout_seconds,
            previous_timeout_seconds = s.previous_timeout_seconds,
            policy_generation = s.generation, stable_windows = s.stable_windows,
            cooldown_windows = s.cooldown_windows, mixed_generation = s.mixed_generation,
            "connection_advice: TCP connect timeout policy; no TLS changes");
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

    fn auto_monitor() -> Monitor {
        Monitor::with_timeout(
            Config {
                mode: Mode::Auto,
                min_samples: 5,
                ..Config::default()
            },
            10,
        )
    }
    fn healthy_window(m: &Monitor, millis: u64) -> Summary {
        for _ in 0..5 {
            m.tcp(Duration::from_millis(millis), true, false);
        }
        m.take_summary()
    }
    #[test]
    fn auto_waits_for_clean_windows_and_limits_step_both_ways() {
        let m = auto_monitor();
        assert!(!healthy_window(&m, 10).applied);
        assert!(!healthy_window(&m, 10).applied);
        let s = healthy_window(&m, 10);
        assert_eq!(
            (s.action, s.effective_timeout_seconds, s.generation),
            ("apply", 8, 1)
        );
        assert_eq!(m.timeout_policy(), (8, 1));
        for _ in 0..2 {
            healthy_window(&m, 3000);
        }
        assert_eq!(healthy_window(&m, 3000).effective_timeout_seconds, 10);
    }
    #[test]
    fn timeout_rolls_back_and_requires_cooldown_plus_new_windows() {
        let m = auto_monitor();
        for _ in 0..3 {
            healthy_window(&m, 10);
        }
        m.tcp(Duration::from_secs(8), false, true);
        let s = m.take_summary();
        assert_eq!((s.action, s.effective_timeout_seconds), ("rollback", 10));
        for _ in 0..3 {
            assert_eq!(healthy_window(&m, 10).action, "cooldown");
        }
        for _ in 0..2 {
            assert!(!healthy_window(&m, 10).applied);
        }
        assert_eq!(healthy_window(&m, 10).effective_timeout_seconds, 8);
    }
    #[test]
    fn insufficient_or_error_window_interrupts_stability() {
        let m = auto_monitor();
        healthy_window(&m, 10);
        healthy_window(&m, 10);
        assert_eq!(m.take_summary().action, "insufficient_data");
        assert!(!healthy_window(&m, 10).applied);
        m.tcp(Duration::ZERO, false, false);
        assert_eq!(m.take_summary().action, "mixed_or_errors");
        assert!(!healthy_window(&m, 10).applied);
    }
    #[test]
    fn stale_attempts_do_not_change_current_policy_or_trigger_false_rollback() {
        let m = auto_monitor();
        let old = m.timeout_policy();
        for _ in 0..3 {
            healthy_window(&m, 10);
        }
        assert_eq!(old, (10, 0));
        assert_eq!(m.timeout_policy(), (8, 1));
        m.tcp_attempt(Duration::from_secs(10), false, true, old.1);
        let s = m.take_summary();
        assert!(s.mixed_generation);
        assert!(!s.applied);
        assert_eq!(s.effective_timeout_seconds, 8);
        // An actual current timeout still rolls back even if old completions share the window.
        m.tcp_attempt(Duration::from_millis(1), true, false, old.1);
        m.tcp(Duration::from_secs(8), false, true);
        assert_eq!(m.take_summary().action, "rollback");
    }
    #[test]
    fn degraded_tls_rolls_back_without_changing_crypto() {
        let m = auto_monitor();
        for _ in 0..3 {
            healthy_window(&m, 10);
        }
        m.tls_attempt(Duration::ZERO, true, 0); // old handshake in the same window
        for _ in 0..5 {
            m.tls(Duration::ZERO, false);
        }
        assert_eq!(m.take_summary().action, "rollback");
        assert_eq!(m.timeout_policy().0, 10);
    }
    #[test]
    fn recommend_and_off_never_apply_even_after_many_windows() {
        let m = monitor();
        for _ in 0..10 {
            assert!(!healthy_window(&m, 10).applied);
        }
        assert_eq!(m.timeout_policy(), (10, 0));
        let off = Monitor::with_timeout(Config::default(), 7);
        assert!(!healthy_window(&off, 10).applied);
        assert_eq!(off.timeout_policy(), (7, 0));
    }
    #[test]
    fn auto_bounds_and_startup_validation() {
        let mut c = Config {
            mode: Mode::Auto,
            ..Config::default()
        };
        assert!(c.validate_initial_timeout(121).is_err());
        assert!(c.validate_initial_timeout(10).is_ok());
        c.stable_windows = 0;
        assert!(c.validate().is_err());
        c.stable_windows = 3;
        c.cooldown_windows = 0;
        assert!(c.validate().is_err());
        c.cooldown_windows = 3;
        c.max_step_seconds = 0;
        assert!(c.validate().is_err());
        c.max_step_seconds = 2;
        assert_eq!(c.validate().is_ok(), !cfg!(feature = "legacy-kernel"));
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
        assert!(toml::from_str::<Config>("mode = 'automatic'").is_err());
        assert!(toml::from_str::<Config>("unknown = 1").is_err());
    }
}

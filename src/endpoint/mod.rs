//! Выбор endpoint: TCP upstream, дочерний процесс или PTY.
//!
//! TCP остаётся поведением по умолчанию. Процесс задаётся явно и без
//! неявного shell: администратор указывает исполняемый файл и аргументы.
use anyhow::{Result, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

use crate::{RelayConfig, advice, session::Session, transport};

pub mod exec;
#[cfg(unix)]
pub mod pty;
pub mod tcp;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Tcp,
    Exec,
    Pty,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Exec => "exec",
            Self::Pty => "pty",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stderr {
    /// В журнал relay (метаданные без содержимого консоли).
    #[default]
    Log,
    /// Клиенту в тот же поток, что и stdout.
    Client,
    /// Отбросить.
    Discard,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_columns")]
    pub columns: u16,
    #[serde(default = "default_term")]
    pub term: String,
}

impl Default for Terminal {
    fn default() -> Self {
        Self {
            rows: default_rows(),
            columns: default_columns(),
            term: default_term(),
        }
    }
}

fn default_rows() -> u16 {
    24
}

fn default_columns() -> u16 {
    80
}

fn default_term() -> String {
    "xterm-256color".to_owned()
}

fn default_start_timeout_seconds() -> u64 {
    10
}

fn default_terminate_grace_seconds() -> u64 {
    5
}

/// Описание запускаемого процесса. Окружение не наследуется: дочерний
/// процесс получает только перечисленные переменные и PATH по умолчанию.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub stderr: Stderr,
    #[serde(default = "default_start_timeout_seconds")]
    pub start_timeout_seconds: u64,
    /// 0 — без ограничения простоя.
    #[serde(default)]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_terminate_grace_seconds")]
    pub terminate_grace_seconds: u64,
    /// 0 — без ограничения длительности сессии.
    #[serde(default)]
    pub max_duration_seconds: u64,
    /// RLIMIT_NPROC для выделенного UID; 0 — без ограничения.
    #[serde(default)]
    pub max_processes: u64,
    /// Допустимо только для endpoint = pty; по умолчанию 24x80/xterm-256color.
    #[serde(default)]
    pub terminal: Option<Terminal>,
}

impl Process {
    pub fn validate(&self, kind: Kind) -> Result<()> {
        if !self.command.is_absolute() {
            bail!(
                "process.command должен быть абсолютным путём: {}",
                self.command.display()
            );
        }
        if self.command.as_os_str().is_empty() {
            bail!("process.command не должен быть пустым");
        }
        for argument in &self.args {
            if argument.contains('\0') {
                bail!("аргумент процесса содержит NUL: {argument:?}");
            }
        }
        if let Some(directory) = &self.working_directory
            && !directory.is_absolute()
        {
            bail!(
                "process.working_directory должен быть абсолютным путём: {}",
                directory.display()
            );
        }
        for (key, value) in &self.environment {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                bail!("неверное имя переменной окружения процесса: {key:?}");
            }
            if value.contains('\0') {
                bail!("значение переменной окружения {key} содержит NUL");
            }
        }
        if kind == Kind::Pty
            && self
                .environment
                .get("TERM")
                .is_some_and(|term| term != &self.terminal.clone().unwrap_or_default().term)
        {
            bail!("process.environment.TERM должен совпадать с process.terminal.term");
        }
        if !(1..=120).contains(&self.start_timeout_seconds) {
            bail!("process.start_timeout_seconds должен быть 1..=120");
        }
        if self.idle_timeout_seconds > 86_400 {
            bail!("process.idle_timeout_seconds должен быть 0..=86400");
        }
        if self.terminate_grace_seconds > 60 {
            bail!("process.terminate_grace_seconds должен быть 0..=60");
        }
        if self.max_duration_seconds > 604_800 {
            bail!("process.max_duration_seconds должен быть 0..=604800");
        }
        if self.max_processes > 65_536 {
            bail!("process.max_processes должен быть 0..=65536");
        }
        if kind != Kind::Pty && self.terminal.is_some() {
            bail!("process.terminal допустим только для endpoint = pty");
        }
        if let Some(terminal) = &self.terminal {
            if !(1..=1000).contains(&terminal.rows) || !(1..=1000).contains(&terminal.columns) {
                bail!("process.terminal rows/columns должны быть 1..=1000");
            }
            if terminal.term.trim().is_empty()
                || terminal.term.chars().any(char::is_whitespace)
                || terminal.term.contains('\0')
            {
                bail!("process.terminal.term должен быть непустым без пробелов");
            }
        }
        Ok(())
    }
}

/// Ограничивает число процессов UID через RLIMIT_NPROC (0 — без лимита).
/// Учитывается суммарно по UID, поэтому профилю нужен отдельный UID.
pub fn apply_process_limit(command: &mut tokio::process::Command, max_processes: u64) {
    if max_processes == 0 {
        return;
    }
    let limit = max_processes as libc::rlim_t;
    // SAFETY: pre_exec выполняется в дочернем процессе после fork.
    unsafe {
        command.pre_exec(move || {
            let mut current = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if libc::getrlimit(libc::RLIMIT_NPROC, current.as_mut_ptr()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let current = current.assume_init();
            let rlimit = libc::rlimit {
                rlim_cur: limit.min(current.rlim_max),
                rlim_max: current.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &rlimit) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Проверяет, что fork+exec уложился в `start_timeout_seconds`.
/// `spawn` синхронный, поэтому тайм-аут проверяется по факту, а не прерывает
/// вызов; при превышении сессия закрывается, а дерево уже убивается вызывающим.
pub fn check_start_time(elapsed: std::time::Duration, limit_seconds: u64) -> Result<()> {
    if elapsed > std::time::Duration::from_secs(limit_seconds) {
        bail!(
            "запуск процесса занял {:?} при start_timeout_seconds = {limit_seconds}",
            elapsed
        );
    }
    Ok(())
}

/// Открывает endpoint после завершения TLS и ACL. Для TCP подключается
/// upstream, для процесса запускается дочерний процесс.
pub async fn open(
    relay: &RelayConfig,
    monitor: &advice::Monitor,
    tls: &transport::Runtime,
) -> Result<Session> {
    match relay.kind()? {
        Kind::Tcp => tcp::open(relay, monitor, tls).await,
        Kind::Exec => exec::open(relay).await,
        #[cfg(unix)]
        Kind::Pty => pty::open(relay).await,
        #[cfg(not(unix))]
        Kind::Pty => bail!("endpoint = pty поддерживается только в Unix"),
    }
}

#[cfg(test)]
mod tests {
    use super::check_start_time;
    use std::time::Duration;

    #[test]
    fn start_time_limit_is_enforced() {
        assert!(check_start_time(Duration::from_millis(500), 1).is_ok());
        assert!(check_start_time(Duration::from_millis(1500), 1).is_err());
    }
}

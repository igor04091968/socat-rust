//! Endpoint EXEC: дочерний процесс через pipes, без неявного shell.
use anyhow::{Context, Result};
use std::{io, process::Stdio, time::Duration};
use tokio::process::Command;
use tracing::info;

use crate::{
    RelayConfig,
    session::{ProcessSession, Session},
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub async fn open(relay: &RelayConfig) -> Result<Session> {
    let process = relay.process.as_ref().context("process не задан")?;
    let mut command = Command::new(&process.command);
    command.args(&process.args);
    if let Some(directory) = &process.working_directory {
        command.current_dir(directory);
    }
    // Окружение не наследуется: только PATH по умолчанию и явные переменные.
    command.env_clear();
    command.env("PATH", DEFAULT_PATH);
    let home = process.environment.get("HOME").cloned().or_else(|| {
        process
            .working_directory
            .as_ref()
            .map(|path| path.display().to_string())
    });
    if let Some(home) = home {
        command.env("HOME", home);
    }
    command.envs(&process.environment);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Своя группа процессов: завершение сессии убивает и потомков.
    // SAFETY: pre_exec выполняется в дочернем процессе после fork.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    super::apply_process_limit(&mut command, process.max_processes);
    let started = std::time::Instant::now();
    let mut child = command
        .spawn()
        .with_context(|| format!("запустить {}", process.command.display()))?;
    if let Err(error) = super::check_start_time(started.elapsed(), process.start_timeout_seconds) {
        let pid = child.id().unwrap_or(0) as i32;
        crate::session::kill_tree(pid);
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(error);
    }
    info!(
        relay = %relay.name,
        command = %process.command.display(),
        pid = child.id(),
        "процесс запущен"
    );
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    Ok(Session::Process(Box::new(ProcessSession {
        group: crate::session::ProcessGroup::register(
            child.id(),
            Duration::from_secs(process.terminate_grace_seconds),
        ),
        child,
        stdin,
        stdout,
        stderr,
        master: None,
        master_fd: None,
        stderr_policy: process.stderr,
        terminate_grace: Duration::from_secs(process.terminate_grace_seconds),
        idle_timeout: (process.idle_timeout_seconds > 0)
            .then(|| Duration::from_secs(process.idle_timeout_seconds)),
        max_duration: (process.max_duration_seconds > 0)
            .then(|| Duration::from_secs(process.max_duration_seconds)),
    })))
}

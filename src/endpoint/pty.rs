//! Endpoint PTY: интерактивная консоль через псевдотерминал.
//!
//! Прозрачный поток байтов; при префиксе консольного протокола размер
//! терминала меняется по кадрам RESIZE.
use anyhow::{Context, Result};
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    process::Stdio,
    task::{Context as TaskContext, Poll, ready},
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::Command,
};
use tracing::info;

use crate::{
    RelayConfig,
    session::{ProcessSession, Session},
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

struct Master(AsyncFd<OwnedFd>);

impl AsyncRead for Master {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.0.poll_read_ready_mut(cx))?;
            let outcome = {
                let target = buffer.initialize_unfilled();
                guard.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    let count = unsafe { libc::read(fd, target.as_mut_ptr().cast(), target.len()) };
                    if count < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(count as usize)
                    }
                })
            };
            match outcome {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Master {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let count = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn open(relay: &RelayConfig) -> Result<Session> {
    let process = relay.process.as_ref().context("process не задан")?;
    let terminal = process.terminal.clone().unwrap_or_default();

    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: terminal.rows,
        ws_col: terminal.columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty заполняет оба дескриптора; termios по умолчанию.
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("создать PTY");
    }
    // SAFETY: дескрипторы только что созданы и больше не используются как c_int.
    let master = unsafe { OwnedFd::from_raw_fd(master_fd) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error()).context("перевести PTY master в nonblocking");
    }
    // Master не должен наследоваться дочерним процессом.
    unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };

    let slave_raw = slave.as_raw_fd();
    let stdin = File::from(slave.try_clone()?);
    let stdout = File::from(slave.try_clone()?);
    let stderr = File::from(slave);

    let mut command = Command::new(&process.command);
    command.args(&process.args);
    if let Some(directory) = &process.working_directory {
        command.current_dir(directory);
    }
    command.env_clear();
    command.env("PATH", DEFAULT_PATH);
    let home = process
        .environment
        .get("HOME")
        .cloned()
        .or_else(|| {
            process
                .working_directory
                .as_ref()
                .map(|path| path.display().to_string())
        })
        .or_else(|| passwd_home(unsafe { libc::geteuid() }));
    if let Some(home) = home {
        command.env("HOME", home);
    }
    command.envs(&process.environment);
    command.env("TERM", &terminal.term);
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    // SAFETY: pre_exec выполняется в дочернем процессе после fork; вызовы
    // setsid/ioctl асинхронно-безопасны, slave_raw остаётся открытым.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(slave_raw, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

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
    // Закрыть родительские копии slave, иначе master не увидит EOF.
    drop(command);

    let master = AsyncFd::new(master).context("зарегистрировать PTY master")?;
    info!(
        relay = %relay.name,
        command = %process.command.display(),
        pid = child.id(),
        rows = terminal.rows,
        columns = terminal.columns,
        "PTY-процесс запущен"
    );
    Ok(Session::Process(Box::new(ProcessSession {
        group: crate::session::ProcessGroup::register(child.id()),
        child,
        stdin: None,
        stdout: None,
        stderr: None,
        master_fd: Some(master.get_ref().as_raw_fd()),
        master: Some(Box::new(Master(master))),
        stderr_policy: process.stderr,
        terminate_grace: Duration::from_secs(process.terminate_grace_seconds),
        idle_timeout: (process.idle_timeout_seconds > 0)
            .then(|| Duration::from_secs(process.idle_timeout_seconds)),
        max_duration: (process.max_duration_seconds > 0)
            .then(|| Duration::from_secs(process.max_duration_seconds)),
    })))
}

fn passwd_home(uid: libc::uid_t) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let _name = fields.next()?;
            let _password = fields.next()?;
            let entry_uid = fields.next()?.parse::<libc::uid_t>().ok()?;
            let _gid = fields.next()?;
            let _gecos = fields.next()?;
            let home = fields.next()?;
            (entry_uid == uid).then(|| home.to_owned())
        })
}

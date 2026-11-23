//! Сессия владеет второй стороной соединения: upstream-потоком или
//! дочерним процессом. Клиентский поток передаётся уже после TLS и ACL.
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::Mutex,
    time::timeout,
};
use tracing::{info, warn};

use crate::{RelayConfig, endpoint, framing, transport};

/// Реестр групп процессов активных сессий: нужен для остановки службы,
/// чтобы не оставлять потомков shell после SIGTERM.
static GROUPS: LazyLock<std::sync::Mutex<HashSet<i32>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

pub struct ProcessGroup(i32);

impl ProcessGroup {
    pub fn register(pid: Option<u32>) -> Self {
        let id = pid.unwrap_or(0) as i32;
        if id > 0 {
            GROUPS.lock().expect("реестр групп процессов").insert(id);
        }
        Self(id)
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.0 > 0 {
            GROUPS
                .lock()
                .expect("реестр групп процессов")
                .remove(&self.0);
        }
    }
}

/// Принудительно завершает все группы процессов (вызывается при остановке).
pub async fn stop_all_groups() {
    let groups: Vec<i32> = GROUPS
        .lock()
        .expect("реестр групп процессов")
        .iter()
        .copied()
        .collect();
    let mut children = Vec::new();
    for id in &groups {
        if *id > 0 {
            children.extend(descendants(*id));
            // SAFETY: id is a positive registered process group.
            unsafe { libc::kill(-*id, libc::SIGTERM) };
        }
    }
    children.sort_unstable();
    children.dedup();
    for pid in &children {
        // SAFETY: pid was read from the registered process tree in /proc.
        unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    if !groups.is_empty() {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    for id in groups {
        kill_tree(id);
    }
    for pid in children {
        // SAFETY: terminate any descendant still alive after the grace period.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// Потомки по /proc. Интерактивный shell с job control создаёт отдельные
/// группы для заданий, поэтому одной группы процесса недостаточно.
fn descendants(pid: i32) -> Vec<i32> {
    let mut found = Vec::new();
    let mut stack = vec![pid];
    while let Some(current) = stack.pop() {
        let path = format!("/proc/{current}/task/{current}/children");
        if let Ok(text) = std::fs::read_to_string(path) {
            for child in text
                .split_whitespace()
                .filter_map(|value| value.parse().ok())
            {
                found.push(child);
                stack.push(child);
            }
        }
    }
    found
}

/// Процессы той же группы или сессии: после выхода лидера потомки
/// переподвешиваются к init и пропадают из /proc/<pid>/children.
fn group_members(pid: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Some(candidate) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{candidate}/stat")) else {
            continue;
        };
        // После имени в скобках идут state, ppid, pgrp, session.
        let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let matches = |index: usize| {
            fields
                .get(index)
                .and_then(|value| value.parse::<i32>().ok())
                == Some(pid)
        };
        if matches(2) || matches(3) {
            found.push(candidate);
        }
    }
    found
}

pub(crate) fn kill_tree(pid: i32) {
    if pid <= 0 {
        return;
    }
    let mut victims = descendants(pid);
    victims.extend(group_members(pid));
    victims.sort_unstable();
    victims.dedup();
    for child in victims {
        // SAFETY: pid получен из /proc.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    // SAFETY: отрицательный pid адресует группу процессов.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
}

/// Даёт процессу `grace` на штатный выход, затем посылает SIGTERM всей
/// группе, ждёт ещё `grace` и только потом убивает дерево через SIGKILL.
/// pid берётся из сессии: tokio успевает пожать ребёнка, и child.id()
/// к моменту очистки уже может быть None.
async fn stop_group(
    child: &mut Child,
    pid: i32,
    grace: Duration,
) -> Result<std::process::ExitStatus> {
    let status = match timeout(grace, child.wait()).await {
        Ok(status) => status.context("дождаться процесса")?,
        Err(_) => {
            if pid > 0 {
                // SAFETY: отрицательный pid адресует группу процессов.
                unsafe { libc::kill(-pid, libc::SIGTERM) };
            }
            match timeout(grace, child.wait()).await {
                Ok(status) => status.context("дождаться процесса")?,
                Err(_) => {
                    kill_tree(pid);
                    let _ = child.start_kill();
                    child
                        .wait()
                        .await
                        .context("дождаться завершения процесса")?
                }
            }
        }
    };
    // Лидер мог выйти сам, оставив фоновые задания.
    kill_tree(pid);
    Ok(status)
}

pub enum Session {
    Tcp { upstream: transport::Stream },
    Process(Box<ProcessSession>),
}

pub struct ProcessSession {
    pub child: Child,
    pub group: ProcessGroup,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    /// PTY master вместо pipes.
    pub master: Option<transport::Stream>,
    pub master_fd: Option<std::os::fd::RawFd>,
    pub stderr_policy: endpoint::Stderr,
    pub terminate_grace: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_duration: Option<Duration>,
}

impl Session {
    pub async fn run(
        self,
        client: transport::Stream,
        relay: &RelayConfig,
        peer: std::net::SocketAddr,
    ) -> Result<()> {
        match self {
            Self::Tcp { upstream } => run_tcp(client, upstream, relay, peer).await,
            Self::Process(process) => run_process(client, *process, relay, peer).await,
        }
    }
}

async fn run_tcp(
    client: transport::Stream,
    upstream: transport::Stream,
    relay: &RelayConfig,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let (client_reader, client_writer) = tokio::io::split(client);
    let (upstream_reader, upstream_writer) = tokio::io::split(upstream);
    let mut client_to_upstream = tokio::spawn(relay_direction(
        client_reader,
        upstream_writer,
        relay.verbose_payload_logging,
        "клиент -> upstream",
    ));
    let mut upstream_to_client = tokio::spawn(relay_direction(
        upstream_reader,
        client_writer,
        relay.verbose_payload_logging,
        "upstream -> клиент",
    ));
    tokio::select! {
        result = &mut client_to_upstream => {
            info!(relay = %relay.name, peer = %peer, direction = "клиент -> upstream", "направление завершилось; ожидается ответная сторона в пределах EOF grace");
            if !upstream_to_client.is_finished()
                && timeout(Duration::from_secs(relay.eof_grace_seconds), &mut upstream_to_client).await.is_err()
            {
                warn!(relay = %relay.name, peer = %peer, grace_seconds = relay.eof_grace_seconds, "EOF grace истёк; закрываем upstream и клиентскую стороны");
                upstream_to_client.abort();
                // Дождаться отмены важно: пока задача не уничтожена, принадлежащая
                // ей половина TcpStream удерживает исходящее TCP-соединение.
                let _ = upstream_to_client.await;
            }
            result.context("задача клиент -> upstream")?.context("копирование клиент -> upstream")?;
        }
        result = &mut upstream_to_client => {
            info!(relay = %relay.name, peer = %peer, direction = "upstream -> клиент", "направление завершилось; ожидается клиентская сторона в пределах EOF grace");
            if !client_to_upstream.is_finished()
                && timeout(Duration::from_secs(relay.eof_grace_seconds), &mut client_to_upstream).await.is_err()
            {
                warn!(relay = %relay.name, peer = %peer, grace_seconds = relay.eof_grace_seconds, "EOF grace истёк; закрываем клиентскую и upstream стороны");
                client_to_upstream.abort();
                let _ = client_to_upstream.await;
            }
            result.context("задача upstream -> клиент")?.context("копирование upstream -> клиент")?;
        }
    }
    Ok(())
}

async fn run_process(
    client: transport::Stream,
    process: ProcessSession,
    relay: &RelayConfig,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let ProcessSession {
        mut child,
        group,
        stdin,
        stdout,
        stderr,
        master,
        master_fd,
        stderr_policy,
        terminate_grace,
        idle_timeout,
        max_duration,
    } = process;
    let (mut client_reader, client_writer) = tokio::io::split(client);
    let client_writer = Arc::new(Mutex::new(client_writer));
    let activity = Arc::new(AtomicU64::new(now_millis()));

    let mut pending = Vec::new();
    let mut console = false;
    let (process_reader, process_writer): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) = match master {
        Some(master) => {
            // Префикс консольного протокола опционален: без него остаётся
            // прозрачный поток, а прочитанные байты уходят процессу как есть.
            // Ожидание ограничено, иначе raw-клиент ждал бы приглашения,
            // которое сервер ещё не отправил.
            let mut probe = [0_u8; framing::PREFACE.len()];
            let mut filled = 0;
            let mut matches = true;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while filled < probe.len() && matches {
                let wait_for = if filled == 0 {
                    Duration::from_millis(300)
                } else {
                    deadline.saturating_duration_since(tokio::time::Instant::now())
                };
                if wait_for.is_zero() {
                    break;
                }
                match timeout(wait_for, client_reader.read(&mut probe[filled..])).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(count)) => {
                        filled += count;
                        matches = framing::PREFACE.starts_with(&probe[..filled]);
                    }
                    Ok(Err(error)) => return Err(error).context("прочитать префикс консоли"),
                    Err(_) if filled == 0 => break,
                    Err(_) => bail!("неполный префикс консоли: тайм-аут чтения"),
                }
            }
            console = filled == probe.len() && matches;
            if !console {
                pending.extend_from_slice(&probe[..filled]);
            }
            let (reader, writer) = tokio::io::split(master);
            (Box::new(reader), Box::new(writer))
        }
        None => (
            Box::new(stdout.context("stdout процесса не открыт")?),
            Box::new(stdin.context("stdin процесса не открыт")?),
        ),
    };
    let framed = console;

    let mut client_to_process = if framed {
        tokio::spawn(copy_framed_to_process(
            client_reader,
            process_writer,
            activity.clone(),
            master_fd.expect("pty master"),
            relay.name.clone(),
        ))
    } else {
        tokio::spawn(copy_to_process(
            client_reader,
            process_writer,
            pending,
            activity.clone(),
            relay.verbose_payload_logging,
        ))
    };
    let mut process_to_client = if framed {
        tokio::spawn(copy_framed_to_shared(
            process_reader,
            client_writer.clone(),
            activity.clone(),
        ))
    } else {
        tokio::spawn(copy_to_shared(
            process_reader,
            client_writer.clone(),
            activity.clone(),
            relay.verbose_payload_logging,
            "процесс -> клиент",
        ))
    };

    let mut stderr_tasks = Vec::new();
    if let Some(stderr) = stderr {
        match stderr_policy {
            endpoint::Stderr::Client => {
                stderr_tasks.push(tokio::spawn(copy_to_shared(
                    stderr,
                    client_writer.clone(),
                    activity.clone(),
                    false,
                    "stderr -> клиент",
                )));
            }
            endpoint::Stderr::Log => {
                let activity = activity.clone();
                let relay_name = relay.name.clone();
                stderr_tasks.push(tokio::spawn(async move {
                    log_stderr(stderr, activity, relay_name).await;
                    Ok(0)
                }));
            }
            endpoint::Stderr::Discard => {
                stderr_tasks.push(tokio::spawn(async move {
                    drain(stderr).await;
                    Ok(0)
                }));
            }
        }
    }

    let idle = idle_monitor(activity.clone(), idle_timeout);
    tokio::pin!(idle);
    let deadline = async {
        match max_duration {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);

    let status = tokio::select! {
        result = &mut client_to_process => {
            match result {
                Ok(Ok(_)) => info!(relay = %relay.name, peer = %peer, "клиентский поток завершён; ожидание процесса"),
                // Сброс соединения не должен отменять очистку дерева процессов.
                Ok(Err(error)) => warn!(relay = %relay.name, peer = %peer, %error, "клиентский поток прерван; ожидание процесса"),
                Err(error) => warn!(relay = %relay.name, peer = %peer, %error, "задача клиентского потока упала; ожидание процесса"),
            }
            match timeout(terminate_grace, child.wait()).await {
                Ok(status) => {
                    let status = status.context("дождаться процесса")?;
                    // Фоновые задания не должны переживать лидера.
                    kill_tree(group.0);
                    status
                }
                Err(_) => {
                    warn!(relay = %relay.name, peer = %peer, grace_seconds = terminate_grace.as_secs(), "процесс не завершился; останавливаем группу");
                    stop_group(&mut child, group.0, terminate_grace).await?
                }
            }
        }
        status = child.wait() => {
            let status = status.context("дождаться процесса")?;
            // Фоновые задания не должны переживать лидера.
            kill_tree(group.0);
            status
        }
        _ = &mut idle => {
            warn!(relay = %relay.name, peer = %peer, "простой сессии истёк; завершаем процесс");
            stop_group(&mut child, group.0, terminate_grace).await?
        }
        _ = &mut deadline => {
            warn!(relay = %relay.name, peer = %peer, "предельная длительность сессии истекла; завершаем процесс");
            stop_group(&mut child, group.0, terminate_grace).await?
        }
    };

    let output_result = if process_to_client.is_finished() {
        (&mut process_to_client).await
    } else {
        match timeout(terminate_grace, &mut process_to_client).await {
            Ok(result) => result,
            Err(_) => {
                process_to_client.abort();
                (&mut process_to_client).await
            }
        }
    };
    match output_result {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            warn!(relay = %relay.name, peer = %peer, %error, "вывод процесса клиенту завершился с ошибкой")
        }
        Err(error) if !error.is_cancelled() => {
            warn!(relay = %relay.name, peer = %peer, %error, "задача вывода процесса завершилась с ошибкой")
        }
        Err(_) => {}
    }
    for mut task in stderr_tasks {
        let joined = if task.is_finished() {
            (&mut task).await
        } else {
            match timeout(terminate_grace, &mut task).await {
                Ok(result) => result,
                Err(_) => {
                    task.abort();
                    (&mut task).await
                }
            }
        };
        match joined {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                warn!(relay = %relay.name, peer = %peer, %error, "обработка stderr процесса завершилась с ошибкой")
            }
            Err(error) if !error.is_cancelled() => {
                warn!(relay = %relay.name, peer = %peer, %error, "задача stderr завершилась с ошибкой")
            }
            Err(_) => {}
        }
    }
    if !client_to_process.is_finished() {
        client_to_process.abort();
        let _ = client_to_process.await;
    }

    if framed {
        use std::os::unix::process::ExitStatusExt;
        let code = status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
        let mut writer = client_writer.lock().await;
        let _ = framing::write_message(&mut *writer, &framing::Message::Exit { code }).await;
    }
    log_exit(relay, peer, status);
    Ok(())
}

fn log_exit(relay: &RelayConfig, peer: std::net::SocketAddr, status: std::process::ExitStatus) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) if code == 0 => {
                info!(relay = %relay.name, peer = %peer, exit_status = code, "процесс завершён")
            }
            (Some(code), _) => {
                warn!(relay = %relay.name, peer = %peer, exit_status = code, "процесс завершён с ошибкой")
            }
            (None, Some(signal)) => {
                warn!(relay = %relay.name, peer = %peer, signal, "процесс завершён сигналом")
            }
            (None, None) => warn!(relay = %relay.name, peer = %peer, "статус процесса неизвестен"),
        }
    }
    #[cfg(not(unix))]
    info!(relay = %relay.name, peer = %peer, exit_status = ?status, "процесс завершён");
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

async fn idle_monitor(activity: Arc<AtomicU64>, limit: Option<Duration>) {
    let Some(limit) = limit else {
        std::future::pending::<()>().await;
        return;
    };
    let limit = limit.as_millis() as u64;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if now_millis().saturating_sub(activity.load(Ordering::Relaxed)) >= limit {
            return;
        }
    }
}

async fn copy_to_process<R, W>(
    mut reader: R,
    mut writer: W,
    pending: Vec<u8>,
    activity: Arc<AtomicU64>,
    verbose: bool,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    if !pending.is_empty() {
        writer.write_all(&pending).await?;
        total += pending.len() as u64;
    }
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            // Закрытие stdin (или write-половины master) передаёт EOF процессу.
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        writer.write_all(&buffer[..count]).await?;
        activity.store(now_millis(), Ordering::Relaxed);
        total += count as u64;
        if verbose {
            info!(direction = "клиент -> процесс", bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "данные relay");
        }
    }
}

async fn copy_to_shared<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    activity: Arc<AtomicU64>,
    verbose: bool,
    direction: &'static str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(total);
        }
        writer.lock().await.write_all(&buffer[..count]).await?;
        activity.store(now_millis(), Ordering::Relaxed);
        total += count as u64;
        if verbose {
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "данные relay");
        }
    }
}

async fn copy_framed_to_process<R, W>(
    mut reader: R,
    mut writer: W,
    activity: Arc<AtomicU64>,
    master_fd: std::os::fd::RawFd,
    relay: String,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0_u64;
    loop {
        match framing::read_message(&mut reader).await? {
            Some(framing::Message::Data(data)) => {
                activity.store(now_millis(), Ordering::Relaxed);
                writer.write_all(&data).await?;
                total += data.len() as u64;
            }
            Some(framing::Message::Resize { rows, columns }) => {
                let size = libc::winsize {
                    ws_row: rows,
                    ws_col: columns,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: master_fd принадлежит живой сессии.
                if unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &size) } < 0 {
                    warn!(relay = %relay, %rows, %columns, error = %std::io::Error::last_os_error(), "не удалось изменить размер PTY");
                }
            }
            Some(framing::Message::Exit { .. }) | None => {
                // poll_shutdown у PTY master ничего не делает, поэтому EOF
                // терминалу передаётся символом VEOF (Ctrl-D).
                let _ = writer.write_all(&[libc::VEOF as u8]).await;
                let _ = writer.shutdown().await;
                return Ok(total);
            }
        }
    }
}

async fn copy_framed_to_shared<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    activity: Arc<AtomicU64>,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => return Ok(total),
            Ok(count) => {
                activity.store(now_millis(), Ordering::Relaxed);
                let mut writer = writer.lock().await;
                framing::write_message(
                    &mut *writer,
                    &framing::Message::Data(buffer[..count].to_vec()),
                )
                .await?;
                total += count as u64;
            }
            // PTY master отдаёт EIO после выхода ребёнка.
            Err(error)
                if error.kind() == std::io::ErrorKind::Other
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                return Ok(total);
            }
            Err(error) => return Err(error).context("чтение процесса"),
        }
    }
}

async fn log_stderr(mut stderr: ChildStderr, activity: Arc<AtomicU64>, relay: String) {
    let mut buffer = [0_u8; 4 * 1024];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) => return,
            Ok(count) => {
                activity.store(now_millis(), Ordering::Relaxed);
                warn!(
                    relay = %relay,
                    bytes = count,
                    text = %String::from_utf8_lossy(&buffer[..count]).trim_end(),
                    "stderr процесса"
                );
            }
            Err(error) => {
                warn!(relay = %relay, %error, "чтение stderr процесса прервано");
                return;
            }
        }
    }
}

async fn drain(mut reader: impl AsyncRead + Unpin) {
    let mut buffer = [0_u8; 4 * 1024];
    while matches!(reader.read(&mut buffer).await, Ok(count) if count > 0) {}
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    verbose: bool,
    direction: &'static str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = relay_copy(&mut reader, &mut writer, verbose, direction).await;
    let _ = writer.shutdown().await;
    result
}

async fn relay_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    verbose: bool,
    direction: &'static str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(total);
        }
        writer.write_all(&buffer[..count]).await?;
        total += count as u64;
        if verbose {
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "данные relay");
        } else {
            tracing::debug!(direction, bytes = count, "передача данных relay");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalid_pid_does_not_signal_any_process_group() {
        super::kill_tree(0);
        super::kill_tree(-1);
    }
}

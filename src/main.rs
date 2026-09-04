#![cfg_attr(feature = "legacy-kernel", allow(dead_code, unused_imports))]

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::Semaphore,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "socat-rust", version, about = "Стабильный TCP-релей для Linux")]
struct Cli {
    // Конфигурация общая для всех relay. Параметр --relay выбирает ровно
    // один профиль: это позволяет безопасно назначить ему отдельный UID.
    #[arg(short, long, default_value = "/etc/socat-rust/relays.toml")]
    config: PathBuf,
    #[arg(short, long)]
    relay: Option<String>,
    /// Запустить relay в фоне и удерживать эксклюзивную блокировку профиля.
    #[arg(long, alias = "background")]
    daemon: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[cfg(unix)]
struct DaemonGuard {
    // Дескриптор должен оставаться открытым всё время работы relay. При его
    // закрытии flock() освобождается, и второй экземпляр сможет запуститься.
    _lock: File,
}

#[cfg(unix)]
fn daemonize(relay: &RelayConfig, enabled: bool) -> Result<Option<DaemonGuard>> {
    let lock_path = relay
        .pid_file
        .clone()
        .unwrap_or_else(|| Path::new("/var/run/socat-rust").join(format!("{}.lock", relay.name)));
    if let Some(parent) = lock_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("создать каталог блокировок {}", parent.display()))?;
    }
    // flock() надёжнее ручной проверки PID-файла: после падения процесса
    // ядро само освобождает блокировку, и устаревший PID не мешает запуску.
    let mut lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("открыть блокировку daemon {}", lock_path.display()))?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&lock);
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "relay {} уже запущен (захватить блокировку {})",
                relay.name,
                lock_path.display()
            );
        }
        return Err(error).with_context(|| format!("захватить блокировку {}", lock_path.display()));
    }

    // В foreground lock также удерживается, но fork/setsid и перенаправление
    // stdio не выполняются: диагностические ошибки должны быть видны в терминале.
    if !enabled {
        lock.set_len(0).context("очистить данные блокировки")?;
        writeln!(lock, "{}", std::process::id()).context("записать PID")?;
        return Ok(Some(DaemonGuard { _lock: lock }));
    }

    // Fork выполняется до создания Tokio и открытия сокетов. Родительский
    // процесс завершается, а дочерний сохраняет lock и продолжает настройку
    // UID и bind. Это исключает второй экземпляр одного профиля.
    match unsafe { libc::fork() } {
        -1 => return Err(std::io::Error::last_os_error()).context("создать фоновый процесс fork"),
        0 => {}
        _parent_pid => std::process::exit(0),
    }
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error()).context("создать сессию daemon");
    }
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("сменить каталог daemon");
    }
    unsafe { libc::umask(0o027) };

    let null = std::fs::File::open("/dev/null").context("открыть /dev/null для daemon")?;
    let null_fd = std::os::fd::AsRawFd::as_raw_fd(&null);
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(null_fd, target) } < 0 {
            return Err(std::io::Error::last_os_error()).context("перенаправить stdio daemon");
        }
    }

    lock.set_len(0)
        .context("очистить данные блокировки daemon")?;
    writeln!(lock, "{}", std::process::id()).context("записать PID daemon")?;
    Ok(Some(DaemonGuard { _lock: lock }))
}

#[cfg(not(unix))]
fn daemonize(relay: &RelayConfig, enabled: bool) -> Result<Option<()>> {
    if enabled {
        bail!(
            "relay {}: режим daemon поддерживается только в Unix",
            relay.name
        );
    }
    Ok(None)
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Проверить все профили relay без открытия сетевых сокетов.
    ConfigCheck,
}

#[derive(Debug, Deserialize)]
struct Config {
    relay: Vec<RelayConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct RelayConfig {
    name: String,
    listen: String,
    upstream: String,
    #[serde(default)]
    allow: Vec<IpNet>,
    #[serde(default = "default_backlog")]
    backlog: u32,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_eof_grace_seconds")]
    eof_grace_seconds: u64,
    #[serde(default)]
    client_keepalive: KeepaliveConfig,
    #[serde(default)]
    upstream_keepalive: KeepaliveConfig,
    #[serde(default)]
    connect_timeout_seconds: u64,
    #[serde(default)]
    verbose_payload_logging: bool,
    #[serde(default)]
    log_file: Option<PathBuf>,
    /// PID-файл и lock-файл для Monit/старых init-скриптов.
    /// Если поле не задано, используется /var/run/socat-rust/<имя>.lock.
    #[serde(default)]
    pid_file: Option<PathBuf>,
    /// UID банкомата/relay. Firewall на целевой системе проверяет UID
    /// исходящего upstream-соединения, поэтому каждый relay запускается
    /// отдельным процессом со своим UID.
    #[serde(default)]
    uid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct KeepaliveConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    idle_seconds: u64,
    #[serde(default)]
    interval_seconds: u64,
    #[serde(default)]
    count: u32,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_seconds: 60,
            interval_seconds: 15,
            count: 8,
        }
    }
}

fn default_backlog() -> u32 {
    1
}

fn default_max_connections() -> usize {
    1
}

fn default_eof_grace_seconds() -> u64 {
    1
}

impl RelayConfig {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.contains('/') || self.name.contains(' ') {
            bail!(
                "имя relay должно быть непустым и безопасным для пути: {:?}",
                self.name
            );
        }
        let listen = self
            .listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("неверный адрес listen для {}", self.name))?;
        if !listen.ip().is_ipv4() {
            bail!(
                "{}: в v0.1 поддерживаются только IPv4-адреса listen",
                self.name
            );
        }
        self.upstream
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("неверный адрес upstream для {}", self.name))?;
        if self.backlog == 0 || self.backlog > 65535 {
            bail!("{}: backlog должен быть от 1 до 65535", self.name);
        }
        if self.max_connections == 0 {
            bail!("{}: max_connections должен быть положительным", self.name);
        }
        if self.uid == Some(0) {
            bail!(
                "{}: uid должен быть положительным ненулевым числом",
                self.name
            );
        }
        for keepalive in [&self.client_keepalive, &self.upstream_keepalive] {
            if keepalive.enabled
                && (keepalive.idle_seconds == 0
                    || keepalive.interval_seconds == 0
                    || keepalive.count == 0)
            {
                bail!(
                    "{}: включённые параметры keepalive должны быть положительными",
                    self.name
                );
            }
        }
        Ok(())
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("прочитать {}", path.display()))?;
    let config: Config = toml::from_str(&raw)
        .with_context(|| format!("разобрать конфигурацию {}", path.display()))?;
    if config.relay.is_empty() {
        bail!("{} не содержит профилей relay", path.display());
    }
    let mut names = std::collections::HashSet::new();
    for relay in &config.relay {
        relay.validate()?;
        if !names.insert(relay.name.clone()) {
            bail!("дублирующееся имя relay: {}", relay.name);
        }
    }
    Ok(config)
}

/// Применяет UID профиля до открытия любых relay-сокетов.
///
/// Важно: это выполняется до создания Tokio runtime. На Linux учётные данные
/// должны быть унаследованы всеми рабочими потоками и upstream-соединениями.
/// Нельзя сначала поднять общий runtime от root, а затем менять UID внутри
/// async-кода: это может привести к разным учётным данным у потоков.
///
/// Если процесс уже запущен под нужным UID, смена не выполняется. Если он
/// запущен от root, дополнительно сбрасываются группы, затем устанавливаются
/// GID и UID профиля. После этого вернуть привилегии невозможно.
#[cfg(unix)]
fn apply_configured_uid(relay: &RelayConfig) -> Result<()> {
    let Some(uid) = relay.uid else {
        return Ok(());
    };
    let current = unsafe { libc::geteuid() } as u32;
    if current == uid {
        return Ok(());
    }
    if current != 0 {
        bail!(
            "relay {} требует uid {}, но процесс запущен с uid {}; запустите от root или нужного UID",
            relay.name,
            uid,
            current
        );
    }

    let gid = uid as libc::gid_t;
    let uid = uid as libc::uid_t;
    let clear_groups = unsafe { libc::setgroups(0, std::ptr::null()) };
    if clear_groups != 0 {
        return Err(std::io::Error::last_os_error())
            .context("очистить дополнительные группы перед сменой UID");
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("установить GID {gid} для relay {}", relay.name));
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("установить UID {uid} для relay {}", relay.name));
    }
    let effective = unsafe { libc::geteuid() } as u32;
    if effective != uid as u32 {
        bail!(
            "relay {}: проверка смены UID не пройдена (эффективный UID {effective})",
            relay.name
        );
    }
    Ok(())
}

/// Подготавливает файл журнала до сброса UID процесса.
///
/// Для каталогов вроде /var/log relay уже не может создать файл после
/// setuid(). Поэтому root создаёт файл заранее, назначает владельцем UID
/// relay и устанавливает права 0640. Бинарник не вызывает sudo сам: sudo
/// должен быть применён к команде запуска.
#[cfg(unix)]
fn prepare_log_file(relay: &RelayConfig) -> Result<()> {
    let Some(path) = &relay.log_file else {
        return Ok(());
    };
    let Some(uid) = relay.uid else {
        return Ok(());
    };
    let euid = unsafe { libc::geteuid() } as u32;
    if euid != 0 && euid != uid {
        bail!(
            "relay {}: файл журнала {} требует запуска через sudo для подготовки прав",
            relay.name,
            path.display()
        );
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("создать каталог журнала {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("создать или открыть файл журнала {}", path.display()))?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
    if euid == 0 && unsafe { libc::fchown(fd, uid, !0 as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("назначить владельца UID {uid} для {}", path.display()));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("назначить права 0640 для {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_log_file(_relay: &RelayConfig) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn apply_configured_uid(relay: &RelayConfig) -> Result<()> {
    if relay.uid.is_some() {
        bail!(
            "relay {}: смена UID поддерживается только в Unix",
            relay.name
        );
    }
    Ok(())
}

fn init_logging(
    relay: &RelayConfig,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    // Если RUST_LOG не задан, оставляем информационный уровень. Payload
    // пишется только при verbose_payload_logging=true, поскольку может
    // содержать платёжные данные и быстро увеличивать файл журнала.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Some(path) = &relay.log_file {
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("создать каталог журнала {}", parent.display()))?;
        let filename = path
            .file_name()
            .context("log_file должен содержать имя файла")?
            .to_string_lossy()
            .into_owned();
        let appender = tracing_appender::rolling::never(parent, filename);
        let (writer, guard) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(writer)
            .try_init()
            .map_err(|error| anyhow!("инициализировать файловый журнал: {error}"))?;
        Ok(Some(guard))
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .try_init()
            .map_err(|error| anyhow!("инициализировать журнал journald/stdout: {error}"))?;
        Ok(None)
    }
}

fn main() {
    #[cfg(feature = "legacy-kernel")]
    {
        if let Err(error) = legacy_main() {
            eprintln!("Ошибка: {error:#}");
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "legacy-kernel"))]
    if let Err(error) = async_main() {
        eprintln!("Ошибка: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "legacy-kernel"))]
fn async_main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;
    if matches!(cli.command, Some(Command::ConfigCheck)) {
        for relay in &config.relay {
            println!(
                "ПРОВЕРЕНО: {} listen={} upstream={}",
                relay.name, relay.listen, relay.upstream
            );
        }
        return Ok(());
    }
    let relay_name = cli
        .relay
        .as_deref()
        .context("--relay is required when starting a relay")?;
    let relay = config
        .relay
        .into_iter()
        .find(|item| item.name == relay_name)
        .with_context(|| format!("профиль relay не найден: {relay_name}"))?;
    prepare_log_file(&relay)?;
    let _daemon_guard = daemonize(&relay, cli.daemon)?;
    // Один процесс = один relay = один UID. Это обязательная схема для
    // firewall-правил, которые различают трафик банкоматов по UID процесса.
    apply_configured_uid(&relay)?;
    let _log_guard = init_logging(&relay)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("создать Tokio runtime")?;
    let result = runtime.block_on(run_relay(relay));
    if let Err(error) = &result {
        error!(error = %error, "ошибка работы relay");
    }
    result
}

#[cfg(feature = "legacy-kernel")]
fn legacy_main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;
    if matches!(cli.command, Some(Command::ConfigCheck)) {
        for relay in &config.relay {
            println!(
                "ПРОВЕРЕНО: {} listen={} upstream={}",
                relay.name, relay.listen, relay.upstream
            );
        }
        return Ok(());
    }
    let name = cli
        .relay
        .as_deref()
        .context("--relay is required when starting a relay")?;
    let relay = config
        .relay
        .into_iter()
        .find(|item| item.name == name)
        .with_context(|| format!("профиль relay не найден: {name}"))?;
    prepare_log_file(&relay)?;
    let _daemon_guard = daemonize(&relay, cli.daemon)?;
    // Legacy-бинарь для CentOS 5 также запускается отдельным процессом на
    // каждый профиль. Стартуем от root, после чего безвозвратно переходим
    // на UID из конфигурации до bind/connect. Для запуска в фоне используйте
    // --daemon; под supervisord/systemd этот флаг не нужен.
    apply_configured_uid(&relay)?;
    let _log_guard = init_logging(&relay)?;
    let result = legacy_run_relay(relay);
    if let Err(error) = &result {
        error!(error = %error, "ошибка работы relay");
    }
    result
}

#[cfg(feature = "legacy-kernel")]
fn legacy_run_relay(relay: RelayConfig) -> Result<()> {
    // Legacy-режим специально использует std::thread и блокирующие TCP API.
    // Это исключает зависимость от возможностей старого ядра CentOS 5 и
    // оставляет поведение близким к классическому socat.
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listen: std::net::SocketAddr = relay.listen.parse()?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket
        .bind(&listen.into())
        .with_context(|| format!("занять адрес listen {}", relay.listen))?;
    socket
        .listen(relay.backlog as i32)
        .with_context(|| format!("запустить прослушивание {}", relay.listen))?;
    let listener: TcpListener = socket.into();
    // Явно включаем blocking-режим. Если listener окажется non-blocking,
    // std::net::TcpListener::incoming() будет получать EAGAIN и крутиться
    // без ожидания, занимая почти 100% CPU в простое.
    listener
        .set_nonblocking(false)
        .context("включить blocking-режим listener")?;
    let active = std::sync::Arc::new(AtomicUsize::new(0));
    info!(relay = %relay.name, listen = %relay.listen, upstream = %relay.upstream, "legacy relay слушает входящий порт");
    for incoming in listener.incoming() {
        let client = incoming.context("принять клиентское соединение")?;
        let peer = client.peer_addr().context("получить адрес клиента")?;
        if active.load(Ordering::Acquire) >= relay.max_connections {
            warn!(relay = %relay.name, peer = %peer, "клиент отклонён: достигнут лимит соединений");
            continue;
        }
        if !relay.allow.is_empty()
            && !relay
                .allow
                .iter()
                .any(|network| network.contains(&peer.ip()))
        {
            warn!(relay = %relay.name, peer = %peer, "клиент отклонён правилом ACL");
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let profile = relay.clone();
        let active = std::sync::Arc::clone(&active);
        std::thread::spawn(move || {
            if let Err(error) = legacy_handle_connection(profile, client, peer) {
                warn!(peer = %peer, error = %error, "соединение legacy relay завершилось с ошибкой");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

#[cfg(feature = "legacy-kernel")]
fn legacy_handle_connection(
    relay: RelayConfig,
    client: std::net::TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    legacy_configure_keepalive(&client, &relay.client_keepalive)?;
    let upstream = legacy_connect_forever(&relay)?;
    legacy_configure_keepalive(&upstream, &relay.upstream_keepalive)?;
    let client_reader = client.try_clone()?;
    let upstream_reader = upstream.try_clone()?;
    let verbose = relay.verbose_payload_logging;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let left_stop = std::sync::Arc::clone(&stop);
    let right_stop = std::sync::Arc::clone(&stop);
    let grace = std::time::Duration::from_secs(relay.eof_grace_seconds.max(1));
    let left = std::thread::spawn(move || {
        legacy_copy(
            client_reader,
            upstream,
            verbose,
            "клиент -> upstream",
            left_stop,
            grace,
        )
    });
    let right = std::thread::spawn(move || {
        legacy_copy(
            upstream_reader,
            client,
            verbose,
            "upstream -> клиент",
            right_stop,
            grace,
        )
    });
    left.join()
        .map_err(|_| anyhow::anyhow!("поток клиентского направления аварийно завершился"))??;
    right
        .join()
        .map_err(|_| anyhow::anyhow!("поток upstream-направления аварийно завершился"))??;
    info!(relay = %relay.name, peer = %peer, "соединение legacy relay закрыто");
    Ok(())
}

#[cfg(feature = "legacy-kernel")]
fn legacy_connect_forever(relay: &RelayConfig) -> Result<std::net::TcpStream> {
    let address: std::net::SocketAddr = relay.upstream.parse()?;
    let timeout = std::time::Duration::from_secs(if relay.connect_timeout_seconds == 0 {
        10
    } else {
        relay.connect_timeout_seconds
    });
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match std::net::TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                warn!(relay = %relay.name, upstream = %relay.upstream, %error, "ошибка подключения к upstream; повторная попытка")
            }
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(std::time::Duration::from_secs(30));
    }
}

#[cfg(feature = "legacy-kernel")]
fn legacy_configure_keepalive(
    stream: &std::net::TcpStream,
    config: &KeepaliveConfig,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(config.idle_seconds))
        .with_interval(std::time::Duration::from_secs(config.interval_seconds))
        .with_retries(config.count);
    socket
        .set_tcp_keepalive(&keepalive)
        .context("настроить TCP keepalive")?;
    Ok(())
}

#[cfg(feature = "legacy-kernel")]
fn legacy_copy(
    mut reader: std::net::TcpStream,
    mut writer: std::net::TcpStream,
    verbose: bool,
    direction: &'static str,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    eof_grace: std::time::Duration,
) -> Result<u64> {
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;
    // Короткий тайм-аут чтения нужен, чтобы после EOF второго направления
    // корректно выдержать eof_grace и закрыть половину TCP-соединения.
    reader.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    let mut stop_deadline = None;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if stop.load(Ordering::Acquire)
                    && stop_deadline
                        .get_or_insert(std::time::Instant::now())
                        .elapsed()
                        >= eof_grace
                {
                    let _ = writer.shutdown(std::net::Shutdown::Write);
                    return Ok(total);
                }
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            stop.store(true, Ordering::Release);
            let _ = writer.shutdown(std::net::Shutdown::Write);
            return Ok(total);
        }
        writer.write_all(&buffer[..count])?;
        total += count as u64;
        if verbose {
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "данные relay");
        }
    }
}

async fn run_relay(relay: RelayConfig) -> Result<()> {
    let listen_addr: std::net::SocketAddr =
        relay.listen.parse().context("разобрать адрес listen")?;
    let socket = if listen_addr.ip().is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket
        .bind(listen_addr)
        .with_context(|| format!("занять адрес listen {}", relay.listen))?;
    let listener = socket
        .listen(relay.backlog)
        .with_context(|| format!("запустить прослушивание {}", relay.listen))?;
    let slots = Arc::new(Semaphore::new(relay.max_connections));
    info!(relay = %relay.name, listen = %relay.listen, upstream = %relay.upstream,
        max_connections = relay.max_connections, backlog = relay.backlog,
        "relay слушает входящий порт");

    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        if slots.available_permits() == 0 {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = sleep(Duration::from_millis(100)) => continue,
            }
        }
        let (client, peer) = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => accepted.context("принять клиентское соединение")?,
        };
        let peer_ip = peer.ip();
        if !relay.allow.is_empty() && !relay.allow.iter().any(|network| network.contains(&peer_ip))
        {
            warn!(relay = %relay.name, peer = %peer, "клиент отклонён правилом ACL");
            drop(client);
            continue;
        }
        let permit = match slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(relay = %relay.name, peer = %peer, "клиент отклонён: достигнут лимит соединений");
                drop(client);
                continue;
            }
        };
        let profile = relay.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(profile, client, peer).await {
                warn!(peer = %peer, error = %error, "соединение relay завершилось с ошибкой");
            }
        });
    }
    info!(relay = %relay.name, "приёмник relay остановлен");
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let ctrl_c = tokio::signal::ctrl_c();
    let mut terminate = signal(SignalKind::terminate()).expect("установить обработчик SIGTERM");
    tokio::select! {
        _ = ctrl_c => info!("получен Ctrl-C; завершение работы"),
        _ = terminate.recv() => info!("получен SIGTERM; завершение работы"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("получен Ctrl-C; завершение работы");
}

async fn handle_connection(
    relay: RelayConfig,
    client: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    configure_keepalive(&client, &relay.client_keepalive)?;
    info!(relay = %relay.name, peer = %peer, "клиент подключён");
    let upstream = connect_forever(&relay).await?;
    configure_keepalive(&upstream, &relay.upstream_keepalive)?;
    let (client_reader, client_writer) = client.into_split();
    let (upstream_reader, upstream_writer) = upstream.into_split();
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
            if timeout(Duration::from_secs(relay.eof_grace_seconds), &mut upstream_to_client).await.is_err() {
                upstream_to_client.abort();
            }
            result.context("задача клиент -> upstream")?.context("копирование клиент -> upstream")?;
        }
        result = &mut upstream_to_client => {
            if timeout(Duration::from_secs(relay.eof_grace_seconds), &mut client_to_upstream).await.is_err() {
                client_to_upstream.abort();
            }
            result.context("задача upstream -> клиент")?.context("копирование upstream -> клиент")?;
        }
    }
    info!(relay = %relay.name, peer = %peer, "соединение relay закрыто");
    Ok(())
}

async fn connect_forever(relay: &RelayConfig) -> Result<TcpStream> {
    let timeout_seconds = if relay.connect_timeout_seconds == 0 {
        10
    } else {
        relay.connect_timeout_seconds
    };
    let mut delay = Duration::from_secs(1);
    loop {
        match timeout(
            Duration::from_secs(timeout_seconds),
            TcpStream::connect(&relay.upstream),
        )
        .await
        {
            Ok(Ok(stream)) => {
                info!(relay = %relay.name, upstream = %relay.upstream, "upstream подключён");
                return Ok(stream);
            }
            Ok(Err(error)) => {
                warn!(relay = %relay.name, upstream = %relay.upstream, %error, "ошибка подключения к upstream; повторная попытка")
            }
            Err(_) => {
                warn!(relay = %relay.name, upstream = %relay.upstream, timeout_seconds, "истёк тайм-аут подключения к upstream; повторная попытка")
            }
        }
        sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

fn configure_keepalive(stream: &TcpStream, config: &KeepaliveConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(config.idle_seconds))
        .with_interval(Duration::from_secs(config.interval_seconds))
        .with_retries(config.count);
    socket
        .set_tcp_keepalive(&keepalive)
        .context("настроить TCP keepalive")?;
    Ok(())
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
        let count = tokio::io::AsyncReadExt::read(reader, &mut buffer).await?;
        if count == 0 {
            return Ok(total);
        }
        tokio::io::AsyncWriteExt::write_all(writer, &buffer[..count]).await?;
        total += count as u64;
        if verbose {
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "данные relay");
        } else {
            tracing::debug!(direction, bytes = count, "передача данных relay");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn validates_profile_and_acl() {
        let raw = r#"
            [[relay]]
            name = "bnk2450034"
            listen = "10.34.0.1:8034"
            upstream = "172.22.22.34:8000"
            allow = ["10.19.63.0/24"]
            max_connections = 1
            backlog = 1
        "#;
        let config: Config = toml::from_str(raw).unwrap();
        config.relay[0].validate().unwrap();
        let network: IpNet = "10.19.63.0/24".parse().unwrap();
        let allowed: IpAddr = "10.19.63.10".parse().unwrap();
        let denied: IpAddr = "10.19.64.10".parse().unwrap();
        assert!(network.contains(&allowed));
        assert!(!network.contains(&denied));
    }

    #[test]
    fn rejects_zero_connection_limit() {
        let raw = r#"
            [[relay]]
            name = "bad"
            listen = "10.34.0.1:8034"
            upstream = "172.22.22.34:8000"
            max_connections = 0
        "#;
        let config: Config = toml::from_str(raw).unwrap();
        assert!(config.relay[0].validate().is_err());
    }
}

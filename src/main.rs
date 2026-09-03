#![cfg_attr(feature = "legacy-kernel", allow(dead_code, unused_imports))]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

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
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "socat-rust", version, about = "Stable Debian TCP relay")]
struct Cli {
    #[arg(short, long, default_value = "/etc/socat-rust/relays.toml")]
    config: PathBuf,
    #[arg(short, long)]
    relay: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate every relay profile without opening sockets.
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
    /// Applied by the systemd unit generator; the daemon itself must not run as root.
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
                "relay name must be a non-empty path-safe value: {:?}",
                self.name
            );
        }
        let listen = self
            .listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("invalid listen address for {}", self.name))?;
        if !listen.ip().is_ipv4() {
            bail!(
                "{}: only IPv4 listen addresses are supported in v0.1",
                self.name
            );
        }
        self.upstream
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("invalid upstream address for {}", self.name))?;
        if self.backlog == 0 || self.backlog > 65535 {
            bail!("{}: backlog must be between 1 and 65535", self.name);
        }
        if self.max_connections == 0 {
            bail!("{}: max_connections must be positive", self.name);
        }
        if self.uid == Some(0) {
            bail!("{}: uid must be a non-root positive integer", self.name);
        }
        for keepalive in [&self.client_keepalive, &self.upstream_keepalive] {
            if keepalive.enabled
                && (keepalive.idle_seconds == 0
                    || keepalive.interval_seconds == 0
                    || keepalive.count == 0)
            {
                bail!("{}: enabled keepalive values must be positive", self.name);
            }
        }
        Ok(())
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config: Config =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if config.relay.is_empty() {
        bail!("{} contains no relay profiles", path.display());
    }
    let mut names = std::collections::HashSet::new();
    for relay in &config.relay {
        relay.validate()?;
        if !names.insert(relay.name.clone()) {
            bail!("duplicate relay name: {}", relay.name);
        }
    }
    Ok(config)
}

/// Apply the profile identity before opening any relay sockets.
///
/// This is intentionally done before constructing the Tokio runtime: on Linux
/// the effective credentials used by the firewall must also be inherited by
/// every runtime worker thread and every upstream connection.
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
            "relay {} requires uid {}, but process runs as uid {}; start it as root or as the configured uid",
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
            .context("clear supplementary groups before uid drop");
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setgid({gid}) for relay {}", relay.name));
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setuid({uid}) for relay {}", relay.name));
    }
    let effective = unsafe { libc::geteuid() } as u32;
    if effective != uid as u32 {
        bail!(
            "relay {}: uid drop verification failed (effective uid {effective})",
            relay.name
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_configured_uid(relay: &RelayConfig) -> Result<()> {
    if relay.uid.is_some() {
        bail!(
            "relay {}: uid switching is supported only on Unix",
            relay.name
        );
    }
    Ok(())
}

fn init_logging(
    relay: &RelayConfig,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Some(path) = &relay.log_file {
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create log directory {}", parent.display()))?;
        let filename = path
            .file_name()
            .context("log_file must contain a filename")?
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
            .map_err(|error| anyhow!("initialize file logging: {error}"))?;
        Ok(Some(guard))
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .try_init()
            .map_err(|error| anyhow!("initialize journald/stdout logging: {error}"))?;
        Ok(None)
    }
}

fn main() {
    #[cfg(feature = "legacy-kernel")]
    {
        if let Err(error) = legacy_main() {
            eprintln!("Error: {error:#}");
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "legacy-kernel"))]
    if let Err(error) = async_main() {
        eprintln!("Error: {error:#}");
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
                "OK {} listen={} upstream={}",
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
        .with_context(|| format!("relay profile not found: {relay_name}"))?;
    apply_configured_uid(&relay)?;
    let _log_guard = init_logging(&relay)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime")?;
    runtime.block_on(run_relay(relay))
}

#[cfg(feature = "legacy-kernel")]
fn legacy_main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;
    if matches!(cli.command, Some(Command::ConfigCheck)) {
        for relay in &config.relay {
            println!(
                "OK {} listen={} upstream={}",
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
        .with_context(|| format!("relay profile not found: {name}"))?;
    apply_configured_uid(&relay)?;
    let _log_guard = init_logging(&relay)?;
    legacy_run_relay(relay)
}

#[cfg(feature = "legacy-kernel")]
fn legacy_run_relay(relay: RelayConfig) -> Result<()> {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listen: std::net::SocketAddr = relay.listen.parse()?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&listen.into())?;
    socket.listen(relay.backlog as i32)?;
    let listener: TcpListener = socket.into();
    let active = std::sync::Arc::new(AtomicUsize::new(0));
    info!(relay = %relay.name, listen = %relay.listen, upstream = %relay.upstream, "legacy relay listening");
    for incoming in listener.incoming() {
        let client = incoming.context("accept client")?;
        let peer = client.peer_addr().context("read client peer address")?;
        if active.load(Ordering::Acquire) >= relay.max_connections {
            warn!(relay = %relay.name, peer = %peer, "client rejected: connection limit");
            continue;
        }
        if !relay.allow.is_empty()
            && !relay
                .allow
                .iter()
                .any(|network| network.contains(&peer.ip()))
        {
            warn!(relay = %relay.name, peer = %peer, "client rejected by ACL");
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let profile = relay.clone();
        let active = std::sync::Arc::clone(&active);
        std::thread::spawn(move || {
            if let Err(error) = legacy_handle_connection(profile, client, peer) {
                warn!(peer = %peer, error = %error, "legacy relay connection ended with error");
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
            "client_to_upstream",
            left_stop,
            grace,
        )
    });
    let right = std::thread::spawn(move || {
        legacy_copy(
            upstream_reader,
            client,
            verbose,
            "upstream_to_client",
            right_stop,
            grace,
        )
    });
    left.join()
        .map_err(|_| anyhow::anyhow!("client direction panicked"))??;
    right
        .join()
        .map_err(|_| anyhow::anyhow!("upstream direction panicked"))??;
    info!(relay = %relay.name, peer = %peer, "legacy relay connection closed");
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
                warn!(relay = %relay.name, upstream = %relay.upstream, %error, "upstream connect failed; retrying")
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
        .context("set TCP keepalive")?;
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
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "legacy relay data");
        }
    }
}

async fn run_relay(relay: RelayConfig) -> Result<()> {
    let listen_addr: std::net::SocketAddr =
        relay.listen.parse().context("parse listener address")?;
    let socket = if listen_addr.ip().is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(listen_addr)?;
    let listener = socket.listen(relay.backlog)?;
    let slots = Arc::new(Semaphore::new(relay.max_connections));
    info!(relay = %relay.name, listen = %relay.listen, upstream = %relay.upstream,
        max_connections = relay.max_connections, backlog = relay.backlog,
        "relay listening");

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
            accepted = listener.accept() => accepted.context("accept client")?,
        };
        let peer_ip = peer.ip();
        if !relay.allow.is_empty() && !relay.allow.iter().any(|network| network.contains(&peer_ip))
        {
            warn!(relay = %relay.name, peer = %peer, "client rejected by ACL");
            drop(client);
            continue;
        }
        let permit = match slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(relay = %relay.name, peer = %peer, "client rejected: connection limit");
                drop(client);
                continue;
            }
        };
        let profile = relay.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(profile, client, peer).await {
                warn!(peer = %peer, error = %error, "relay connection ended with error");
            }
        });
    }
    info!(relay = %relay.name, "relay listener stopped");
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let ctrl_c = tokio::signal::ctrl_c();
    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => info!("received Ctrl-C; shutting down"),
        _ = terminate.recv() => info!("received SIGTERM; shutting down"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received Ctrl-C; shutting down");
}

async fn handle_connection(
    relay: RelayConfig,
    client: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    configure_keepalive(&client, &relay.client_keepalive)?;
    info!(relay = %relay.name, peer = %peer, "client accepted");
    let upstream = connect_forever(&relay).await?;
    configure_keepalive(&upstream, &relay.upstream_keepalive)?;
    let (client_reader, client_writer) = client.into_split();
    let (upstream_reader, upstream_writer) = upstream.into_split();
    let mut client_to_upstream = tokio::spawn(relay_direction(
        client_reader,
        upstream_writer,
        relay.verbose_payload_logging,
        "client_to_upstream",
    ));
    let mut upstream_to_client = tokio::spawn(relay_direction(
        upstream_reader,
        client_writer,
        relay.verbose_payload_logging,
        "upstream_to_client",
    ));
    tokio::select! {
        result = &mut client_to_upstream => {
            if timeout(Duration::from_secs(relay.eof_grace_seconds), &mut upstream_to_client).await.is_err() {
                upstream_to_client.abort();
            }
            result.context("client to upstream task")?.context("client to upstream copy")?;
        }
        result = &mut upstream_to_client => {
            if timeout(Duration::from_secs(relay.eof_grace_seconds), &mut client_to_upstream).await.is_err() {
                client_to_upstream.abort();
            }
            result.context("upstream to client task")?.context("upstream to client copy")?;
        }
    }
    info!(relay = %relay.name, peer = %peer, "relay connection closed");
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
                info!(relay = %relay.name, upstream = %relay.upstream, "upstream connected");
                return Ok(stream);
            }
            Ok(Err(error)) => {
                warn!(relay = %relay.name, upstream = %relay.upstream, %error, "upstream connect failed; retrying")
            }
            Err(_) => {
                warn!(relay = %relay.name, upstream = %relay.upstream, timeout_seconds, "upstream connect timed out; retrying")
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
        .context("set TCP keepalive")?;
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
            info!(direction, bytes = count, payload = %String::from_utf8_lossy(&buffer[..count]), "relay data");
        } else {
            tracing::debug!(direction, bytes = count, "relay data");
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

//! TCP endpoint: подключение к upstream с повторами и исходящим TLS.
use anyhow::{Context, Result, bail};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::{RelayConfig, advice, session::Session, transport};

pub async fn open(
    relay: &RelayConfig,
    monitor: &advice::Monitor,
    tls: &transport::Runtime,
) -> Result<Session> {
    let (upstream, policy_generation) = connect_forever(relay, monitor).await?;
    configure_keepalive(&upstream, &relay.upstream_keepalive)?;
    #[cfg(feature = "tls")]
    let upstream = {
        let started = std::time::Instant::now();
        let result = tls.connect(upstream).await;
        if relay.outbound_tls.is_some() {
            monitor.tls_attempt(started.elapsed(), result.is_ok(), policy_generation);
        }
        result?
    };
    #[cfg(not(feature = "tls"))]
    let upstream = {
        let _ = policy_generation;
        tls.connect(upstream).await?
    };
    Ok(Session::Tcp { upstream })
}

pub fn retry_time_remaining(window_seconds: u64, elapsed: Duration) -> Option<Duration> {
    if window_seconds == 0 {
        None
    } else {
        Some(Duration::from_secs(window_seconds).saturating_sub(elapsed))
    }
}

async fn connect_forever(
    relay: &RelayConfig,
    monitor: &advice::Monitor,
) -> Result<(TcpStream, u64)> {
    let upstream = relay.upstream()?;
    let mut delay = Duration::from_secs(1);
    let started_at = tokio::time::Instant::now();
    loop {
        let remaining =
            retry_time_remaining(relay.upstream_retry_window_seconds, started_at.elapsed());
        if remaining.is_some_and(|remaining| remaining.is_zero()) {
            bail!(
                "relay {}: upstream {} недоступен дольше {} секунд; завершаем клиентскую сессию и освобождаем ресурсы",
                relay.name,
                upstream,
                relay.upstream_retry_window_seconds
            );
        }
        let (timeout_seconds, policy_generation) = monitor.timeout_policy();
        let attempt_timeout = remaining
            .map(|left| left.min(Duration::from_secs(timeout_seconds)))
            .unwrap_or_else(|| Duration::from_secs(timeout_seconds));
        let started = std::time::Instant::now();
        match timeout(attempt_timeout, TcpStream::connect(upstream)).await {
            Ok(Ok(stream)) => {
                monitor.tcp_attempt(started.elapsed(), true, false, policy_generation);
                info!(relay = %relay.name, upstream, tcp_timeout_seconds = timeout_seconds, policy_generation, "upstream подключён");
                return Ok((stream, policy_generation));
            }
            Ok(Err(error)) => {
                monitor.tcp_attempt(started.elapsed(), false, false, policy_generation);
                warn!(relay = %relay.name, upstream, %error, "ошибка подключения к upstream; повторная попытка")
            }
            Err(_) => {
                monitor.tcp_attempt(started.elapsed(), false, true, policy_generation);
                if retry_time_remaining(relay.upstream_retry_window_seconds, started_at.elapsed())
                    .is_some_and(|remaining| remaining.is_zero())
                {
                    continue;
                }
                warn!(relay = %relay.name, upstream, timeout_seconds, "истёк тайм-аут подключения к upstream; повторная попытка")
            }
        }
        let sleep_for =
            retry_time_remaining(relay.upstream_retry_window_seconds, started_at.elapsed())
                .map(|left| left.min(delay))
                .unwrap_or(delay);
        sleep(sleep_for).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

pub fn configure_keepalive(stream: &TcpStream, config: &crate::KeepaliveConfig) -> Result<()> {
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

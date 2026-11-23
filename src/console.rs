//! Клиент консольного режима: локальный терминал в raw, кадры поверх TLS.
use anyhow::{Context, Result, bail};
use std::{os::fd::AsRawFd, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info};

use crate::{framing, transport};

pub struct Options {
    pub address: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub server_name: String,
}

/// Восстанавливает termios при выходе, в том числе по ошибке.
struct RawTerminal(libc::termios);

impl RawTerminal {
    fn enable() -> Result<Self> {
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: termios заполняется ядром; дескриптор stdin открыт.
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            bail!(
                "stdin не является терминалом: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut raw = original;
        // SAFETY: raw — копия валидной структуры.
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            bail!(
                "перевести терминал в raw: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self(original))
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: структура получена из tcgetattr.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &self.0) };
    }
}

fn terminal_size() -> (u16, u16) {
    // SAFETY: ioctl заполняет winsize; при ошибке остаются значения по умолчанию.
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(std::io::stdout().as_raw_fd(), libc::TIOCGWINSZ, &mut size) } != 0 {
        return (24, 80);
    }
    (size.ws_row.max(1), size.ws_col.max(1))
}

pub async fn run(options: Options) -> Result<i32> {
    let outbound = transport::OutboundTls {
        mode: transport::Mode::Tls,
        ca_file: options.ca,
        server_name: options.server_name,
        certificate: Some(options.certificate),
        private_key: Some(options.private_key),
        gost_cipher: None,
        handshake_timeout_seconds: 10,
    };
    outbound.validate()?;
    let runtime = transport::Runtime::build(None, Some(&outbound))?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&options.address),
    )
    .await
    .context("таймаут подключения к relay")?
    .with_context(|| format!("подключиться к {}", options.address))?;
    tcp.set_nodelay(true).ok();
    let mut stream = runtime.connect(tcp).await?;
    stream.write_all(framing::PREFACE).await?;
    let (rows, columns) = terminal_size();
    framing::write_message(&mut stream, &framing::Message::Resize { rows, columns }).await?;
    info!(address = %options.address, "консоль подключена");

    let _raw = RawTerminal::enable()?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut window = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .context("подписаться на SIGWINCH")?;
    let mut input = [0_u8; 8192];
    let mut input_open = true;

    let code = loop {
        tokio::select! {
            read = stdin.read(&mut input), if input_open => {
                let count = read.context("чтение stdin")?;
                if count == 0 {
                    input_open = false;
                    framing::write_message(&mut writer, &framing::Message::Exit { code: 0 }).await?;
                } else {
                    framing::write_message(&mut writer, &framing::Message::Data(input[..count].to_vec())).await?;
                }
            }
            message = framing::read_message(&mut reader) => {
                match message? {
                    Some(framing::Message::Data(data)) => {
                        stdout.write_all(&data).await?;
                        // stdout буферизован построчно: приглашение без \n
                        // иначе останется в буфере.
                        stdout.flush().await?;
                    }
                    Some(framing::Message::Exit { code }) => break code,
                    Some(framing::Message::Resize { .. }) => debug!("resize от сервера"),
                    None => break 0,
                }
            }
            _ = window.recv() => {
                let (rows, columns) = terminal_size();
                framing::write_message(&mut writer, &framing::Message::Resize { rows, columns }).await?;
            }
        }
    };
    stdout.flush().await.ok();
    Ok(code)
}

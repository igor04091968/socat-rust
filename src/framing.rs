//! Версионированное обрамление консольного протокола.
//!
//! Клиент `console` сразу после TLS отправляет [`PREFACE`]. Дальше обе стороны
//! обмениваются кадрами: тип (1 байт), длина (4 байта, big-endian), полезная
//! нагрузка. Обычные данные идут кадрами [`DATA`], поэтому управляющие
//! сообщения не смешиваются с потоком.
use anyhow::{Context, Result, bail};
use std::borrow::Cow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PREFACE: &[u8; 5] = b"\0SRC1";
pub const DATA: u8 = 1;
pub const RESIZE: u8 = 2;
pub const EXIT: u8 = 3;
/// Верхняя граница кадра: защищает от повреждённой или враждебной длины.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Data(Vec<u8>),
    Resize { rows: u16, columns: u16 },
    Exit { code: i32 },
}

pub async fn write_message<W>(writer: &mut W, message: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let (kind, payload): (u8, Cow<'_, [u8]>) = match message {
        Message::Data(data) => (DATA, Cow::Borrowed(data)),
        Message::Resize { rows, columns } => {
            let mut payload = Vec::with_capacity(4);
            payload.extend_from_slice(&rows.to_be_bytes());
            payload.extend_from_slice(&columns.to_be_bytes());
            (RESIZE, Cow::Owned(payload))
        }
        Message::Exit { code } => (EXIT, Cow::Owned(code.to_be_bytes().to_vec())),
    };
    if payload.len() > MAX_FRAME {
        bail!("кадр консоли больше {MAX_FRAME} байт");
    }
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await.context("заголовок кадра")?;
    writer
        .write_all(&payload)
        .await
        .context("полезная нагрузка кадра")?;
    Ok(())
}

/// `Ok(None)` — чистое закрытие соединения на границе кадра.
pub async fn read_message<R>(reader: &mut R) -> Result<Option<Message>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("заголовок кадра"),
    }
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_FRAME {
        bail!("кадр консоли длиной {length} превышает {MAX_FRAME}");
    }
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("полезная нагрузка кадра")?;
    match header[0] {
        DATA => Ok(Some(Message::Data(payload))),
        RESIZE if length == 4 => Ok(Some(Message::Resize {
            rows: u16::from_be_bytes([payload[0], payload[1]]),
            columns: u16::from_be_bytes([payload[2], payload[3]]),
        })),
        EXIT if length == 4 => Ok(Some(Message::Exit {
            code: i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
        })),
        RESIZE => bail!("кадр RESIZE имеет длину {length}, ожидалось 4"),
        EXIT => bail!("кадр EXIT имеет длину {length}, ожидалось 4"),
        other => bail!("неизвестный тип кадра консоли: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_all_messages() {
        let mut buffer = Vec::new();
        for message in [
            Message::Data(b"hello".to_vec()),
            Message::Resize {
                rows: 40,
                columns: 120,
            },
            Message::Exit { code: 7 },
        ] {
            write_message(&mut buffer, &message).await.unwrap();
        }
        let mut reader = buffer.as_slice();
        assert_eq!(
            read_message(&mut reader).await.unwrap(),
            Some(Message::Data(b"hello".to_vec()))
        );
        assert_eq!(
            read_message(&mut reader).await.unwrap(),
            Some(Message::Resize {
                rows: 40,
                columns: 120
            })
        );
        assert_eq!(
            read_message(&mut reader).await.unwrap(),
            Some(Message::Exit { code: 7 })
        );
        assert_eq!(read_message(&mut reader).await.unwrap(), None);
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let mut buffer = vec![DATA];
        buffer.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        let mut reader = buffer.as_slice();
        assert!(read_message(&mut reader).await.is_err());
    }
}

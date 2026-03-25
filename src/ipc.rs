//! Length-prefixed JSON over a Unix stream (u32 BE length + UTF-8 body).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};

use crate::adapters::claude::HookResponse;

/// Client → server request.
#[derive(Debug, Deserialize)]
pub struct AdjudicateRequest {
    /// e.g. `pre-tool-use`, or `ping`, `reload`
    pub hook: String,
    /// Claude hook JSON body
    #[serde(default)]
    pub payload: Value,
}

/// Server → client response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdjudicateOk {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HookResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AdjudicateOk {
    pub fn success(response: HookResponse) -> Self {
        Self {
            ok: true,
            response: Some(response),
            data: None,
            error: None,
        }
    }

    pub fn data(data: Value) -> Self {
        Self {
            ok: true,
            response: None,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            response: None,
            data: None,
            error: Some(msg.into()),
        }
    }

    pub fn pong() -> Self {
        Self {
            ok: true,
            response: Some(HookResponse::allow()),
            data: None,
            error: None,
        }
    }
}

const MAX_FRAME: u32 = 64 * 1024 * 1024;

fn ensure_frame_len(n: u32) -> std::io::Result<()> {
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {n}"),
        ));
    }
    Ok(())
}

pub fn read_frame(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let n = u32::from_be_bytes(len_buf);
    ensure_frame_len(n)?;
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    let n: u32 = body
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "body too large"))?;
    ensure_frame_len(n)?;
    w.write_all(&n.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

pub async fn read_frame_async(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf);
    ensure_frame_len(n)?;
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame_async(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    body: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let n: u32 = body
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "body too large"))?;
    ensure_frame_len(n)?;
    w.write_all(&n.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sync_frame_round_trip() {
        for payload in [b"".as_slice(), b"hello", b"\x00\xff\x00"] {
            let mut buf = Vec::new();
            write_frame(&mut buf, payload).unwrap();
            let out = read_frame(&mut Cursor::new(buf)).unwrap();
            assert_eq!(out, payload);
        }
    }

    #[test]
    fn rejects_oversized_length_header() {
        let len: u32 = MAX_FRAME + 1;
        let mut buf = len.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let err = read_frame(&mut Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn async_frame_round_trip() {
        let payload = b"async payload";
        let mut buf = Vec::new();
        write_frame_async(&mut buf, payload).await.unwrap();
        let out = read_frame_async(&mut buf.as_slice()).await.unwrap();
        assert_eq!(out, payload);
    }
}

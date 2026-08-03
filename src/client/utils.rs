use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use rand::RngExt;
use std::fmt::Write as _;
use std::future::Future;
use tokio::task::JoinHandle;
use tracing::warn;
use uuid::Uuid;

use crate::client::constants::{MIN_PADDING, PADDING_POOL};
use crate::shaper::{self, FrameCipher};

#[inline]
fn build_cookie_into(buf: &mut String, name: &str, value: impl std::fmt::Display) {
    buf.clear();
    let cap = name.len() + 1 + 36 + 2 + MIN_PADDING + PADDING_POOL.len();
    buf.reserve(cap);
    buf.push_str(name);
    buf.push('=');
    let _ = write!(buf, "{value}");
    buf.push_str("; ");
    let padding_len = rand::rng().random_range(MIN_PADDING..PADDING_POOL.len());
    buf.push_str(std::str::from_utf8(&PADDING_POOL[..padding_len]).expect("Invalid UTF-8"))
}

#[inline]
pub fn build_tunnel_cookie(buf: &mut String, session_val: &str) {
    build_cookie_into(buf, "session", session_val)
}

#[inline]
pub fn build_stream_cookie(buf: &mut String, stream_id: Uuid) {
    build_cookie_into(buf, "stream", stream_id.as_hyphenated())
}

pub fn encode_initial_payload(
    initial_payload: &[u8],
    max_bytes: usize,
    cipher: Option<&dyn FrameCipher>,
    config: &shaper::TrafficConfig,
) -> Result<(Vec<u8>, Bytes, u64)> {
    let take_len = initial_payload.len().min(max_bytes);
    let data_to_send = &initial_payload[..take_len];
    let remaining = if take_len < initial_payload.len() {
        Bytes::copy_from_slice(&initial_payload[take_len..])
    } else {
        Bytes::new()
    };

    let raw_payload_limit = match (cipher.is_some(), config.encoding_type) {
        (true, shaper::EncodingType::Json) => shaper::JSON_PAYLOAD_CAP_CIPHER,
        (false, shaper::EncodingType::Json) => shaper::JSON_PAYLOAD_CAP_PLAIN,
        _ => shaper::MAX_RAW_PAYLOAD,
    };
    let mut body = Vec::new();
    let mut offset = 0;
    let mut seq: u64 = 0;

    while offset < data_to_send.len() {
        let chunk_end = (offset + raw_payload_limit).min(data_to_send.len());
        let chunk = &data_to_send[offset..chunk_end];
        let frame = shaper::encode_frame(
            chunk,
            seq,
            cipher,
            config.global.padding_threshold,
            config.global.padding_range,
            config.encoding_type,
        )
        .context("encode_frame failed on initial payload")?;
        body.extend_from_slice(&frame);
        offset = chunk_end;
        seq += 1;
    }

    Ok((body, remaining, seq))
}

pub async fn race_upload_download<F: Future<Output = Result<()>>>(
    mut upload_task: JoinHandle<Result<()>>,
    download_fut: F,
    download_label: Option<&'static str>,
) -> Result<()> {
    tokio::pin!(download_fut);
    tokio::select! {
        biased;
        upload_res = &mut upload_task => {
            let upload_outcome: Result<()> = match upload_res {
                Ok(r) => r,
                Err(e) if e.is_cancelled() => Ok(()),
                Err(e) => Err(anyhow::anyhow!("upload task panicked: {e}")),
            };
            if let Err(ref e) = upload_outcome {
                warn!(reason = %e, "upload failed; aborting download");
                return upload_outcome;
            }
            download_fut.await
        }
        dl_res = &mut download_fut => {
            upload_task.abort();
            let _ = upload_task.await;
            if let Err(ref e) = dl_res {
                warn!(reason = %e, "download failed; upload task aborted");
            }
            if let Some(label) = download_label {
                dl_res.context(label)
            } else {
                dl_res
            }
        }
    }
}

#[inline]
pub fn is_silent_error(root: &(dyn std::error::Error + 'static)) -> bool {
    use std::io::ErrorKind::*;
    if let Some(e) = root.downcast_ref::<h2::Error>() {
        return e.is_reset()
            || e.is_library()
            || matches!(
                e.reason(),
                Some(
                    h2::Reason::CANCEL
                        | h2::Reason::REFUSED_STREAM
                        | h2::Reason::ENHANCE_YOUR_CALM
                        | h2::Reason::FLOW_CONTROL_ERROR
                        | h2::Reason::STREAM_CLOSED
                        | h2::Reason::INTERNAL_ERROR
                )
            );
    }
    if let Some(e) = root.downcast_ref::<std::io::Error>() {
        return matches!(
            e.kind(),
            ConnectionReset | UnexpectedEof | NotConnected | BrokenPipe
        );
    }
    root.to_string()
        .contains("connection closed during header parsing")
}

pub(crate) async fn check_response_status(
    response: wreq::Response,
    context: &str,
) -> Result<wreq::Response> {
    if !response.status().is_success() {
        let status = response.status();
        let _ = response.bytes().await;
        return Err(anyhow!("{context}: {status}"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cookie_contains_session() {
        let mut buf = String::new();
        build_tunnel_cookie(&mut buf, "abc:def:ghi");
        assert!(buf.starts_with("session=abc:def:ghi; "));
        assert!(buf.len() > 25);
    }

    #[test]
    fn encode_zero_payload() {
        let config = shaper::TrafficConfig {
            global: shaper::PaddingConfig {
                padding_threshold: 16384,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: Default::default(),
            max_download_bytes: None,
        };
        let (body, remaining, seq) =
            encode_initial_payload(b"", shaper::MAX_RAW_PAYLOAD, None, &config).unwrap();
        assert!(body.is_empty());
        assert!(remaining.is_empty());
        assert_eq!(seq, 0);
    }

    #[test]
    fn is_silent_reset() {
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(is_silent_error(&e));
    }

    #[test]
    fn is_not_silent_other() {
        let e = std::io::Error::other("other");
        assert!(!is_silent_error(&e));
    }

    #[test]
    fn encode_initial_payload_json_chunks_roundtrip() {
        use crate::shaper::{
            DecodedFrame, EncodingType, PaddingConfig, TrafficConfig, decode_frame,
        };
        use bytes::BytesMut;
        let cfg = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Json,
            max_download_bytes: None,
        };
        let data: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
        let (body, remaining, seq) = encode_initial_payload(&data, usize::MAX, None, &cfg).unwrap();
        assert!(remaining.is_empty());
        let mut src = BytesMut::from(&body[..]);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut decoded = Vec::new();
        let mut count = 0u64;
        while let Some(frame) = decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Json,
        )
        .unwrap()
        {
            match frame {
                DecodedFrame::Owned { data, .. } => decoded.extend_from_slice(&data),
                DecodedFrame::InScratch { start, end, .. } => {
                    decoded.extend_from_slice(&scratch[start..end])
                }
            }
            count += 1;
        }
        assert_eq!(count, seq);
        assert_eq!(decoded, data);
    }

    #[test]
    fn h2_reset_error_is_silent() {
        let e = h2::Error::from(h2::Reason::CANCEL);
        assert!(is_silent_error(&e));
        let other = h2::Error::from(h2::Reason::CONNECT_ERROR);
        assert!(!is_silent_error(&other));
    }
}

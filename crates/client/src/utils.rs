use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use rand::RngExt;
use std::fmt::Write as _;
use std::future::Future;
use tokio::task::JoinHandle;
use tracing::warn;
use uuid::Uuid;

use crate::constants::{MIN_PADDING, PADDING_POOL};
use crate::cronet::Response;
use httproxy_core::shaper::{self, FrameCipher};

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
    initial_payload: &Bytes,
    max_bytes: usize,
    cipher: &dyn FrameCipher,
    config: &shaper::TrafficConfig,
) -> Result<(Bytes, Bytes, u64)> {
    let take_len = initial_payload.len().min(max_bytes);
    let data_to_send = &initial_payload[..take_len];
    let remaining = if take_len < initial_payload.len() {
        initial_payload.slice(take_len..)
    } else {
        Bytes::new()
    };

    let raw_payload_limit = match config.encoding_type {
        shaper::EncodingType::Json => shaper::JSON_PAYLOAD_CAP,
        shaper::EncodingType::Binary => shaper::MAX_RAW_PAYLOAD,
    };
    let frame_count = data_to_send.len().div_ceil(raw_payload_limit.max(1));
    let mut body =
        Vec::with_capacity(frame_count * shaper::max_encoded_frame_len(config.encoding_type));
    let mut offset = 0;
    let mut seq: u64 = 0;

    while offset < data_to_send.len() {
        let chunk_end = (offset + raw_payload_limit).min(data_to_send.len());
        let chunk = &data_to_send[offset..chunk_end];
        shaper::encode_frame_into(
            chunk,
            seq,
            cipher,
            config.global.padding_threshold,
            config.global.padding_range,
            config.encoding_type,
            &mut body,
        )
        .context("encode_frame failed on initial payload")?;
        offset = chunk_end;
        seq += 1;
    }

    Ok((shaper::pooled_frame_bytes(body), remaining, seq))
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn race_upload_download<F: Future<Output = Result<()>>>(
    mut upload_task: JoinHandle<Result<()>>,
    download_fut: F,
    download_label: Option<&'static str>,
) -> Result<()> {
    let _upload_guard = AbortOnDrop(upload_task.abort_handle());
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

pub(crate) fn check_response_status(response: Response, context: &str) -> Result<Response> {
    if !response.status().is_success() {
        let status = response.status();
        return Err(anyhow!("{context}: {status}"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httproxy_core::test_support::test_cipher;

    #[tokio::test]
    async fn cancelling_the_connection_aborts_the_upload_task() {
        let (released, receiver) = tokio::sync::oneshot::channel::<()>();
        let upload = tokio::spawn(async move {
            let _released = released;
            std::future::pending::<Result<()>>().await
        });
        let mut connection = Box::pin(race_upload_download(
            upload,
            std::future::pending::<Result<()>>(),
            None,
        ));
        assert!(futures::poll!(&mut connection).is_pending());
        drop(connection);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
                .await
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn encode_initial_payload_json_chunks_roundtrip() {
        use bytes::BytesMut;
        use httproxy_core::shaper::{
            DecodedFrame, EncodingType, PaddingConfig, TrafficConfig, decode_frame,
        };
        let cfg = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            handshake: None,
            stages: vec![],
            encoding_type: EncodingType::Json,
            max_download_bytes: None,
        };
        let data: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
        let cipher = test_cipher();
        let (body, remaining, seq) =
            encode_initial_payload(&Bytes::from(data.clone()), usize::MAX, &cipher, &cfg).unwrap();
        assert!(remaining.is_empty());
        let mut src = BytesMut::from(&body[..]);
        let mut json_scratch = Vec::new();
        let mut decoded = Vec::new();
        let mut count = 0u64;
        while let Some(frame) =
            decode_frame(&mut src, &mut json_scratch, &cipher, EncodingType::Json).unwrap()
        {
            match frame {
                DecodedFrame::Owned { data, .. } => decoded.extend_from_slice(&data),
                DecodedFrame::InJsonScratch { start, end, .. } => {
                    decoded.extend_from_slice(&json_scratch[start..end])
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

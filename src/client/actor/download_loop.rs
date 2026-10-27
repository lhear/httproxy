use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::oneshot;
use tracing::{Instrument, warn};
use uuid::Uuid;

use super::super::state::SharedState;
use crate::client::constants::{
    DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT, PREFETCH_LEAD_BYTES, PREFETCH_ROTATE_TIMEOUT,
    WRITE_BUF_CAPACITY, WRITE_FLUSH_TIMEOUT,
};
use crate::client::utils;
use crate::crypto::AesFrameCipher;
use crate::shaper::{self, DecodedFrame, EncodingType, FrameCipher};

enum Phase {
    Streaming {
        response: Box<wreq::Response>,
        expected_seq: u64,
        prefetch_at: Option<u64>,
        prefetch_trigger: Option<oneshot::Sender<()>>,
        prefetch_rx: Option<oneshot::Receiver<Result<wreq::Response>>>,
    },
    Rotating {
        expected_seq: u64,
        prefetch_rx: Option<oneshot::Receiver<Result<wreq::Response>>>,
    },
    Done,
}

pub struct DownloadLoopActor {
    write_half: OwnedWriteHalf,
    cipher: Option<Arc<dyn FrameCipher>>,
    encoding: EncodingType,
    stream_id: Uuid,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    max_bytes: Option<u64>,
    phase: Phase,
    buffers: DecodeBuffers,
}

/// 跨轮转复用的解码缓冲。
///
/// 每轮（`max_download_bytes` 触发换连接）都重新分配 16 KiB 解码缓冲 + 64 KiB
/// 写缓冲的代价不小，这里随 actor 一起存活，只保留容量。
struct DecodeBuffers {
    /// 未解完的帧字节
    input: BytesMut,
    /// 解密输出
    scratch: BytesMut,
    /// Base122 解码输出
    json_scratch: Vec<u8>,
    /// 待写回浏览器的明文
    out: BytesMut,
}

impl DecodeBuffers {
    fn new() -> Self {
        Self {
            input: BytesMut::with_capacity(DECODE_BUF_CAPACITY),
            scratch: BytesMut::new(),
            json_scratch: Vec::new(),
            out: BytesMut::with_capacity(WRITE_BUF_CAPACITY),
        }
    }

    /// 并入一个响应分块，并把其中所有完整帧解到 `out`。
    ///
    /// 缓冲为空且分块独占时直接接管其分配，整条路径不产生额外拷贝。
    fn ingest(
        &mut self,
        chunk: Bytes,
        cipher: Option<&dyn FrameCipher>,
        encoding: EncodingType,
        expected_seq: &mut u64,
    ) -> Result<()> {
        let mut src = if self.input.is_empty() {
            match chunk.try_into_mut() {
                Ok(chunk_mut) => chunk_mut,
                Err(chunk) => {
                    self.input.extend_from_slice(&chunk);
                    std::mem::take(&mut self.input)
                }
            }
        } else {
            self.input.extend_from_slice(&chunk);
            std::mem::take(&mut self.input)
        };

        while let Some(frame) = shaper::decode_frame(
            &mut src,
            &mut self.scratch,
            &mut self.json_scratch,
            cipher,
            encoding,
        )? {
            self.push_frame(frame, expected_seq)?;
        }

        // 保留残留字节，同时保留其容量给下一个分块复用
        self.input = src;
        Ok(())
    }

    #[inline]
    fn push_frame(&mut self, frame: DecodedFrame, expected_seq: &mut u64) -> Result<()> {
        let (seq, data): (u64, &[u8]) = match &frame {
            DecodedFrame::InScratch { seq, start, end } => (*seq, &self.scratch[*start..*end]),
            DecodedFrame::Owned { seq, data } => (*seq, &data[..]),
        };
        if seq != *expected_seq {
            return Err(anyhow!(
                "download frame seq {seq} out of order, expected {expected_seq}"
            ));
        }
        *expected_seq += 1;
        self.out.extend_from_slice(data);
        Ok(())
    }

    #[inline]
    async fn flush(&mut self, write_half: &mut OwnedWriteHalf) -> Result<()> {
        if !self.out.is_empty() {
            write_half.write_all(&self.out).await?;
            self.out.clear();
        }
        Ok(())
    }
}

impl DownloadLoopActor {
    pub fn new(
        initial_response: wreq::Response,
        write_half: OwnedWriteHalf,
        cipher: Option<Arc<AesFrameCipher>>,
        stream_id: Uuid,
        http_client: Arc<wreq::Client>,
        state: Arc<SharedState>,
    ) -> Self {
        let encoding = state.traffic_config.encoding_type;
        let cipher_dyn: Option<Arc<dyn FrameCipher>> = cipher.map(|c| c as Arc<dyn FrameCipher>);
        let max_bytes = state.max_download_bytes;
        let rotate_enabled = max_bytes.is_some_and(|m| m > 0);
        let prefetch_at = max_bytes.map(|m| m.saturating_sub(PREFETCH_LEAD_BYTES));
        let use_prefetch = prefetch_at.is_some_and(|at| at > 0);

        let (prefetch_trigger, prefetch_rx) = if rotate_enabled && use_prefetch {
            let (tx, rx) = spawn_prefetch_continuation(&http_client, &state, stream_id);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        Self {
            write_half,
            cipher: cipher_dyn,
            encoding,
            stream_id,
            http_client,
            state,
            max_bytes,
            phase: Phase::Streaming {
                response: Box::new(initial_response),
                expected_seq: 0,
                prefetch_at,
                prefetch_trigger,
                prefetch_rx,
            },
            buffers: DecodeBuffers::new(),
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            self.phase = match std::mem::replace(&mut self.phase, Phase::Done) {
                Phase::Streaming {
                    response,
                    expected_seq,
                    prefetch_at,
                    prefetch_trigger,
                    prefetch_rx,
                } => {
                    self.do_streaming(
                        *response,
                        expected_seq,
                        prefetch_at,
                        prefetch_trigger,
                        prefetch_rx,
                    )
                    .await?
                }
                Phase::Rotating {
                    expected_seq,
                    prefetch_rx,
                } => self.do_rotate(expected_seq, prefetch_rx).await?,
                Phase::Done => break,
            };
        }
        let _ = self.write_half.shutdown().await;
        Ok(())
    }

    async fn do_streaming(
        &mut self,
        response: wreq::Response,
        expected_seq: u64,
        prefetch_at: Option<u64>,
        prefetch_trigger: Option<oneshot::Sender<()>>,
        prefetch_rx: Option<oneshot::Receiver<Result<wreq::Response>>>,
    ) -> Result<Phase> {
        let (bytes, next_seq) = self
            .drain_response(response, expected_seq, prefetch_at, prefetch_trigger)
            .await?;

        let should_rotate = bytes > 0 && self.max_bytes.is_some_and(|m| bytes >= m);
        if !should_rotate {
            return Ok(Phase::Done);
        }

        Ok(Phase::Rotating {
            expected_seq: next_seq,
            prefetch_rx,
        })
    }

    async fn drain_response(
        &mut self,
        response: wreq::Response,
        mut expected_seq: u64,
        prefetch_at: Option<u64>,
        mut prefetch_trigger: Option<oneshot::Sender<()>>,
    ) -> Result<(u64, u64)> {
        let flush_deadline = tokio::time::sleep(WRITE_FLUSH_TIMEOUT);
        tokio::pin!(flush_deadline);
        let mut data_stream = response.into_data_stream();
        let mut bytes_received: u64 = 0;

        loop {
            tokio::select! {
                chunk = data_stream.next() => {
                    let Some(chunk) = chunk else { break };
                    let chunk = chunk.context("response read error")?;
                    bytes_received += chunk.len() as u64;

                    if let Some(at) = prefetch_at
                        && bytes_received >= at
                        && let Some(tx) = prefetch_trigger.take()
                    {
                        let _ = tx.send(());
                    }

                    self.buffers
                        .ingest(chunk, self.cipher.as_deref(), self.encoding, &mut expected_seq)?;

                    if self.buffers.out.len() >= WRITE_BUF_CAPACITY {
                        self.buffers.flush(&mut self.write_half).await?;
                        flush_deadline
                            .as_mut()
                            .reset(tokio::time::Instant::now() + WRITE_FLUSH_TIMEOUT);
                    }
                }
                _ = &mut flush_deadline, if !self.buffers.out.is_empty() => {
                    self.buffers.flush(&mut self.write_half).await?;
                    flush_deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + WRITE_FLUSH_TIMEOUT);
                }
            }
        }

        self.buffers.flush(&mut self.write_half).await?;

        if !self.buffers.input.is_empty() {
            warn!(
                remaining = self.buffers.input.len(),
                "download stream ended with undecoded data"
            );
            // 残留的半帧不能带到下一轮，直接丢弃
            self.buffers.input.clear();
        }
        Ok((bytes_received, expected_seq))
    }

    async fn do_rotate(
        &mut self,
        expected_seq: u64,
        prefetch_rx: Option<oneshot::Receiver<Result<wreq::Response>>>,
    ) -> Result<Phase> {
        let response = if let Some(rx) = prefetch_rx {
            tokio::pin!(rx);
            match tokio::time::timeout(PREFETCH_ROTATE_TIMEOUT, &mut rx).await {
                Ok(Ok(Ok(resp))) => resp,
                Ok(Ok(Err(_))) | Ok(Err(_)) => {
                    send_continue_request(&self.http_client, &self.state, self.stream_id).await?
                }
                Err(_elapsed) => {
                    warn!("prefetch slow, waiting one more window");
                    match tokio::time::timeout(PREFETCH_ROTATE_TIMEOUT, &mut rx).await {
                        Ok(Ok(Ok(resp))) => resp,
                        _ => {
                            return Err(anyhow!(
                                "prefetch continuation timed out after {}s",
                                2 * PREFETCH_ROTATE_TIMEOUT.as_secs()
                            ));
                        }
                    }
                }
            }
        } else {
            send_continue_request(&self.http_client, &self.state, self.stream_id).await?
        };

        let use_prefetch = self
            .max_bytes
            .map(|m| m.saturating_sub(PREFETCH_LEAD_BYTES))
            .is_some_and(|at| at > 0);
        let (prefetch_trigger, prefetch_rx) = if use_prefetch {
            let (tx, rx) =
                spawn_prefetch_continuation(&self.http_client, &self.state, self.stream_id);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let prefetch_at = self
            .max_bytes
            .map(|m| m.saturating_sub(PREFETCH_LEAD_BYTES));

        Ok(Phase::Streaming {
            response: Box::new(response),
            expected_seq,
            prefetch_at,
            prefetch_trigger,
            prefetch_rx,
        })
    }
}

async fn send_continue_request(
    http_client: &wreq::Client,
    state: &SharedState,
    stream_id: Uuid,
) -> Result<wreq::Response> {
    let mut cookie = String::new();
    utils::build_stream_cookie(&mut cookie, stream_id);
    let mut req = http_client
        .post(state.remote_str.as_str())
        .header("Cookie", cookie);
    if state.server_public_key.is_none() {
        req = req.header("Authorization", state.auth_header.as_str());
    }
    let resp = tokio::time::timeout(DOWNLOAD_CONNECT_TIMEOUT, req.send())
        .await
        .context("continuation timed out")?
        .context("continuation failed")?;
    let resp = utils::check_response_status(resp, "continuation rejected").await?;
    Ok(resp)
}

fn spawn_prefetch_continuation(
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
    stream_id: Uuid,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<Result<wreq::Response>>,
) {
    let (trigger_tx, trigger_rx) = oneshot::channel();
    let (result_tx, result_rx) = oneshot::channel();
    let pre_client = Arc::clone(http_client);
    let pre_state = Arc::clone(state);
    tokio::spawn(
        async move {
            if trigger_rx.await.is_err() {
                return;
            }
            match send_continue_request(&pre_client, &pre_state, stream_id).await {
                Ok(resp) => {
                    let _ = result_tx.send(Ok(resp));
                }
                Err(e) => {
                    warn!(error = %e, "prefetch failed");
                    let _ = result_tx.send(Err(e));
                }
            }
        }
        .instrument(tracing::Span::current()),
    );
    (trigger_tx, result_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffers() -> DecodeBuffers {
        DecodeBuffers::new()
    }

    #[test]
    fn ingest_accepts_frames_in_order() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        for (i, msg) in [b"abc".as_slice(), b"de".as_slice()].iter().enumerate() {
            let frame =
                shaper::encode_frame(msg, i as u64, None, 0, [0, 0], EncodingType::Binary).unwrap();
            bufs.ingest(
                Bytes::from(frame),
                None,
                EncodingType::Binary,
                &mut expected_seq,
            )
            .unwrap();
        }
        assert_eq!(&bufs.out[..], b"abcde");
        assert_eq!(expected_seq, 2);
        assert!(bufs.input.is_empty());
    }

    #[test]
    fn ingest_handles_split_frames() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        let frame =
            shaper::encode_frame(b"hello world", 0, None, 0, [0, 0], EncodingType::Binary).unwrap();
        let split = frame.len() / 2;

        bufs.ingest(
            Bytes::from(frame[..split].to_vec()),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();
        assert!(bufs.out.is_empty());
        assert!(!bufs.input.is_empty());

        bufs.ingest(
            Bytes::from(frame[split..].to_vec()),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();
        assert_eq!(&bufs.out[..], b"hello world");
        assert!(bufs.input.is_empty());
    }

    #[test]
    fn ingest_rejects_out_of_order() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        let frame = shaper::encode_frame(b"x", 5, None, 0, [0, 0], EncodingType::Binary).unwrap();
        assert!(
            bufs.ingest(
                Bytes::from(frame),
                None,
                EncodingType::Binary,
                &mut expected_seq
            )
            .is_err()
        );
        assert!(bufs.out.is_empty());
        assert_eq!(expected_seq, 0);
    }

    #[test]
    fn ingest_reuses_buffers_across_chunks() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        let initial_out_capacity = bufs.out.capacity();
        for i in 0..8u64 {
            let frame =
                shaper::encode_frame(&[0xAA; 1024], i, None, 0, [0, 0], EncodingType::Binary)
                    .unwrap();
            bufs.ingest(
                Bytes::from(frame),
                None,
                EncodingType::Binary,
                &mut expected_seq,
            )
            .unwrap();
            bufs.out.clear();
        }
        assert_eq!(expected_seq, 8);
        // 写缓冲容量被整批复用，不会随分块数量增长
        assert_eq!(bufs.out.capacity(), initial_out_capacity);
        assert!(bufs.input.is_empty());
    }
}

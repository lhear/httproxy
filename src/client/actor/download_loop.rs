use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::BodyExt;
use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::oneshot;
use tracing::{Instrument, warn};
use uuid::Uuid;

use super::super::state::SharedState;
use crate::client::constants::{
    DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT, MAX_WRITE_IOV, PREFETCH_LEAD_BYTES,
    PREFETCH_ROTATE_TIMEOUT, WRITE_BUF_CAPACITY, WRITE_FLUSH_TIMEOUT,
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
/// 每轮（`max_download_bytes` 触发换连接）都重新分配 16 KiB 解码缓冲的代价不小，
/// 这里随 actor 一起存活，只保留容量。
struct DecodeBuffers {
    /// 未解完的帧字节
    input: BytesMut,
    /// 解密输出
    scratch: BytesMut,
    /// Base122 解码输出
    json_scratch: Vec<u8>,
    /// 待写回浏览器的明文分块，用 `Bytes` 队列避免再拷一遍到写缓冲
    pending: VecDeque<Bytes>,
    pending_bytes: usize,
}

impl DecodeBuffers {
    fn new() -> Self {
        Self {
            input: BytesMut::with_capacity(DECODE_BUF_CAPACITY),
            scratch: BytesMut::new(),
            json_scratch: Vec::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
        }
    }

    /// 并入一个响应分块，并把其中所有完整帧放进待写队列。
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
        let (seq, data) = match frame {
            // 明文帧本来就是输入缓冲上的切片，直接排队，零拷贝
            DecodedFrame::Owned { seq, data } => (seq, data),
            DecodedFrame::InScratch { seq, start, end } => {
                // 解密结果落在可复用的 scratch 里：把它的分配整体交给 Bytes，
                // 下一帧再按需分配（比再 memcpy 一遍到写缓冲更划算）
                let plain = std::mem::replace(&mut self.scratch, BytesMut::new());
                (seq, plain.freeze().slice(start..end))
            }
        };
        if seq != *expected_seq {
            return Err(anyhow!(
                "download frame seq {seq} out of order, expected {expected_seq}"
            ));
        }
        *expected_seq += 1;
        self.pending_bytes += data.len();
        self.pending.push_back(data);
        Ok(())
    }

    #[inline]
    fn has_pending(&self) -> bool {
        self.pending_bytes > 0
    }

    #[inline]
    fn needs_flush(&self) -> bool {
        self.pending_bytes >= WRITE_BUF_CAPACITY
    }

    /// 用向量写把排队的明文一次吐给浏览器：省掉「拷进写缓冲」这一步，
    /// 同时仍然把多个小帧合并进同一次系统调用。
    async fn flush(&mut self, write_half: &mut OwnedWriteHalf) -> Result<()> {
        while !self.pending.is_empty() {
            let written = {
                let mut slices: [IoSlice<'_>; MAX_WRITE_IOV] =
                    std::array::from_fn(|_| IoSlice::new(&[]));
                let mut count = 0;
                let mut total = 0;
                for chunk in &self.pending {
                    slices[count] = IoSlice::new(chunk);
                    count += 1;
                    total += chunk.len();
                    if count == MAX_WRITE_IOV || total >= WRITE_BUF_CAPACITY {
                        break;
                    }
                }
                write_half.write_vectored(&slices[..count]).await?
            };
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            self.consume(written);
        }
        Ok(())
    }

    /// 从队头丢弃已经写出的 `n` 字节。
    fn consume(&mut self, mut n: usize) {
        while n > 0 {
            let Some(front) = self.pending.front_mut() else {
                break;
            };
            if front.len() <= n {
                n -= front.len();
                self.pending_bytes -= front.len();
                self.pending.pop_front();
            } else {
                // Bytes::advance 只是移动游标，不拷贝
                front.advance(n);
                self.pending_bytes -= n;
                n = 0;
            }
        }
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

                    if self.buffers.needs_flush() {
                        self.buffers.flush(&mut self.write_half).await?;
                        flush_deadline
                            .as_mut()
                            .reset(tokio::time::Instant::now() + WRITE_FLUSH_TIMEOUT);
                    }
                }
                _ = &mut flush_deadline, if self.buffers.has_pending() => {
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
    use crate::crypto::AesFrameCipher;
    use zeroize::Zeroizing;

    fn buffers() -> DecodeBuffers {
        DecodeBuffers::new()
    }

    /// 把待写队列拼成一段字节，方便断言。
    fn queued(bufs: &DecodeBuffers) -> Vec<u8> {
        bufs.pending
            .iter()
            .flat_map(|b| b.iter().copied())
            .collect()
    }

    fn frame(data: &[u8], seq: u64) -> Bytes {
        Bytes::from(shaper::encode_frame(data, seq, None, 0, [0, 0], EncodingType::Binary).unwrap())
    }

    #[test]
    fn ingest_accepts_frames_in_order() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        bufs.ingest(
            frame(b"abc", 0),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();
        bufs.ingest(
            frame(b"de", 1),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();

        assert_eq!(queued(&bufs), b"abcde");
        assert_eq!(bufs.pending_bytes, 5);
        assert_eq!(expected_seq, 2);
        assert!(bufs.input.is_empty());
    }

    #[test]
    fn ingest_hands_over_plain_frames_without_copying() {
        // 明文帧是输入分配上的切片：入队后仍与输入缓冲共用同一块内存
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        let raw = frame(&[0xAB; 512], 0);
        let raw_ptr = raw.as_ptr();
        bufs.ingest(raw, None, EncodingType::Binary, &mut expected_seq)
            .unwrap();

        let head = bufs.pending.front().expect("one pending chunk");
        assert_eq!(head.len(), 512);
        assert_eq!(
            head.as_ptr(),
            raw_ptr.wrapping_add(12),
            "payload must alias the input buffer, not a copy"
        );
    }

    #[test]
    fn ingest_handles_split_frames() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        let raw =
            shaper::encode_frame(b"hello world", 0, None, 0, [0, 0], EncodingType::Binary).unwrap();
        let split = raw.len() / 2;

        bufs.ingest(
            Bytes::from(raw[..split].to_vec()),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();
        assert!(!bufs.has_pending());
        assert!(!bufs.input.is_empty());

        bufs.ingest(
            Bytes::from(raw[split..].to_vec()),
            None,
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();
        assert_eq!(queued(&bufs), b"hello world");
        assert!(bufs.input.is_empty());
    }

    #[test]
    fn ingest_queues_decrypted_frames_without_copy() {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut *key);
        let cipher = AesFrameCipher::new(&key);
        let plain: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        let raw = shaper::encode_frame(
            &plain,
            0,
            Some(&cipher as &dyn FrameCipher),
            0,
            [0, 0],
            EncodingType::Binary,
        )
        .unwrap();

        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        bufs.ingest(
            Bytes::from(raw),
            Some(&cipher as &dyn FrameCipher),
            EncodingType::Binary,
            &mut expected_seq,
        )
        .unwrap();

        assert_eq!(queued(&bufs), plain);
        // scratch 的分配被交给 Bytes，槽位本身已经空了
        assert!(bufs.scratch.is_empty());
    }

    #[test]
    fn ingest_rejects_out_of_order() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        assert!(
            bufs.ingest(
                frame(b"x", 5),
                None,
                EncodingType::Binary,
                &mut expected_seq
            )
            .is_err()
        );
        assert!(!bufs.has_pending());
        assert_eq!(expected_seq, 0);
    }

    #[test]
    fn consume_walks_partial_chunks() {
        let mut bufs = buffers();
        bufs.pending.push_back(Bytes::from_static(b"aaa"));
        bufs.pending.push_back(Bytes::from_static(b"bbb"));
        bufs.pending.push_back(Bytes::from_static(b"ccc"));
        bufs.pending_bytes = 9;

        // 写出 4 字节：第一块整块消耗，第二块只前进 1 字节
        bufs.consume(4);
        assert_eq!(bufs.pending_bytes, 5);
        assert_eq!(bufs.pending.len(), 2);
        assert_eq!(&bufs.pending[0][..], b"bb");
        assert_eq!(&bufs.pending[1][..], b"ccc");

        bufs.consume(5);
        assert_eq!(bufs.pending_bytes, 0);
        assert!(bufs.pending.is_empty());
        assert!(!bufs.has_pending());
    }

    #[test]
    fn ingest_leaves_no_state_behind_across_chunks() {
        let mut bufs = buffers();
        let mut expected_seq = 0u64;
        for i in 0..8u64 {
            bufs.ingest(
                frame(&[0xAA; 1024], i),
                None,
                EncodingType::Binary,
                &mut expected_seq,
            )
            .unwrap();
            let written = bufs.pending_bytes;
            bufs.consume(written);
            assert!(
                bufs.input.is_empty(),
                "no leftover input after a full frame"
            );
            assert!(!bufs.has_pending());
        }
        assert_eq!(expected_seq, 8);
    }
}

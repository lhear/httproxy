use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, Waker};
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::Instrument;
use uuid::Uuid;

use super::super::state::SharedState;
use crate::client::constants::{
    BATCH_BUF_INITIAL_CAPACITY, MAX_BATCH_BYTES, UPLOAD_REQUEST_TIMEOUT,
};
use crate::client::utils;
use crate::crypto::AesFrameCipher;
use crate::shaper::{self, SealInto};

type ShaperStream = Pin<Box<dyn SealInto + Send>>;

enum Phase {
    Batching { batch_buf: BytesMut },
    Draining { inflight: usize },
    Done,
}

pub struct UploadLoopActor {
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    stream_id: Uuid,
    shaped: ShaperStream,
    request_sem: Arc<Semaphore>,
    bytes_sem: Arc<Semaphore>,
    max_batch_bytes: usize,
    tasks: JoinSet<Result<(), anyhow::Error>>,
    phase: Phase,
}

impl UploadLoopActor {
    pub fn new(
        http_client: Arc<wreq::Client>,
        state: Arc<SharedState>,
        initial_payload: Bytes,
        read_half: tokio::net::tcp::OwnedReadHalf,
        cipher: Option<Arc<AesFrameCipher>>,
        stream_id: Uuid,
        start_seq: u64,
    ) -> Self {
        let reader = AsyncReadExt::chain(std::io::Cursor::new(initial_payload), read_half);
        let traffic_cipher: Option<Arc<dyn shaper::FrameCipher>> =
            cipher.map(|c| c as Arc<dyn shaper::FrameCipher>);
        let shaped: ShaperStream = Box::pin(shaper::TrafficShaper::with_seq(
            reader,
            &state.resolved_traffic,
            traffic_cipher,
            start_seq,
        ));
        let upload_concurrency = state.upload_concurrency;
        let max_in_flight_bytes = state.max_in_flight_bytes;
        Self {
            http_client,
            state,
            stream_id,
            shaped,
            request_sem: Arc::new(Semaphore::new(upload_concurrency)),
            bytes_sem: Arc::new(Semaphore::new(max_in_flight_bytes)),
            max_batch_bytes: MAX_BATCH_BYTES.min(max_in_flight_bytes),
            tasks: JoinSet::new(),
            phase: Phase::Batching {
                batch_buf: BytesMut::with_capacity(BATCH_BUF_INITIAL_CAPACITY),
            },
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            self.phase = match std::mem::replace(&mut self.phase, Phase::Done) {
                Phase::Batching { batch_buf } => self.do_batching(batch_buf).await?,
                Phase::Draining { inflight } => {
                    self.do_drain(inflight).await?;
                    return Ok(());
                }
                Phase::Done => return Ok(()),
            };
        }
    }

    fn poll_seal(
        &mut self,
        cx: &mut TaskContext<'_>,
        batch_buf: &mut BytesMut,
    ) -> Poll<io::Result<Option<u64>>> {
        self.shaped.as_mut().poll_seal_into(cx, batch_buf)
    }

    async fn do_batching(&mut self, mut batch_buf: BytesMut) -> Result<Phase> {
        let mut stream_ended = false;

        if batch_buf.is_empty() {
            let seal =
                std::future::poll_fn(|cx| self.shaped.as_mut().poll_seal_into(cx, &mut batch_buf));
            tokio::select! {
                r = seal => match r {
                    Ok(Some(_)) => {}
                    Ok(None) => stream_ended = true,
                    Err(e) => return Err(e.into()),
                },
                result = self.tasks.join_next(), if !self.tasks.is_empty() => match result {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(e))) => return Err(e.context("upload POST failed")),
                    Some(Err(e)) => return Err(anyhow!("upload task panicked: {e}")),
                },
            }
        }

        if !stream_ended {
            let waker = Waker::noop();
            let mut cx = TaskContext::from_waker(waker);
            while batch_buf.len() < self.max_batch_bytes {
                match self.poll_seal(&mut cx, &mut batch_buf) {
                    Poll::Ready(Ok(Some(_))) => {}
                    Poll::Ready(Ok(None)) => {
                        stream_ended = true;
                        break;
                    }
                    Poll::Ready(Err(e)) => return Err(e.into()),
                    Poll::Pending => break,
                }
            }
        }

        if batch_buf.is_empty() {
            return if stream_ended {
                Ok(Phase::Draining {
                    inflight: self.tasks.len(),
                })
            } else {
                Ok(Phase::Batching { batch_buf })
            };
        }

        let req_permit = self
            .request_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("request semaphore closed"))?;
        let bytes_permit: OwnedSemaphorePermit = self
            .bytes_sem
            .clone()
            .acquire_many_owned(batch_buf.len() as u32)
            .await
            .map_err(|_| anyhow!("bytes semaphore closed"))?;
        let body = batch_buf.freeze();
        let http_client = Arc::clone(&self.http_client);
        let state_ref = Arc::clone(&self.state);
        let stream_id = self.stream_id;
        self.tasks.spawn(
            async move {
                let _req_guard = req_permit;
                let _bytes = bytes_permit;
                send_upload_post(&http_client, &state_ref, body, stream_id).await
            }
            .instrument(tracing::Span::current()),
        );
        while let Some(result) = self.tasks.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.context("upload POST failed")),
                Err(e) => return Err(anyhow!("upload task panicked: {e}")),
            }
        }
        if stream_ended {
            Ok(Phase::Draining {
                inflight: self.tasks.len(),
            })
        } else {
            Ok(Phase::Batching {
                batch_buf: BytesMut::with_capacity(BATCH_BUF_INITIAL_CAPACITY),
            })
        }
    }

    async fn do_drain(&mut self, mut inflight: usize) -> Result<()> {
        while inflight > 0 {
            match self.tasks.join_next().await {
                Some(Ok(Ok(()))) => {
                    inflight -= 1;
                }
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => return Err(anyhow!("upload task panicked: {e}")),
                None => break,
            }
        }
        Ok(())
    }
}

#[inline]
async fn send_upload_post(
    http_client: &wreq::Client,
    state: &SharedState,
    body: Bytes,
    stream_id: Uuid,
) -> Result<()> {
    debug_assert!(!body.is_empty(), "empty upload body");
    let mut cookie = String::new();
    utils::build_stream_cookie(&mut cookie, stream_id);
    let mut req = http_client
        .post(state.remote_str.as_str())
        .header("Accept-Encoding", "identity")
        .header("Cache-Control", "no-store, no-transform")
        .header("Content-Type", "application/octet-stream")
        .header("Cookie", cookie);
    if state.server_public_key.is_none() {
        req = req.header("Authorization", state.auth_header.as_str());
    }
    let response = tokio::time::timeout(
        UPLOAD_REQUEST_TIMEOUT,
        req.body(wreq::Body::from(body)).send(),
    )
    .await
    .context("upload POST timed out")?
    .context("http post failed")?;
    let response = utils::check_response_status(response, "upstream rejected upload").await?;
    response.bytes().await.context("drain upload response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaper::{
        DecodedFrame, EncodingType, PaddingConfig, ResolvedShaperConfig, TrafficConfig,
        decode_frame,
    };
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;

    fn test_state(remote: &str, max_in_flight: usize) -> Arc<SharedState> {
        let traffic = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        Arc::new(SharedState {
            remote_str: remote.to_string(),
            auth_header: "Bearer test-token".to_string(),
            traffic_config: traffic.clone(),
            resolved_traffic: Arc::new(ResolvedShaperConfig::resolve(&traffic)),
            bypass: None,
            server_public_key: None,
            proxy_auth: None,
            initial_master: Mutex::new(None),
            handshake_lock: Mutex::new(()),
            max_download_bytes: None,
            max_connections: 8,
            max_in_flight_bytes: max_in_flight,
            upload_concurrency: 4,
        })
    }

    async fn spawn_collector() -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut collected = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    r = listener.accept() => {
                        let Ok((mut sock, _)) = r else { break };
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 8192];
                        let header_end = loop {
                            let n = match sock.read(&mut tmp).await {
                                Ok(0) | Err(_) => break None,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(p + 4);
                            }
                        };
                        let Some(header_end) = header_end else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&buf[..header_end]);
                        let content_length = headers
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let mut body = buf[header_end..].to_vec();
                        while body.len() < content_length {
                            let n = match sock.read(&mut tmp).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            body.extend_from_slice(&tmp[..n]);
                        }
                        body.truncate(content_length);
                        collected.extend_from_slice(&body);
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            }
            collected
        });
        (addr, stop_tx, handle)
    }

    fn decode_all(received: &[u8]) -> Vec<u8> {
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut src = BytesMut::from(received);
        let mut decoded = Vec::new();
        while let Some(frame) = decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        )
        .unwrap()
        {
            match frame {
                DecodedFrame::Owned { data, .. } => decoded.extend_from_slice(&data),
                DecodedFrame::InScratch { .. } => panic!("unexpected InScratch frame"),
            }
        }
        decoded
    }

    fn test_client() -> Arc<wreq::Client> {
        Arc::new(wreq::Client::builder().no_proxy().build().unwrap())
    }

    async fn tcp_pair() -> (tokio::net::tcp::OwnedReadHalf, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        let (read_half, _write_half) = server_stream.into_split();
        (read_half, client)
    }

    #[tokio::test]
    async fn run_uploads_all_data_with_contiguous_seqs() {
        let (addr, stop_tx, collector) = spawn_collector().await;
        let state = test_state(&format!("http://{addr}/"), 64 * 1024);
        let client = test_client();
        let (read_half, mut writer) = tcp_pair().await;

        let initial: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let extra: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        let mut all = initial.clone();
        all.extend_from_slice(&extra);

        let actor = UploadLoopActor::new(
            client,
            state,
            Bytes::from(initial),
            read_half,
            None,
            Uuid::new_v4(),
            0,
        );
        let handle = tokio::spawn(async move { actor.run().await });

        writer.write_all(&extra).await.unwrap();
        drop(writer);
        handle
            .await
            .unwrap()
            .expect("upload loop must finish cleanly");

        let _ = stop_tx.send(());
        let received = collector.await.unwrap();
        assert!(!received.is_empty(), "server must receive upload frames");
        assert_eq!(decode_all(&received), all);
    }

    #[tokio::test]
    async fn run_starts_seq_from_configured_value() {
        let (addr, stop_tx, collector) = spawn_collector().await;
        let state = test_state(&format!("http://{addr}/"), 64 * 1024);
        let client = test_client();
        let (read_half, writer) = tcp_pair().await;
        drop(writer);

        let initial = vec![0xABu8; 40_000];
        let actor = UploadLoopActor::new(
            client,
            state,
            Bytes::from(initial),
            read_half,
            None,
            Uuid::new_v4(),
            7,
        );
        let handle = tokio::spawn(async move { actor.run().await });
        handle.await.unwrap().unwrap();

        let _ = stop_tx.send(());
        let received = collector.await.unwrap();
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut src = BytesMut::from(&received[..]);
        let mut seqs = Vec::new();
        while let Some(frame) = decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        )
        .unwrap()
        {
            match frame {
                DecodedFrame::Owned { seq, .. } => seqs.push(seq),
                DecodedFrame::InScratch { .. } => panic!("unexpected InScratch frame"),
            }
        }
        assert_eq!(seqs.first(), Some(&7));
        for w in seqs.windows(2) {
            assert_eq!(w[1], w[0] + 1, "seqs must be contiguous");
        }
    }

    #[tokio::test]
    async fn upload_failure_propagates_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);

        let state = test_state(&format!("http://{dead}/"), 64 * 1024);
        let client = test_client();
        let (read_half, writer) = tcp_pair().await;
        drop(writer);

        let initial = vec![0xCDu8; 30_000];
        let actor = UploadLoopActor::new(
            client,
            state,
            Bytes::from(initial),
            read_half,
            None,
            Uuid::new_v4(),
            0,
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), actor.run()).await;
        let err = result.expect("upload loop must fail fast").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("upload POST failed") || msg.contains("http post failed"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn empty_input_sends_no_requests() {
        let (addr, stop_tx, collector) = spawn_collector().await;
        let state = test_state(&format!("http://{addr}/"), 64 * 1024);
        let client = test_client();
        let (read_half, writer) = tcp_pair().await;
        drop(writer);

        let actor = UploadLoopActor::new(
            client,
            state,
            Bytes::new(),
            read_half,
            None,
            Uuid::new_v4(),
            5,
        );
        let handle = tokio::spawn(async move { actor.run().await });
        handle.await.unwrap().unwrap();

        let _ = stop_tx.send(());
        let received = collector.await.unwrap();
        assert!(received.is_empty(), "empty input must not send any POST");
    }
}

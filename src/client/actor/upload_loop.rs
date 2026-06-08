use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use futures::FutureExt;
use futures::StreamExt;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::Instrument;

use super::super::state::SharedState;
use crate::client::constants::{
    BATCH_BUF_INITIAL_CAPACITY, MAX_BATCH_BYTES, MAX_IN_FLIGHT_BYTES, UPLOAD_CONCURRENCY,
    UPLOAD_REQUEST_TIMEOUT,
};
use crate::client::utils;
use crate::crypto::AesFrameCipher;
use crate::shaper::{self, FrameCipher};

type ShaperStream = Pin<Box<dyn futures::Stream<Item = std::io::Result<(u64, Bytes)>> + Send>>;

enum Phase {
    Batching {
        batch_buf: BytesMut,
        bytes_permits: Vec<OwnedSemaphorePermit>,
        leftover: Option<Bytes>,
    },
    Draining {
        inflight: usize,
    },
    Done,
}

pub struct UploadLoopActor {
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    stream_id: String,
    shaped: ShaperStream,
    request_sem: Arc<Semaphore>,
    bytes_sem: Arc<Semaphore>,
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
        stream_id: String,
        start_seq: u64,
    ) -> Self {
        let reader = AsyncReadExt::chain(std::io::Cursor::new(initial_payload), read_half);
        let traffic_cipher: Option<Arc<dyn FrameCipher>> =
            cipher.map(|c| c as Arc<dyn FrameCipher>);
        let shaped: ShaperStream = Box::pin(shaper::TrafficShaper::with_seq(
            reader,
            state.traffic_config.clone(),
            traffic_cipher,
            start_seq,
        ));
        Self {
            http_client,
            state,
            stream_id,
            shaped,
            request_sem: Arc::new(Semaphore::new(UPLOAD_CONCURRENCY)),
            bytes_sem: Arc::new(Semaphore::new(MAX_IN_FLIGHT_BYTES)),
            tasks: JoinSet::new(),
            phase: Phase::Batching {
                batch_buf: BytesMut::with_capacity(BATCH_BUF_INITIAL_CAPACITY),
                bytes_permits: vec![],
                leftover: None,
            },
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            self.phase = match std::mem::replace(&mut self.phase, Phase::Done) {
                Phase::Batching {
                    batch_buf,
                    bytes_permits,
                    leftover,
                } => self.do_batching(batch_buf, bytes_permits, leftover).await?,
                Phase::Draining { inflight } => {
                    self.do_drain(inflight).await?;
                    return Ok(());
                }
                Phase::Done => return Ok(()),
            };
        }
    }

    async fn do_batching(
        &mut self,
        mut batch_buf: BytesMut,
        mut bytes_permits: Vec<OwnedSemaphorePermit>,
        mut leftover: Option<Bytes>,
    ) -> Result<Phase> {
        if let Some(data) = leftover.take() {
            let size = data.len() as u32;
            let permit = self
                .bytes_sem
                .clone()
                .acquire_many_owned(size)
                .await
                .map_err(|_| anyhow!("bytes semaphore closed"))?;
            batch_buf.put_slice(&data);
            bytes_permits.push(permit);
        }
        let mut stream_ended = false;
        if batch_buf.is_empty() {
            tokio::select! {
                frame = self.shaped.next() => match frame {
                    Some(Ok((_seq, data))) => {
                        let size = data.len() as u32;
                        let permit = self.bytes_sem.clone().acquire_many_owned(size).await.map_err(|_| anyhow!("bytes semaphore closed"))?;
                        batch_buf.put_slice(&data); bytes_permits.push(permit);
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => stream_ended = true,
                },
                result = self.tasks.join_next(), if !self.tasks.is_empty() => match result {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(e))) => return Err(e.context("upload POST failed")),
                    Some(Err(e)) => return Err(anyhow!("upload task panicked: {e}")),
                },
            }
        }
        while !stream_ended {
            match self.shaped.next().now_or_never() {
                Some(Some(Ok((_seq, data)))) => {
                    let frame_size = data.len();
                    if batch_buf.len() + frame_size > MAX_BATCH_BYTES {
                        leftover = Some(data);
                        break;
                    }
                    match self
                        .bytes_sem
                        .clone()
                        .try_acquire_many_owned(frame_size as u32)
                    {
                        Ok(permit) => {
                            batch_buf.put_slice(&data);
                            bytes_permits.push(permit);
                        }
                        Err(_) => {
                            leftover = Some(data);
                            break;
                        }
                    }
                }
                Some(Some(Err(e))) => return Err(e.into()),
                Some(None) => stream_ended = true,
                None => break,
            }
        }
        if batch_buf.is_empty() {
            return if stream_ended {
                Ok(Phase::Draining {
                    inflight: self.tasks.len(),
                })
            } else {
                Ok(Phase::Batching {
                    batch_buf,
                    bytes_permits,
                    leftover,
                })
            };
        }
        let req_permit = self
            .request_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("request semaphore closed"))?;
        let body = batch_buf.freeze();
        let http_client = Arc::clone(&self.http_client);
        let state_ref = Arc::clone(&self.state);
        let stream_id = self.stream_id.clone();
        self.tasks.spawn(
            async move {
                let _req_guard = req_permit;
                let _bytes = bytes_permits;
                send_upload_post(&http_client, &state_ref, body, &stream_id).await
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
                bytes_permits: vec![],
                leftover,
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
    stream_id: &str,
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

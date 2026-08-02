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

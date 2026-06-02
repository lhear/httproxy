use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use futures::StreamExt;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tracing::{Instrument, warn};

use super::super::state::SharedState;
use crate::client::constants::{
    DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT, PREFETCH_LEAD_BYTES, PREFETCH_ROTATE_TIMEOUT,
};
use crate::client::utils;
use crate::crypto::AesFrameCipher;
use crate::shaper::{self, EncodingType, FrameCipher};

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
    write_half: tokio::net::tcp::OwnedWriteHalf,
    cipher: Option<Arc<dyn FrameCipher>>,
    encoding: EncodingType,
    cookie_val: String,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    max_bytes: Option<u64>,
    phase: Phase,
}

impl DownloadLoopActor {
    pub fn new(
        initial_response: wreq::Response,
        write_half: tokio::net::tcp::OwnedWriteHalf,
        cipher: Option<Arc<AesFrameCipher>>,
        cookie_val: String,
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
            let (tx, rx) = spawn_prefetch_continuation(&http_client, &state, &cookie_val);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        Self {
            write_half,
            cipher: cipher_dyn,
            encoding,
            cookie_val,
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
        let (bytes, next_seq) = download_single_response(
            response,
            &mut self.write_half,
            self.cipher.as_deref(),
            self.encoding,
            expected_seq,
            prefetch_at,
            prefetch_trigger,
        )
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

    async fn do_rotate(
        &mut self,
        expected_seq: u64,
        prefetch_rx: Option<oneshot::Receiver<Result<wreq::Response>>>,
    ) -> Result<Phase> {
        let response = if let Some(rx) = prefetch_rx {
            match tokio::time::timeout(PREFETCH_ROTATE_TIMEOUT, rx).await {
                Ok(Ok(Ok(resp))) => resp,
                Ok(Ok(Err(_))) | Ok(Err(_)) => {
                    send_continue_request(&self.http_client, &self.state, &self.cookie_val).await?
                }
                Err(_elapsed) => {
                    warn!("prefetch timed out, falling back to synchronous continue");
                    send_continue_request(&self.http_client, &self.state, &self.cookie_val).await?
                }
            }
        } else {
            send_continue_request(&self.http_client, &self.state, &self.cookie_val).await?
        };

        let use_prefetch = self
            .max_bytes
            .map(|m| m.saturating_sub(PREFETCH_LEAD_BYTES))
            .is_some_and(|at| at > 0);
        let (prefetch_trigger, prefetch_rx) = if use_prefetch {
            let (tx, rx) =
                spawn_prefetch_continuation(&self.http_client, &self.state, &self.cookie_val);
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

async fn download_single_response(
    response: wreq::Response,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: Option<&dyn FrameCipher>,
    encoding: EncodingType,
    mut expected_seq: u64,
    prefetch_at: Option<u64>,
    mut prefetch_trigger: Option<oneshot::Sender<()>>,
) -> Result<(u64, u64)> {
    let mut buffer = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
    let mut data_stream = response.into_data_stream();
    let mut bytes_received: u64 = 0;

    while let Some(chunk) = data_stream.next().await {
        let chunk = chunk.context("response read error")?;
        bytes_received += chunk.len() as u64;

        if let Some(at) = prefetch_at
            && bytes_received >= at
            && let Some(tx) = prefetch_trigger.take()
        {
            let _ = tx.send(());
        }

        buffer.extend_from_slice(&chunk);
        while let Some((seq, frame_data, start, end)) =
            shaper::decode_frame_owned(&mut buffer, cipher, encoding)?
        {
            if seq != expected_seq {
                return Err(anyhow!(
                    "download frame seq {seq} out of order, expected {expected_seq}"
                ));
            }
            expected_seq += 1;
            write_half.write_all(&frame_data[start..end]).await?;
        }
    }

    if !buffer.is_empty() {
        warn!(
            remaining = buffer.len(),
            "download stream ended with undecoded data"
        );
    }
    Ok((bytes_received, expected_seq))
}

async fn send_continue_request(
    http_client: &wreq::Client,
    state: &SharedState,
    cookie_val: &str,
) -> Result<wreq::Response> {
    let mut cookie = String::new();
    utils::build_tunnel_cookie(&mut cookie, cookie_val);
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
    cookie_val: &str,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<Result<wreq::Response>>,
) {
    let (trigger_tx, trigger_rx) = oneshot::channel();
    let (result_tx, result_rx) = oneshot::channel();
    let pre_client = Arc::clone(http_client);
    let pre_state = Arc::clone(state);
    let pre_cookie = cookie_val.to_owned();
    tokio::spawn(
        async move {
            if trigger_rx.await.is_err() {
                return;
            }
            match send_continue_request(&pre_client, &pre_state, &pre_cookie).await {
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

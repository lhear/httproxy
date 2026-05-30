use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{FutureExt, StreamExt};
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tracing::warn;

use crate::client::constants::{
    DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT, MAX_BATCH_BYTES, MAX_IN_FLIGHT_BYTES,
    PREFETCH_LEAD_BYTES, UPLOAD_CONCURRENCY, UPLOAD_REQUEST_TIMEOUT,
};
use crate::client::utils;
use crate::crypto::AesFrameCipher;
use crate::shaper::{self, EncodingType, FrameCipher};

use super::state::SharedState;

#[inline]
pub async fn send_upload_post(
    http_client: &wreq::Client,
    state: &SharedState,
    body: Bytes,
    session_cookie_val: &str,
) -> Result<()> {
    debug_assert!(!body.is_empty(), "empty upload body");
    let mut cookie = String::new();
    utils::build_tunnel_cookie(&mut cookie, session_cookie_val);
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

    if !response.status().is_success() {
        let status = response.status();
        let _ = response.bytes().await;
        return Err(anyhow!("upstream rejected upload: {status}"));
    }
    response.bytes().await.context("drain upload response")?;
    Ok(())
}

pub async fn upload_loop(
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    initial_payload: Bytes,
    read_half: tokio::net::tcp::OwnedReadHalf,
    cipher: Option<Arc<AesFrameCipher>>,
    encrypted_session: String,
    start_seq: u64,
) -> Result<()> {
    let reader = AsyncReadExt::chain(std::io::Cursor::new(initial_payload), read_half);
    let traffic_cipher: Option<Arc<dyn FrameCipher>> = cipher.map(|c| c as Arc<dyn FrameCipher>);

    let mut shaped = Box::pin(shaper::TrafficShaper::with_seq(
        reader,
        state.traffic_config.clone(),
        traffic_cipher,
        start_seq,
    ));

    let request_sem = Arc::new(Semaphore::new(UPLOAD_CONCURRENCY));
    let bytes_sem = Arc::new(Semaphore::new(MAX_IN_FLIGHT_BYTES));

    let mut tasks: JoinSet<Result<(), anyhow::Error>> = JoinSet::new();
    let mut leftover: Option<Bytes> = None;

    loop {
        let mut batch_buf = BytesMut::with_capacity(8 * 1024);
        let mut stream_ended = false;
        let mut bytes_permits: Vec<OwnedSemaphorePermit> = Vec::new();

        if let Some(data) = leftover.take() {
            let size = data.len() as u32;
            let permit = bytes_sem
                .clone()
                .acquire_many_owned(size)
                .await
                .map_err(|_| anyhow!("bytes semaphore closed"))?;
            batch_buf.put_slice(&data);
            bytes_permits.push(permit);
        }

        if batch_buf.is_empty() {
            tokio::select! {
                frame = shaped.next() => {
                    match frame {
                        Some(Ok((_seq, data))) => {
                            let size = data.len() as u32;
                            let permit = bytes_sem
                                .clone()
                                .acquire_many_owned(size)
                                .await
                                .map_err(|_| anyhow!("bytes semaphore closed"))?;
                            batch_buf.put_slice(&data);
                            bytes_permits.push(permit);
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => {
                            stream_ended = true;
                        }
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok(Ok(()))) => {}
                        Some(Ok(Err(e))) => return Err(e.context("upload POST failed")),
                        Some(Err(join_err)) => return Err(anyhow!("upload task panicked: {}", join_err)),
                        None => {}
                    }
                }
            }
        }

        loop {
            match shaped.next().now_or_never() {
                Some(Some(Ok((_seq, data)))) => {
                    let frame_size = data.len();
                    if batch_buf.len() + frame_size > MAX_BATCH_BYTES {
                        leftover = Some(data);
                        break;
                    }
                    match bytes_sem.clone().try_acquire_many_owned(frame_size as u32) {
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
                Some(None) => {
                    stream_ended = true;
                    break;
                }
                None => break,
            }
        }

        if batch_buf.is_empty() {
            if stream_ended {
                break;
            }
            continue;
        }

        let req_permit = request_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("request semaphore closed"))?;

        let body = batch_buf.freeze();
        let http_client = Arc::clone(&http_client);
        let state_ref = Arc::clone(&state);
        let session_val = encrypted_session.clone();

        tasks.spawn(async move {
            let _req_guard = req_permit;
            let _bytes_guards = bytes_permits;
            send_upload_post(&http_client, &state_ref, body, &session_val).await
        });

        while let Some(result) = tasks.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.context("upload POST failed")),
                Err(join_err) => return Err(anyhow!("upload task panicked: {}", join_err)),
            }
        }

        if stream_ended {
            break;
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(join_err) => return Err(anyhow!("upload task panicked: {}", join_err)),
        }
    }

    Ok(())
}

async fn download_single_response(
    response: wreq::Response,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: Option<&dyn FrameCipher>,
    encoding: EncodingType,
    start_seq: u64,
    prefetch_at: Option<u64>,
    mut prefetch_trigger: Option<oneshot::Sender<()>>,
) -> Result<(u64, u64)> {
    let mut buffer = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
    let mut data_stream = response.into_data_stream();
    let mut expected_seq: u64 = start_seq;
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
        while let Some((seq, frame)) = shaper::decode_from_buffer(&mut buffer, cipher, encoding)? {
            if seq != expected_seq {
                return Err(anyhow!(
                    "download frame seq {} out of order, expected {}",
                    seq,
                    expected_seq
                ));
            }
            expected_seq += 1;
            write_half.write_all(&frame).await?;
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
        .context("continuation request timed out")?
        .context("continuation request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let _ = resp.bytes().await;
        return Err(anyhow!("continuation rejected: {status}"));
    }
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

    tokio::spawn(async move {
        if trigger_rx.await.is_err() {
            return;
        }
        match send_continue_request(&pre_client, &pre_state, &pre_cookie).await {
            Ok(resp) => {
                let _ = result_tx.send(Ok(resp));
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "prefetch continuation request failed"
                );
                let _ = result_tx.send(Err(e));
            }
        }
    });

    (trigger_tx, result_rx)
}

pub async fn download_loop(
    initial_response: wreq::Response,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    cipher: Option<Arc<AesFrameCipher>>,
    cookie_val: String,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    let encoding = state.traffic_config.encoding_type;
    let cipher_dyn: Option<Arc<dyn FrameCipher>> = cipher.map(|c| c as Arc<dyn FrameCipher>);
    let cipher_ref: Option<&dyn FrameCipher> = cipher_dyn.as_deref();

    let max_bytes = state.max_download_bytes;
    let rotate_enabled = max_bytes.is_some_and(|m| m > 0);

    let prefetch_at = max_bytes.map(|m| m.saturating_sub(PREFETCH_LEAD_BYTES));
    let use_prefetch = prefetch_at.is_some_and(|at| at > 0);

    let mut response = initial_response;
    let mut expected_seq: u64 = 0;

    loop {
        let (prefetch_trigger, prefetch_rx) = if rotate_enabled && use_prefetch {
            let (tx, rx) = spawn_prefetch_continuation(&http_client, &state, &cookie_val);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let (bytes_received, next_seq) = download_single_response(
            response,
            &mut write_half,
            cipher_ref,
            encoding,
            expected_seq,
            prefetch_at,
            prefetch_trigger,
        )
        .await?;

        expected_seq = next_seq;

        let should_rotate = match max_bytes {
            Some(max) => bytes_received >= max,
            None => false,
        };
        if !should_rotate {
            break;
        }

        response = if use_prefetch {
            let prefetch = prefetch_rx
                .expect("prefetch_rx must be Some when use_prefetch")
                .await
                .map_err(|_| anyhow!("prefetch task panicked"))?;
            match prefetch {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(
                        error = %e,
                        "prefetch failed, falling back to synchronous continuation"
                    );
                    send_continue_request(&http_client, &state, &cookie_val).await?
                }
            }
        } else {
            send_continue_request(&http_client, &state, &cookie_val).await?
        };
    }

    let _ = write_half.shutdown().await;
    Ok(())
}

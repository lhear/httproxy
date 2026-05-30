use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{Instrument, info, warn};
use zeroize::Zeroizing;

use crate::client::{
    constants::{
        CONNECT_RESPONSE, DOWNLOAD_CONNECT_TIMEOUT, EARLY_READ_WINDOW, MASTER_RESUME_WINDOW_SECS,
        PROXY_AUTH_REQUIRED_RESPONSE, PROXY_REQUEST_PARSE_TIMEOUT,
    },
    handshake::{self, try_pq_connect},
    proxy,
    state::SharedState,
    tunnel, utils,
};

pub async fn handle_connection(
    socket: TcpStream,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut read_half, mut write_half) = socket.into_split();

    let mut buffer = BytesMut::with_capacity(16 * 1024);

    let (method, header_len, url) = loop {
        let (method, header_len, url, proxy_auth_header) = tokio::time::timeout(
            PROXY_REQUEST_PARSE_TIMEOUT,
            proxy::parse_proxy_request(&mut read_half, &mut buffer),
        )
        .await
        .map_err(|_| anyhow!("proxy request parse timeout"))??;

        if let Some((ref expected_auth, _)) = state.proxy_auth
            && proxy_auth_header
                .as_ref()
                .is_none_or(|h| h.trim() != expected_auth.as_str())
        {
            write_half.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await?;
            write_half.flush().await?;
            buffer.advance(header_len);
            continue;
        }
        break (method, header_len, url);
    };

    if method == "CONNECT" {
        buffer.advance(header_len);
        write_half.write_all(CONNECT_RESPONSE).await?;
        let deadline = tokio::time::Instant::now() + EARLY_READ_WINDOW;
        loop {
            let remaining = crate::shaper::MAX_RAW_PAYLOAD.saturating_sub(buffer.len());
            if remaining == 0 {
                break;
            }
            match tokio::time::timeout_at(deadline, read_half.read_buf(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
    }

    let target_host = proxy::resolve_target_host(&method, &url)?;
    tracing::Span::current().record("target", target_host.as_str());

    if let Some(ref bypass) = state.bypass
        && bypass.should_bypass(&target_host)
    {
        info!(mode = "bypass", "direct connect");
        let payload = buffer.split().freeze();
        return handle_bypass(read_half, write_half, &target_host, payload).await;
    }

    let payload = buffer.split().freeze();
    info!(mode = "proxy", "connecting");

    let server_pk_opt = state.server_public_key;
    if let Some(ref server_pk) = server_pk_opt {
        handle_pq_proxy(
            read_half,
            write_half,
            http_client,
            state,
            payload,
            &target_host,
            server_pk,
        )
        .await
    } else {
        handle_plain_proxy(
            read_half,
            write_half,
            http_client,
            state,
            payload,
            &target_host,
        )
        .await
    }
}

async fn handle_pq_proxy(
    read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    initial_payload: Bytes,
    target_host: &str,
    server_pk: &x25519_dalek::PublicKey,
) -> Result<()> {
    let mut read_half = Some(read_half);
    let mut write_half = Some(write_half);

    {
        let mut master_guard = state.initial_master.lock().await;
        if let Some((session_id, master, created)) = master_guard.as_ref() {
            if crate::now_secs().saturating_sub(*created) < MASTER_RESUME_WINDOW_SECS {
                let ticket = handshake::PqSessionTicket {
                    master: Zeroizing::new(**master),
                    session_id: session_id.clone(),
                };
                drop(master_guard);
                match try_pq_connect(
                    &http_client,
                    &state,
                    &ticket,
                    target_host,
                    initial_payload.clone(),
                    &mut read_half,
                    &mut write_half,
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!("session resumption failed, falling back to full handshake: {e}");
                        if read_half.is_none() {
                            return Err(e);
                        }
                    }
                }
            } else {
                *master_guard = None;
            }
        }
    }

    {
        let handshake_mutex = state
            .handshake_lock
            .get_or_init(|| async { tokio::sync::Mutex::new(()) })
            .await;
        let _guard = handshake_mutex.lock().await;

        {
            let master_guard = state.initial_master.lock().await;
            if let Some((session_id, master, created)) = master_guard.as_ref()
                && crate::now_secs().saturating_sub(*created) < MASTER_RESUME_WINDOW_SECS
            {
                let ticket = handshake::PqSessionTicket {
                    master: Zeroizing::new(**master),
                    session_id: session_id.clone(),
                };
                drop(master_guard);
                match try_pq_connect(
                    &http_client,
                    &state,
                    &ticket,
                    target_host,
                    initial_payload.clone(),
                    &mut read_half,
                    &mut write_half,
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!(
                            "session resumption (post-lock) failed, falling back to full handshake: {e}"
                        );
                        if read_half.is_none() {
                            return Err(e);
                        }
                        let mut mg = state.initial_master.lock().await;
                        if let Some((ref cur_sid, _, _)) = *mg
                            && cur_sid == &ticket.session_id
                        {
                            *mg = None;
                        }
                    }
                }
            }
        }

        let rh = read_half.take().context("read half already consumed")?;
        let wh = write_half.take().context("write half already consumed")?;
        handshake::full_handshake(
            &http_client,
            &state,
            server_pk,
            target_host,
            initial_payload,
            rh,
            wh,
        )
        .await
    }
}

async fn handle_plain_proxy(
    read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    payload: Bytes,
    target_host: &str,
) -> Result<()> {
    let stream_id = uuid::Uuid::new_v4().to_string();
    let mut cookie = String::new();
    utils::build_tunnel_cookie(&mut cookie, &stream_id);

    let (early_data, remaining_payload, frames_sent) = utils::encode_initial_payload(
        &payload,
        crate::shaper::MAX_RAW_PAYLOAD,
        None,
        &state.traffic_config,
    )?;

    info!(target = %target_host, "connection initiated");

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .header("Authorization", state.auth_header.as_str())
            .header("X-Target", target_host)
            .header("Cookie", cookie)
            .body(wreq::Body::from(early_data))
            .send(),
    )
    .await
    .context("download connect timed out")?
    .context("download request failed")?;

    if !response.status().is_success() {
        let status = response.status();
        let _ = response.bytes().await;
        return Err(anyhow!("upstream rejected download: {status}"));
    }

    let encoding = state.traffic_config.encoding_type;
    let upload_client = Arc::clone(&http_client);
    let upload_state = Arc::clone(&state);
    let stream_id_clone = stream_id.clone();

    let upload_task = tokio::spawn(
        async move {
            tunnel::upload_loop(
                upload_client,
                upload_state,
                remaining_payload,
                read_half,
                None,
                stream_id_clone,
                frames_sent,
            )
            .await
        }
        .instrument(tracing::Span::current()),
    );

    let download_http_client = Arc::clone(&http_client);
    let download_state = Arc::clone(&state);
    let cookie_val_for_dl = stream_id.clone();

    let download_fut = tunnel::download_loop(
        response,
        write_half,
        None,
        encoding,
        cookie_val_for_dl,
        download_http_client,
        download_state,
    );

    utils::race_upload_download(upload_task, download_fut, None).await
}

async fn handle_bypass(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    initial_payload: Bytes,
) -> Result<()> {
    let mut remote = TcpStream::connect(target)
        .await
        .with_context(|| format!("bypass connect to {target} failed"))?;
    remote.set_nodelay(true)?;

    info!(target = %target, initial_bytes = %initial_payload.len(), "bypass connected");

    if !initial_payload.is_empty() {
        remote.write_all(&initial_payload).await?;
    }

    let (mut remote_read, mut remote_write) = remote.into_split();

    let up = async {
        tokio::io::copy(&mut read_half, &mut remote_write).await?;
        remote_write.shutdown().await
    };

    let down = async {
        tokio::io::copy(&mut remote_read, &mut write_half).await?;
        write_half.shutdown().await
    };

    let (up_res, down_res) = tokio::join!(up, down);
    up_res.context("bypass client->remote")?;
    down_res.context("bypass remote->client")?;
    info!(target = %target, "bypass connection closed");
    Ok(())
}

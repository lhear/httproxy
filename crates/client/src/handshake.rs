use anyhow::{Context, Result, anyhow};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{Instrument, info};
use zeroize::Zeroizing;

use crate::actor::download_loop::DownloadLoopActor;
use crate::actor::upload_loop::UploadLoopActor;
use crate::cronet::Client;
use crate::utils;
use httproxy_core::crypto::{self, AesFrameCipher, TlsInspector};
use httproxy_core::shaper::{self, MAX_RAW_PAYLOAD, ShaperStream};

use super::state::SharedState;
use crate::constants::{DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT};

pub struct SessionTicket {
    pub master: Zeroizing<[u8; 32]>,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct RehandshakeRequired(pub String);

impl std::fmt::Display for RehandshakeRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RehandshakeRequired {}

pub async fn try_connect(
    http_client: &Arc<Client>,
    state: &Arc<SharedState>,
    ticket: &SessionTicket,
    target_host: &str,
    initial_payload: Bytes,
    read_half: &mut Option<tokio::net::tcp::OwnedReadHalf>,
    write_half: &mut Option<tokio::net::tcp::OwnedWriteHalf>,
) -> Result<()> {
    let master = &ticket.master;
    let session_id = &ticket.session_id;
    info!(session_id = %session_id, target = %target_host, "session resumption: attempting to reuse session");

    let stream_id = uuid::Uuid::new_v4();
    let stream_id_bytes: [u8; 16] = *stream_id.as_bytes();
    let (upload_key, download_key, target_key) =
        crypto::derive_connection_keys(master, &stream_id_bytes);
    let upload_cipher: Arc<dyn shaper::FrameCipher> =
        Arc::new(httproxy_core::crypto::StreamCipher::new(&upload_key));
    let download_cipher: Arc<dyn shaper::FrameCipher> =
        Arc::new(httproxy_core::crypto::StreamCipher::new(&download_key));

    let enc_target = crypto::encrypt_bytes(&target_key, target_host.as_bytes())?;

    let cookie_stream_key = crypto::derive_cookie_stream_key(master);
    let enc_stream_id = crypto::encrypt_bytes(&cookie_stream_key, &stream_id_bytes)?;

    let cookie_val = format!(
        "{}:{}:{}",
        session_id,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&enc_target),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&enc_stream_id)
    );

    let (early_data, remaining_payload, frames_sent) = utils::encode_initial_payload(
        &initial_payload,
        MAX_RAW_PAYLOAD,
        upload_cipher.as_ref(),
        &state.traffic_config,
    )?;

    let early_len = initial_payload.len() - remaining_payload.len();
    let mut inspector = TlsInspector::new();
    inspector.feed(&initial_payload[..early_len]);

    let mut session_cookie = String::new();
    utils::build_tunnel_cookie(&mut session_cookie, &cookie_val);

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .header("Cookie", &session_cookie)
            .body(early_data)
            .send(),
    )
    .await
    .context("session resumption download connect timed out")?
    .context("session resumption POST failed")?;

    if response.status().as_u16() == 428 {
        let _ = tokio::time::timeout(DOWNLOAD_CONNECT_TIMEOUT, response.discard()).await;
        return Err(anyhow::Error::new(RehandshakeRequired(
            "server requests re-handshake (428)".into(),
        )));
    }
    let response = utils::check_response_status(response, "server rejected session resumption")?;

    let read_half = read_half
        .take()
        .ok_or_else(|| anyhow!("read half already consumed"))?;
    let write_half = write_half
        .take()
        .ok_or_else(|| anyhow!("write half already consumed"))?;

    let upload_client = Arc::clone(http_client);
    let upload_state = Arc::clone(state);

    let reader = std::io::Cursor::new(remaining_payload).chain(read_half);
    let shaped: ShaperStream = Box::pin(shaper::TrafficShaper::with_inspector(
        reader,
        &state.resolved_traffic,
        upload_cipher,
        frames_sent,
        Some(inspector),
    ));

    let upload_actor = UploadLoopActor::new(
        upload_client.clone(),
        upload_state.clone(),
        shaped,
        stream_id,
    );
    let upload_task =
        tokio::spawn(async move { upload_actor.run().await }.instrument(tracing::Span::current()));

    let download_actor = DownloadLoopActor::new(
        response,
        write_half,
        download_cipher,
        stream_id,
        Arc::clone(http_client),
        Arc::clone(state),
    );

    utils::race_upload_download(upload_task, download_actor.run(), Some("download failed")).await
}

pub async fn perform_handshake(
    http_client: &Client,
    state: &SharedState,
    server_pk: &crypto::PublicKey,
) -> Result<SessionTicket> {
    info!("handshake initiated");

    let (eph_sk, eph_pk) = crypto::generate_keypair();
    let handshake_ss = crypto::diffie_hellman(&eph_sk, server_pk)?;
    let handshake_key = crypto::derive_handshake_key(&handshake_ss);

    let sealed = crypto::encrypt_bytes(&handshake_key, state.auth_token.as_bytes())?;
    let mut payload = Vec::with_capacity(crypto::KEY_LEN + sealed.len());
    payload.extend_from_slice(eph_pk.as_bytes());
    payload.extend_from_slice(&sealed);

    let encoding = state.traffic_config.encoding_type;

    let body = shaper::encode_frame_padded(
        &payload,
        0,
        &crypto::PlainFrameCipher,
        state.traffic_config.handshake_padding_range(),
        encoding,
    )?;

    info!("ClientHello ready, sending to server");

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .body(Bytes::from(body))
            .send(),
    )
    .await
    .context("handshake download connect timed out")?
    .context("handshake POST failed")?;

    let response = utils::check_response_status(response, "server rejected handshake")?;

    let handshake_cipher = AesFrameCipher::new(&handshake_key);
    let mut body_buf = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
    let mut stream = response.into_body();
    let server_hello = loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                body_buf.extend_from_slice(&chunk);
                if let Some((_, data)) =
                    shaper::decode_from_buffer(&mut body_buf, &handshake_cipher, encoding)?
                {
                    break data;
                }
            }
            Some(Err(e)) => return Err(e),
            None => return Err(anyhow!("ServerHello not received")),
        }
    };

    let (sid_len, rest) = server_hello
        .split_at_checked(2)
        .ok_or_else(|| anyhow!("ServerHello too short"))?;
    let sid_len = u16::from_be_bytes([sid_len[0], sid_len[1]]) as usize;
    let (session_id, server_eph_pk) = rest
        .split_at_checked(sid_len)
        .ok_or_else(|| anyhow!("ServerHello truncated"))?;
    let session_id = std::str::from_utf8(session_id)
        .context("invalid session_id")?
        .to_owned();
    let server_eph_pk = crypto::public_key_from_slice(server_eph_pk)?;

    info!(session_id = %session_id, "ServerHello received, deriving master key");

    let master_ss = crypto::diffie_hellman(&eph_sk, &server_eph_pk)?;
    let master = crypto::derive_initial_master(&master_ss);

    {
        let mut lock = state.initial_master.lock().await;
        *lock = Some((
            session_id.clone(),
            Zeroizing::new(*master),
            httproxy_core::monotonic_secs(),
        ));
    }

    Ok(SessionTicket { master, session_id })
}

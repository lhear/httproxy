use anyhow::{Context, Result, anyhow};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{Instrument, info};
use zeroize::Zeroizing;

use crate::client::actor::download_loop::DownloadLoopActor;
use crate::client::actor::upload_loop::UploadLoopActor;
use crate::client::utils;
use crate::cronet::Client;
use crate::crypto::{self, AesFrameCipher, TlsInspector};
use crate::shaper::{self, MAX_RAW_PAYLOAD, ShaperStream};

use super::state::SharedState;
use crate::client::constants::{DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT};

pub struct PqSessionTicket {
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

pub async fn try_pq_connect(
    http_client: &Arc<Client>,
    state: &Arc<SharedState>,
    ticket: &PqSessionTicket,
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
        Arc::new(crate::crypto::StreamCipher::new(&upload_key));
    let download_cipher: Arc<dyn shaper::FrameCipher> =
        Arc::new(crate::crypto::StreamCipher::new(&download_key));

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
        let _ = tokio::time::timeout(DOWNLOAD_CONNECT_TIMEOUT, response.bytes()).await;
        return Err(anyhow::Error::new(RehandshakeRequired(
            "server requests re-handshake (428)".into(),
        )));
    }
    let response =
        utils::check_response_status(response, "server rejected session resumption").await?;

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

pub async fn perform_pq_handshake(
    http_client: &Client,
    state: &SharedState,
    server_pk: &crypto::EncapsulationKey,
) -> Result<PqSessionTicket> {
    info!("PQ handshake initiated");

    let (static_ct, static_ss) = crypto::mlkem_encapsulate(server_pk)?;
    let handshake_key = crypto::derive_handshake_key(&static_ss);
    let handshake_cipher = AesFrameCipher::new(&handshake_key);

    let (kem_sk, kem_pk) = crypto::generate_mlkem_keypair()?;
    let kem_pk_bytes = crypto::mlkem_public_key_bytes(&kem_pk)?;

    let (eph_sk_b, eph_pk_b) = crypto::generate_keypair();
    let eph_pk_b_bytes = eph_pk_b.to_bytes().to_vec();

    let token = state.auth_token.as_bytes();
    let token_len = u16::try_from(token.len()).context("auth token too long")?;
    let mut client_hello =
        Vec::with_capacity(2 + token.len() + 2 + kem_pk_bytes.len() + 2 + eph_pk_b_bytes.len());
    client_hello.extend_from_slice(&token_len.to_be_bytes());
    client_hello.extend_from_slice(token);
    client_hello.extend_from_slice(&(kem_pk_bytes.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&kem_pk_bytes);
    client_hello.extend_from_slice(&(eph_pk_b_bytes.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&eph_pk_b_bytes);
    let client_hello_frame = shaper::encode_frame(
        &client_hello,
        0,
        &handshake_cipher,
        state.traffic_config.global.padding_threshold,
        state.traffic_config.global.padding_range,
        state.traffic_config.encoding_type,
    )?;

    let static_ct_frame = shaper::encode_frame(
        static_ct.as_ref(),
        0,
        &crypto::PlainFrameCipher,
        state.traffic_config.global.padding_threshold,
        state.traffic_config.global.padding_range,
        state.traffic_config.encoding_type,
    )?;

    let mut handshake_body = Vec::with_capacity(static_ct_frame.len() + client_hello_frame.len());
    handshake_body.extend_from_slice(&static_ct_frame);
    handshake_body.extend_from_slice(&client_hello_frame);

    info!("ClientHello ready, sending to server");

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .body(Bytes::from(handshake_body))
            .send(),
    )
    .await
    .context("handshake download connect timed out")?
    .context("handshake POST failed")?;

    let response = utils::check_response_status(response, "server rejected handshake").await?;

    let mut body_buf = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
    let mut stream = response.into_body();
    let server_hello_data = loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                body_buf.extend_from_slice(&chunk);
                if let Some((_, data)) = shaper::decode_from_buffer(
                    &mut body_buf,
                    &handshake_cipher,
                    state.traffic_config.encoding_type,
                )? {
                    break data;
                }
            }
            Some(Err(e)) => return Err(e),
            None => return Err(anyhow!("ServerHello not received")),
        }
    };

    if server_hello_data.len() < 2 {
        return Err(anyhow!("ServerHello too short"));
    }

    info!("ServerHello received, deriving master key");

    let sid_len = u16::from_be_bytes([server_hello_data[0], server_hello_data[1]]) as usize;
    let ct_start = 2 + sid_len;
    let ct_end = ct_start + 1088;
    if server_hello_data.len() < ct_end + 32 {
        return Err(anyhow!("ServerHello truncated"));
    }
    let session_id = std::str::from_utf8(&server_hello_data[2..2 + sid_len])
        .context("invalid session_id")?
        .to_owned();
    let ct_bytes = &server_hello_data[ct_start..ct_end];
    let server_eph_pk_bytes: [u8; 32] = server_hello_data[ct_end..ct_end + 32].try_into().unwrap();
    let server_eph_pk = x25519_dalek::PublicKey::from(server_eph_pk_bytes);

    let master = {
        let ss_mlkem = crypto::mlkem_decapsulate(&kem_sk, ct_bytes)?;
        let ss_x25519 = crypto::diffie_hellman(&eph_sk_b, &server_eph_pk);
        crypto::derive_initial_master(&ss_mlkem, &ss_x25519)
    };

    info!(session_id = %session_id, "handshake complete, master key derived");

    {
        let mut lock = state.initial_master.lock().await;
        *lock = Some((
            session_id.clone(),
            Zeroizing::new(*master),
            crate::now_secs(),
        ));
    }

    Ok(PqSessionTicket { master, session_id })
}

pub async fn full_handshake(
    http_client: &Arc<Client>,
    state: &Arc<SharedState>,
    server_pk: &crypto::EncapsulationKey,
    target_host: &str,
    initial_payload: Bytes,
    read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let ticket = perform_pq_handshake(http_client, state, server_pk).await?;

    let mut rh = Some(read_half);
    let mut wh = Some(write_half);
    try_pq_connect(
        http_client,
        state,
        &ticket,
        target_host,
        initial_payload,
        &mut rh,
        &mut wh,
    )
    .await
}

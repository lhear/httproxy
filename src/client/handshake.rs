use anyhow::{Context, Result, anyhow};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use crypto_common::KeyExport;
use futures::StreamExt;
use http_body_util::BodyExt;
use rand::RngExt;
use std::sync::Arc;
use tracing::{Instrument, info};
use zeroize::Zeroizing;

use crate::client::actor::download_loop::DownloadLoopActor;
use crate::client::actor::upload_loop::UploadLoopActor;
use crate::client::utils;
use crate::crypto::{self, AesFrameCipher};
use crate::shaper::{self, FrameCipher, MAX_RAW_PAYLOAD};

use super::state::SharedState;
use crate::client::constants::{
    DECODE_BUF_CAPACITY, DOWNLOAD_CONNECT_TIMEOUT, MIN_PADDING, PADDING_POOL,
};

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
    http_client: &Arc<wreq::Client>,
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
    let upload_cipher = Arc::new(AesFrameCipher::new(&upload_key));
    let download_cipher = Arc::new(AesFrameCipher::new(&download_key));

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
        Some(upload_cipher.as_ref() as &dyn FrameCipher),
        &state.traffic_config,
    )?;

    let mut session_cookie = String::new();
    utils::build_tunnel_cookie(&mut session_cookie, &cookie_val);

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .header("Cookie", &session_cookie)
            .body(wreq::Body::from(early_data))
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
    let upload_cipher_clone = Arc::clone(&upload_cipher);

    let upload_actor = UploadLoopActor::new(
        upload_client.clone(),
        upload_state.clone(),
        remaining_payload,
        read_half,
        Some(upload_cipher_clone),
        stream_id,
        frames_sent,
    );
    let upload_task =
        tokio::spawn(async move { upload_actor.run().await }.instrument(tracing::Span::current()));

    let download_actor = DownloadLoopActor::new(
        response,
        write_half,
        Some(download_cipher),
        stream_id,
        Arc::clone(http_client),
        Arc::clone(state),
    );

    utils::race_upload_download(upload_task, download_actor.run(), Some("download failed")).await
}

pub async fn perform_pq_handshake(
    http_client: &wreq::Client,
    state: &SharedState,
    server_pk: &x25519_dalek::PublicKey,
) -> Result<PqSessionTicket> {
    info!("PQ handshake initiated");

    let (eph_sk_a, eph_pk_a) = crypto::generate_keypair();
    let eph_sk_a = Zeroizing::new(eph_sk_a);
    let x25519_shared_a = crypto::diffie_hellman(&eph_sk_a, server_pk);
    let handshake_key = crypto::derive_handshake_key(&x25519_shared_a);
    let handshake_cipher = AesFrameCipher::new(&handshake_key);

    let (kem_sk, kem_pk) = crypto::generate_mlkem_keypair();
    let kem_pk_bytes = kem_pk.to_bytes();

    let (eph_sk_b, eph_pk_b) = crypto::generate_keypair();
    let eph_sk_b = Zeroizing::new(eph_sk_b);
    let eph_pk_b_bytes = eph_pk_b.to_bytes().to_vec();

    let mut client_hello = Vec::with_capacity(2 + kem_pk_bytes.len() + 2 + eph_pk_b_bytes.len());
    client_hello.extend_from_slice(&(kem_pk_bytes.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&kem_pk_bytes);
    client_hello.extend_from_slice(&(eph_pk_b_bytes.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&eph_pk_b_bytes);
    let client_hello_frame = shaper::encode_frame(
        &client_hello,
        0,
        Some(&handshake_cipher),
        state.traffic_config.global.padding_threshold,
        state.traffic_config.global.padding_range,
        state.traffic_config.encoding_type,
    )?;

    let eph_pk_a_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(eph_pk_a.as_bytes());

    let mut handshake_cookie =
        String::with_capacity(9 + eph_pk_a_b64.len() + 2 + MIN_PADDING + PADDING_POOL.len());
    handshake_cookie.push_str("eph_pk_a=");
    handshake_cookie.push_str(&eph_pk_a_b64);
    handshake_cookie.push_str("; ");
    let padding_len = rand::rng().random_range(MIN_PADDING..PADDING_POOL.len());
    handshake_cookie
        .push_str(std::str::from_utf8(&PADDING_POOL[..padding_len]).expect("Invalid UTF-8"));

    info!("ClientHello ready, sending to server");

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .header("Authorization", state.auth_header.as_str())
            .header("Cookie", &handshake_cookie)
            .body(wreq::Body::from(client_hello_frame))
            .send(),
    )
    .await
    .context("handshake download connect timed out")?
    .context("handshake POST failed")?;

    let response = utils::check_response_status(response, "server rejected handshake").await?;

    let handshake_cipher_ref: &dyn FrameCipher = &handshake_cipher;
    let mut body_buf = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
    let mut stream = response.into_data_stream();
    let server_hello_data = loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                body_buf.extend_from_slice(&chunk);
                if let Some((_, data)) = shaper::decode_from_buffer(
                    &mut body_buf,
                    Some(handshake_cipher_ref),
                    state.traffic_config.encoding_type,
                )? {
                    break data;
                }
            }
            Some(Err(e)) => return Err(e.into()),
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
    let ct: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ct: wrong length"))?;
    let server_eph_pk_bytes: [u8; 32] = server_hello_data[ct_end..ct_end + 32].try_into().unwrap();
    let server_eph_pk = x25519_dalek::PublicKey::from(server_eph_pk_bytes);

    let master = {
        let ss_mlkem = crypto::mlkem_decapsulate(&kem_sk, &ct);
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
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
    server_pk: &x25519_dalek::PublicKey,
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

use axum::body::HttpBody;
use axum::{body::Body, extract::State, http::HeaderMap, response::Response};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use jsonwebtoken::{DecodingKey, Validation};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tracing::{Instrument, debug, info, warn};
use uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, AesFrameCipher, AesKey};
use crate::error::ServerError;
use crate::server::constants::{
    CONNECT_TIMEOUT, MASTER_EXPIRY, MAX_UPLOAD_BODY_SIZE, UPLOAD_CHANNEL_CAPACITY,
    UPLOAD_DONE_TIMEOUT,
};
use crate::server::{
    connection::{self, connect_upstream},
    state::{DownloadStream, FrameOrEos, StreamBundle, UploadStream},
    utils,
};
use crate::shaper::{self, FrameCipher};

use super::AppState;

pub async fn dispatch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ServerError> {
    let span = tracing::Span::current();

    let has_x_target = headers.get("X-Target").is_some();
    let session_cookie = utils::extract_cookie_value(&headers, "session");

    if let Some(cookie_val) = session_cookie
        && state.streams.contains_key(cookie_val)
    {
        if is_body_empty(&headers, &body) {
            return handle_download_continuation(state, cookie_val, span).await;
        }
        let session_id = cookie_val.split(':').next().unwrap_or(cookie_val);
        if let Some(entry) = state.master_store.get(session_id) {
            span.record("user", &entry.value().0);
        }
        return handle_stream_upload(state, cookie_val.to_owned(), body, span).await;
    }

    if has_x_target {
        return handle_plaintext_download(state, headers, body, span).await;
    }

    if session_cookie.is_none() {
        return handle_fresh_handshake(state, headers, body, span).await;
    }

    let cookie_val = session_cookie.unwrap();
    let session_id = cookie_val.split(':').next().unwrap_or(cookie_val);
    let is_pq = state.master_store.get(session_id).is_some();

    if !is_pq {
        return Err(ServerError::precondition_required("session not found"));
    }

    let body_bytes = axum::body::to_bytes(body, MAX_UPLOAD_BODY_SIZE)
        .await
        .map_err(|e| ServerError::bad_request(format!("failed to read body: {e}")))?;

    handle_pq_download(state, cookie_val, body_bytes, span).await
}

#[inline]
fn is_body_empty(headers: &HeaderMap, body: &Body) -> bool {
    if let Some(cl) = headers.get("content-length").and_then(|v| v.to_str().ok()) {
        return cl == "0";
    }
    body.is_end_stream()
}

#[inline]
fn build_download_response(
    download: DownloadStream,
    _log_key: &str,
) -> Result<Response, ServerError> {
    let padding = utils::random_padding();
    Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .body(Body::from_stream(download))
        .map_err(|e| ServerError::internal(e.to_string()))
}

async fn handle_plaintext_download(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let user = validate_jwt_if_needed(&headers, false, &state.decoding_key, &state.jwt_validation)?;
    span.record("user", &user);

    let early_data = axum::body::to_bytes(body, MAX_UPLOAD_BODY_SIZE)
        .await
        .map_err(|e| ServerError::bad_request(format!("failed to read body: {e}")))?;

    let target = headers
        .get("X-Target")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::bad_request("missing X-Target header"))?;

    span.record("target", target);
    info!(user = %user, target = %target, body_len = %early_data.len(), "connection initiated");

    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| ServerError::bad_request("target must be host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ServerError::bad_request("invalid port"))?;

    let mut upstream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_upstream(
            state.dns_client.as_ref(),
            state.client_subnet,
            state.socks5_proxy.as_ref(),
            host,
            port,
        ),
    )
    .await
    .map_err(|_| ServerError::gateway_timeout("connect timeout"))?
    .map_err(ServerError::bad_gateway)?;

    upstream.set_nodelay(true)?;

    let frames_written: u64 = if !early_data.is_empty() {
        let mut buf = BytesMut::from(&early_data[..]);
        let mut count: u64 = 0;
        while let Some((_seq, data)) =
            shaper::decode_from_buffer(&mut buf, None, state.traffic_config.encoding_type)?
        {
            upstream.write_all(&data).await.map_err(|e| {
                ServerError::bad_gateway(format!("initial upload write error: {e}"))
            })?;
            count += 1;
        }
        if !buf.is_empty() {
            return Err(ServerError::bad_request(
                "trailing data in initial upload body",
            ));
        }
        count
    } else {
        0
    };

    let (upstream_read, upstream_write) = upstream.into_split();
    let session_id = utils::extract_cookie_value(&headers, "session")
        .map(|s| s.to_owned())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let (frame_tx, frame_rx) = mpsc::channel::<FrameOrEos>(UPLOAD_CHANNEL_CAPACITY);

    let upload = Arc::new(UploadStream::new(frame_tx, None));

    let encoding = state.traffic_config.encoding_type;
    let max_bytes = state.traffic_config.max_download_bytes;

    let shaper = crate::shaper::TrafficShaper::with_seq(
        upstream_read,
        (*state.traffic_config).clone(),
        None,
        0,
    );

    let bundle = Arc::new(StreamBundle {
        upload: Arc::clone(&upload),
        upstream_reader: std::sync::Mutex::new(Some(Box::pin(shaper))),
        download_cipher: None,
        encoding,
        max_download_bytes: max_bytes,
        handoff_tx: Mutex::new(None),
    });

    match state.streams.entry(session_id.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Err(ServerError::bad_request("stream already exists"));
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&bundle));
        }
    }

    info!(stream_id = %session_id, user = %user, target = %target,
          initial_frames = %frames_written, "stream established");

    tokio::spawn(
        connection::ordered_frame_writer(
            frame_rx,
            upstream_write,
            session_id.clone(),
            upload,
            frames_written,
        )
        .instrument(tracing::Span::current()),
    );

    let shutdown_fut = {
        let notify = Arc::clone(&bundle.upload.shutdown);
        Box::pin(async move { notify.notified().await })
    };

    let download = DownloadStream {
        bundle: Arc::clone(&bundle),
        streams: Arc::clone(&state.streams),
        map_key: session_id.clone(),
        log_key: session_id.clone(),
        shutdown_fut: Some(shutdown_fut),
        done: false,
        rotated: false,
        bytes_sent: 0,
        handoff_rx: None,
    };

    #[allow(clippy::needless_borrow)]
    build_download_response(download, &session_id)
}

#[allow(clippy::explicit_auto_deref)]
async fn handle_fresh_handshake(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let user = validate_jwt_if_needed(&headers, false, &state.decoding_key, &state.jwt_validation)?;
    span.record("user", &user);

    info!(user = %user, "handshake: received ClientHello");

    let eph_pk_a_b64 = utils::extract_cookie_value(&headers, "eph_pk_a")
        .ok_or_else(|| ServerError::bad_request("missing eph_pk_a cookie"))?;
    let eph_pk_a_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(eph_pk_a_b64.as_bytes())
        .map_err(|_| ServerError::bad_request("invalid eph_pk_a base64"))?;
    if eph_pk_a_bytes.len() != 32 {
        return Err(ServerError::bad_request("eph_pk_a must be 32 bytes"));
    }
    let eph_pk_a_arr: [u8; 32] = eph_pk_a_bytes[..].try_into().unwrap();
    let eph_pk_a = x25519_dalek::PublicKey::from(eph_pk_a_arr);

    let private_key = state
        .private_key
        .as_ref()
        .ok_or_else(|| ServerError::internal("server private key not configured"))?;

    let shared_a = crypto::diffie_hellman(private_key, &eph_pk_a);
    let handshake_key = crypto::derive_handshake_key(&*shared_a);
    let handshake_cipher = AesFrameCipher::new(AesKey::from(*handshake_key));

    let body_bytes = axum::body::to_bytes(body, MAX_UPLOAD_BODY_SIZE)
        .await
        .map_err(|e| ServerError::bad_request(format!("failed to read body: {e}")))?;

    let mut buf = BytesMut::from(&body_bytes[..]);
    let Some((_seq, client_hello_data)) = shaper::decode_from_buffer(
        &mut buf,
        Some(&handshake_cipher as &dyn FrameCipher),
        state.traffic_config.encoding_type,
    )?
    else {
        return Err(ServerError::bad_request("invalid ClientHello frame"));
    };

    if client_hello_data.len() < 2 {
        return Err(ServerError::bad_request("ClientHello too short"));
    }

    let len_kem = u16::from_be_bytes([client_hello_data[0], client_hello_data[1]]) as usize;
    let kem_end = 2 + len_kem;
    if client_hello_data.len() < kem_end {
        return Err(ServerError::bad_request("ClientHello truncated (KEM part)"));
    }
    let kem_pk_bytes = &client_hello_data[2..kem_end];
    let kem_pk = crypto::bytes_to_encapsulation_key(kem_pk_bytes)
        .map_err(|e| ServerError::bad_request(format!("invalid mlkem public key: {e}")))?;

    if client_hello_data.len() < kem_end + 2 {
        return Err(ServerError::bad_request(
            "ClientHello truncated (no X25519 part)",
        ));
    }
    let len_x25519 =
        u16::from_be_bytes([client_hello_data[kem_end], client_hello_data[kem_end + 1]]) as usize;
    let x25519_end = kem_end + 2 + len_x25519;
    if client_hello_data.len() < x25519_end {
        return Err(ServerError::bad_request(
            "ClientHello truncated (X25519 part)",
        ));
    }
    let eph_pk_b_bytes = &client_hello_data[kem_end + 2..x25519_end];
    let eph_pk_b: [u8; 32] = eph_pk_b_bytes
        .try_into()
        .map_err(|_| ServerError::bad_request("invalid client x25519 pk length"))?;
    let client_eph_pk_b = x25519_dalek::PublicKey::from(eph_pk_b);

    let (ct, ss_mlkem) = crypto::mlkem_encapsulate(&kem_pk);
    let (server_eph_sk, server_eph_pk) = crypto::generate_keypair();

    let master = {
        let server_eph_sk = Zeroizing::new(server_eph_sk);
        let ss_x25519 = crypto::diffie_hellman(&server_eph_sk, &client_eph_pk_b);
        crypto::derive_initial_master(&*ss_mlkem, &*ss_x25519)
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    state.master_store.insert(
        session_id.clone(),
        (user.clone(), master, crate::now_secs()),
    );

    info!(session_id = %session_id, user = %user, "handshake: master key derived");

    let ct_bytes: &[u8] = &ct;
    let ct_bytes = ct_bytes.to_vec();
    let sid_bytes = session_id.as_bytes();
    let mut server_hello = Vec::with_capacity(2 + sid_bytes.len() + ct_bytes.len() + 32);
    server_hello.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
    server_hello.extend_from_slice(sid_bytes);
    server_hello.extend_from_slice(&ct_bytes);
    server_hello.extend_from_slice(server_eph_pk.as_bytes());

    let server_hello_frame = shaper::encode_frame(
        &server_hello,
        0,
        Some(&handshake_cipher as &dyn FrameCipher),
        &state.traffic_config,
    )
    .map_err(|e| ServerError::internal(format!("encode ServerHello: {e}")))?;

    drop(handshake_key);

    info!(session_id = %session_id, "handshake: ServerHello sent");

    let padding = utils::random_padding();
    let resp = Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .body(Body::from(server_hello_frame))
        .map_err(|e| ServerError::internal(e.to_string()))?;

    Ok(resp)
}

#[allow(clippy::explicit_auto_deref)]
async fn handle_pq_download(
    state: Arc<AppState>,
    cookie_val: &str,
    early_data: Bytes,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let parts: Vec<&str> = cookie_val.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(ServerError::bad_request("invalid session cookie format"));
    }
    let (session_id, enc_target_b64, enc_nonce_b64) = (parts[0], parts[1], parts[2]);
    info!(session_id = %session_id, body_len = %early_data.len(),
          "session resumption: download request received");

    let entry = state
        .master_store
        .get(session_id)
        .ok_or_else(|| ServerError::precondition_required("session not found"))?;

    let value_ref = entry.value();
    let mut master = Zeroizing::new([0u8; 32]);
    let (username, master_z, created) = value_ref;
    master.copy_from_slice(&**master_z);
    let username = username.clone();
    let created = *created;
    if crate::now_secs().saturating_sub(created) > MASTER_EXPIRY.as_secs() {
        drop(entry);
        state.master_store.remove(session_id);
        return Err(ServerError::precondition_required("master key expired"));
    }

    let cookie_nonce_key = crypto::derive_cookie_nonce_key(&*master);

    let enc_target = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(enc_target_b64)
        .map_err(|_| ServerError::bad_request("invalid cookie encoding"))?;

    let enc_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(enc_nonce_b64)
        .map_err(|_| ServerError::bad_request("invalid cookie encoding"))?;
    let conn_nonce_bytes = crypto::decrypt_bytes(&cookie_nonce_key, &enc_nonce)
        .map_err(|_| ServerError::bad_request("failed to decrypt conn_nonce"))?;
    let conn_nonce: [u8; 16] = conn_nonce_bytes
        .try_into()
        .map_err(|_| ServerError::bad_request("invalid conn_nonce length"))?;

    {
        let nonce_set = state.used_nonces.entry(session_id.to_string()).or_default();
        if !nonce_set.insert(conn_nonce) {
            return Err(ServerError::precondition_required(
                "nonce already used (replay detected)",
            ));
        }
    }

    drop(entry);

    let (upload_key, download_key, target_key) =
        crypto::derive_connection_keys(&*master, &conn_nonce);

    let target_bytes = crypto::decrypt_bytes(&target_key, &enc_target)
        .map_err(|_| ServerError::bad_request("failed to decrypt target"))?;
    let target = String::from_utf8(target_bytes)
        .map_err(|_| ServerError::bad_request("invalid target utf8"))?;

    let upload_cipher = Arc::new(AesFrameCipher::new(upload_key));
    let download_cipher: Arc<dyn FrameCipher> = Arc::new(AesFrameCipher::new(download_key));

    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| ServerError::bad_request("target must be host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ServerError::bad_request("invalid port"))?;

    span.record("user", &username);
    span.record("target", &target);

    info!(session_id = %session_id, user = %username, "session resumption: connecting to {}", target);

    let mut upstream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_upstream(
            state.dns_client.as_ref(),
            state.client_subnet,
            state.socks5_proxy.as_ref(),
            host,
            port,
        ),
    )
    .await
    .map_err(|_| ServerError::gateway_timeout("connect timeout"))?
    .map_err(ServerError::bad_gateway)?;

    upstream.set_nodelay(true)?;

    let upload_cipher_ref: &dyn FrameCipher = upload_cipher.as_ref() as &dyn FrameCipher;
    let frames_written: u64 = if !early_data.is_empty() {
        let mut buf = BytesMut::from(&early_data[..]);
        let mut count: u64 = 0;
        while let Some((_seq, data)) = shaper::decode_from_buffer(
            &mut buf,
            Some(upload_cipher_ref),
            state.traffic_config.encoding_type,
        )? {
            upstream.write_all(&data).await.map_err(|e| {
                ServerError::bad_gateway(format!("initial upload write error: {e}"))
            })?;
            count += 1;
        }
        if !buf.is_empty() {
            return Err(ServerError::bad_request(
                "trailing data in initial upload body",
            ));
        }
        count
    } else {
        0
    };

    let (upstream_read, upstream_write) = upstream.into_split();
    let (frame_tx, frame_rx) = mpsc::channel::<FrameOrEos>(UPLOAD_CHANNEL_CAPACITY);

    let upload = Arc::new(UploadStream::new(frame_tx, Some(upload_cipher)));

    let encoding = state.traffic_config.encoding_type;
    let max_bytes = state.traffic_config.max_download_bytes;

    let download_cipher_clone: Arc<dyn FrameCipher> = Arc::clone(&download_cipher);
    let shaper = crate::shaper::TrafficShaper::with_seq(
        upstream_read,
        (*state.traffic_config).clone(),
        Some(download_cipher_clone),
        0,
    );

    let bundle = Arc::new(StreamBundle {
        upload: Arc::clone(&upload),
        upstream_reader: std::sync::Mutex::new(Some(Box::pin(shaper))),
        download_cipher: Some(download_cipher),
        encoding,
        max_download_bytes: max_bytes,
        handoff_tx: Mutex::new(None),
    });

    match state.streams.entry(cookie_val.to_owned()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Err(ServerError::bad_request("stream already exists"));
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&bundle));
        }
    }

    let display_key = session_id.to_owned();

    tokio::spawn(
        connection::ordered_frame_writer(
            frame_rx,
            upstream_write,
            display_key,
            upload,
            frames_written,
        )
        .instrument(tracing::Span::current()),
    );

    let shutdown_fut = {
        let notify = Arc::clone(&bundle.upload.shutdown);
        Box::pin(async move { notify.notified().await })
    };

    let download = DownloadStream {
        bundle: Arc::clone(&bundle),
        streams: Arc::clone(&state.streams),
        map_key: cookie_val.to_owned(),
        log_key: session_id.to_owned(),
        shutdown_fut: Some(shutdown_fut),
        done: false,
        rotated: false,
        bytes_sent: 0,
        handoff_rx: None,
    };

    #[allow(clippy::needless_borrow)]
    build_download_response(download, &session_id)
}

async fn handle_download_continuation(
    state: Arc<AppState>,
    cookie_val: &str,
    _span: tracing::Span,
) -> Result<Response, ServerError> {
    let bundle = state
        .streams
        .get(cookie_val)
        .map(|r| Arc::clone(r.value()))
        .ok_or_else(|| ServerError::not_found("stream not found for continuation"))?;

    bundle.upload.clear_rotation();

    let session_id = cookie_val.split(':').next().unwrap_or(cookie_val);

    if let Some(entry) = state.master_store.get(session_id) {
        let user = &entry.value().0;
        tracing::Span::current().record("user", user);
    }

    debug!(stream_id = %session_id, "download continuation requested");

    let (handoff_tx, handoff_rx) = oneshot::channel();
    {
        let mut tx_guard = bundle.handoff_tx.lock().expect("handoff_tx poisoned");
        *tx_guard = Some(handoff_tx);
    }

    let shutdown_fut = {
        let notify = Arc::clone(&bundle.upload.shutdown);
        Box::pin(async move { notify.notified().await })
    };

    let download = DownloadStream {
        bundle: Arc::clone(&bundle),
        streams: Arc::clone(&state.streams),
        map_key: cookie_val.to_owned(),
        log_key: session_id.to_owned(),
        shutdown_fut: Some(shutdown_fut),
        done: false,
        rotated: false,
        bytes_sent: 0,
        handoff_rx: Some(Box::pin(handoff_rx)),
    };

    build_download_response(download, session_id)
}

async fn handle_stream_upload(
    state: Arc<AppState>,
    cookie_val: String,
    body: Body,
    _span: tracing::Span,
) -> Result<Response, ServerError> {
    let bundle = state
        .streams
        .get(&cookie_val)
        .map(|r| Arc::clone(r.value()))
        .ok_or_else(|| ServerError::not_found("unknown upload stream"))?;

    let session_id = cookie_val.split(':').next().unwrap_or(&cookie_val);
    if let Some(entry) = state.master_store.get(session_id) {
        let user = &entry.value().0;
        tracing::Span::current().record("user", user);
    }

    let cipher_ref: Option<&dyn FrameCipher> = bundle
        .upload
        .upload_cipher
        .as_deref()
        .map(|c| c as &dyn FrameCipher);
    let encoding_type = state.traffic_config.encoding_type;

    let mut body = body.into_data_stream();
    let mut buf = BytesMut::with_capacity(8192);
    let mut total_read = 0usize;
    let mut max_seq = 0u64;

    while let Some(chunk) = body.next().await {
        let chunk =
            chunk.map_err(|e| ServerError::bad_request(format!("failed to read body: {e}")))?;
        total_read += chunk.len();
        if total_read > MAX_UPLOAD_BODY_SIZE {
            return Err(ServerError::payload_too_large(
                "body exceeds max upload size",
            ));
        }
        buf.extend_from_slice(&chunk);

        loop {
            let Some((seq, data)) =
                shaper::decode_from_buffer(&mut buf, cipher_ref, encoding_type)?
            else {
                break;
            };
            if seq > max_seq {
                max_seq = seq;
            }
            bundle
                .upload
                .tx
                .send(FrameOrEos::Data { seq, data })
                .await
                .map_err(|_| ServerError::bad_gateway("upload channel closed"))?;
        }
    }

    if !buf.is_empty() {
        return Err(ServerError::bad_request("incomplete frame in batch body"));
    }

    let (done_tx, done_rx) = oneshot::channel();
    bundle
        .upload
        .tx
        .send(FrameOrEos::Eos {
            max_seq,
            done: done_tx,
        })
        .await
        .map_err(|_| ServerError::bad_gateway("upload channel closed"))?;

    tokio::time::timeout(UPLOAD_DONE_TIMEOUT, done_rx)
        .await
        .map_err(|_| ServerError::gateway_timeout("upload drain timeout"))?
        .map_err(|_| ServerError::bad_gateway("upload stream closed"))?;

    bundle.upload.touch();

    let padding = utils::random_padding();
    let resp = Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .status(axum::http::StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|e| ServerError::internal(e.to_string()))?;

    Ok(resp)
}

#[inline]
pub fn validate_jwt_if_needed(
    headers: &HeaderMap,
    has_valid_session: bool,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<String, ServerError> {
    if has_valid_session {
        return Ok("session-resumed".into());
    }

    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!("rejected: missing or invalid authorization header");
            ServerError::unauthorized("invalid header")
        })?;

    if !auth_header.starts_with("Bearer ") {
        warn!("rejected: invalid authorization format");
        return Err(ServerError::unauthorized("invalid header"));
    }

    let token = &auth_header[7..];

    jsonwebtoken::decode::<super::Claims>(token, key, validation)
        .map(|td| td.claims.sub)
        .map_err(|e| {
            warn!("rejected: invalid token - {:?}", e);
            ServerError::unauthorized("invalid token")
        })
}

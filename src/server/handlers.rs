use axum::{body::Body, extract::State, http::HeaderMap, response::Response};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use jsonwebtoken::{DecodingKey, Validation};
use std::io;
use std::sync::Arc;
use tracing::{Instrument, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, AesFrameCipher};
use crate::error::ServerError;
use crate::server::actor::tunnel::TunnelCmd;
use crate::server::connection::connect_upstream;
use crate::server::constants::{
    CONNECT_TIMEOUT, DOWNLOAD_CHANNEL_CAPACITY, MASTER_EXPIRY, MAX_FRAME_BUF_SIZE,
    TUNNEL_CMD_CHANNEL_CAPACITY,
};
use crate::server::stream::FrameDecoder;
use crate::server::stream_registry::StreamQueryResult;
use crate::server::{SessionHandle, utils};
use crate::shaper::{self, FrameCipher};
use tokio::sync::oneshot;

use super::AppState;
use crate::server::stream_registry::StreamRegistry;

struct StreamGuard {
    registry: Arc<StreamRegistry>,
    stream_id: Uuid,
    armed: bool,
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        if self.armed {
            self.registry.mark_consumed(self.stream_id);
        }
    }
}
impl StreamGuard {
    fn new(registry: Arc<StreamRegistry>, stream_id: Uuid) -> Self {
        Self {
            registry,
            stream_id,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

struct ActorGuard {
    actors: Arc<dashmap::DashMap<Uuid, SessionHandle>>,
    key: Uuid,
    armed: bool,
}
impl Drop for ActorGuard {
    fn drop(&mut self) {
        if self.armed {
            self.actors.remove(&self.key);
        }
    }
}
impl ActorGuard {
    fn new(actors: Arc<dashmap::DashMap<Uuid, SessionHandle>>, key: Uuid) -> Self {
        Self {
            actors,
            key,
            armed: true,
        }
    }
}

struct TunnelGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}
impl TunnelGuard {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
    fn disarm(&mut self) {
        self.handle = None;
    }
}

#[allow(clippy::too_many_arguments)]
async fn setup_tunnel_response(
    state: &Arc<AppState>,
    body: Body,
    host: &str,
    port: u16,
    stream_id: Uuid,
    upload_cipher: Option<Arc<dyn FrameCipher>>,
    download_cipher: Option<Arc<dyn FrameCipher>>,
) -> Result<Response, ServerError> {
    let tunnel_permit = state
        .tunnel_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| ServerError::service_unavailable("too many concurrent tunnels"))?;

    let encoding = state.traffic_config.encoding_type;

    let max_download_bytes = state.traffic_config.max_download_bytes;
    let direct = max_download_bytes.is_none();
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(crate::now_secs()));

    let (download_tx, download_rx) = if direct {
        (None, None)
    } else {
        let (tx, rx) =
            tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(DOWNLOAD_CHANNEL_CAPACITY);
        (Some(tx), Some(rx))
    };
    let (actor_tx, actor_rx) = tokio::sync::mpsc::channel::<TunnelCmd>(TUNNEL_CMD_CHANNEL_CAPACITY);

    let upstream = tokio::time::timeout(
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
    .map_err(|e| ServerError::bad_gateway(e.to_string()))?;

    let (upstream_read, upstream_write) = upstream.into_split();

    let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<
        crate::server::actor::upload::UploadCmd,
    >(crate::server::constants::UPLOAD_CMD_CHANNEL_CAPACITY);
    let upload_actor = crate::server::actor::upload::UploadActor::new(upload_rx, upstream_write, 0);
    let upload_handle =
        tokio::spawn(async move { upload_actor.run().await }.instrument(tracing::Span::current()));

    let byte_stream = body.into_data_stream().map(|r| r.map_err(io::Error::other));
    let mut decoder = FrameDecoder::new(
        byte_stream,
        upload_cipher.clone(),
        encoding,
        MAX_FRAME_BUF_SIZE,
    );

    while let Some(result) = decoder.next().await {
        let (seq, data) =
            result.map_err(|e| ServerError::bad_request(format!("decode error: {e}")))?;
        upload_tx
            .send(crate::server::actor::upload::UploadCmd::Frame { seq, data })
            .await
            .map_err(|_| ServerError::bad_gateway("upload actor closed during initial stream"))?;
    }

    let upload_tx_for_actor = upload_tx.clone();

    let mut actor = crate::server::actor::tunnel::TunnelActor::new(
        actor_rx,
        download_tx,
        stream_id,
        Arc::clone(&state.stream_registry),
        max_download_bytes,
        Arc::clone(&last_activity),
    );
    actor.set_upload_channel(upload_tx_for_actor, upload_handle);

    let body_stream = if direct {
        let shaper = crate::shaper::TrafficShaper::with_seq(
            upstream_read,
            &state.resolved_traffic,
            download_cipher,
            0,
        );
        let activity = Arc::clone(&last_activity);
        Body::from_stream(shaper.map(move |r| {
            if r.is_ok() {
                activity.store(crate::now_secs(), std::sync::atomic::Ordering::Relaxed);
            }
            r.map(|(_seq, data)| data)
        }))
    } else {
        actor.on_upstream_connected(
            upstream_read,
            None,
            &state.resolved_traffic,
            download_cipher,
            0,
        );
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(
            download_rx.expect("download channel must exist when rotation is enabled"),
        ))
    };

    let handle = SessionHandle {
        cmd_tx: actor_tx.clone(),
        upload_cipher,
        encoding,
    };
    state.actors.insert(stream_id, handle);
    let mut early_guard = ActorGuard::new(Arc::clone(&state.actors), stream_id);

    let key = stream_id;
    let actors_ref2 = Arc::clone(&state.actors);
    let actor_handle = tokio::spawn(
        async move {
            let _permit = tunnel_permit;
            let _guard = ActorGuard::new(actors_ref2, key);
            actor.run().await;
        }
        .instrument(tracing::Span::current()),
    );

    let mut tunnel_guard = TunnelGuard::new(actor_handle);

    early_guard.armed = false;

    let padding = utils::random_padding();
    let response = Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .body(body_stream)
        .map_err(|e| ServerError::internal(e.to_string()))?;

    tunnel_guard.disarm();
    Ok(response)
}

async fn spawn_encrypted_tunnel(
    state: Arc<AppState>,
    session_cookie_val: &str,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let parts: Vec<&str> = session_cookie_val.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(ServerError::precondition_required(
            "invalid session cookie format",
        ));
    }
    let (session_id, enc_target_b64, enc_stream_id_b64) = (parts[0], parts[1], parts[2]);

    utils::validate_uuid(session_id)?;

    let entry = state
        .master_store
        .get(session_id)
        .ok_or_else(|| ServerError::precondition_required("session not found"))?;
    let value_ref = entry.value();
    let mut master = Zeroizing::new([0u8; 32]);
    let (username, master_z, created) = value_ref;
    master.copy_from_slice(&**master_z);
    let username = Arc::clone(username);
    let created = *created;
    if crate::now_secs().saturating_sub(created) > MASTER_EXPIRY.as_secs() {
        drop(entry);
        state.master_store.remove(session_id);
        return Err(ServerError::precondition_required("master key expired"));
    }
    span.record("user", username.as_ref());
    drop(entry);

    let cookie_stream_key = crypto::derive_cookie_stream_key(&master);
    let enc_stream_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(enc_stream_id_b64)
        .map_err(|_| ServerError::precondition_required("invalid cookie encoding"))?;
    let stream_id_bytes = crypto::decrypt_bytes(&cookie_stream_key, &enc_stream_id)
        .map_err(|_| ServerError::precondition_required("failed to decrypt stream ID"))?;
    let stream_id_bytes_arr: [u8; 16] = stream_id_bytes
        .try_into()
        .map_err(|_| ServerError::precondition_required("invalid stream ID length"))?;
    let stream_id = Uuid::from_bytes(stream_id_bytes_arr);

    if !state.stream_registry.register(stream_id, crate::now_secs()) {
        warn!(stream_id = %stream_id, session_id = %session_id, "duplicate stream registration attempt");
        return Err(ServerError::precondition_required("stream already active"));
    }

    let mut stream_guard = StreamGuard::new(Arc::clone(&state.stream_registry), stream_id);

    let (upload_key, download_key, target_key) =
        crypto::derive_connection_keys(&master, stream_id.as_bytes());
    let enc_target = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(enc_target_b64)
        .map_err(|_| ServerError::precondition_required("invalid cookie encoding"))?;
    let target_bytes = crypto::decrypt_bytes(&target_key, &enc_target)
        .map_err(|_| ServerError::precondition_required("failed to decrypt target"))?;
    let target = String::from_utf8(target_bytes)
        .map_err(|_| ServerError::precondition_required("invalid target utf8"))?;
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| ServerError::bad_request("target must be host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ServerError::bad_request("invalid port"))?;
    span.record("target", &target);

    let download_cipher: Arc<dyn FrameCipher> = Arc::new(AesFrameCipher::new(&download_key));
    let upload_cipher = Arc::new(AesFrameCipher::new(&upload_key));

    let response = setup_tunnel_response(
        &state,
        body,
        host,
        port,
        stream_id,
        Some(upload_cipher as Arc<dyn FrameCipher>),
        Some(download_cipher),
    )
    .await?;

    stream_guard.disarm();

    info!(stream_id = %stream_id, session_id = %session_id, "tunnel established");
    Ok(response)
}

async fn dispatch_to_actor(handle: SessionHandle, body: Body) -> Result<Response, ServerError> {
    let byte_stream = body.into_data_stream().map(|r| r.map_err(io::Error::other));
    let mut decoder = FrameDecoder::new(
        byte_stream,
        handle.upload_cipher.clone(),
        handle.encoding,
        MAX_FRAME_BUF_SIZE,
    );

    let mut max_seq: u64 = 0;
    let mut frame_count = 0;

    while let Some(result) = decoder.next().await {
        let (seq, data) =
            result.map_err(|e| ServerError::bad_request(format!("frame decode error: {e}")))?;
        max_seq = max_seq.max(seq);
        handle
            .cmd_tx
            .send(TunnelCmd::UploadFrame { seq, data })
            .await
            .map_err(|_| ServerError::bad_gateway("actor closed"))?;
        frame_count += 1;
    }

    if frame_count == 0 {
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .map_err(|_| ServerError::bad_gateway("actor closed"))?;

        match tokio::time::timeout(crate::server::constants::UPLOAD_DONE_TIMEOUT, reply_rx).await {
            Ok(Ok(Some(new_download_rx))) => {
                let padding = utils::random_padding();
                return Response::builder()
                    .header("Cache-Control", "no-store")
                    .header("Set-Cookie", padding)
                    .body(Body::from_stream(
                        tokio_stream::wrappers::ReceiverStream::new(new_download_rx),
                    ))
                    .map_err(|e| ServerError::internal(e.to_string()));
            }
            Ok(Ok(None)) | Ok(Err(_)) => {
                let padding = utils::random_padding();
                return Response::builder()
                    .header("Cache-Control", "no-store")
                    .header("Set-Cookie", padding)
                    .status(axum::http::StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .map_err(|e| ServerError::internal(e.to_string()));
            }
            Err(_) => {
                return Err(ServerError::gateway_timeout("continue timed out"));
            }
        }
    }

    let (ack_tx, ack_rx) = oneshot::channel();
    handle
        .cmd_tx
        .send(TunnelCmd::UploadEos {
            max_seq,
            ack: ack_tx,
        })
        .await
        .map_err(|_| ServerError::bad_gateway("actor closed"))?;

    match tokio::time::timeout(crate::server::constants::UPLOAD_DONE_TIMEOUT, ack_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(e),
        Ok(Err(_)) => return Err(ServerError::bad_gateway("actor closed before upload ack")),
        Err(_) => return Err(ServerError::gateway_timeout("upload drain timeout")),
    }

    let padding = utils::random_padding();
    Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .status(axum::http::StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|e| ServerError::internal(e.to_string()))
}

pub async fn dispatch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ServerError> {
    let span = tracing::Span::current();
    let has_target = headers.get("X-Target").is_some();

    if let Some(stream_cookie_val) = utils::extract_cookie_value(&headers, "stream") {
        let stream_id = Uuid::parse_str(stream_cookie_val)
            .map_err(|_| ServerError::precondition_required("invalid stream id"))?;

        if let Some(handle) = state.actors.get(&stream_id).map(|r| r.value().clone()) {
            return dispatch_to_actor(handle, body).await;
        }

        if has_target {
            return handle_plaintext_tunnel(state, headers, body, span, Some(stream_id)).await;
        }

        return handle_stream_not_found(&state, stream_id);
    }

    if let Some(session_val) = utils::extract_cookie_value(&headers, "session") {
        if session_val.contains(':') {
            return spawn_encrypted_tunnel(state, session_val, body, span).await;
        }
        if has_target {
            let stream_id = Uuid::parse_str(session_val)
                .map_err(|_| ServerError::precondition_required("invalid stream id"))?;
            return handle_plaintext_tunnel(state, headers, body, span, Some(stream_id)).await;
        }
        return Err(ServerError::precondition_required(
            "invalid session cookie — missing target or encrypted payload",
        ));
    }

    if has_target {
        return handle_plaintext_tunnel(state, headers, body, span, None).await;
    }

    let has_handshake_cookie = utils::extract_cookie_value(&headers, "eph_pk_a").is_some();
    if has_handshake_cookie {
        return handle_fresh_handshake(state, headers, body, span).await;
    }

    Err(ServerError::bad_request(
        "missing required cookies or headers",
    ))
}

fn handle_stream_not_found(
    state: &Arc<AppState>,
    stream_id: Uuid,
) -> Result<Response, ServerError> {
    match state.stream_registry.check(stream_id) {
        StreamQueryResult::Consumed => {
            warn!(stream_id = %stream_id, "replay attempt on consumed stream");
            Err(ServerError::precondition_required(
                "stream already consumed",
            ))
        }
        StreamQueryResult::Active => {
            warn!(stream_id = %stream_id, "stream registered but initial tunnel setup did not complete");
            Err(ServerError::precondition_required(
                "stream setup incomplete",
            ))
        }
        StreamQueryResult::Fresh => {
            warn!(stream_id = %stream_id, "upload for unknown stream");
            Err(ServerError::precondition_required("stream not found"))
        }
    }
}

async fn handle_plaintext_tunnel(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Body,
    span: tracing::Span,
    stream_id_opt: Option<Uuid>,
) -> Result<Response, ServerError> {
    let user = validate_jwt_if_needed(&headers, &state.decoding_key, &state.jwt_validation)?;
    span.record("user", &user);

    let target = headers
        .get("X-Target")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::bad_request("missing X-Target header"))?;
    span.record("target", target);

    let stream_id = match stream_id_opt {
        Some(id) => id,
        None => Uuid::new_v4(),
    };

    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| ServerError::bad_request("target must be host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ServerError::bad_request("invalid port"))?;

    if !state.stream_registry.register(stream_id, crate::now_secs()) {
        warn!(stream_id = %stream_id, "duplicate stream registration for plaintext tunnel");
        return Err(ServerError::precondition_required("stream already active"));
    }

    let mut stream_guard = StreamGuard::new(Arc::clone(&state.stream_registry), stream_id);

    let response = setup_tunnel_response(&state, body, host, port, stream_id, None, None).await?;

    stream_guard.disarm();

    info!(stream_id = %stream_id, "tunnel established");
    Ok(response)
}

async fn handle_fresh_handshake(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let user = validate_jwt_if_needed(&headers, &state.decoding_key, &state.jwt_validation)?;
    span.record("user", &user);

    info!("handshake: received ClientHello");

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
    let handshake_key = crypto::derive_handshake_key(&shared_a);
    let handshake_cipher = AesFrameCipher::new(&handshake_key);

    let body_bytes = axum::body::to_bytes(body, MAX_FRAME_BUF_SIZE)
        .await
        .map_err(|e| ServerError::payload_too_large(format!("request body error: {e}")))?;

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
        crypto::derive_initial_master(&ss_mlkem, &ss_x25519)
    };

    let session_id = Uuid::new_v4().to_string();
    state.master_store.insert(
        session_id.clone(),
        (Arc::from(user.as_str()), master, crate::now_secs()),
    );

    info!(session_id = %session_id, "handshake: master key derived");

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
        state.traffic_config.global.padding_threshold,
        state.traffic_config.global.padding_range,
        state.traffic_config.encoding_type,
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

pub fn validate_jwt_if_needed(
    headers: &HeaderMap,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<String, ServerError> {
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

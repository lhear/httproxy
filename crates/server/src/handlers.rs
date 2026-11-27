use aws_lc_rs::aead::LessSafeKey;
use axum::{body::Body, extract::State, http::HeaderMap, response::Response};
use base64::Engine;
use bytes::BytesMut;
use futures::StreamExt;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{Instrument, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::actor::tunnel::TunnelCmd;
use crate::actor::upload::UploadCmd;
use crate::connection::connect_upstream;
use crate::constants::{
    BODY_READ_TIMEOUT, CONNECT_TIMEOUT, MASTER_EXPIRY, MAX_FRAME_BUF_SIZE, MAX_HANDSHAKE_BODY_SIZE,
    TOKEN_CACHE_TTL, TUNNEL_CMD_CHANNEL_CAPACITY, UPLOAD_CMD_CHANNEL_CAPACITY,
};
use crate::error::ServerError;
use crate::janitor;
use crate::stream::FrameDecoder;
use crate::stream_registry::StreamQueryResult;
use crate::upstream::{Upstream, UpstreamWrite};
use crate::{SessionHandle, utils};
use httproxy_core::crypto::{self, AesFrameCipher, StreamCipher, TlsInspector};
use httproxy_core::shaper::{self, FrameCipher};
use tokio::sync::oneshot;

use super::AppState;
use crate::stream_registry::StreamRegistry;

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

struct TunnelRequest {
    user: Arc<str>,
    body: Body,
    host: String,
    port: u16,
    stream_id: Uuid,
    upload_cipher: Arc<dyn FrameCipher>,
    download_cipher: Arc<dyn FrameCipher>,
}

async fn setup_tunnel_response(
    state: &Arc<AppState>,
    request: TunnelRequest,
) -> Result<Response, ServerError> {
    let tunnel_permit = state
        .tunnel_quota
        .try_acquire(&request.user)
        .ok_or_else(|| ServerError::service_unavailable("too many concurrent tunnels"))?;

    let encoding = state.traffic_config.encoding_type;

    let max_download_bytes = state.traffic_config.max_download_bytes;
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(
        httproxy_core::monotonic_secs(),
    ));

    let (actor_tx, actor_rx) = tokio::sync::mpsc::channel::<TunnelCmd>(TUNNEL_CMD_CHANNEL_CAPACITY);

    let upstream = open_upstream(state, &request.host, request.port).await?;

    let (upstream_read, upstream_write) = upstream.into_split();

    let (upload_tx, upload_handle) = spawn_upload_actor(upstream_write);

    let upload_cipher = request.upload_cipher;
    pump_initial_body(request.body, &upload_tx, upload_cipher.clone(), encoding).await?;

    let upload_tx_for_actor = upload_tx.clone();

    let mut actor = crate::actor::tunnel::TunnelActor::new(
        actor_rx,
        request.stream_id,
        Arc::clone(&state.stream_registry),
        max_download_bytes,
        Arc::clone(&last_activity),
    );
    actor.set_upload_channel(upload_tx_for_actor, upload_handle);

    actor.on_upstream_connected(
        upstream_read,
        None,
        &state.resolved_traffic,
        request.download_cipher,
        0,
        Some(TlsInspector::new()),
    );

    let body_stream = Body::from_stream(
        actor
            .take_segment()
            .ok_or_else(|| ServerError::internal("download segment unavailable"))?,
    );

    let handle = SessionHandle {
        cmd_tx: actor_tx.clone(),
        upload_tx: upload_tx.clone(),
        upload_cipher,
        encoding,
    };
    state.actors.insert(request.stream_id, handle);
    let mut early_guard = ActorGuard::new(Arc::clone(&state.actors), request.stream_id);

    let key = request.stream_id;
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

async fn open_upstream(
    state: &Arc<AppState>,
    host: &str,
    port: u16,
) -> Result<Upstream, ServerError> {
    if let Some(dns) = state
        .dns_client
        .as_ref()
        .filter(|dns| port == 53 && dns.hijack_enabled())
    {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let dns = Arc::clone(dns);
        tokio::spawn(async move { serve_dns_tcp(server, dns).await });
        return Ok(Upstream::Dns(client));
    }

    tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_upstream(
            state.warp.as_ref(),
            state.dns_client.as_ref(),
            state.client_subnet,
            state.socks5_proxy.as_ref(),
            host,
            port,
        ),
    )
    .await
    .map_err(|_| ServerError::gateway_timeout("connect timeout"))?
    .map_err(|e| ServerError::bad_gateway(e.to_string()))
}

fn spawn_upload_actor(
    upstream_write: UpstreamWrite,
) -> (
    tokio::sync::mpsc::Sender<UploadCmd>,
    tokio::task::JoinHandle<()>,
) {
    let (upload_tx, upload_rx) =
        tokio::sync::mpsc::channel::<UploadCmd>(UPLOAD_CMD_CHANNEL_CAPACITY);
    let actor = crate::actor::upload::UploadActor::new(upload_rx, upstream_write, 0);
    let handle =
        tokio::spawn(async move { actor.run().await }.instrument(tracing::Span::current()));
    (upload_tx, handle)
}

async fn pump_initial_body(
    body: Body,
    upload_tx: &tokio::sync::mpsc::Sender<UploadCmd>,
    cipher: Arc<dyn FrameCipher>,
    encoding: httproxy_core::shaper::EncodingType,
) -> Result<(), ServerError> {
    let byte_stream = body.into_data_stream().map(|r| r.map_err(io::Error::other));
    let mut decoder = FrameDecoder::new(byte_stream, cipher, encoding, MAX_FRAME_BUF_SIZE);

    let deadline = tokio::time::Instant::now() + BODY_READ_TIMEOUT;
    while let Some(result) = tokio::time::timeout_at(deadline, decoder.next())
        .await
        .map_err(|_| ServerError::request_timeout("request body read timed out"))?
    {
        let (seq, data) =
            result.map_err(|e| ServerError::bad_request(format!("decode error: {e}")))?;
        upload_tx
            .send(UploadCmd::Frame { seq, data })
            .await
            .map_err(|_| ServerError::bad_gateway("upload actor closed during initial stream"))?;
    }
    Ok(())
}

async fn serve_dns_tcp(
    mut stream: tokio::io::DuplexStream,
    dns: Arc<httproxy_core::dns::DnsClient>,
) {
    loop {
        let mut length = [0; 2];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let query_len = u16::from_be_bytes(length) as usize;
        if !(12..=u16::MAX as usize).contains(&query_len) {
            return;
        }
        let mut query = vec![0; query_len];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let Ok(response) = dns.query(&query).await else {
            return;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            return;
        };
        if stream.write_all(&response_len.to_be_bytes()).await.is_err()
            || stream.write_all(&response).await.is_err()
            || stream.flush().await.is_err()
        {
            return;
        }
    }
}

async fn spawn_encrypted_tunnel(
    state: Arc<AppState>,
    session_cookie_val: &str,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let Some((session_id, rest)) = session_cookie_val.split_once(':') else {
        return Err(ServerError::precondition_required(
            "invalid session cookie format",
        ));
    };
    let Some((enc_target_b64, enc_stream_id_b64)) = rest.split_once(':') else {
        return Err(ServerError::precondition_required(
            "invalid session cookie format",
        ));
    };

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
    if httproxy_core::monotonic_secs().saturating_sub(created) > MASTER_EXPIRY.as_secs() {
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

    if !state
        .stream_registry
        .register(stream_id, httproxy_core::monotonic_secs())
    {
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

    let download_cipher: Arc<dyn FrameCipher> = Arc::new(StreamCipher::new(&download_key));
    let upload_cipher: Arc<dyn FrameCipher> = Arc::new(StreamCipher::new(&upload_key));

    let response = setup_tunnel_response(
        &state,
        TunnelRequest {
            user: username,
            body,
            host: host.to_owned(),
            port,
            stream_id,
            upload_cipher,
            download_cipher,
        },
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

    let body_deadline = tokio::time::Instant::now() + BODY_READ_TIMEOUT;
    while let Some(result) = tokio::time::timeout_at(body_deadline, decoder.next())
        .await
        .map_err(|_| ServerError::request_timeout("request body read timed out"))?
    {
        let (seq, data) =
            result.map_err(|e| ServerError::bad_request(format!("frame decode error: {e}")))?;
        max_seq = max_seq.max(seq);
        handle
            .upload_tx
            .send(UploadCmd::Frame { seq, data })
            .await
            .map_err(|_| ServerError::bad_gateway("upload actor closed"))?;
        frame_count += 1;
    }

    if frame_count == 0 {
        let (reply_tx, reply_rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .map_err(|_| ServerError::bad_gateway("actor closed"))?;

        match tokio::time::timeout(crate::constants::UPLOAD_DONE_TIMEOUT, reply_rx).await {
            Ok(Ok(Some(segment))) => {
                let padding = utils::random_padding();
                return Response::builder()
                    .header("Cache-Control", "no-store")
                    .header("Set-Cookie", padding)
                    .body(Body::from_stream(segment))
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
        .upload_tx
        .send(UploadCmd::Eos {
            max_seq,
            ack: ack_tx,
        })
        .await
        .map_err(|_| ServerError::bad_gateway("upload actor closed"))?;

    match tokio::time::timeout(crate::constants::UPLOAD_DONE_TIMEOUT, ack_rx).await {
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

    if let Some(stream_cookie_val) = utils::extract_cookie_value(&headers, "stream") {
        let stream_id = Uuid::parse_str(stream_cookie_val)
            .map_err(|_| ServerError::precondition_required("invalid stream id"))?;

        if let Some(handle) = state.actors.get(&stream_id).map(|r| r.value().clone()) {
            return dispatch_to_actor(handle, body).await;
        }

        return handle_stream_not_found(&state, stream_id);
    }

    if let Some(session_val) = utils::extract_cookie_value(&headers, "session") {
        if !session_val.contains(':') {
            return Err(ServerError::precondition_required(
                "invalid session cookie: encrypted session required",
            ));
        }
        return spawn_encrypted_tunnel(state, session_val, body, span).await;
    }

    handle_fresh_handshake(state, body, span).await
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

async fn handle_fresh_handshake(
    state: Arc<AppState>,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    info!("handshake: received ClientHello");

    let body_bytes = tokio::time::timeout(
        BODY_READ_TIMEOUT,
        axum::body::to_bytes(body, MAX_HANDSHAKE_BODY_SIZE),
    )
    .await
    .map_err(|_| ServerError::request_timeout("request body read timed out"))?
    .map_err(|e| ServerError::payload_too_large(format!("request body error: {e}")))?;

    let encoding = state.traffic_config.encoding_type;
    let mut buf = BytesMut::from(&body_bytes[..]);

    let Some((_seq, payload)) =
        shaper::decode_from_buffer(&mut buf, &crypto::PlainFrameCipher, encoding)?
    else {
        return Err(ServerError::bad_request("invalid client handshake frame"));
    };
    let (eph_pk, sealed) = payload
        .split_at_checked(crypto::KEY_LEN)
        .ok_or_else(|| ServerError::bad_request("client handshake frame too short"))?;
    let eph_pk = crypto::public_key_from_slice(eph_pk)
        .map_err(|e| ServerError::bad_request(e.to_string()))?;

    let handshake_ss = crypto::diffie_hellman(&state.private_key, &eph_pk)
        .map_err(|e| ServerError::bad_request(e.to_string()))?;
    let handshake_key = crypto::derive_handshake_key(&handshake_ss);

    let token = Zeroizing::new(
        crypto::decrypt_bytes(&handshake_key, sealed)
            .map_err(|_| ServerError::bad_request("invalid handshake payload"))?,
    );
    let token =
        std::str::from_utf8(&token).map_err(|_| ServerError::unauthorized("invalid token"))?;
    let user = validate_token_if_needed(token, &state.token_key, &state.token_cache).await?;
    span.record("user", &*user);

    let (server_eph_sk, server_eph_pk) = crypto::generate_keypair();
    let master_ss = crypto::diffie_hellman(&server_eph_sk, &eph_pk)
        .map_err(|e| ServerError::bad_request(e.to_string()))?;
    let master = crypto::derive_initial_master(&master_ss);

    let session_id = Uuid::new_v4().to_string();
    let now = httproxy_core::monotonic_secs();
    janitor::ensure_session_capacity(&state.master_store, now, state.max_sessions);
    state
        .master_store
        .insert(session_id.clone(), (user, master, now));

    info!(session_id = %session_id, "handshake: master key derived");

    let sid_bytes = session_id.as_bytes();
    let mut server_hello = Vec::with_capacity(2 + sid_bytes.len() + crypto::KEY_LEN);
    server_hello.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
    server_hello.extend_from_slice(sid_bytes);
    server_hello.extend_from_slice(server_eph_pk.as_bytes());

    let server_hello_frame = shaper::encode_frame_padded(
        &server_hello,
        0,
        &AesFrameCipher::new(&handshake_key),
        state.traffic_config.handshake_padding_range(),
        encoding,
    )
    .map_err(|e| ServerError::internal(format!("encode ServerHello: {e}")))?;

    drop(handshake_key);

    info!(session_id = %session_id, "handshake: ServerHello sent");

    let cookie_padding = utils::random_padding();
    Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", cookie_padding)
        .body(Body::from(server_hello_frame))
        .map_err(|e| ServerError::internal(e.to_string()))
}

pub async fn validate_token_if_needed(
    token: &str,
    key: &LessSafeKey,
    cache: &moka::future::Cache<Box<str>, Arc<str>>,
) -> Result<Arc<str>, ServerError> {
    if token.is_empty() || token.len() > crate::token::MAX_TOKEN_LEN {
        warn!("rejected: invalid token length");
        return Err(ServerError::unauthorized("invalid token"));
    }

    if let Some(user) = cache.get(token).await {
        return Ok(user);
    }

    let claims = crate::token::open(key, token).map_err(|e| {
        warn!("rejected: invalid token - {e}");
        ServerError::unauthorized("invalid token")
    })?;

    let user: Arc<str> = Arc::from(claims.sub);
    let now = httproxy_core::unix_secs();
    if claims.exp > now.saturating_add(TOKEN_CACHE_TTL.as_secs()) {
        cache
            .insert(token.to_owned().into_boxed_str(), Arc::clone(&user))
            .await;
    }
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::http::StatusCode;

    async fn test_state() -> Arc<AppState> {
        test_state_with_public_key(None).await.0
    }

    async fn test_state_with_public_key(
        handshake_padding: Option<[usize; 2]>,
    ) -> (Arc<AppState>, crypto::PublicKey) {
        let (private_key, public_key) = crypto::generate_keypair();
        let mut cfg = httproxy_core::config::ServerTopConfig {
            server: httproxy_core::config::ServerSection {
                listen: "127.0.0.1:0".to_string(),
                path: "/secret".to_string(),
                private_key: crypto::private_key_to_b64(&private_key),
                max_tunnels: None,
                max_sessions: None,
            },
            auth: httproxy_core::config::AuthSection {
                secret: "test-secret".to_string(),
            },
            proxy: None,
            log: None,
            dns: None,
            warp: None,
            traffic_shaping: httproxy_core::shaper::TrafficConfig {
                global: httproxy_core::shaper::PaddingConfig {
                    padding_threshold: 0,
                    padding_range: [0, 0],
                },
                handshake: handshake_padding
                    .map(|padding_range| httproxy_core::shaper::HandshakePadding { padding_range }),
                stages: vec![],
                encoding_type: httproxy_core::shaper::EncodingType::Binary,
                max_download_bytes: None,
            },
        };
        let state = crate::build_state(&mut cfg).await.unwrap();
        (state, public_key)
    }

    fn valid_token() -> String {
        crate::token::issue(
            &crate::token::key_from_secret(b"test-secret"),
            &crate::Claims {
                sub: "user".to_string(),
                exp: 4_102_444_800,
            },
        )
    }

    fn token_with_exp(exp: u64) -> String {
        crate::token::issue(
            &crate::token::key_from_secret(b"test-secret"),
            &crate::Claims {
                sub: "user".to_string(),
                exp,
            },
        )
    }

    #[tokio::test]
    async fn invalid_tokens_are_never_cached() {
        let state = test_state().await;
        assert!(
            validate_token_if_needed("not-a-token", &state.token_key, &state.token_cache)
                .await
                .is_err()
        );
        assert!(state.token_cache.get("not-a-token").await.is_none());
    }

    #[tokio::test]
    async fn token_close_to_expiry_is_not_cached() {
        let state = test_state().await;
        let token = token_with_exp(httproxy_core::unix_secs() + 5);
        assert!(
            validate_token_if_needed(&token, &state.token_key, &state.token_cache)
                .await
                .is_ok()
        );
        assert!(state.token_cache.get(token.as_str()).await.is_none());
    }

    #[tokio::test]
    async fn dispatch_rejects_without_cookies_or_target() {
        let state = test_state().await;
        let err = dispatch(State(state), HeaderMap::new(), Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dispatch_rejects_malformed_stream_cookie() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "stream=not-a-uuid".parse().unwrap());
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::PRECONDITION_REQUIRED);
    }

    fn encrypted_client_hello(
        state: &Arc<AppState>,
        server_pk: &crypto::PublicKey,
        token: &str,
    ) -> Body {
        let (eph_sk, eph_pk) = crypto::generate_keypair();
        let handshake_ss = crypto::diffie_hellman(&eph_sk, server_pk).unwrap();
        let handshake_key = crypto::derive_handshake_key(&handshake_ss);
        let sealed = crypto::encrypt_bytes(&handshake_key, token.as_bytes()).unwrap();

        let mut payload = Vec::with_capacity(crypto::KEY_LEN + sealed.len());
        payload.extend_from_slice(eph_pk.as_bytes());
        payload.extend_from_slice(&sealed);

        Body::from(
            shaper::encode_frame_padded(
                &payload,
                0,
                &crypto::PlainFrameCipher,
                state.traffic_config.handshake_padding_range(),
                state.traffic_config.encoding_type,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn dispatch_rejects_bad_token_in_client_hello() {
        let (state, public_key) = test_state_with_public_key(None).await;
        let body = encrypted_client_hello(&state, &public_key, "invalid-token");
        let err = dispatch(State(state), HeaderMap::new(), body)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn handshake_response_uses_handshake_padding() {
        let (state, public_key) = test_state_with_public_key(Some([1024, 1024])).await;
        let body = encrypted_client_hello(&state, &public_key, &valid_token());
        let response = dispatch(State(state), HeaderMap::new(), body)
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.len() > 1024, "ServerHello was not padded");
    }

    #[tokio::test]
    async fn dispatch_rejects_plaintext_tunnel() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert("X-Target", "127.0.0.1:1".parse().unwrap());
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dispatch_rejects_malformed_session_cookie() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc".parse().unwrap());
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::PRECONDITION_REQUIRED);
    }

    #[tokio::test]
    async fn dispatch_rejects_expired_token_on_handshake_path() {
        let (state, public_key) = test_state_with_public_key(None).await;
        let body = encrypted_client_hello(&state, &public_key, &token_with_exp(1));
        let err = dispatch(State(state), HeaderMap::new(), body)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}

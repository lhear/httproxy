use axum::{body::Body, extract::State, http::HeaderMap, response::Response};
use base64::Engine;
use bytes::BytesMut;
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
use crate::server::actor::upload::UploadCmd;
use crate::server::connection::connect_upstream;
use crate::server::constants::{
    BODY_READ_TIMEOUT, CONNECT_TIMEOUT, JWT_CACHE_TTL, MASTER_EXPIRY, MAX_FRAME_BUF_SIZE,
    TUNNEL_CMD_CHANNEL_CAPACITY, UPLOAD_CMD_CHANNEL_CAPACITY,
};
use crate::server::stream::FrameDecoder;
use crate::server::stream_registry::StreamQueryResult;
use crate::server::vnet;
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

    let (actor_tx, actor_rx) = tokio::sync::mpsc::channel::<TunnelCmd>(TUNNEL_CMD_CHANNEL_CAPACITY);

    let upstream = match state.vnet.open(host, port).await? {
        Some(sock) => sock,
        None => tokio::time::timeout(
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
        .map_err(|e| ServerError::bad_gateway(e.to_string()))?,
    };

    let (upstream_read, upstream_write) = upstream.into_split();

    let (upload_tx, upload_rx) =
        tokio::sync::mpsc::channel::<UploadCmd>(UPLOAD_CMD_CHANNEL_CAPACITY);
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

    let body_deadline = tokio::time::Instant::now() + BODY_READ_TIMEOUT;
    while let Some(result) = tokio::time::timeout_at(body_deadline, decoder.next())
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

    let upload_tx_for_actor = upload_tx.clone();

    let mut actor = crate::server::actor::tunnel::TunnelActor::new(
        actor_rx,
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
        // 响应体直接从 shaper 拉取，不再经过"额外任务 + 每帧 mpsc"
        Body::from_stream(
            actor
                .take_segment()
                .ok_or_else(|| ServerError::internal("download segment unavailable"))?,
        )
    };

    let handle = SessionHandle {
        cmd_tx: actor_tx.clone(),
        upload_tx: upload_tx.clone(),
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

        match tokio::time::timeout(crate::server::constants::UPLOAD_DONE_TIMEOUT, reply_rx).await {
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

    // 虚拟内网的两条专用通道：`vnet` 是长连接的响应体（下行），
    // `vnet_up` 是并发上传的数据帧（上行）
    if let Some(cookie) = utils::extract_cookie_value(&headers, "vnet") {
        let cookie = cookie.to_owned();
        return handle_vnet_downlink(state, headers, &cookie).await;
    }
    if let Some(cookie) = utils::extract_cookie_value(&headers, "vnet_up") {
        let cookie = cookie.to_owned();
        return handle_vnet_uplink(state, headers, &cookie, body).await;
    }

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
    let user = validate_jwt_if_needed(
        &headers,
        &state.decoding_key,
        &state.jwt_validation,
        &state.jwt_cache,
    )
    .await?;
    span.record("user", &*user);

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

/// 虚拟内网：在线节点的身份。
struct PeerIdentity {
    id: Uuid,
    ip: std::net::IpAddr,
    /// 加密模式下的下行帧密文（服务端 → 节点）
    down_cipher: Option<Arc<dyn FrameCipher>>,
}

fn b64_decode(value: &str, what: &str) -> Result<Vec<u8>, ServerError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ServerError::precondition_required(format!("invalid {what} encoding")))
}

/// 取出一条未过期的会话主密钥。
fn load_master(state: &AppState, session_id: &str) -> Result<Zeroizing<[u8; 32]>, ServerError> {
    utils::validate_uuid(session_id)?;
    let entry = state
        .master_store
        .get(session_id)
        .ok_or_else(|| ServerError::precondition_required("session not found"))?;
    let (_, master_z, created) = entry.value();
    let created = *created;
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&**master_z);
    drop(entry);

    if crate::now_secs().saturating_sub(created) > MASTER_EXPIRY.as_secs() {
        state.master_store.remove(session_id);
        return Err(ServerError::precondition_required("master key expired"));
    }
    Ok(master)
}

/// 解密节点标识：`<session_id>:<b64(enc peer_id)>`。
fn decode_peer_id(
    state: &AppState,
    session_id: &str,
    enc_id: &str,
) -> Result<(Uuid, Zeroizing<[u8; 32]>), ServerError> {
    let master = load_master(state, session_id)?;
    let key = crypto::derive_cookie_stream_key(&master);
    let raw = crypto::decrypt_bytes(&key, &b64_decode(enc_id, "peer id")?)
        .map_err(|_| ServerError::precondition_required("failed to decrypt peer id"))?;
    let bytes: [u8; 16] = raw
        .try_into()
        .map_err(|_| ServerError::precondition_required("invalid peer id length"))?;
    Ok((Uuid::from_bytes(bytes), master))
}

/// 明文模式的节点身份：`<b64(IP)>.<节点 id>`。
fn decode_plain_identity(cookie: &str) -> Result<(Uuid, std::net::IpAddr), ServerError> {
    let (ip_part, session) = cookie
        .split_once('.')
        .ok_or_else(|| ServerError::bad_request("invalid vnet cookie"))?;
    let raw = b64_decode(ip_part, "vnet ip")?;
    let ip = String::from_utf8(raw)
        .ok()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| ServerError::bad_request("invalid virtual ip in vnet cookie"))?;
    let session =
        Uuid::parse_str(session).map_err(|_| ServerError::bad_request("invalid peer id"))?;
    Ok((session, ip))
}

/// 虚拟内网的下行通道：一次 POST 的响应体就是节点的长连接。
async fn handle_vnet_downlink(
    state: Arc<AppState>,
    headers: HeaderMap,
    cookie: &str,
) -> Result<Response, ServerError> {
    let span = tracing::Span::current();
    let user = validate_jwt_if_needed(
        &headers,
        &state.decoding_key,
        &state.jwt_validation,
        &state.jwt_cache,
    )
    .await?;
    span.record("user", &*user);

    let ports = headers
        .get("X-Vnet-Ports")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::bad_request("missing X-Vnet-Ports header"))?;
    let ports = crate::config::PortSet::parse_list(ports)
        .map_err(|e| ServerError::bad_request(format!("invalid X-Vnet-Ports: {e}")))?;

    let identity = match cookie.split_once(':') {
        None => {
            let (id, ip) = decode_plain_identity(cookie)?;
            PeerIdentity {
                id,
                ip,
                down_cipher: None,
            }
        }
        Some((session_id, rest)) => {
            let (enc_id, enc_ip) = rest
                .split_once(':')
                .ok_or_else(|| ServerError::precondition_required("invalid vnet cookie"))?;
            let (id, master) = decode_peer_id(&state, session_id, enc_id)?;
            let (_, down_key, target_key) = crypto::derive_connection_keys(&master, id.as_bytes());
            let ip_bytes = crypto::decrypt_bytes(&target_key, &b64_decode(enc_ip, "vnet ip")?)
                .map_err(|_| ServerError::precondition_required("failed to decrypt vnet ip"))?;
            let ip = String::from_utf8(ip_bytes)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .ok_or_else(|| ServerError::precondition_required("invalid vnet ip"))?;
            PeerIdentity {
                id,
                ip,
                down_cipher: Some(Arc::new(AesFrameCipher::new(&down_key))),
            }
        }
    };

    let target = identity.ip.to_string();
    span.record("target", target.as_str());

    let max_data = vnet::max_data_chunk(
        identity.down_cipher.is_some(),
        state.traffic_config.encoding_type,
    );
    let (peer, down_rx) = state.vnet.register(
        identity.id,
        identity.ip,
        ports,
        identity.down_cipher,
        max_data,
    )?;

    let frames = vnet::spawn_downlink(
        Arc::clone(&state.vnet),
        peer,
        down_rx,
        Arc::clone(&state.resolved_traffic),
    );

    let padding = utils::random_padding();
    Response::builder()
        .header("Cache-Control", "no-store")
        // 这条响应是永不结束的流，反向代理一缓冲就全毁了：帧（尤其是 20s
        // 一次的心跳）会滞留在代理的缓冲里，节点收不到 PING 也就不回 PONG，
        // 服务端随后判定节点失联并摘掉注册——表现为「用一会儿就全断了」。
        // nginx 认这个头；其他代理按 §部署 里的说明关掉缓冲。
        .header("X-Accel-Buffering", "no")
        .header("Set-Cookie", padding)
        .body(Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(frames),
        ))
        .map_err(|e| ServerError::internal(e.to_string()))
}

/// 虚拟内网的上行通道：节点把自己一侧的字节批量 POST 上来。
async fn handle_vnet_uplink(
    state: Arc<AppState>,
    headers: HeaderMap,
    cookie: &str,
    body: Body,
) -> Result<Response, ServerError> {
    let (peer, cipher): (Option<Arc<vnet::VnetPeer>>, Option<Arc<dyn FrameCipher>>) =
        match cookie.split_once(':') {
            None => {
                // 明文模式与普通隧道的上传保持一致：带 token 才认
                validate_jwt_if_needed(
                    &headers,
                    &state.decoding_key,
                    &state.jwt_validation,
                    &state.jwt_cache,
                )
                .await?;
                let id = Uuid::parse_str(cookie)
                    .map_err(|_| ServerError::bad_request("invalid peer id"))?;
                (state.vnet.get_by_id(&id), None)
            }
            Some((session_id, enc_id)) => {
                let (id, master) = decode_peer_id(&state, session_id, enc_id)?;
                let (upload_key, _, _) = crypto::derive_connection_keys(&master, id.as_bytes());
                let cipher: Arc<dyn FrameCipher> = Arc::new(AesFrameCipher::new(&upload_key));
                (state.vnet.get_by_id(&id), Some(cipher))
            }
        };

    let Some(peer) = peer else {
        return Err(ServerError::precondition_required("peer not found"));
    };

    let byte_stream = body.into_data_stream().map(|r| r.map_err(io::Error::other));
    let mut decoder = FrameDecoder::new(
        byte_stream,
        cipher,
        state.traffic_config.encoding_type,
        MAX_FRAME_BUF_SIZE,
    );

    let deadline = tokio::time::Instant::now() + BODY_READ_TIMEOUT;
    while let Some(result) = tokio::time::timeout_at(deadline, decoder.next())
        .await
        .map_err(|_| ServerError::request_timeout("peer uplink read timed out"))?
    {
        let (seq, payload) = result
            .map_err(|e| ServerError::bad_request(format!("peer frame decode error: {e}")))?;
        if !peer.push_uplink(vnet::UplinkFrame { seq, payload }).await {
            break;
        }
    }

    let padding = utils::random_padding();
    Response::builder()
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", padding)
        .status(axum::http::StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|e| ServerError::internal(e.to_string()))
}

async fn handle_fresh_handshake(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Body,
    span: tracing::Span,
) -> Result<Response, ServerError> {
    let user = validate_jwt_if_needed(
        &headers,
        &state.decoding_key,
        &state.jwt_validation,
        &state.jwt_cache,
    )
    .await?;
    span.record("user", &*user);

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

    let body_bytes = tokio::time::timeout(
        BODY_READ_TIMEOUT,
        axum::body::to_bytes(body, MAX_FRAME_BUF_SIZE),
    )
    .await
    .map_err(|_| ServerError::request_timeout("request body read timed out"))?
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
        let ss_x25519 = crypto::diffie_hellman(&server_eph_sk, &client_eph_pk_b);
        crypto::derive_initial_master(&ss_mlkem, &ss_x25519)
    };

    let session_id = Uuid::new_v4().to_string();
    state
        .master_store
        .insert(session_id.clone(), (user, master, crate::now_secs()));

    info!(session_id = %session_id, "handshake: master key derived");

    let sid_bytes = session_id.as_bytes();
    let mut server_hello = Vec::with_capacity(2 + sid_bytes.len() + ct.len() + 32);
    server_hello.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
    server_hello.extend_from_slice(sid_bytes);
    server_hello.extend_from_slice(&ct);
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

pub async fn validate_jwt_if_needed(
    headers: &HeaderMap,
    key: &DecodingKey,
    validation: &Validation,
    cache: &moka::future::Cache<Box<str>, Arc<str>>,
) -> Result<Arc<str>, ServerError> {
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

    if let Some(user) = cache.get(token).await {
        return Ok(user);
    }

    let claims = jsonwebtoken::decode::<super::Claims>(token, key, validation)
        .map(|td| td.claims)
        .map_err(|e| {
            warn!("rejected: invalid token - {:?}", e);
            ServerError::unauthorized("invalid token")
        })?;

    let user: Arc<str> = Arc::from(claims.sub);
    // 只在 token 剩余寿命明显长于缓存 TTL 时才缓存，避免缓存把过期时间往后拖
    let now = crate::unix_now_secs();
    if claims.exp > now.saturating_add(JWT_CACHE_TTL.as_secs()) {
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
        let mut cfg = crate::config::ServerTopConfig {
            server: crate::config::ServerSection {
                listen: "127.0.0.1:0".to_string(),
                path: "/secret".to_string(),
                private_key: None,
                max_tunnels: None,
            },
            auth: crate::config::AuthSection {
                secret: "test-secret".to_string(),
            },
            proxy: None,
            log: None,
            dns: None,
            traffic_shaping: crate::shaper::TrafficConfig {
                global: crate::shaper::PaddingConfig {
                    padding_threshold: 0,
                    padding_range: [0, 0],
                },
                stages: vec![],
                encoding_type: crate::shaper::EncodingType::Binary,
                max_download_bytes: None,
            },
        };
        crate::server::build_state(&mut cfg).await.unwrap()
    }

    fn valid_token() -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &crate::server::Claims {
                sub: "user".to_string(),
                exp: 4_102_444_800,
            },
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn token_with_exp(exp: u64) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &crate::server::Claims {
                sub: "user".to_string(),
                exp,
            },
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn valid_token_is_cached_and_reused() {
        let state = test_state().await;
        let token = valid_token();
        let headers = bearer(&token);

        let first = validate_jwt_if_needed(
            &headers,
            &state.decoding_key,
            &state.jwt_validation,
            &state.jwt_cache,
        )
        .await
        .unwrap();
        assert_eq!(&*first, "user");
        let cached = state
            .jwt_cache
            .get(token.as_str())
            .await
            .expect("valid token must be cached");
        assert_eq!(&*cached, "user");

        // 第二次命中缓存，返回同一个 Arc，不再做一次签名校验
        let second = validate_jwt_if_needed(
            &headers,
            &state.decoding_key,
            &state.jwt_validation,
            &state.jwt_cache,
        )
        .await
        .unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "cache hit must reuse the entry"
        );
    }

    #[tokio::test]
    async fn invalid_tokens_are_never_cached() {
        let state = test_state().await;
        let headers = bearer("not-a-jwt");
        assert!(
            validate_jwt_if_needed(
                &headers,
                &state.decoding_key,
                &state.jwt_validation,
                &state.jwt_cache
            )
            .await
            .is_err()
        );
        assert!(state.jwt_cache.get("not-a-jwt").await.is_none());
    }

    #[tokio::test]
    async fn token_close_to_expiry_is_not_cached() {
        let state = test_state().await;
        // 5 秒后过期：仍能通过校验（默认 60s leeway），但不能进缓存，
        // 否则缓存 TTL 会把过期时间往后拖。
        let token = token_with_exp(crate::unix_now_secs() + 5);
        let headers = bearer(&token);
        assert!(
            validate_jwt_if_needed(
                &headers,
                &state.decoding_key,
                &state.jwt_validation,
                &state.jwt_cache
            )
            .await
            .is_ok()
        );
        assert!(state.jwt_cache.get(token.as_str()).await.is_none());
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

    #[tokio::test]
    async fn dispatch_rejects_unknown_stream() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("stream={}", Uuid::new_v4()).parse().unwrap(),
        );
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::PRECONDITION_REQUIRED);
    }

    #[tokio::test]
    async fn dispatch_rejects_bad_jwt_with_target() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert("X-Target", "127.0.0.1:1".parse().unwrap());
        headers.insert("Authorization", "Bearer invalid-token".parse().unwrap());
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dispatch_bad_gateway_on_unreachable_target_with_valid_jwt() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert("X-Target", "127.0.0.1:1".parse().unwrap());
        headers.insert(
            "Authorization",
            format!("Bearer {}", valid_token()).parse().unwrap(),
        );
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
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
    async fn dispatch_routes_expired_jwt_to_handshake_cookie_path() {
        let state = test_state().await;
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &crate::server::Claims {
                sub: "user".to_string(),
                exp: 1,
            },
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("X-Target", "127.0.0.1:1".parse().unwrap());
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let err = dispatch(State(state), headers, Body::empty())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}

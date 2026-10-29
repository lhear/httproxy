//! 虚拟内网：客户端侧。
//!
//! 虚拟内网是一张以服务端为中心的覆盖网络：客户端声明 `virtual_ip` 后，就等于
//! 在这张网里占住了一个地址，其他客户端可以直接把它当代理目标。为了做到这点，
//! 本机会主动与服务端保持一条长连接：
//!
//! * **下行**——一个 POST 拿到一条无限的响应体，服务端把 `OPEN / DATA / CLOSE /
//!   PING` 这几类 [`crate::mux`] 帧推下来；
//! * **上行**——`PONG`、`OPEN_OK / OPEN_FAIL` 和业务数据被打包成一帧批，
//!   用小 POST 并发送回服务端（服务端按帧序号重排序）。
//!
//! 收到 `OPEN` 就连本机对应的端口，然后在这条本地连接和通道之间搬字节。
//! 连接断了就退避重连——这正是「必须保持长连接，否则地址不可达」的落点：
//! 服务端的注册表里只有活着的长连接，断掉就等于该虚拟 IP 下线。

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::StreamExt;
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::client::constants::{
    DOWNLOAD_CONNECT_TIMEOUT, MASTER_RESUME_WINDOW_SECS, UPLOAD_REQUEST_TIMEOUT, VNET_BATCH_BYTES,
    VNET_CONN_CAPACITY, VNET_CONNECT_TIMEOUT, VNET_DECODE_BUF, VNET_RECONNECT_MAX,
    VNET_RECONNECT_MIN, VNET_UPLINK_CONCURRENCY, VNET_UPLINK_QUEUE,
};
use crate::client::state::SharedState;
use crate::client::utils;
use crate::config::PortSet;
use crate::crypto::{self, AesFrameCipher};
use crate::mux::{self, Tag, ToSocket};
use crate::shaper::{self, FrameCipher};

/// 校验过的虚拟内网配置。
#[derive(Debug, Clone)]
pub struct VnetSpec {
    /// 其他客户端用来访问本机服务的虚拟地址
    pub ip: IpAddr,
    /// 允许被访问的本地端口
    pub ports: PortSet,
}

impl VnetSpec {
    pub fn new(ip: &str, ports: PortSet) -> Result<Self> {
        let ip: IpAddr = ip
            .trim()
            .parse()
            .with_context(|| format!("invalid [client] virtual_ip: {ip}"))?;
        if ip.is_unspecified() {
            bail!("[client] virtual_ip must not be the unspecified address");
        }
        if ports.is_empty() {
            bail!("[client] virtual_ports must list at least one port");
        }
        Ok(Self { ip, ports })
    }
}

/// 启动虚拟内网通道（幂等：配置里没有虚拟 IP 时直接返回）。
pub fn spawn(http_client: Arc<wreq::Client>, state: Arc<SharedState>) {
    let Some(spec) = state.vnet.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut backoff = VNET_RECONNECT_MIN;
        loop {
            match run_vnet(&http_client, &state, &spec).await {
                Ok(()) => {
                    info!(ip = %spec.ip, "vnet closed, reconnecting");
                    backoff = VNET_RECONNECT_MIN;
                }
                Err(e) => warn!(ip = %spec.ip, error = %e, "vnet failed"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(VNET_RECONNECT_MAX);
        }
    });
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 建立一次虚拟内网通道，直到服务端断开或出错。
async fn run_vnet(
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
    spec: &VnetSpec,
) -> Result<()> {
    let encrypted = state.server_public_key.is_some();
    let ip_b64 = b64(spec.ip.to_string().as_bytes());

    // 下行 cookie：明文模式是 `<b64(IP)>.<节点 id>`，加密模式是
    // `<session_id>:<加密的节点 id>:<加密的 IP>`。
    // 节点 id 保证重连后旧连接上还在飞的帧不会被新会话误收。
    let (down_identity, up_identity, down_cipher, up_cipher) = if encrypted {
        let (session_id, master) = ensure_session(http_client, state).await?;
        let peer_id = Uuid::new_v4();
        let id_bytes = *peer_id.as_bytes();
        let cookie_key = crypto::derive_cookie_stream_key(&master);
        let enc_id = crypto::encrypt_bytes(&cookie_key, &id_bytes)?;
        let (up_key, down_key, target_key) = crypto::derive_connection_keys(&master, &id_bytes);
        let enc_ip = crypto::encrypt_bytes(&target_key, spec.ip.to_string().as_bytes())?;
        (
            format!("{}:{}:{}", session_id, b64(&enc_id), b64(&enc_ip)),
            format!("{}:{}", session_id, b64(&enc_id)),
            Some(Arc::new(AesFrameCipher::new(&down_key)) as Arc<dyn FrameCipher>),
            Some(Arc::new(AesFrameCipher::new(&up_key)) as Arc<dyn FrameCipher>),
        )
    } else {
        let peer_id = Uuid::new_v4();
        (
            format!("{ip_b64}.{peer_id}"),
            peer_id.to_string(),
            None,
            None,
        )
    };

    let chunk =
        shaper::frame_raw_limit_of(down_cipher.is_some(), state.traffic_config.encoding_type)
            .saturating_sub(mux::HEADER_LEN)
            .max(1);

    let mut cookie = String::new();
    utils::build_vnet_cookie(&mut cookie, &down_identity);
    // 下行是“上线”请求，和握手一样始终带 token；上行批量 POST 在
    // 加密模式下不带（避免长连接期间反复暴露 token），只靠加密 cookie 自证。
    let req = http_client
        .post(state.remote_str.as_str())
        .header("Authorization", state.auth_header.as_str())
        .header("Cache-Control", "no-store, no-transform")
        .header("Cookie", cookie)
        .header("X-Vnet-Ports", spec.ports.to_header());

    let response = tokio::time::timeout(DOWNLOAD_CONNECT_TIMEOUT, req.send())
        .await
        .context("vnet connect timed out")?
        .context("vnet connect failed")?;
    let response = utils::check_response_status(response, "server rejected vnet").await?;

    info!(
        ip = %spec.ip,
        ports = spec.ports.len(),
        encrypted,
        "vnet established"
    );

    // 上行：批量 POST
    let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(VNET_UPLINK_QUEUE);
    let mut up_cookie = String::new();
    utils::build_vnet_up_cookie(&mut up_cookie, &up_identity);
    let next_seq = Arc::new(AtomicU64::new(0));
    let uplink_task = tokio::spawn(uplink_loop(
        Arc::clone(http_client),
        Arc::clone(state),
        up_cookie,
        uplink_rx,
        Arc::clone(&next_seq),
        up_cipher,
        encrypted,
    ));

    let conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>> = Arc::new(DashMap::new());
    let result = pump_downlink(
        response,
        state,
        spec,
        down_cipher,
        uplink_tx,
        Arc::clone(&conns),
        chunk,
    )
    .await;

    // 通道没了，本地连接也就没有意义了：丢掉 sender 让 relay 立即收尾
    conns.clear();
    uplink_task.abort();
    let _ = uplink_task.await;

    result
}

/// 拿到一个可用的会话主密钥（加密模式）。
async fn ensure_session(
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
) -> Result<(String, Zeroizing<[u8; 32]>)> {
    if let Some(hit) = cached_session(state).await {
        return Ok(hit);
    }

    let server_pk = state
        .server_public_key
        .ok_or_else(|| anyhow!("server public key is not configured"))?;

    let _guard = state.handshake_lock.lock().await;
    if let Some(hit) = cached_session(state).await {
        return Ok(hit);
    }
    let ticket =
        crate::client::handshake::perform_pq_handshake(http_client, state, &server_pk).await?;
    Ok((ticket.session_id, ticket.master))
}

async fn cached_session(state: &Arc<SharedState>) -> Option<(String, Zeroizing<[u8; 32]>)> {
    let mut guard = state.initial_master.lock().await;
    let (session_id, master, created) = guard.as_ref()?;
    if crate::now_secs().saturating_sub(*created) >= MASTER_RESUME_WINDOW_SECS {
        *guard = None;
        return None;
    }
    Some((session_id.clone(), Zeroizing::new(**master)))
}

/// 消费下行响应体：解码出 mux 帧并派发，直到服务端关闭。
async fn pump_downlink(
    response: wreq::Response,
    state: &Arc<SharedState>,
    spec: &VnetSpec,
    down_cipher: Option<Arc<dyn FrameCipher>>,
    uplink_tx: mpsc::Sender<Bytes>,
    conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>>,
    chunk: usize,
) -> Result<()> {
    let encoding = state.traffic_config.encoding_type;
    let mut stream = response.into_data_stream();
    let mut buf = BytesMut::with_capacity(VNET_DECODE_BUF);

    while let Some(next) = stream.next().await {
        let chunk_bytes = next.context("vnet downlink read error")?;
        buf.extend_from_slice(&chunk_bytes);

        while let Some((_seq, payload)) =
            shaper::decode_from_buffer(&mut buf, down_cipher.as_deref(), encoding)?
        {
            dispatch(payload, spec, &uplink_tx, Arc::clone(&conns), chunk).await;
        }

        if buf.len() > VNET_DECODE_BUF {
            bail!("vnet downlink buffer overflow");
        }
    }

    Ok(())
}

async fn dispatch(
    payload: Bytes,
    spec: &VnetSpec,
    uplink_tx: &mpsc::Sender<Bytes>,
    conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>>,
    chunk: usize,
) {
    let Some(frame) = mux::parse(&payload) else {
        warn!("malformed vnet frame, ignoring");
        return;
    };

    match frame.tag {
        Tag::Open => {
            let Some(port) = mux::open_port(frame.payload) else {
                warn!(conn = frame.conn, "OPEN without a valid port, ignoring");
                return;
            };
            if !spec.ports.contains(port) {
                warn!(port, "server requested a port that is not exposed");
                let _ = uplink_tx
                    .send(mux::encode(Tag::OpenFail, frame.conn, &[]))
                    .await;
                return;
            }
            let conn_id = frame.conn;
            let ip = spec.ip;
            let conns = Arc::clone(&conns);
            let uplink = uplink_tx.clone();
            tokio::spawn(async move {
                serve_local(conn_id, ip, port, conns, uplink, chunk).await;
            });
        }
        Tag::Data => {
            if let Some(tx) = conns.get(&frame.conn).map(|e| e.value().clone()) {
                let _ = tx
                    .send(ToSocket::Data(Bytes::copy_from_slice(frame.payload)))
                    .await;
            }
        }
        Tag::Close => {
            if let Some(tx) = conns.get(&frame.conn).map(|e| e.value().clone()) {
                let _ = tx.send(ToSocket::Eof).await;
            }
        }
        Tag::Ping => {
            let _ = uplink_tx.send(mux::encode(Tag::Pong, 0, &[])).await;
        }
        Tag::Pong | Tag::OpenOk | Tag::OpenFail => {}
    }
}

/// 连上本机端口并开始搬运字节。
async fn serve_local(
    conn_id: u32,
    ip: IpAddr,
    port: u16,
    conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>>,
    uplink: mpsc::Sender<Bytes>,
    chunk: usize,
) {
    let socket = match connect_local(ip, port).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!(port, error = %e, "local port unreachable");
            let _ = uplink.send(mux::encode(Tag::OpenFail, conn_id, &[])).await;
            return;
        }
    };
    socket.set_nodelay(true).ok();
    debug!(port, conn_id, "local connection opened");

    let (tx, rx) = mpsc::channel::<ToSocket>(VNET_CONN_CAPACITY);
    conns.insert(conn_id, tx);
    // 先登记再回执：服务端收到 OPEN_OK 后立刻就可能推 DATA 下来
    if uplink
        .send(mux::encode(Tag::OpenOk, conn_id, &[]))
        .await
        .is_err()
    {
        conns.remove(&conn_id);
        return;
    }

    relay_local(conn_id, socket, rx, uplink, conns, chunk).await;
}

async fn relay_local(
    conn_id: u32,
    socket: TcpStream,
    mut to_socket: mpsc::Receiver<ToSocket>,
    uplink: mpsc::Sender<Bytes>,
    conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>>,
    chunk: usize,
) {
    let (mut read_half, mut write_half) = socket.into_split();
    let mut buf = vec![0u8; chunk.max(1)];
    let mut writer_open = true;

    loop {
        tokio::select! {
            biased;
            cmd = to_socket.recv(), if writer_open => match cmd {
                Some(ToSocket::Data(data)) => {
                    if write_half.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Some(ToSocket::Eof) | None => {
                    let _ = write_half.shutdown().await;
                    writer_open = false;
                }
            },
            read = read_half.read(&mut buf) => match read {
                Ok(0) => {
                    let _ = uplink.send(mux::encode(Tag::Close, conn_id, &[])).await;
                    break;
                }
                Ok(n) => {
                    if uplink
                        .send(mux::encode(Tag::Data, conn_id, &buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    debug!(conn_id, error = %e, "local read failed");
                    let _ = uplink.send(mux::encode(Tag::Close, conn_id, &[])).await;
                    break;
                }
            },
        }
    }

    conns.remove(&conn_id);
}

/// 连接本机服务。
///
/// 优先连配置里的虚拟 IP：它正好是本机地址（最常见的用法）时最自然，服务绑
/// 在 `0.0.0.0` 也能连上；失败再回退到 `127.0.0.1`——虚拟 IP 只是个会合地
/// 址、本机并不持有时，服务只监听回环仍然可用。
async fn connect_local(ip: IpAddr, port: u16) -> Result<TcpStream> {
    let primary = SocketAddr::new(ip, port);
    match dial(primary).await {
        Ok(socket) => Ok(socket),
        Err(err) => {
            let fallback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            if primary == fallback {
                return Err(err);
            }
            debug!(error = %err, %primary, "falling back to loopback");
            dial(fallback)
                .await
                .with_context(|| format!("connect {primary} failed ({err}) and loopback failed"))
        }
    }
}

async fn dial(addr: SocketAddr) -> Result<TcpStream> {
    tokio::time::timeout(VNET_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connect {addr} timed out"))?
        .with_context(|| format!("connect {addr} failed"))
}

/// 上行批量上传循环。
///
/// 帧序号在这里统一分配，因此收集顺序就是序号顺序；POST 并发执行，服务端按
/// 序号重排序还原字节流。
async fn uplink_loop(
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    cookie: String,
    mut rx: mpsc::Receiver<Bytes>,
    next_seq: Arc<AtomicU64>,
    cipher: Option<Arc<dyn FrameCipher>>,
    encrypted: bool,
) -> Result<()> {
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    let sem = Arc::new(Semaphore::new(VNET_UPLINK_CONCURRENCY));
    let encoding = state.traffic_config.encoding_type;
    let padding = state.traffic_config.global.clone();

    loop {
        let Some(first) = rx.recv().await else {
            break;
        };
        let mut batch = BytesMut::with_capacity(VNET_BATCH_BYTES);
        push_frame(
            &mut batch,
            first,
            &next_seq,
            cipher.as_deref(),
            &padding,
            encoding,
        )?;

        while batch.len() < VNET_BATCH_BYTES {
            match rx.try_recv() {
                Ok(next) => push_frame(
                    &mut batch,
                    next,
                    &next_seq,
                    cipher.as_deref(),
                    &padding,
                    encoding,
                )?,
                Err(_) => break,
            }
        }

        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .context("vnet uplink semaphore closed")?;
        let body = batch.freeze();
        let client = Arc::clone(&http_client);
        let shared = Arc::clone(&state);
        let cookie = cookie.clone();
        tasks.spawn(async move {
            let _permit = permit;
            send_batch(&client, &shared, &cookie, body, encrypted).await
        });

        while let Some(done) = tasks.try_join_next() {
            match done {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(anyhow!("vnet uplink task panicked: {e}")),
            }
        }
    }

    while let Some(done) = tasks.join_next().await {
        match done {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(anyhow!("vnet uplink task panicked: {e}")),
        }
    }
    Ok(())
}

fn push_frame(
    out: &mut BytesMut,
    payload: Bytes,
    next_seq: &AtomicU64,
    cipher: Option<&dyn FrameCipher>,
    padding: &shaper::PaddingConfig,
    encoding: shaper::EncodingType,
) -> Result<()> {
    let seq = next_seq.fetch_add(1, Ordering::Relaxed);
    shaper::encode_frame_into(
        &payload,
        seq,
        cipher,
        padding.padding_threshold,
        padding.padding_range,
        encoding,
        out,
    )
    .context("encode vnet uplink frame")
}

async fn send_batch(
    http_client: &Arc<wreq::Client>,
    state: &SharedState,
    cookie: &str,
    body: Bytes,
    encrypted: bool,
) -> Result<()> {
    let mut req = http_client
        .post(state.remote_str.as_str())
        .header("Accept-Encoding", "identity")
        .header("Cache-Control", "no-store, no-transform")
        .header("Content-Type", "application/octet-stream")
        .header("Cookie", cookie);
    if !encrypted {
        req = req.header("Authorization", state.auth_header.as_str());
    }
    let response = tokio::time::timeout(
        UPLOAD_REQUEST_TIMEOUT,
        req.body(wreq::Body::from(body)).send(),
    )
    .await
    .context("vnet uplink timed out")?
    .context("vnet uplink failed")?;
    let response = utils::check_response_status(response, "server rejected vnet uplink").await?;
    response
        .bytes()
        .await
        .context("drain vnet uplink response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(list: &[u16]) -> PortSet {
        PortSet::new(list.to_vec())
    }

    #[test]
    fn spec_rejects_bad_ip() {
        assert!(VnetSpec::new("not-an-ip", ports(&[80])).is_err());
        assert!(VnetSpec::new("", ports(&[80])).is_err());
        assert!(VnetSpec::new("0.0.0.0", ports(&[80])).is_err());
        assert!(VnetSpec::new("::", ports(&[80])).is_err());
    }

    #[test]
    fn spec_rejects_empty_ports() {
        assert!(VnetSpec::new("10.0.0.5", ports(&[])).is_err());
    }

    #[test]
    fn spec_accepts_ipv4_and_ipv6() {
        assert_eq!(
            VnetSpec::new("10.0.0.5", ports(&[80])).unwrap().ip,
            "10.0.0.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            VnetSpec::new(" fd00::5 ", ports(&[443])).unwrap().ip,
            "fd00::5".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn connect_local_falls_back_to_loopback() {
        // 用阻塞 listener 并留在作用域里：只要 socket 还在监听，内核就会替
        // 我们收下连接，不依赖 accept 是否被调度到。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // 127.0.0.9 上没有监听，应该回退到 127.0.0.1
        let socket = connect_local("127.0.0.9".parse().unwrap(), port)
            .await
            .expect("loopback fallback must succeed");
        assert!(socket.peer_addr().is_ok());
        drop(listener);
    }

    #[tokio::test]
    async fn connect_local_reports_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(
            connect_local("127.0.0.1".parse().unwrap(), port)
                .await
                .is_err()
        );
    }
}

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
    VNET_RECONNECT_MIN, VNET_UPLINK_ATTEMPTS, VNET_UPLINK_CONCURRENCY, VNET_UPLINK_QUEUE,
    VNET_UPLINK_RETRY_DELAY, VNET_WRITE_TIMEOUT,
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
            let (live, result) = run_vnet(&http_client, &state, &spec).await;
            match result {
                Ok(()) => info!(ip = %spec.ip, "vnet closed, reconnecting"),
                Err(e) => warn!(ip = %spec.ip, error = %e, "vnet failed"),
            }
            // 上过线就说明配置、鉴权、网络都是通的，断掉只是抖动：立刻重连，
            // 别沿用上一个失败周期攒起来的退避——否则一次抖动之后这个节点要
            // 等半分钟才回来，那段时间里它的地址完全不可用。
            if live {
                backoff = VNET_RECONNECT_MIN;
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
///
/// 两个返回值分别是「这次通道有没有成功上线过」和结果：上过线说明配置、
/// 鉴权、网络都是通的，断了只是抖动，上层应当立刻重连。
async fn run_vnet(
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
    spec: &VnetSpec,
) -> (bool, Result<()>) {
    let mut live = false;
    let result = channel(http_client, state, spec, &mut live).await;
    (live, result)
}

/// 通道本体。`live` 在注册成功那一刻置位，即便随后以 `?` 提前返回也能带回去。
async fn channel(
    http_client: &Arc<wreq::Client>,
    state: &Arc<SharedState>,
    spec: &VnetSpec,
    live: &mut bool,
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
    *live = true;

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
    let mut uplink_task = uplink_task;
    // 上行一死这条通道就废了：数据只能从节点往服务端走，少了它每个请求都会
    // 卡住。所以不能只盯着下行——否则服务端要等到心跳超时（75s）才会发现，
    // 这段时间里所有请求都是失败的。这里直接收尾，交给上层重连。
    let result = tokio::select! {
        biased;
        done = &mut uplink_task => Err(match done {
            Ok(Ok(())) => anyhow!("vnet uplink closed"),
            Ok(Err(e)) => e,
            Err(e) => anyhow!("vnet uplink task stopped: {e}"),
        }),
        result = pump_downlink(
            response,
            state,
            spec,
            down_cipher,
            uplink_tx,
            Arc::clone(&conns),
            chunk,
        ) => result,
    };

    // 通道没了，本地连接也就没有意义了：丢掉 sender 让 relay 立即收尾
    conns.clear();
    if !uplink_task.is_finished() {
        uplink_task.abort();
        let _ = uplink_task.await;
    }

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
    // 完整帧已经全部解掉了，剩下的必然是半帧，所以「缓冲区超过一帧」就等于
    // 「对端在发一个不可能的帧」。上限按当前编码算，别写死一个数字。
    let max_frame = shaper::max_encoded_frame_len(encoding);

    while let Some(next) = stream.next().await {
        let chunk_bytes = next.context("vnet downlink read error")?;
        buf.extend_from_slice(&chunk_bytes);

        while let Some((_seq, payload)) =
            shaper::decode_from_buffer(&mut buf, down_cipher.as_deref(), encoding)?
        {
            dispatch(payload, spec, &uplink_tx, Arc::clone(&conns), chunk).await;
        }

        if buf.len() > max_frame {
            bail!(
                "vnet downlink buffer overflow: {} bytes without a complete frame",
                buf.len()
            );
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
            // 先登记再撒手：服务端把访问方的首包紧跟在 OPEN 后面推下来，
            // 两者常常落在同一个读取块里。派发是串行的，`tokio::spawn` 之后的
            // 任务要等到下次让出执行权才会跑，所以登记必须在这里同步完成，
            // 否则紧跟其后的 DATA 会找不到落点而被丢掉——那是一条永远等不到
            // 请求字节的连接，看起来就是「请求挂死」。
            let (tx, rx) = mpsc::channel::<ToSocket>(VNET_CONN_CAPACITY);
            if conns.insert(conn_id, tx).is_some() {
                warn!(conn_id, "OPEN reused a live connection id");
            }
            let ip = spec.ip;
            let conns = Arc::clone(&conns);
            let uplink = uplink_tx.clone();
            tokio::spawn(async move {
                serve_local(conn_id, ip, port, conns, uplink, chunk, rx).await;
            });
        }
        Tag::Data => {
            if let Some(tx) = conns.get(&frame.conn).map(|e| e.value().clone()) {
                let _ = tx
                    .send(ToSocket::Data(Bytes::copy_from_slice(frame.payload)))
                    .await;
            } else {
                debug!(conn = frame.conn, "DATA for an unknown connection dropped");
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
///
/// 连接在派发 `OPEN` 时就已登记进 `conns`，因此服务端紧跟着推下来的 DATA 会
/// 先落在 `to_socket` 这个有界队列里，等拨号完成再写进 socket。拨号失败时整条
/// 连接被撤掉，排队的数据一并丢弃（服务端也会收到 `OPEN_FAIL` 并收尾）。
#[allow(clippy::too_many_arguments)]
async fn serve_local(
    conn_id: u32,
    ip: IpAddr,
    port: u16,
    conns: Arc<DashMap<u32, mpsc::Sender<ToSocket>>>,
    uplink: mpsc::Sender<Bytes>,
    chunk: usize,
    to_socket: mpsc::Receiver<ToSocket>,
) {
    let socket = match connect_local(ip, port).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!(port, error = %e, "local port unreachable");
            conns.remove(&conn_id);
            let _ = uplink.send(mux::encode(Tag::OpenFail, conn_id, &[])).await;
            return;
        }
    };
    socket.set_nodelay(true).ok();
    debug!(port, conn_id, "local connection opened");

    // 回执只用于观测与快速失败，不在数据路径上
    if uplink
        .send(mux::encode(Tag::OpenOk, conn_id, &[]))
        .await
        .is_err()
    {
        conns.remove(&conn_id);
        return;
    }

    relay_local(conn_id, socket, to_socket, uplink, conns, chunk).await;
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
                    // 写超时同样是自保：本机服务读不动时，这条连接不能把整条
                    // 通道（所有其他连接共用）一起堵死
                    match tokio::time::timeout(VNET_WRITE_TIMEOUT, write_half.write_all(&data)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            debug!(conn_id, error = %e, "local write failed");
                            break;
                        }
                        Err(_) => {
                            warn!(conn_id, "local write stalled, dropping connection");
                            break;
                        }
                    }
                }
                Some(ToSocket::Eof) => {
                    // 服务端那边收完了：半关闭写方向，读方向继续
                    let _ = write_half.shutdown().await;
                    writer_open = false;
                }
                // 连接被撤掉（服务端不再需要它、或通道销毁）：连本地 socket 一起丢
                None => break,
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
/// 回环优先：服务绝大多数时候监听 `0.0.0.0` 或 `127.0.0.1`，一次就连上。
/// 虚拟 IP 只作为备选——它常常只是一个会合地址、本机并不持有，先拨它等于把
/// 一次注定失败的 connect（实测能被拖到 SYN 超时）排在真正能用的那个前面，
/// 白白给每条连接加一截延迟。
async fn connect_local(ip: IpAddr, port: u16) -> Result<TcpStream> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let primary = SocketAddr::new(ip, port);

    match dial(loopback).await {
        Ok(socket) => Ok(socket),
        Err(loopback_err) => {
            if primary == loopback {
                return Err(loopback_err);
            }
            debug!(error = %loopback_err, %primary, "loopback refused, trying the virtual address");
            dial(primary).await.with_context(|| {
                format!("connect {loopback} failed ({loopback_err}) and {primary} failed too")
            })
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
            send_batch_with_retry(&client, &shared, &cookie, body, encrypted).await
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

/// 发一批上行帧，失败就重发同一批。
///
/// 重发是安全的：每帧自带 `seq`，服务端对已经交付过的序号直接丢弃（乱序缓冲
/// 里重复的也丢弃），所以「首发送到一半失败」之后重发整批，服务端看到的仍然
/// 是同一条有序字节流。
///
/// 这一步存在的理由是失败代价太不对等：一批没了，后续各批的序号都会卡在它
/// 后面（服务端重排序要求连续），整条通道立刻不可用；而一次重试只要几百毫秒。
/// 长连接被中间代理按 keepalive 上限掐掉一次，本来不该等于整个虚拟地址下线。
async fn send_batch_with_retry(
    http_client: &Arc<wreq::Client>,
    state: &SharedState,
    cookie: &str,
    body: Bytes,
    encrypted: bool,
) -> Result<()> {
    let mut delay = VNET_UPLINK_RETRY_DELAY;
    for attempt in 1..=VNET_UPLINK_ATTEMPTS {
        match send_batch(http_client, state, cookie, body.clone(), encrypted).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt == VNET_UPLINK_ATTEMPTS => return Err(e),
            Err(e) => {
                debug!(attempt, error = %e, "vnet uplink batch failed, retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    Ok(())
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
    async fn connect_local_reaches_a_loopback_service() {
        // 用阻塞 listener 并留在作用域里：只要 socket 还在监听，内核就会替
        // 我们收下连接，不依赖 accept 是否被调度到。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // 虚拟 IP（127.0.0.9）上没有监听，但服务在回环上，一次就该连上
        let socket = connect_local("127.0.0.9".parse().unwrap(), port)
            .await
            .expect("a loopback service must be reachable");
        assert!(socket.peer_addr().is_ok());
        drop(listener);
    }

    /// `OPEN` 和紧接着的 `DATA` 常常同处一个读取块（服务端把首包紧跟着 OPEN
    /// 推下来，中间不隔任何东西）。派发是串行的，`OPEN` 只是把连接丢给一个
    /// 后台任务——若 DATA 先于那条任务登记到达，它就会被静默丢掉，请求从此
    /// 挂死。这条断言盯的正是「同一批里的 DATA 不能丢」。
    #[tokio::test]
    async fn data_in_the_same_batch_as_open_is_delivered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let service = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 128];
            let n = sock.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let spec = VnetSpec {
            ip: "127.0.0.9".parse().unwrap(),
            ports: ports(&[port]),
        };
        let conns = Arc::new(DashMap::new());
        let (uplink_tx, _uplink_rx) = mpsc::channel::<Bytes>(16);

        // 与 `pump_downlink` 一样：同一个读取块里连续派发，中间不让出执行权
        dispatch(
            mux::encode(Tag::Open, 1, &port.to_be_bytes()),
            &spec,
            &uplink_tx,
            Arc::clone(&conns),
            4096,
        )
        .await;
        dispatch(
            mux::encode(Tag::Data, 1, b"GET / HTTP/1.1\r\n\r\n"),
            &spec,
            &uplink_tx,
            Arc::clone(&conns),
            4096,
        )
        .await;

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), service)
            .await
            .expect("DATA sent right after OPEN must reach the local service")
            .unwrap();
        assert_eq!(&got, b"GET / HTTP/1.1\r\n\r\n");
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

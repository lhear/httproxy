//! 虚拟内网：服务端的地址注册表与中继数据面。
//!
//! 虚拟内网是一张覆盖网络：服务端是中心节点，每个声明了 `virtual_ip` 的客户端
//! 都是一个持有该地址的节点，靠一条长连接挂上来（一个上行 POST 得到的无限
//! 响应体）。这条通道用 [`crate::mux`] 里的多路复用帧承载「打开连接 / 数据 /
//! 关闭 / 心跳」四类消息。
//!
//! 注意这**不是**内网穿透（把内网服务暴露到公网）：没有公网访客，服务端也不会
//! 去连那个地址，它只是在同一个服务端的客户端之间按地址中继。
//!
//! 其他客户端把代理目标写成 `<虚拟 IP>:<端口>` 时，[`VnetRegistry::open`] 会
//! 把这条逻辑连接交给持有该地址的节点：服务端自己造一对 loopback TCP
//! socket，一端交给原有的隧道代码当“上游”，另一端由本模块的 relay 任务与
//! 多路复用通道之间搬运字节。这样正常隧道的整条数据面（分帧、加密、上传
//! 重排序）都不用改动。

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::PortSet;
use crate::error::ServerError;
use crate::mux::{self, Tag, ToSocket};
use crate::server::constants::{
    VNET_CONN_CAPACITY, VNET_DOWNLINK_CAPACITY, VNET_HEARTBEAT, VNET_OPEN_TIMEOUT,
    VNET_REPLACE_GUARD_SECS, VNET_STALE_SECS, VNET_UPLINK_FRAMES, VNET_UPLINK_PENDING_BYTES,
};
use crate::shaper::{self, FrameCipher, ResolvedShaperConfig, encode_frame_into};

struct ConnEntry {
    tx: mpsc::Sender<ToSocket>,
}

/// 上行方向（虚拟内网节点 → 服务端）的一个帧。
///
/// 上行允许并发 POST，到达顺序不保证，`seq` 是重排序的依据。
pub struct UplinkFrame {
    pub seq: u64,
    pub payload: Bytes,
}

pub struct VnetPeer {
    pub id: Uuid,
    pub ip: IpAddr,
    ports: PortSet,
    /// 下行帧（已带 mux 头，尚未编码/加密）投递口
    down_tx: mpsc::Sender<Bytes>,
    /// 上行帧投递口，由 `drain_uplink` 顺序化后派发
    uplink_tx: mpsc::Sender<UplinkFrame>,
    conns: DashMap<u32, ConnEntry>,
    /// 已下发 OPEN、等待虚拟内网节点回执的逻辑连接
    pending: DashMap<u32, oneshot::Sender<bool>>,
    next_conn: AtomicU32,
    /// 最近一次收到上行数据的时间（秒，进程相对时间）
    last_seen: AtomicU64,
    /// 让下行任务立刻收尾（被新注册顶替、或上行异常时使用）
    cancel: Notify,
    /// 加密模式下的下行帧密文
    down_cipher: Option<Arc<dyn FrameCipher>>,
    /// 单个 DATA 帧能带的最大字节数
    max_data: usize,
}

impl VnetPeer {
    #[inline]
    fn touch(&self) {
        self.last_seen.store(crate::now_secs(), Ordering::Relaxed);
    }

    fn is_stale(&self) -> bool {
        crate::now_secs().saturating_sub(self.last_seen.load(Ordering::Relaxed)) > VNET_STALE_SECS
    }

    #[inline]
    fn chunk_size(&self) -> usize {
        self.max_data
    }

    async fn send_frame(&self, frame: Bytes) -> bool {
        self.down_tx.send(frame).await.is_ok()
    }

    /// 把本地服务返回的字节推给客户端。
    async fn send_data(&self, conn: u32, data: &[u8]) -> bool {
        let mut payload = BytesMut::with_capacity(mux::HEADER_LEN + data.len());
        mux::encode_into(Tag::Data, conn, data, &mut payload);
        self.send_frame(payload.freeze()).await
    }

    async fn send_close(&self, conn: u32) {
        self.send_frame(mux::encode(Tag::Close, conn, &[])).await;
    }

    /// 处理一个上行 mux 帧。
    async fn deliver(&self, payload: Bytes) {
        let Some(frame) = mux::parse(&payload) else {
            warn!(ip = %self.ip, "malformed peer frame, ignoring");
            return;
        };
        match frame.tag {
            Tag::Data => {
                let data = Bytes::copy_from_slice(frame.payload);
                if let Some(entry) = self.conns.get(&frame.conn).map(|e| e.tx.clone()) {
                    let _ = entry.send(ToSocket::Data(data)).await;
                }
            }
            Tag::Close => {
                if let Some(entry) = self.conns.get(&frame.conn).map(|e| e.tx.clone()) {
                    let _ = entry.send(ToSocket::Eof).await;
                }
            }
            Tag::OpenOk | Tag::OpenFail => {
                let ok = frame.tag == Tag::OpenOk;
                if let Some((_, ack)) = self.pending.remove(&frame.conn) {
                    let _ = ack.send(ok);
                }
            }
            Tag::Pong | Tag::Ping => {}
            Tag::Open => warn!(ip = %self.ip, "unexpected OPEN from vnet client"),
        }
    }

    fn discard_conn(&self, conn: u32) {
        self.conns.remove(&conn);
        self.pending.remove(&conn);
    }

    /// 收下一个上行帧（由上传 POST 投递，顺序由 `drain_uplink` 负责）。
    pub async fn push_uplink(&self, frame: UplinkFrame) -> bool {
        self.uplink_tx.send(frame).await.is_ok()
    }
}

/// 虚拟 IP → 节点会话的注册表。
pub struct VnetRegistry {
    by_ip: DashMap<IpAddr, Arc<VnetPeer>>,
    by_id: DashMap<Uuid, Arc<VnetPeer>>,
    max_peers: usize,
}

impl VnetRegistry {
    pub fn new(max_peers: usize) -> Self {
        Self {
            by_ip: DashMap::new(),
            by_id: DashMap::new(),
            max_peers,
        }
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    pub fn get_by_ip(&self, ip: IpAddr) -> Option<Arc<VnetPeer>> {
        self.by_ip.get(&ip).map(|e| Arc::clone(e.value()))
    }

    pub fn get_by_id(&self, id: &Uuid) -> Option<Arc<VnetPeer>> {
        self.by_id.get(id).map(|e| Arc::clone(e.value()))
    }

    /// 注册一个虚拟内网节点，返回 `(节点, 下行帧接收端)`。
    ///
    /// 同一个 IP 只允许一条：旧连接还能刷新（`last_seen` 在保护窗口内）时直接
    /// 拒绝，避免两个客户端互相抢占；旧连接已静默则顶替它，这样重启客户端
    /// 不需要等状态过期。
    pub fn register(
        self: &Arc<Self>,
        id: Uuid,
        ip: IpAddr,
        ports: PortSet,
        down_cipher: Option<Arc<dyn FrameCipher>>,
        max_data: usize,
    ) -> Result<(Arc<VnetPeer>, mpsc::Receiver<Bytes>), ServerError> {
        if let Some(existing) = self.by_ip.get(&ip).map(|e| Arc::clone(e.value())) {
            let age = crate::now_secs().saturating_sub(existing.last_seen.load(Ordering::Relaxed));
            if !replace_allowed(age) {
                warn!(ip = %ip, "duplicate vnet peer registration rejected");
                return Err(ServerError::conflict(format!(
                    "virtual address {ip} is already served by another peer"
                )));
            }
            drop(existing);
            warn!(ip = %ip, "replacing stale vnet peer");
            self.unregister_by_ip(ip);
        }

        if self.by_ip.len() >= self.max_peers {
            return Err(ServerError::service_unavailable("too many vnet peers"));
        }

        let (down_tx, down_rx) = mpsc::channel::<Bytes>(VNET_DOWNLINK_CAPACITY);
        let (uplink_tx, uplink_rx) = mpsc::channel::<UplinkFrame>(VNET_UPLINK_FRAMES);
        let peer = Arc::new(VnetPeer {
            id,
            ip,
            ports,
            down_tx,
            uplink_tx,
            conns: DashMap::new(),
            pending: DashMap::new(),
            next_conn: AtomicU32::new(1),
            last_seen: AtomicU64::new(crate::now_secs()),
            cancel: Notify::new(),
            down_cipher,
            max_data: max_data.max(1),
        });

        self.by_ip.insert(ip, Arc::clone(&peer));
        self.by_id.insert(id, Arc::clone(&peer));

        let drain_peer = Arc::clone(&peer);
        tokio::spawn(async move { drain_uplink(drain_peer, uplink_rx).await });

        info!(ip = %ip, peer_id = %id, ports = peer.ports.len(), "vnet peer registered");
        Ok((peer, down_rx))
    }

    pub fn unregister(&self, id: &Uuid) {
        let Some((_, peer)) = self.by_id.remove(id) else {
            return;
        };
        self.by_ip.remove_if(&peer.ip, |_, cur| cur.id == *id);
        peer.cancel.notify_one();
        info!(ip = %peer.ip, peer_id = %id, "vnet peer unregistered");
    }

    fn unregister_by_ip(&self, ip: IpAddr) {
        if let Some((_, peer)) = self.by_ip.remove(&ip) {
            self.by_id.remove(&peer.id);
            peer.cancel.notify_one();
        }
    }

    /// 目标命中某个虚拟 IP 时，为它建立一条逻辑连接。
    ///
    /// - `Ok(None)`：这个目标不是已注册的虚拟 IP，调用方按普通方式直连；
    /// - `Ok(Some(sock))`：已经接上虚拟内网节点，`sock` 当作隧道上游使用；
    /// - `Err(..)`：虚拟 IP 在，但端口没被暴露或客户端连不上。
    pub async fn open(&self, host: &str, port: u16) -> Result<Option<TcpStream>, ServerError> {
        let Ok(ip) = host.parse::<IpAddr>() else {
            return Ok(None);
        };
        let Some(peer) = self.get_by_ip(ip) else {
            return Ok(None);
        };

        if peer.is_stale() {
            warn!(ip = %ip, "vnet peer looks stale, dropping registration");
            self.unregister(&peer.id);
            return Ok(None);
        }

        if !peer.ports.contains(port) {
            warn!(ip = %ip, port, "vnet port is not exposed");
            return Err(ServerError::forbidden(format!(
                "{ip}:{port} is not exposed by the peer that owns this address"
            )));
        }

        let (tunnel_side, client_side) = loopback_pair()
            .await
            .map_err(|e| ServerError::internal(format!("peer loopback pair failed: {e}")))?;

        let conn_id = peer.next_conn.fetch_add(1, Ordering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        peer.pending.insert(conn_id, ack_tx);
        let (to_sock_tx, to_sock_rx) = mpsc::channel::<ToSocket>(VNET_CONN_CAPACITY);
        peer.conns.insert(conn_id, ConnEntry { tx: to_sock_tx });

        let open = mux::encode(Tag::Open, conn_id, &port.to_be_bytes());
        if !peer.send_frame(open).await {
            peer.discard_conn(conn_id);
            return Err(ServerError::bad_gateway("vnet peer channel is closed"));
        }

        match tokio::time::timeout(VNET_OPEN_TIMEOUT, ack_rx).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) | Ok(Err(_)) => {
                peer.discard_conn(conn_id);
                warn!(ip = %ip, port, "vnet client could not reach local port");
                return Err(ServerError::bad_gateway(format!(
                    "vnet client could not reach {ip}:{port}"
                )));
            }
            Err(_) => {
                peer.discard_conn(conn_id);
                warn!(ip = %ip, port, "vnet open timed out");
                return Err(ServerError::gateway_timeout("vnet open timed out"));
            }
        }

        debug!(ip = %ip, port, conn_id, "vnet connection opened");
        let relay_peer = Arc::clone(&peer);
        tokio::spawn(async move {
            relay(relay_peer, conn_id, client_side, to_sock_rx).await;
        });

        Ok(Some(tunnel_side))
    }
}

impl Default for VnetRegistry {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// 既有注册静默了多久之后允许被新注册顶替。
///
/// 太短会让两个抢同一个 IP 的客户端互相顶替（乒乓），太长会让崩溃重启的
/// 客户端迟迟注册不上，`VNET_REPLACE_GUARD_SECS` 取中间值。
#[inline]
fn replace_allowed(age_secs: u64) -> bool {
    age_secs >= VNET_REPLACE_GUARD_SECS
}

/// 造一对 loopback TCP socket：一端交给隧道代码，一端交给 relay。
///
/// 用 TCP 而不是 `tokio::io::duplex` 是为了不把上游类型从 `TcpStream` 泛型化，
/// 正常隧道的分帧/加密/重排序代码因此完全不用改。
async fn loopback_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let tunnel_side = TcpStream::connect(addr).await?;
    let (client_side, _) = listener.accept().await?;
    drop(listener);
    tunnel_side.set_nodelay(true)?;
    client_side.set_nodelay(true)?;
    Ok((tunnel_side, client_side))
}

/// 在本地 socket 与多路复用通道之间搬运字节。
async fn relay(
    peer: Arc<VnetPeer>,
    conn_id: u32,
    socket: TcpStream,
    mut to_socket: mpsc::Receiver<ToSocket>,
) {
    let (mut read_half, mut write_half) = socket.into_split();
    let mut buf = vec![0u8; peer.chunk_size().max(1)];
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
                    peer.send_close(conn_id).await;
                    break;
                }
                Ok(n) => {
                    if !peer.send_data(conn_id, &buf[..n]).await {
                        break;
                    }
                }
                Err(e) => {
                    debug!(conn_id, error = %e, "peer upstream read failed");
                    peer.send_close(conn_id).await;
                    break;
                }
            },
        }
    }

    peer.discard_conn(conn_id);
}

/// 把上行帧按 `seq` 顺序化后派发。
///
/// 上行是并发 POST，帧顺序不保证；这里用一个有界的重排序缓冲，越界就认为
/// 通道已经不可用（与隧道上传的重排序语义一致）。
async fn drain_uplink(peer: Arc<VnetPeer>, mut rx: mpsc::Receiver<UplinkFrame>) {
    let mut next_seq: u64 = 0;
    let mut pending: BTreeMap<u64, Bytes> = BTreeMap::new();
    let mut pending_bytes = 0usize;

    while let Some(frame) = rx.recv().await {
        peer.touch();
        if frame.seq < next_seq {
            continue;
        }
        if frame.seq == next_seq {
            next_seq += 1;
            peer.deliver(frame.payload).await;
            while let Some(data) = pending.remove(&next_seq) {
                pending_bytes -= data.len();
                next_seq += 1;
                peer.deliver(data).await;
            }
            continue;
        }

        if pending.len() >= crate::server::constants::MAX_PENDING_FRAMES
            || pending_bytes + frame.payload.len() > VNET_UPLINK_PENDING_BYTES
        {
            warn!(
                ip = %peer.ip,
                pending_frames = pending.len(),
                pending_bytes,
                "peer uplink reorder buffer overflow, closing peer"
            );
            peer.cancel.notify_one();
            break;
        }
        pending_bytes += frame.payload.len();
        pending.insert(frame.seq, frame.payload);
    }

    // 上行没了，虚拟内网就不可用了
    peer.cancel.notify_one();
}

/// 构造下行响应体：把 mux 帧编码成 shaper 帧流式写给客户端，并负责心跳。
pub fn spawn_downlink(
    registry: Arc<VnetRegistry>,
    peer: Arc<VnetPeer>,
    mut rx: mpsc::Receiver<Bytes>,
    cfg: Arc<ResolvedShaperConfig>,
) -> mpsc::Receiver<io::Result<Bytes>> {
    let (out_tx, out_rx) = mpsc::channel::<io::Result<Bytes>>(2);

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut ticker = tokio::time::interval(VNET_HEARTBEAT);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;

        loop {
            let payload = tokio::select! {
                biased;
                frame = rx.recv() => match frame {
                    Some(frame) => frame,
                    None => break,
                },
                _ = peer.cancel.notified() => {
                    debug!(ip = %peer.ip, "peer downlink cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    if peer.is_stale() {
                        warn!(ip = %peer.ip, "peer heartbeat timed out");
                        break;
                    }
                    mux::encode(Tag::Ping, 0, &[])
                }
            };

            let mut buf = BytesMut::with_capacity(shaper::max_encoded_frame_len(cfg.encoding));
            if let Err(e) = encode_frame_into(
                &payload,
                seq,
                peer.down_cipher.as_deref(),
                cfg.global_threshold,
                cfg.global_range,
                cfg.encoding,
                &mut buf,
            ) {
                warn!(ip = %peer.ip, error = %e, "peer frame encode failed");
                break;
            }
            seq += 1;

            if out_tx.send(Ok(buf.freeze())).await.is_err() {
                break;
            }
        }

        drop(out_tx);
        registry.unregister(&peer.id);
    });

    out_rx
}

/// 单个 DATA 帧能承载的最大原始字节数（受编码方式和是否加密限制）。
pub fn max_data_chunk(encrypted: bool, encoding: shaper::EncodingType) -> usize {
    shaper::frame_raw_limit_of(encrypted, encoding).saturating_sub(mux::HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaper::EncodingType;

    fn registry() -> Arc<VnetRegistry> {
        Arc::new(VnetRegistry::new(8))
    }

    fn ports(list: &[u16]) -> PortSet {
        PortSet::new(list.to_vec())
    }

    fn register(reg: &Arc<VnetRegistry>, ip: &str) -> (Arc<VnetPeer>, mpsc::Receiver<Bytes>) {
        reg.register(
            Uuid::new_v4(),
            ip.parse().unwrap(),
            ports(&[80, 8080]),
            None,
            max_data_chunk(false, EncodingType::Binary),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn register_and_lookup() {
        let reg = registry();
        let (peer, _rx) = register(&reg, "10.0.0.5");
        assert!(reg.get_by_ip("10.0.0.5".parse().unwrap()).is_some());
        assert!(reg.get_by_id(&peer.id).is_some());
        assert_eq!(reg.len(), 1);

        reg.unregister(&peer.id);
        assert!(reg.get_by_ip("10.0.0.5".parse().unwrap()).is_none());
        assert!(reg.get_by_id(&peer.id).is_none());
    }

    #[tokio::test]
    async fn duplicate_ip_rejected_while_fresh() {
        let reg = registry();
        let (peer, _rx) = register(&reg, "10.0.0.6");
        let err = match reg.register(
            Uuid::new_v4(),
            "10.0.0.6".parse().unwrap(),
            ports(&[80]),
            None,
            1024,
        ) {
            Ok(_) => panic!("duplicate registration must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        assert!(reg.get_by_id(&peer.id).is_some());
    }

    #[test]
    fn replace_guard_window() {
        assert!(!replace_allowed(0), "刚注册的不能被顶替");
        assert!(!replace_allowed(VNET_REPLACE_GUARD_SECS - 1));
        assert!(replace_allowed(VNET_REPLACE_GUARD_SECS));
        assert!(replace_allowed(VNET_STALE_SECS + 60));
    }

    #[tokio::test]
    async fn unregister_frees_the_ip_for_a_new_session() {
        let reg = registry();
        let (old, _rx) = register(&reg, "10.0.0.7");
        reg.unregister(&old.id);
        let (new, _rx) = register(&reg, "10.0.0.7");
        assert_ne!(old.id, new.id);
        assert_eq!(
            reg.get_by_ip("10.0.0.7".parse().unwrap()).unwrap().id,
            new.id
        );
        assert!(reg.get_by_id(&old.id).is_none());
    }

    #[tokio::test]
    async fn open_returns_none_for_unknown_target() {
        let reg = registry();
        assert!(reg.open("10.9.9.9", 80).await.unwrap().is_none());
        assert!(reg.open("example.com", 80).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn open_rejects_unexposed_port() {
        let reg = registry();
        let (_peer, _rx) = register(&reg, "10.0.0.8");
        let err = reg.open("10.0.0.8", 22).await.unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn open_fails_when_client_never_acks() {
        tokio::time::pause();
        let reg = registry();
        let (_peer, mut rx) = register(&reg, "10.0.0.9");
        let handle = tokio::spawn({
            let reg = Arc::clone(&reg);
            async move { reg.open("10.0.0.9", 80).await }
        });
        // 收到 OPEN 但故意不回执
        let frame = rx.recv().await.expect("OPEN frame");
        let parsed = mux::parse(&frame).unwrap();
        assert_eq!(parsed.tag, Tag::Open);
        assert_eq!(mux::open_port(parsed.payload), Some(80));

        tokio::time::advance(VNET_OPEN_TIMEOUT + std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn open_ok_returns_connected_socket() {
        let reg = registry();
        let (peer, mut rx) = register(&reg, "10.0.0.10");
        let handle = tokio::spawn({
            let reg = Arc::clone(&reg);
            async move { reg.open("10.0.0.10", 8080).await }
        });
        let frame = rx.recv().await.expect("OPEN frame");
        let parsed = mux::parse(&frame).unwrap();
        assert_eq!(mux::open_port(parsed.payload), Some(8080));

        // 虚拟内网节点回执：连上了
        peer.deliver(mux::encode(Tag::OpenOk, parsed.conn, &[]))
            .await;

        let sock = handle.await.unwrap().unwrap().expect("peerd socket");
        assert!(sock.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn data_flows_both_ways() {
        let reg = registry();
        let (peer, mut down_rx) = register(&reg, "10.0.0.11");
        let handle = tokio::spawn({
            let reg = Arc::clone(&reg);
            async move { reg.open("10.0.0.11", 80).await }
        });
        let frame = down_rx.recv().await.unwrap();
        let conn = mux::parse(&frame).unwrap().conn;
        peer.deliver(mux::encode(Tag::OpenOk, conn, &[])).await;
        let mut tunnel_side = handle.await.unwrap().unwrap().unwrap();

        // 虚拟内网节点 → 隧道：DATA 帧应该出现在隧道上游的 socket 上
        peer.deliver(mux::encode(Tag::Data, conn, b"from-vnet"))
            .await;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tunnel_side.read(&mut buf),
        )
        .await
        .expect("read timeout")
        .unwrap();
        assert_eq!(&buf[..n], b"from-vnet");

        // 隧道 → 虚拟内网节点：写进 socket 的字节要变成 DATA 帧
        tunnel_side.write_all(b"from-tunnel").await.unwrap();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), down_rx.recv())
            .await
            .expect("frame timeout")
            .unwrap();
        let parsed = mux::parse(&frame).unwrap();
        assert_eq!(parsed.tag, Tag::Data);
        assert_eq!(parsed.conn, conn);
        assert_eq!(parsed.payload, b"from-tunnel");
    }
}

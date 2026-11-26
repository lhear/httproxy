use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, OnceLock, PoisonError},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, RootCertStore, pki_types::ServerName},
};
use tracing::{debug, warn};

use super::config::{DnsConfig, Protocol};
use crate::warp::WarpClient;

static ROOT_CERT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

const UDP_RECV_BUF: usize = u16::MAX as usize;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);

type PendingMap = Arc<StdMutex<HashMap<u16, Option<oneshot::Sender<Result<Vec<u8>>>>>>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type Connector = Arc<dyn Fn() -> BoxFuture<Result<DnsStream>> + Send + Sync>;

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct PendingGuard {
    pending: PendingMap,
    id: u16,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
    }
}

fn assign_id_and_register(
    pending: &PendingMap,
    data: &mut [u8],
    tx: oneshot::Sender<Result<Vec<u8>>>,
) -> Result<u16> {
    anyhow::ensure!(
        (2..=u16::MAX as usize).contains(&data.len()),
        "invalid DNS query length"
    );
    let mut map = pending.lock().unwrap_or_else(PoisonError::into_inner);
    anyhow::ensure!(map.len() <= u16::MAX as usize, "DNS query IDs exhausted");
    let id = loop {
        let candidate: u16 = rand::random();
        if let Entry::Vacant(entry) = map.entry(candidate) {
            entry.insert(Some(tx));
            break candidate;
        }
    };
    data[0..2].copy_from_slice(&id.to_be_bytes());
    Ok(id)
}

pub(super) struct UdpTransport {
    tx: mpsc::Sender<(Vec<u8>, u16)>,
    pending: PendingMap,
    _task: AbortOnDrop,
}

impl UdpTransport {
    pub(super) fn new(upstream: SocketAddr) -> Self {
        let pending: PendingMap = Default::default();
        let actor_pending = Arc::clone(&pending);
        let (tx, rx) = mpsc::channel::<(Vec<u8>, u16)>(32);
        let task = tokio::spawn(async move { Self::run(upstream, rx, actor_pending).await });
        Self {
            tx,
            pending,
            _task: AbortOnDrop(task),
        }
    }

    async fn run(
        upstream: SocketAddr,
        mut rx: mpsc::Receiver<(Vec<u8>, u16)>,
        pending: PendingMap,
    ) {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(error) => {
                fail_pending(&pending, &format!("DNS upstream bind failed: {error}"));
                return;
            }
        };
        let mut buf = BytesMut::with_capacity(UDP_RECV_BUF);
        loop {
            buf.clear();
            tokio::select! {
                request = rx.recv() => {
                    let Some((data, id)) = request else { break; };
                    if let Err(error) = socket.send_to(&data, upstream).await
                        && let Some(tx) = take_pending(&pending, id)
                    {
                        let _ = tx.send(Err(anyhow!("DNS upstream send failed: {error}")));
                    }
                }
                received = socket.recv_buf_from(&mut buf) => {
                    match received {
                        Ok((len, from)) if from == upstream && len >= 2 => {
                            let id = u16::from_be_bytes([buf[0], buf[1]]);
                            if let Some(tx) = take_pending(&pending, id) {
                                let _ = tx.send(Ok(buf[..len].to_vec()));
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            warn!(%error, "DNS upstream receive failed");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn send(&self, mut data: Vec<u8>) -> Result<(Vec<u8>, u16)> {
        let (tx, rx) = oneshot::channel();
        let id = assign_id_and_register(&self.pending, &mut data, tx)?;
        let _pending_guard = PendingGuard {
            pending: Arc::clone(&self.pending),
            id,
        };

        let response = timeout(Duration::from_secs(2), async {
            self.tx
                .send((data, id))
                .await
                .map_err(|_| anyhow!("DNS transport actor closed"))?;
            rx.await
                .map_err(|_| anyhow!("DNS response channel closed"))?
        })
        .await
        .context("UDP upstream timeout")??;
        Ok((response, id))
    }
}

fn take_pending(pending: &PendingMap, id: u16) -> Option<oneshot::Sender<Result<Vec<u8>>>> {
    pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(&id)
        .and_then(Option::take)
}

fn fail_pending(pending: &PendingMap, reason: &str) {
    for tx in pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values_mut()
        .filter_map(Option::take)
    {
        let _ = tx.send(Err(anyhow!("{reason}")));
    }
}

pub(super) struct DnsStream(Box<dyn DnsStreamInner>);

trait DnsStreamInner: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DnsStreamInner for T {}

impl DnsStream {
    fn new(stream: impl AsyncRead + AsyncWrite + Send + Unpin + 'static) -> Self {
        Self(Box::new(stream))
    }
}

impl AsyncRead for DnsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut *self.get_mut().0), cx, buf)
    }
}

impl AsyncWrite for DnsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut *self.get_mut().0), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut *self.get_mut().0), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut *self.get_mut().0), cx)
    }
}

pub(super) struct StreamTransport {
    tx: mpsc::Sender<(Vec<u8>, u16)>,
    pending: PendingMap,
    _task: AbortOnDrop,
}

impl StreamTransport {
    pub(super) fn new(connector: Connector) -> Self {
        let pending: PendingMap = Default::default();
        let actor_pending = pending.clone();
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, u16)>(32);

        let task = tokio::spawn(async move {
            let mut writer: Option<tokio::io::WriteHalf<DnsStream>> = None;
            let mut reader_task: Option<AbortOnDrop> = None;

            loop {
                tokio::select! {
                    req = rx.recv() => {
                        let Some((data, id)) = req else { break; };

                        if writer.is_none() {
                            match (connector)().await {
                                Ok(s) => {
                                    let (r, w) = tokio::io::split(s);
                                    writer = Some(w);
                                    let pm = actor_pending.clone();
                                    reader_task = Some(AbortOnDrop(tokio::spawn(Self::reader_loop(r, pm))));
                                    debug!("DNS stream transport connected");
                                }
                                Err(e) => {
                                    if let Some(tx) = actor_pending
                                        .lock()
                                        .unwrap_or_else(PoisonError::into_inner)
                                        .get_mut(&id)
                                        .and_then(Option::take)
                                    {
                                        let _ = tx.send(Err(anyhow!("connect failed: {}", e)));
                                    }
                                    continue;
                                }
                            }
                        }

                        let write_result = timeout(Duration::from_secs(10), async {
                            let w = writer.as_mut().unwrap();
                            let len_prefix = (data.len() as u16).to_be_bytes();
                            w.write_all(&len_prefix).await?;
                            w.write_all(&data).await?;
                            w.flush().await
                        })
                        .await;
                        if !matches!(write_result, Ok(Ok(()))) {
                            warn!("DNS upstream write failed or timed out, dropping connection");

                            for tx in actor_pending
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .values_mut()
                                .filter_map(Option::take)
                            {
                                let _ = tx.send(Err(anyhow!("write failed, connection reset")));
                            }
                            writer = None;
                            reader_task = None;
                        }
                    }

                    _ = async {
                        if let Some(ref mut t) = reader_task {
                            (&mut t.0).await.ok();
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        debug!("DNS upstream reader exited, cleaning up connection");
                        writer = None;
                        reader_task = None;

                        for tx in actor_pending
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .values_mut()
                            .filter_map(Option::take)
                        {
                            let _ = tx.send(Err(anyhow!("connection reset by remote")));
                        }
                    }
                }
            }
        });

        Self {
            tx,
            pending,
            _task: AbortOnDrop(task),
        }
    }

    async fn reader_loop(mut r: tokio::io::ReadHalf<DnsStream>, pending: PendingMap) {
        let mut len_buf = [0u8; 2];
        loop {
            let len_res = timeout(Duration::from_secs(30), r.read_exact(&mut len_buf)).await;
            if !matches!(len_res, Ok(Ok(_))) {
                break;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                continue;
            }
            let mut buf = vec![0u8; msg_len];
            let read_res = timeout(Duration::from_secs(30), r.read_exact(&mut buf)).await;
            if !matches!(read_res, Ok(Ok(_))) {
                break;
            }
            if buf.len() >= 2 {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                if let Some(tx) = pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_mut(&id)
                    .and_then(Option::take)
                {
                    let _ = tx.send(Ok(buf));
                }
            }
        }
    }

    pub(super) async fn send(&self, mut data: Vec<u8>) -> Result<(Vec<u8>, u16)> {
        let (tx, rx) = oneshot::channel();

        let id = assign_id_and_register(&self.pending, &mut data, tx)?;
        let _pending_guard = PendingGuard {
            pending: Arc::clone(&self.pending),
            id,
        };

        let response = timeout(Duration::from_secs(5), async {
            self.tx
                .send((data, id))
                .await
                .map_err(|_| anyhow!("DNS transport actor closed"))?;
            rx.await
                .map_err(|_| anyhow!("DNS response channel closed"))?
        })
        .await
        .context("DNS query timeout")??;
        Ok((response, id))
    }
}

pub(super) enum Transport {
    Udp(UdpTransport),
    Stream(StreamTransport),
}

impl Transport {
    pub(super) async fn send(&self, data: Vec<u8>) -> Result<(Vec<u8>, u16)> {
        match self {
            Transport::Udp(t) => t.send(data).await,
            Transport::Stream(t) => t.send(data).await,
        }
    }
}

pub(super) fn build_transport(
    config: &DnsConfig,
    warp: Option<&Arc<WarpClient>>,
) -> Result<Transport> {
    let upstream = config.upstream;
    let via_warp = warp.filter(|w| !w.is_direct_ip(upstream.ip())).cloned();

    match (config.options.protocol, via_warp) {
        (Protocol::Udp, None) => Ok(Transport::Udp(UdpTransport::new(upstream))),
        (Protocol::Udp, Some(warp)) => {
            debug!(
                upstream = %upstream,
                "dns: UDP upstream carried as DNS-over-TCP through WARP"
            );
            Ok(Transport::Stream(StreamTransport::new(warp_connector(
                warp, upstream,
            ))))
        }
        (Protocol::Dot, via_warp) => {
            let name = tls_server_name(config)?;
            let tls = TlsConnector::from(Arc::new(rustls_client_config()));
            let connector = match via_warp {
                Some(warp) => warp_dot_connector(warp, upstream, name, tls),
                None => direct_dot_connector(upstream, name, tls),
            };
            Ok(Transport::Stream(StreamTransport::new(connector)))
        }
    }
}

fn tls_server_name(config: &DnsConfig) -> Result<ServerName<'static>> {
    let domain = config
        .tls_domain
        .as_deref()
        .context("DoT requires a TLS domain")?;
    ServerName::try_from(domain)
        .map_err(|_| anyhow!("invalid TLS domain: {domain}"))
        .map(|n| n.to_owned())
}

fn rustls_client_config() -> rustls::ClientConfig {
    let root_store = ROOT_CERT_STORE
        .get_or_init(|| {
            Arc::new(RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        })
        .clone();
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn warp_connector(warp: Arc<WarpClient>, upstream: SocketAddr) -> Connector {
    Arc::new(move || {
        let warp = Arc::clone(&warp);
        Box::pin(async move {
            let stream = warp.dial(upstream.ip(), upstream.port()).await?;
            Ok(DnsStream::new(stream.into_io()))
        })
    })
}

fn direct_dot_connector(
    upstream: SocketAddr,
    name: ServerName<'static>,
    tls: TlsConnector,
) -> Connector {
    Arc::new(move || {
        let tls = tls.clone();
        let name = name.clone();
        Box::pin(async move {
            let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream))
                .await
                .context("connect timeout")??;
            tcp.set_nodelay(true)?;
            let stream = timeout(TLS_TIMEOUT, tls.connect(name, tcp))
                .await
                .context("TLS handshake timeout")??;
            Ok(DnsStream::new(stream))
        })
    })
}

fn warp_dot_connector(
    warp: Arc<WarpClient>,
    upstream: SocketAddr,
    name: ServerName<'static>,
    tls: TlsConnector,
) -> Connector {
    Arc::new(move || {
        let warp = Arc::clone(&warp);
        let tls = tls.clone();
        let name = name.clone();
        Box::pin(async move {
            let io = warp.dial(upstream.ip(), upstream.port()).await?.into_io();
            let stream = timeout(TLS_TIMEOUT, tls.connect(name, io))
                .await
                .context("TLS handshake timeout")??;
            Ok(DnsStream::new(stream))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn spawn_udp_echo_server() -> SocketAddr {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let mut resp = vec![buf[0], buf[1], 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
                resp.extend_from_slice(&buf[12..n]);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_transport_matches_concurrent_responses_by_id() {
        let server_addr = spawn_udp_echo_server().await;
        let transport = Arc::new(UdpTransport::new(server_addr));
        let mut tasks = tokio::task::JoinSet::new();
        for marker in 0..32u8 {
            let transport = Arc::clone(&transport);
            tasks.spawn(async move {
                let mut query = vec![0u8; 14];
                query[12] = marker;
                query[13] = marker;
                let (response, id) = transport.send(query).await.unwrap();
                (marker, id, response)
            });
        }
        while let Some(done) = tasks.join_next().await {
            let (marker, id, response) = done.unwrap();
            assert_eq!(response[0..2], id.to_be_bytes());
            assert_eq!(response[12..14], [marker, marker]);
        }
    }

    #[tokio::test]
    async fn udp_transport_times_out_when_no_reply() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let t = UdpTransport::new(addr);
        let start = std::time::Instant::now();
        let r = t.send(vec![0u8; 12]).await;
        assert!(r.is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
        assert!(t.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stream_transport_uses_length_prefixed_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            socket.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; len];
            socket.read_exact(&mut msg).await.unwrap();
            socket.write_all(&len_buf).await.unwrap();
            socket.write_all(&msg).await.unwrap();
            socket.flush().await.unwrap();
            assert_eq!(socket.read(&mut len_buf).await.unwrap(), 0);
        });

        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let tcp = TcpStream::connect(addr).await?;
                Ok(DnsStream::new(tcp))
            })
        });
        let t = StreamTransport::new(connector);

        let mut query = vec![0u8; 12];
        let (resp, id) = t.send(query.clone()).await.unwrap();
        query[..2].copy_from_slice(&id.to_be_bytes());
        assert_eq!(resp, query);
        drop(t);
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stream_transport_reports_connect_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let tcp = TcpStream::connect(addr).await?;
                Ok(DnsStream::new(tcp))
            })
        });
        let t = StreamTransport::new(connector);
        assert!(t.send(vec![0u8; 12]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn queued_queries_time_out_and_release_a_stalled_connector() {
        let owner = Arc::new(());
        let watch = Arc::downgrade(&owner);
        let connector: Connector = Arc::new(move || {
            let owner = Arc::clone(&owner);
            Box::pin(async move {
                let _owner = owner;
                std::future::pending().await
            })
        });
        let transport = StreamTransport::new(connector);
        let results = timeout(
            Duration::from_secs(6),
            futures::future::join_all((0..64).map(|_| transport.send(vec![0; 12]))),
        )
        .await
        .unwrap();
        assert!(results.into_iter().all(|result| {
            result
                .unwrap_err()
                .to_string()
                .contains("DNS query timeout")
        }));
        assert!(transport.pending.lock().unwrap().is_empty());
        drop(transport);
        tokio::time::resume();
        timeout(Duration::from_secs(1), async {
            while watch.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

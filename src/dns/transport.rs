use anyhow::{Context, Result, anyhow};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, mpsc, oneshot},
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

const UDP_RECV_BUF: usize = 2048;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);

type PendingMap = Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Vec<u8>>>>>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type Connector = Arc<dyn Fn() -> BoxFuture<Result<DnsStream>> + Send + Sync>;

async fn assign_id_and_register(
    pending: &PendingMap,
    data: &mut [u8],
    tx: oneshot::Sender<Result<Vec<u8>>>,
) -> u16 {
    let mut map = pending.lock().await;
    let id = loop {
        let candidate: u16 = rand::random();
        if !map.contains_key(&candidate) {
            break candidate;
        }
    };
    data[0..2].copy_from_slice(&id.to_be_bytes());
    map.insert(id, tx);
    id
}

pub(super) struct UdpTransport {
    upstream: SocketAddr,
}

impl UdpTransport {
    pub(super) fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }

    pub(super) async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.upstream).await?;
        let id: u16 = rand::random();
        data[0..2].copy_from_slice(&id.to_be_bytes());
        socket.send(data).await?;
        let mut buf = [0u8; UDP_RECV_BUF];
        let len = timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .context("UDP upstream timeout")??;
        Ok((buf[..len].to_vec(), id))
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
}

impl StreamTransport {
    pub(super) fn new(connector: Connector) -> Self {
        let pending: PendingMap = Default::default();
        let actor_pending = pending.clone();
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, u16)>(32);

        tokio::spawn(async move {
            let mut writer: Option<tokio::io::WriteHalf<DnsStream>> = None;
            let mut reader_task: Option<tokio::task::JoinHandle<()>> = None;

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
                                    reader_task = Some(tokio::spawn(Self::reader_loop(r, pm)));
                                    debug!("DNS stream transport connected");
                                }
                                Err(e) => {
                                    if let Some(tx) = actor_pending.lock().await.remove(&id) {
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

                            for (_, tx) in actor_pending.lock().await.drain() {
                                let _ = tx.send(Err(anyhow!("write failed, connection reset")));
                            }
                            writer = None;
                            if let Some(t) = reader_task.take() { t.abort(); }
                        }
                    }

                    _ = async {
                        if let Some(ref mut t) = reader_task {
                            t.await.ok();
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        debug!("DNS upstream reader exited, cleaning up connection");
                        writer = None;
                        reader_task = None;

                        for (_, tx) in actor_pending.lock().await.drain() {
                            let _ = tx.send(Err(anyhow!("connection reset by remote")));
                        }
                    }
                }
            }
        });

        Self { tx, pending }
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
                if let Some(tx) = pending.lock().await.remove(&id) {
                    let _ = tx.send(Ok(buf));
                }
            }
        }
    }

    pub(super) async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
        let (tx, rx) = oneshot::channel();

        let id = assign_id_and_register(&self.pending, data, tx).await;

        if self.tx.send((data.to_vec(), id)).await.is_err() {
            self.pending.lock().await.remove(&id);
            return Err(anyhow!("DNS transport actor closed"));
        }

        match timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(res)) => Ok((res?, id)),
            Ok(Err(_)) => Err(anyhow!("DNS response channel closed")),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(anyhow!("DNS query timeout"))
            }
        }
    }
}

pub(super) enum Transport {
    Udp(UdpTransport),
    Stream(StreamTransport),
}

impl Transport {
    pub(super) async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
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
    async fn udp_transport_roundtrip() {
        let server_addr = spawn_udp_echo_server().await;
        let t = UdpTransport::new(server_addr);
        let mut query = [0u8; 12];
        query[12 - 12] = 0;
        let (resp, id) = t.send(&mut query).await.unwrap();
        assert_eq!(resp[0..2], query[0..2]);
        assert_eq!(id, u16::from_be_bytes([query[0], query[1]]));
    }

    #[tokio::test]
    async fn udp_transport_times_out_when_no_reply() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let t = UdpTransport::new(addr);
        let mut query = [0u8; 12];
        let start = std::time::Instant::now();
        let r = t.send(&mut query).await;
        assert!(r.is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn stream_transport_uses_length_prefixed_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            socket.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; len];
            socket.read_exact(&mut msg).await.unwrap();
            socket.write_all(&len_buf).await.unwrap();
            socket.write_all(&msg).await.unwrap();
            socket.flush().await.unwrap();
            std::future::pending::<()>().await;
        });

        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let tcp = TcpStream::connect(addr).await?;
                Ok(DnsStream::new(tcp))
            })
        });
        let t = StreamTransport::new(connector);

        let mut query = vec![0u8; 12];
        let (resp, id) = t.send(&mut query).await.unwrap();
        assert_eq!(id, u16::from_be_bytes([query[0], query[1]]));
        assert_eq!(resp, query);
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
        let mut query = [0u8; 12];
        assert!(t.send(&mut query).await.is_err());
    }
}

use anyhow::{Context, Result, anyhow};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{self, RootCertStore, pki_types::ServerName},
};
use tracing::{debug, error, warn};

use super::config::DnsConfig;

static ROOT_CERT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

type PendingMap = Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Vec<u8>>>>>>;

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
    socket: Arc<UdpSocket>,
    pending: PendingMap,
    recv_handle: tokio::task::AbortHandle,
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        self.recv_handle.abort();
    }
}

impl UdpTransport {
    pub(super) async fn new(upstream: SocketAddr) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(upstream).await?;
        let pending: PendingMap = Default::default();
        let (rs, rp) = (socket.clone(), pending.clone());
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut consecutive_errors = 0u32;
            loop {
                match rs.recv(&mut buf).await {
                    Ok(len) if len >= 2 => {
                        consecutive_errors = 0;
                        let id = u16::from_be_bytes([buf[0], buf[1]]);
                        if let Some(tx) = rp.lock().await.remove(&id) {
                            let _ = tx.send(Ok(buf[..len].to_vec()));
                        }
                    }
                    Ok(_) => {
                        consecutive_errors = 0;
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        error!(error = %e, consecutive_errors, "UDP recv error");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
            }
        });
        Ok(Self {
            socket,
            pending,
            recv_handle: handle.abort_handle(),
        })
    }

    pub(super) async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
        let (tx, rx) = oneshot::channel();
        let id = assign_id_and_register(&self.pending, data, tx).await;

        if let Err(e) = self.socket.send(data).await {
            self.pending.lock().await.remove(&id);
            return Err(anyhow!("UDP send failed: {}", e));
        }

        match timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(res)) => Ok((res?, id)),
            Ok(Err(_)) => Err(anyhow!("UDP channel closed")),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(anyhow!("UDP upstream timeout"))
            }
        }
    }
}

pub(super) struct DotTransport {
    tx: mpsc::Sender<(Vec<u8>, u16)>,
    pending: PendingMap,
}

impl DotTransport {
    pub(super) fn new(
        upstream: SocketAddr,
        tls_connector: TlsConnector,
        server_name: ServerName<'static>,
    ) -> Self {
        let pending: PendingMap = Default::default();
        let actor_pending = pending.clone();
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, u16)>(32);

        tokio::spawn(async move {
            let mut writer: Option<tokio::io::WriteHalf<TlsStream<TcpStream>>> = None;
            let mut reader_task: Option<tokio::task::JoinHandle<()>> = None;

            loop {
                tokio::select! {
                    req = rx.recv() => {
                        let Some((data, id)) = req else { break; };

                        if writer.is_none() {
                            match Self::connect(upstream, &tls_connector, server_name.clone()).await {
                                Ok(s) => {
                                    let (r, w) = tokio::io::split(s);
                                    writer = Some(w);
                                    let pm = actor_pending.clone();
                                    reader_task = Some(tokio::spawn(Self::reader_loop(r, pm)));
                                    debug!("DoT connection established");
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
                            warn!("DoT write failed or timed out, dropping connection");

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
                        debug!("DoT reader task exited, cleaning up connection");
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

    async fn reader_loop(mut r: tokio::io::ReadHalf<TlsStream<TcpStream>>, pending: PendingMap) {
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

    async fn connect(
        upstream: SocketAddr,
        connector: &TlsConnector,
        name: ServerName<'static>,
    ) -> Result<TlsStream<TcpStream>> {
        let stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream)).await??;
        stream.set_nodelay(true)?;
        Ok(timeout(Duration::from_secs(5), connector.connect(name, stream)).await??)
    }

    pub(super) async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
        let (tx, rx) = oneshot::channel();

        let id = assign_id_and_register(&self.pending, data, tx).await;

        if self.tx.send((data.to_vec(), id)).await.is_err() {
            self.pending.lock().await.remove(&id);
            return Err(anyhow!("DoT actor closed"));
        }

        match timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(res)) => Ok((res?, id)),
            Ok(Err(_)) => Err(anyhow!("DoT response channel closed")),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(anyhow!("DoT query timeout"))
            }
        }
    }
}

pub(super) fn init_dot_transport(config: &DnsConfig) -> Result<DotTransport> {
    let domain = config
        .tls_domain
        .as_deref()
        .context("DoT requires a TLS domain")?;
    let server_name = ServerName::try_from(domain)
        .map_err(|_| anyhow!("invalid TLS domain: {domain}"))?
        .to_owned();
    let root_store = ROOT_CERT_STORE
        .get_or_init(|| {
            Arc::new(RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        })
        .clone();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(DotTransport::new(
        config.upstream,
        TlsConnector::from(Arc::new(cfg)),
        server_name,
    ))
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
        let t = UdpTransport::new(server_addr).await.unwrap();
        let mut query = [0u8; 12];
        query[12 - 12] = 0;
        let (resp, id) = t.send(&mut query).await.unwrap();
        assert_eq!(resp[0..2], query[0..2]);
        assert_eq!(id, u16::from_be_bytes([query[0], query[1]]));
    }

    #[tokio::test]
    async fn udp_transport_times_out_when_no_reply() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        let t = UdpTransport::new(addr).await.unwrap();
        let mut query = [0u8; 12];
        let start = std::time::Instant::now();
        let r = t.send(&mut query).await;
        assert!(r.is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn udp_id_assignment_avoids_collision() {
        let pending: PendingMap = Default::default();
        let mut data1 = [0u8; 12];
        let (tx1, _rx1) = oneshot::channel();
        let id1 = assign_id_and_register(&pending, &mut data1, tx1).await;
        assert_eq!(data1[0..2], id1.to_be_bytes());
        let mut data2 = [0u8; 12];
        let (tx2, _rx2) = oneshot::channel();
        let id2 = assign_id_and_register(&pending, &mut data2, tx2).await;
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn dot_transport_connect_failure_reports_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ));
        let t = DotTransport::new(
            addr,
            connector,
            ServerName::try_from("example.com").unwrap().to_owned(),
        );
        let mut query = [0u8; 12];
        let r = t.send(&mut query).await;
        assert!(r.is_err());
    }
}

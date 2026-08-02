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

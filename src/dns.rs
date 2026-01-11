use anyhow::{Context, Result, anyhow};
use domain::base::{
    iana::{Class, Rcode, Rtype},
    opt::{ClientSubnet, Opt},
};
use domain::{
    base::{Message, MessageBuilder, Name, Question, Record, Ttl},
    rdata::{A, Aaaa},
};
use moka::future::Cache;
use rand::seq::SliceRandom;
use serde::Deserialize;
use singleflight_async::SingleFlight;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{RootCertStore, pki_types::ServerName},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, error, warn};

static ROOT_CERT_STORE: OnceLock<rustls::RootCertStore> = OnceLock::new();

type CacheKey = (String, u16, Option<IpAddr>);

fn default_dns_cache_size() -> u64 {
    1024
}

fn default_dns_protocol() -> String {
    "udp".into()
}

#[derive(Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    created_at: Instant,
    ttl: Duration,
}

type SharedDnsResult = Result<(Vec<IpAddr>, Duration), Arc<anyhow::Error>>;

struct PendingRequest {
    resp_tx: oneshot::Sender<Result<Vec<u8>>>,
}

type PendingMap = Arc<Mutex<HashMap<u16, PendingRequest>>>;

#[derive(Deserialize, Debug)]
pub struct DnsConfigJson {
    upstream: String,
    #[serde(default = "default_dns_protocol")]
    protocol: String,
    prefer_ipv6: Option<bool>,
    pub client_subnet: Option<IpAddr>,
    #[serde(default = "default_dns_cache_size")]
    cache_size: u64,
}

#[derive(Clone)]
pub struct DnsConfig {
    pub upstream: SocketAddr,
    pub protocol: Protocol,
    pub tls_domain: Option<String>,
    pub prefer_ipv6: bool,
    pub cache_size: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Protocol {
    Udp,
    Dot,
}

struct UdpTransport {
    socket: Arc<UdpSocket>,
    pending: PendingMap,
}

impl UdpTransport {
    async fn new(upstream: SocketAddr) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(upstream).await?;
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        let recv_socket = socket.clone();
        let recv_pending = pending.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match recv_socket.recv(&mut buf).await {
                    Ok(len) => {
                        let data = buf[0..len].to_vec();
                        if data.len() >= 2 {
                            let id = u16::from_be_bytes([data[0], data[1]]);
                            let mut map = recv_pending.lock().await;
                            if let Some(req) = map.remove(&id) {
                                let _ = req.resp_tx.send(Ok(data));
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(Self { socket, pending })
    }

    async fn send(&self, data: &[u8], id: u16) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(id, PendingRequest { resp_tx: tx });
        }

        if let Err(e) = self.socket.send(data).await {
            let mut map = self.pending.lock().await;
            map.remove(&id);
            return Err(anyhow!("UDP send failed: {}", e));
        }
        match timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(anyhow!("UDP channel closed")),
            Err(_) => {
                let mut map = self.pending.lock().await;
                map.remove(&id);
                Err(anyhow!("UDP upstream timeout"))
            }
        }
    }
}

struct DotTransport {
    tx: mpsc::Sender<(Vec<u8>, u16, oneshot::Sender<Result<Vec<u8>>>)>,
}

impl DotTransport {
    fn new(
        upstream: SocketAddr,
        tls_connector: TlsConnector,
        server_name: ServerName<'static>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, u16, oneshot::Sender<Result<Vec<u8>>>)>(32);

        tokio::spawn(async move {
            let mut stream_writer: Option<tokio::io::WriteHalf<TlsStream<TcpStream>>> = None;
            let mut reader_task: Option<tokio::task::JoinHandle<()>> = None;
            let pending_map: PendingMapInner = Arc::new(Mutex::new(HashMap::new()));

            loop {
                tokio::select! {
                    req = rx.recv() => {
                        let Some((data, id, resp_tx)) = req else { break; };
                        if stream_writer.is_none() {
                            match Self::connect(upstream, &tls_connector, server_name.clone()).await {
                                Ok(s) => {
                                    let (r_half, w_half) = tokio::io::split(s);
                                    stream_writer = Some(w_half);
                                    let pm = pending_map.clone();
                                    reader_task = Some(tokio::spawn(async move {
                                        Self::reader_loop(r_half, pm).await;
                                    }));
                                    debug!("DoT connection established");
                                }
                                Err(e) => {
                                    let _ = resp_tx.send(Err(anyhow!("connect failed: {}", e)));
                                    continue;
                                }
                            }
                        }
                        {
                            let mut map = pending_map.lock().await;
                            map.insert(id, resp_tx);
                        }
                        let w = stream_writer.as_mut().unwrap();
                        let len_u16 = (data.len() as u16).to_be_bytes();
                        if w.write_all(&len_u16).await.is_err() || w.write_all(&data).await.is_err() || w.flush().await.is_err() {
                            warn!("DoT write failed, dropping connection");
                            stream_writer = None;
                            if let Some(task) = reader_task.take() { task.abort(); }
                        }
                    }
                    _res = async {
                        if let Some(ref mut task) = reader_task {
                            task.await.ok();
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        debug!("DoT reader task exited, cleaning up connection");
                        stream_writer = None;
                        reader_task = None;
                        let mut map = pending_map.lock().await;
                        for (_, tx) in map.drain() {
                            let _ = tx.send(Err(anyhow!("connection reset by remote")));
                        }
                    }
                }
            }
        });

        Self { tx }
    }

    async fn reader_loop(
        mut r_half: tokio::io::ReadHalf<TlsStream<TcpStream>>,
        pending: PendingMapInner,
    ) {
        let mut len_buf = [0u8; 2];
        while r_half.read_exact(&mut len_buf).await.is_ok() {
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if r_half.read_exact(&mut buf).await.is_err() {
                break;
            }

            if len >= 2 {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let mut map = pending.lock().await;
                if let Some(tx) = map.remove(&id) {
                    let _ = tx.send(Ok(buf));
                }
            }
        }
    }

    async fn connect(
        upstream: SocketAddr,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<TlsStream<TcpStream>> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect(upstream)).await??;
        stream.set_nodelay(true)?;
        let tls_stream = connector.connect(server_name, stream).await?;
        Ok(tls_stream)
    }

    async fn send(&self, data: &[u8], id: u16) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();

        if self.tx.send((data.to_vec(), id, tx)).await.is_err() {
            return Err(anyhow!("DoT actor closed"));
        }

        match timeout(Duration::from_secs(4), rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(anyhow!("DoT response channel closed")),
            Err(_) => Err(anyhow!("DoT query timeout")),
        }
    }
}

type PendingMapInner = Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Vec<u8>>>>>>;

pub struct DnsClient {
    config: DnsConfig,
    cache: Cache<CacheKey, CacheEntry>,
    single_flight: SingleFlight<CacheKey, SharedDnsResult>,
    semaphore: Arc<Semaphore>,
    udp_transport: Option<UdpTransport>,
    dot_transport: Option<DotTransport>,
}

impl DnsClient {
    pub async fn new(config: DnsConfig) -> Result<Self> {
        let (udp_transport, dot_transport) = match config.protocol {
            Protocol::Udp => {
                let transport = UdpTransport::new(config.upstream).await?;
                (Some(transport), None)
            }
            Protocol::Dot => {
                let root_store = ROOT_CERT_STORE.get_or_init(|| {
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
                });
                let client_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store.clone())
                    .with_no_client_auth();

                let domain_str = config
                    .tls_domain
                    .clone()
                    .unwrap_or_else(|| "cloudflare-dns.com".to_string());
                let server_name = ServerName::try_from(domain_str)?.to_owned();
                let connector = TlsConnector::from(Arc::new(client_config));

                let transport = DotTransport::new(config.upstream, connector, server_name);
                (None, Some(transport))
            }
        };

        Ok(Self {
            config: config.clone(),
            cache: Cache::builder()
                .max_capacity(config.cache_size)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            single_flight: SingleFlight::new(),
            semaphore: Arc::new(Semaphore::new(1024)),
            udp_transport,
            dot_transport,
        })
    }

    pub async fn lookup(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> Result<Vec<IpAddr>> {
        let key = (domain.to_string(), rtype.to_int(), ecs);

        if let Some(entry) = self.cache.get(&key).await {
            if entry.created_at.elapsed() < entry.ttl {
                debug!("cache hit for {} {:?}", domain, rtype);
                return Ok(entry.ips);
            }
            self.cache.invalidate(&key).await;
        }

        let result = self
            .single_flight
            .work(key.clone(), || async {
                self.query_upstream(domain, rtype, ecs)
                    .await
                    .map_err(Arc::new)
            })
            .await;

        let (ips, ttl) = result.map_err(|e| anyhow!("DNS resolution error: {}", e))?;

        if !ips.is_empty() {
            self.cache
                .insert(
                    key,
                    CacheEntry {
                        ips: ips.clone(),
                        created_at: Instant::now(),
                        ttl,
                    },
                )
                .await;
        }
        Ok(ips)
    }

    async fn query_upstream(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let _permit = self.semaphore.acquire().await?;
        let request_id: u16 = rand::random();
        let query_bytes = self.build_query(domain, rtype, ecs, request_id)?;

        let response_bytes = if let Some(ref udp) = self.udp_transport {
            udp.send(&query_bytes, request_id).await?
        } else if let Some(ref dot) = self.dot_transport {
            dot.send(&query_bytes, request_id).await?
        } else {
            return Err(anyhow!("no transport configured"));
        };

        self.parse_response(&response_bytes, request_id, rtype)
    }

    fn build_query(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
        id: u16,
    ) -> Result<Vec<u8>> {
        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_id(id);
        msg.header_mut().set_rd(true);
        msg.header_mut()
            .set_opcode(domain::base::iana::Opcode::QUERY);
        let dname = Name::<Vec<u8>>::from_str(domain).context("invalid domain name")?;
        let mut question = msg.question();
        question.push(Question::new(dname.clone(), rtype, Class::IN))?;
        let mut additional = question.additional();
        let mut opt = Opt::<Vec<u8>>::empty();
        if let Some(ip) = ecs {
            let source_netmask = match ip {
                IpAddr::V4(_) => 24,
                IpAddr::V6(_) => 56,
            };
            let cs = ClientSubnet::new(source_netmask, 0, ip);
            opt.push(&cs)?;
        }
        additional.push(Record::new(
            Name::<Vec<u8>>::root(),
            Class::from(1232u16),
            Ttl::from_secs(0),
            opt,
        ))?;
        Ok(additional.into_message().into_octets())
    }

    fn parse_response(
        &self,
        data: &[u8],
        request_id: u16,
        qtype: Rtype,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let msg = Message::from_octets(data).map_err(|_| anyhow!("invalid DNS response"))?;
        if msg.header().id() != request_id {
            return Err(anyhow!("DNS ID mismatch"));
        }
        if msg.header().rcode() != Rcode::NOERROR {
            return Err(anyhow!("DNS Rcode Error: {}", msg.header().rcode()));
        }

        let mut ips = Vec::new();
        let mut min_ttl_secs = u32::MAX;
        let mut found_records = false;

        if let Ok(section) = msg.answer() {
            for record in section.flatten() {
                if record.rtype() == qtype {
                    found_records = true;
                    min_ttl_secs = min_ttl_secs.min(record.ttl().as_secs());
                    match qtype {
                        Rtype::A => {
                            if let Ok(Some(rec)) = record.into_record::<A>() {
                                ips.push(IpAddr::V4(rec.data().addr()));
                            }
                        }
                        Rtype::AAAA => {
                            if let Ok(Some(rec)) = record.into_record::<Aaaa>() {
                                ips.push(IpAddr::V6(rec.data().addr()));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        if !found_records || ips.is_empty() {
            return Err(anyhow!("no records found"));
        }
        let effective_ttl = Duration::from_secs(min_ttl_secs.max(30).min(3600) as u64);
        Ok((ips, effective_ttl))
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        ecs: Option<IpAddr>,
        socks5_proxy: Option<String>,
    ) -> Result<TcpStream> {
        if let Ok(ip) = IpAddr::from_str(host) {
            debug!("host is an IP address: {}, connecting directly", ip);
            return self
                .happy_eyeballs_connect(vec![ip], port, socks5_proxy)
                .await;
        }
        let (res_a, res_aaaa) = tokio::join!(
            self.lookup(host, Rtype::A, ecs),
            self.lookup(host, Rtype::AAAA, ecs)
        );
        let mut ips_v4 = res_a.unwrap_or_default();
        let mut ips_v6 = res_aaaa.unwrap_or_default();
        if ips_v4.is_empty() && ips_v6.is_empty() {
            return Err(anyhow!("resolution failed for {}", host));
        }
        {
            let mut rng = rand::rng();
            ips_v4.shuffle(&mut rng);
            ips_v6.shuffle(&mut rng);
        }
        let sorted_ips = self.interleave_ips(ips_v4, ips_v6);
        debug!(
            "happy Eyeballs connecting to {} with IPs: {:?}",
            host, sorted_ips
        );
        self.happy_eyeballs_connect(sorted_ips, port, socks5_proxy)
            .await
    }

    fn interleave_ips(&self, v4: Vec<IpAddr>, v6: Vec<IpAddr>) -> Vec<IpAddr> {
        let mut result = Vec::with_capacity(v4.len() + v6.len());
        let (mut primary, mut secondary) = if self.config.prefer_ipv6 {
            (v6.into_iter(), v4.into_iter())
        } else {
            (v4.into_iter(), v6.into_iter())
        };
        loop {
            match (primary.next(), secondary.next()) {
                (Some(p), Some(s)) => {
                    result.push(p);
                    result.push(s);
                }
                (Some(p), None) => result.push(p),
                (None, Some(s)) => result.push(s),
                (None, None) => break,
            }
        }
        result
    }

    async fn happy_eyeballs_connect(
        &self,
        ips: Vec<IpAddr>,
        port: u16,
        socks5_proxy: Option<String>,
    ) -> Result<TcpStream> {
        if ips.is_empty() {
            return Err(anyhow!("no IPs to connect"));
        }
        let mut join_set = JoinSet::new();
        let mut ip_iter = ips.into_iter();
        let proxy = Arc::new(socks5_proxy);

        if let Some(first_ip) = ip_iter.next() {
            let p = proxy.clone();
            join_set.spawn(Self::connect_single(first_ip, port, (*p).clone()));
        }
        let delay = Duration::from_millis(250);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        let mut all_started = false;
        loop {
            tokio::select! {
                Some(result) = join_set.join_next() => {
                    match result {
                        Err(e) => warn!("connection task panicked: {}", e),
                        Ok(Ok(stream)) => return Ok(stream),
                        Ok(Err(_)) => { if all_started && join_set.is_empty() { break; } }
                    }
                }
                () = &mut sleep, if !all_started => {
                    match ip_iter.next() {
                        Some(ip) => {
                            let p = proxy.clone();
                            join_set.spawn(Self::connect_single(ip, port, (*p).clone()));
                            sleep.as_mut().reset(Instant::now() + delay);
                        }
                        None => { all_started = true; }
                    }
                }
                else => break,
            }
        }
        Err(anyhow!(
            "all connection attempts failed (via proxy: {:?})",
            *proxy
        ))
    }

    async fn connect_single(
        ip: IpAddr,
        port: u16,
        socks5_proxy: Option<String>,
    ) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
        let target_addr = SocketAddr::new(ip, port);
        let connect_timeout = Duration::from_secs(3);

        let stream = match socks5_proxy {
            Some(proxy_url) => {
                let s = timeout(
                    connect_timeout,
                    Socks5Stream::connect(proxy_url.as_str(), target_addr),
                )
                .await??;
                s.into_inner()
            }
            None => timeout(connect_timeout, TcpStream::connect(target_addr)).await??,
        };

        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

pub async fn init_dns(dns_cfg: &DnsConfigJson) -> anyhow::Result<Arc<DnsClient>> {
    let proto = if dns_cfg.protocol.eq_ignore_ascii_case("dot") {
        Protocol::Dot
    } else {
        Protocol::Udp
    };

    let internal_config = DnsConfig {
        upstream: dns_cfg
            .upstream
            .parse()
            .context("invalid dns upstream address")?,
        protocol: proto,
        tls_domain: dns_cfg
            .upstream
            .parse::<axum::http::uri::Authority>()
            .map(|auth| auth.host().to_string())
            .ok(),
        prefer_ipv6: dns_cfg.prefer_ipv6.unwrap_or_default(),
        cache_size: dns_cfg.cache_size,
    };

    let dns_client = Arc::new(DnsClient::new(internal_config).await?);
    Ok(dns_client)
}

use anyhow::{Context, Result, anyhow};
use domain::{
    base::{
        Message, MessageBuilder, Name, Question, Record, Ttl,
        iana::{Class, Rcode, Rtype},
        opt::{ClientSubnet, Opt},
    },
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
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
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
    rustls::{self, RootCertStore, pki_types::ServerName},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, error, warn};

static ROOT_CERT_STORE: OnceLock<RootCertStore> = OnceLock::new();

type CacheKey = (String, u16, Option<IpAddr>);
type PendingMap = Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Vec<u8>>>>>>;
type SharedDnsResult = Result<(Vec<IpAddr>, Duration), Arc<anyhow::Error>>;

fn deserialize_upstream<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
    String::deserialize(d)?
        .parse()
        .map_err(serde::de::Error::custom)
}

#[derive(Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    created_at: u64,
    ttl: Duration,
    is_refreshing: Arc<AtomicBool>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct DnsConfig {
    #[serde(deserialize_with = "deserialize_upstream")]
    pub upstream: SocketAddr,
    pub tls_domain: Option<String>,
    #[serde(flatten, default)]
    pub options: DnsOptions,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(default)]
pub struct DnsOptions {
    #[serde(rename = "protocol")]
    pub protocol: Protocol,
    pub prefer_ipv6: bool,
    pub cache_size: u64,
    pub client_subnet: Option<IpAddr>,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub swr_ttl: u64,
    pub empty_ttl: u64,
    pub happy_eyeballs_delay_ms: u64,
    pub max_concurrent_queries: usize,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            protocol: Protocol::Udp,
            prefer_ipv6: false,
            cache_size: 1024,
            client_subnet: None,
            min_ttl: 30,
            max_ttl: 3600,
            swr_ttl: 3600,
            empty_ttl: 300,
            happy_eyeballs_delay_ms: 250,
            max_concurrent_queries: 1024,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Dot,
}

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

struct UdpTransport {
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
    async fn new(upstream: SocketAddr) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(upstream).await?;
        let pending: PendingMap = Default::default();
        let (rs, rp) = (socket.clone(), pending.clone());
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match rs.recv(&mut buf).await {
                    Ok(len) if len >= 2 => {
                        let id = u16::from_be_bytes([buf[0], buf[1]]);
                        if let Some(tx) = rp.lock().await.remove(&id) {
                            let _ = tx.send(Ok(buf[..len].to_vec()));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("UDP recv error: {}", e);
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

    async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
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

struct DotTransport {
    tx: mpsc::Sender<(Vec<u8>, u16)>,
    pending: PendingMap,
}

impl DotTransport {
    fn new(
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

                        let w = writer.as_mut().unwrap();
                        let len_prefix = (data.len() as u16).to_be_bytes();
                        if w.write_all(&len_prefix).await.is_err()
                            || w.write_all(&data).await.is_err()
                            || w.flush().await.is_err()
                        {
                            warn!("DoT write failed, dropping connection");

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
        while r.read_exact(&mut len_buf).await.is_ok() {
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                continue;
            }
            let mut buf = vec![0u8; msg_len];
            if r.read_exact(&mut buf).await.is_err() {
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
        Ok(connector.connect(name, stream).await?)
    }

    async fn send(&self, data: &mut [u8]) -> Result<(Vec<u8>, u16)> {
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

pub struct DnsClient {
    config: DnsConfig,
    cache: Cache<CacheKey, CacheEntry>,
    single_flight: SingleFlight<CacheKey, SharedDnsResult>,
    semaphore: Arc<Semaphore>,
    udp_transport: Option<UdpTransport>,
    dot_transport: Option<DotTransport>,
}

impl DnsClient {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        let (udp, dot) = match config.options.protocol {
            Protocol::Udp => (Some(UdpTransport::new(config.upstream).await?), None),
            Protocol::Dot => (None, Some(Self::init_dot_transport(config).await?)),
        };
        Ok(Self {
            config: config.clone(),
            cache: Cache::builder()
                .max_capacity(config.options.cache_size)
                .time_to_live(Duration::from_secs(
                    config.options.max_ttl + config.options.swr_ttl,
                ))
                .build(),
            single_flight: SingleFlight::new(),
            semaphore: Arc::new(Semaphore::new(config.options.max_concurrent_queries)),
            udp_transport: udp,
            dot_transport: dot,
        })
    }

    async fn init_dot_transport(config: &DnsConfig) -> Result<DotTransport> {
        let domain = config
            .tls_domain
            .as_deref()
            .context("DoT requires a TLS domain")?;
        let server_name = ServerName::try_from(domain)
            .map_err(|_| anyhow!("invalid TLS domain: {domain}"))?
            .to_owned();
        let root_store = ROOT_CERT_STORE.get_or_init(|| {
            RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        });
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();
        Ok(DotTransport::new(
            config.upstream,
            TlsConnector::from(Arc::new(cfg)),
            server_name,
        ))
    }

    pub async fn lookup(
        self: &Arc<Self>,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> Result<Vec<IpAddr>> {
        let key = (domain.to_string(), rtype.to_int(), ecs);

        if let Some(entry) = self.cache.get(&key).await {
            let elapsed = crate::now_secs().saturating_sub(entry.created_at);

            if elapsed < entry.ttl.as_secs() {
                debug!("cache hit: {} {:?}, ips: {:?}", domain, rtype, entry.ips);
                return Ok(entry.ips);
            }

            if elapsed < entry.ttl.as_secs() + self.config.options.swr_ttl {
                if entry
                    .is_refreshing
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    let (sc, kc, dc, flag) = (
                        self.clone(),
                        key.clone(),
                        domain.to_string(),
                        entry.is_refreshing.clone(),
                    );
                    tokio::spawn(async move {
                        debug!("background refresh triggered: {} {:?}", dc, rtype);
                        let _ = sc
                            .single_flight
                            .work(kc.clone(), || async {
                                sc.query_upstream_and_cache(&dc, rtype, ecs, kc).await
                            })
                            .await;
                        flag.store(false, Ordering::Release);
                    });
                }
                debug!("stale hit: {} {:?}, ips: {:?}", domain, rtype, entry.ips);
                return Ok(entry.ips);
            }
        }

        self.single_flight
            .work(key.clone(), || async {
                self.query_upstream_and_cache(domain, rtype, ecs, key).await
            })
            .await
            .map(|(ips, _)| ips)
            .map_err(|e| anyhow!("DNS resolution error: {}", e))
    }

    async fn query_upstream_and_cache(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
        key: CacheKey,
    ) -> SharedDnsResult {
        let (ips, ttl) = self
            .query_upstream(domain, rtype, ecs)
            .await
            .map_err(Arc::new)?;
        let entry = CacheEntry {
            ips: ips.clone(),
            created_at: crate::now_secs(),
            ttl,
            is_refreshing: Arc::new(false.into()),
        };
        self.cache.insert(key, entry).await;
        Ok((ips, ttl))
    }

    async fn query_upstream(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let _permit = self.semaphore.acquire().await?;

        let mut query = self.build_query(domain, rtype, ecs, 0)?;

        let (resp, id) = match (&self.udp_transport, &self.dot_transport) {
            (Some(udp), _) => udp.send(&mut query).await?,
            (_, Some(dot)) => dot.send(&mut query).await?,
            _ => return Err(anyhow!("no transport configured")),
        };

        self.parse_response(&resp, id, rtype)
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
        let mut question = msg.question();
        question.push(Question::new(
            Name::<Vec<u8>>::from_str(domain).context("invalid domain name")?,
            rtype,
            Class::IN,
        ))?;
        let mut additional = question.additional();
        let mut opt = Opt::<Vec<u8>>::empty();
        if let Some(ip) = ecs {
            opt.push(&ClientSubnet::new(
                if ip.is_ipv4() { 24 } else { 56 },
                0,
                ip,
            ))?;
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
        id: u16,
        qtype: Rtype,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let msg = Message::from_octets(data).map_err(|_| anyhow!("invalid DNS response"))?;
        if msg.header().id() != id {
            return Err(anyhow!(
                "DNS ID mismatch: expected {}, got {}",
                id,
                msg.header().id()
            ));
        }
        let rcode = msg.header().rcode();
        if rcode == Rcode::NXDOMAIN {
            return Ok((vec![], Duration::from_secs(self.config.options.empty_ttl)));
        }
        if rcode != Rcode::NOERROR {
            return Err(anyhow!("DNS Rcode Error: {}", rcode));
        }

        let (mut ips, mut min_ttl) = (Vec::new(), u32::MAX);
        if let Ok(section) = msg.answer() {
            for rec in section.flatten().filter(|r| r.rtype() == qtype) {
                min_ttl = min_ttl.min(rec.ttl().as_secs());
                match qtype {
                    Rtype::A => {
                        if let Some(r) = rec.into_record::<A>().ok().flatten() {
                            ips.push(IpAddr::V4(r.data().addr()));
                        }
                    }
                    Rtype::AAAA => {
                        if let Some(r) = rec.into_record::<Aaaa>().ok().flatten() {
                            ips.push(IpAddr::V6(r.data().addr()));
                        }
                    }
                    _ => {}
                }
            }
        }

        let ttl = if ips.is_empty() {
            Duration::from_secs(self.config.options.empty_ttl)
        } else {
            Duration::from_secs(
                (min_ttl as u64).clamp(self.config.options.min_ttl, self.config.options.max_ttl),
            )
        };
        Ok((ips, ttl))
    }

    pub async fn connect(
        self: &Arc<Self>,
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

        let mut v4 = res_a.unwrap_or_else(|e| {
            warn!("A record lookup failed for {}: {}", host, e);
            vec![]
        });
        let mut v6 = res_aaaa.unwrap_or_else(|e| {
            warn!("AAAA record lookup failed for {}: {}", host, e);
            vec![]
        });

        if v4.is_empty() && v6.is_empty() {
            return Err(anyhow!(
                "DNS resolution failed for {}: no A/AAAA records found",
                host
            ));
        }
        {
            let mut rng = rand::rng();
            v4.shuffle(&mut rng);
            v6.shuffle(&mut rng);
        }
        let sorted = self.interleave_ips(v4, v6);
        debug!(
            "Happy Eyeballs connecting to {} with IPs: {:?}",
            host, sorted
        );
        self.happy_eyeballs_connect(sorted, port, socks5_proxy)
            .await
    }

    fn interleave_ips(&self, v4: Vec<IpAddr>, v6: Vec<IpAddr>) -> Vec<IpAddr> {
        let (p, s) = if self.config.options.prefer_ipv6 {
            (v6, v4)
        } else {
            (v4, v6)
        };
        let mut r = Vec::with_capacity(p.len() + s.len());
        let (mut pi, mut si) = (p.into_iter(), s.into_iter());
        loop {
            match (pi.next(), si.next()) {
                (Some(a), Some(b)) => {
                    r.push(a);
                    r.push(b);
                }
                (Some(a), None) | (None, Some(a)) => {
                    r.push(a);
                    r.extend(pi);
                    r.extend(si);
                    break;
                }
                _ => break,
            }
        }
        r
    }

    async fn happy_eyeballs_connect(
        &self,
        ips: Vec<IpAddr>,
        port: u16,
        proxy: Option<String>,
    ) -> Result<TcpStream> {
        if ips.is_empty() {
            return Err(anyhow!("no IPs to connect"));
        }
        let mut set = JoinSet::new();
        let mut iter = ips.into_iter();
        let proxy = Arc::new(proxy);

        set.spawn(Self::connect_single(
            iter.next().unwrap(),
            port,
            (*proxy).clone(),
        ));

        let delay = Duration::from_millis(self.config.options.happy_eyeballs_delay_ms);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        let mut all_started = false;

        loop {
            tokio::select! {
                Some(result) = set.join_next() => {
                    match result {
                        Ok(Ok(stream)) => return Ok(stream),
                        Ok(Err(e)) => debug!("connection attempt failed: {}", e),
                        Err(e) => warn!("connection task panicked: {}", e),
                    }

                    if all_started && set.is_empty() { break; }
                },
                () = &mut sleep, if !all_started => match iter.next() {
                    Some(ip) => {
                        set.spawn(Self::connect_single(ip, port, (*proxy).clone()));
                        sleep.as_mut().reset(Instant::now() + delay);
                    }
                    None => { all_started = true; }
                },
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
        proxy: Option<String>,
    ) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
        let addr = SocketAddr::new(ip, port);
        let t = Duration::from_secs(10);
        let stream = match proxy {
            Some(url) => {
                let proxy_addr = url
                    .strip_prefix("socks5://")
                    .or_else(|| url.strip_prefix("socks5h://"))
                    .unwrap_or(&url);
                timeout(t, Socks5Stream::connect(proxy_addr, addr))
                    .await??
                    .into_inner()
            }
            None => timeout(t, TcpStream::connect(addr)).await??,
        };
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

pub async fn init_dns(config: &mut DnsConfig) -> Result<Arc<DnsClient>> {
    if config.options.protocol == Protocol::Dot && config.tls_domain.is_none() {
        config.tls_domain = Some(config.upstream.ip().to_string());
    }
    Ok(Arc::new(DnsClient::new(config).await?))
}

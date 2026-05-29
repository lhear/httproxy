use anyhow::{Context, Result, anyhow};
use domain::{
    base::{
        Message, MessageBuilder, Name, Question, Record, Ttl,
        iana::{Class, Opcode, Rcode, Rtype},
        opt::{ClientSubnet, Opt},
    },
    rdata::{A, Aaaa},
};
use moka::future::Cache;
use rand::seq::SliceRandom;
use singleflight_async::SingleFlight;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, warn};

use super::config::{DnsConfig, Protocol};
use super::transport::{DotTransport, UdpTransport, init_dot_transport};

type CacheKey = (String, u16, Option<IpAddr>);
type SharedDnsResult = Result<(Vec<IpAddr>, Duration), Arc<anyhow::Error>>;

enum Transport {
    Udp(UdpTransport),
    Dot(DotTransport),
}

#[derive(Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    created_at: u64,
    ttl: Duration,
    is_refreshing: Arc<AtomicBool>,
}

pub struct DnsClient {
    config: DnsConfig,
    cache: Cache<CacheKey, CacheEntry>,
    single_flight: SingleFlight<CacheKey, SharedDnsResult>,
    semaphore: Arc<Semaphore>,
    transport: Transport,
}

impl DnsClient {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        let transport = match config.options.protocol {
            Protocol::Udp => Transport::Udp(UdpTransport::new(config.upstream).await?),
            Protocol::Dot => Transport::Dot(init_dot_transport(config)?),
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
            transport,
        })
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

        let (resp, id) = match &self.transport {
            Transport::Udp(udp) => udp.send(&mut query).await?,
            Transport::Dot(dot) => dot.send(&mut query).await?,
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
        msg.header_mut().set_opcode(Opcode::QUERY);
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

    async fn connect_single(ip: IpAddr, port: u16, proxy: Option<String>) -> Result<TcpStream> {
        let addr = SocketAddr::new(ip, port);
        let t = Duration::from_secs(10);
        let stream = match proxy {
            Some(url) => {
                let proxy_addr = url
                    .strip_prefix("socks5://")
                    .or_else(|| url.strip_prefix("socks5h://"))
                    .unwrap_or(&url);
                timeout(t, Socks5Stream::connect(proxy_addr, addr))
                    .await
                    .context("connect timeout")?
                    .map_err(|e| anyhow!("socks5 connect: {e}"))?
                    .into_inner()
            }
            None => timeout(t, TcpStream::connect(addr))
                .await
                .context("connect timeout")?
                .map_err(|e| anyhow!("tcp connect: {e}"))?,
        };
        stream.set_nodelay(true).context("set_nodelay")?;
        Ok(stream)
    }
}

pub async fn init_dns(config: &mut DnsConfig) -> Result<Arc<DnsClient>> {
    if config.options.protocol == Protocol::Dot && config.tls_domain.is_none() {
        config.tls_domain = Some(config.upstream.ip().to_string());
    }
    Ok(Arc::new(DnsClient::new(config).await?))
}

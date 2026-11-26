use anyhow::{Context, Result, anyhow};
use domain::{
    base::{
        Message, MessageBuilder, Name, Question, Record, Ttl,
        iana::{Class, Opcode, Rcode, Rtype},
        opt::{ClientSubnet, Opt},
    },
    rdata::{A, Aaaa},
};
use futures::{StreamExt, stream::FuturesUnordered};
use moka::future::Cache;
use rand::seq::SliceRandom;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::{Instant, timeout},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, warn};

use super::config::{DnsConfig, Protocol};
use super::transport::{self, Transport};
use crate::warp::WarpClient;

type CacheKey = (String, u16, Option<IpAddr>);
type SharedDnsResult = Result<(Vec<IpAddr>, Duration), Arc<anyhow::Error>>;
type InFlight = HashMap<CacheKey, watch::Receiver<Option<SharedDnsResult>>>;

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
    in_flight: Mutex<InFlight>,
    semaphore: Arc<Semaphore>,
    transport: Transport,
}

struct InFlightGuard {
    client: Weak<DnsClient>,
    key: CacheKey,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(client) = self.client.upgrade() {
            client
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.key);
        }
    }
}

async fn wait_for_lookup(
    mut receiver: watch::Receiver<Option<SharedDnsResult>>,
) -> SharedDnsResult {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        if receiver.changed().await.is_err() {
            return Err(Arc::new(anyhow!("DNS lookup task ended without a result")));
        }
    }
}

impl DnsClient {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        let transport = transport::build_transport(config, None)?;
        Ok(Self::with_transport(config, transport))
    }

    fn with_transport(config: &DnsConfig, transport: Transport) -> Self {
        Self {
            config: config.clone(),
            cache: Cache::builder()
                .max_capacity(config.options.cache_size)
                .time_to_live(Duration::from_secs(
                    config.options.max_ttl + config.options.swr_ttl,
                ))
                .build(),
            in_flight: Mutex::new(HashMap::new()),
            semaphore: Arc::new(Semaphore::new(config.options.max_concurrent_queries)),
            transport,
        }
    }

    pub fn hijack_enabled(&self) -> bool {
        self.config.options.hijack
    }

    pub async fn query(&self, query: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(
            (12..=u16::MAX as usize).contains(&query.len()),
            "invalid DNS query length"
        );
        anyhow::ensure!(query[2] & 0x80 == 0, "DNS message is not a query");
        anyhow::ensure!(query[4..6] != [0, 0], "DNS query has no questions");
        let original_id = u16::from_be_bytes([query[0], query[1]]);
        let _permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| anyhow!(error))?;
        let payload = super::ecs::rewrite(query, self.config.options.client_subnet)
            .unwrap_or_else(|| query.to_vec());
        let (mut response, upstream_id) = self.transport.send(payload).await?;
        anyhow::ensure!(response.len() >= 12, "invalid DNS response length");
        anyhow::ensure!(
            u16::from_be_bytes([response[0], response[1]]) == upstream_id,
            "DNS response ID mismatch"
        );
        response[..2].copy_from_slice(&original_id.to_be_bytes());
        Ok(response)
    }

    pub async fn lookup(
        self: &Arc<Self>,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> Result<Vec<IpAddr>> {
        let key = (domain.to_string(), rtype.to_int(), ecs);

        if let Some(entry) = self.cache.get(&key).await {
            let elapsed = crate::monotonic_secs().saturating_sub(entry.created_at);

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
                    let (sc, kc, flag) = (self.clone(), key.clone(), entry.is_refreshing.clone());
                    tokio::spawn(async move {
                        debug!("background refresh triggered: {} {:?}", kc.0, rtype);
                        let _ = sc.lookup_uncached(kc, rtype, ecs).await;
                        flag.store(false, Ordering::Release);
                    });
                }
                debug!("stale hit: {} {:?}, ips: {:?}", domain, rtype, entry.ips);
                return Ok(entry.ips);
            }
        }

        self.lookup_uncached(key, rtype, ecs)
            .await
            .map(|(ips, _)| ips)
            .map_err(|e| anyhow!("DNS resolution error: {}", e))
    }

    async fn lookup_uncached(
        self: &Arc<Self>,
        key: CacheKey,
        rtype: Rtype,
        ecs: Option<IpAddr>,
    ) -> SharedDnsResult {
        let existing = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned();
        if let Some(receiver) = existing {
            return wait_for_lookup(receiver).await;
        }

        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| Arc::new(anyhow!(error)))?;

        let (receiver, sender, leader) = {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(receiver) = in_flight.get(&key) {
                (receiver.clone(), None, false)
            } else {
                let (sender, receiver) = watch::channel(None);
                in_flight.insert(key.clone(), receiver.clone());
                (receiver, Some(sender), true)
            }
        };

        if leader {
            let sender = sender.expect("leader owns the lookup result sender");
            let client = Arc::clone(self);
            let cleanup = Arc::downgrade(self);
            let cleanup_key = key.clone();
            let domain = key.0.clone();
            tokio::spawn(async move {
                let _cleanup = InFlightGuard {
                    client: cleanup,
                    key: cleanup_key,
                };
                let result = client
                    .query_upstream_and_cache(&domain, rtype, ecs, key, permit)
                    .await;
                let _ = sender.send(Some(result));
            });
        }

        wait_for_lookup(receiver).await
    }

    async fn query_upstream_and_cache(
        &self,
        domain: &str,
        rtype: Rtype,
        ecs: Option<IpAddr>,
        key: CacheKey,
        _permit: OwnedSemaphorePermit,
    ) -> SharedDnsResult {
        let (ips, ttl) = self
            .query_upstream(domain, rtype, ecs)
            .await
            .map_err(Arc::new)?;
        let entry = CacheEntry {
            ips: ips.clone(),
            created_at: crate::monotonic_secs(),
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
        let query = self.build_query(domain, rtype, ecs, 0)?;

        let (resp, id) = self.transport.send(query).await?;

        self.parse_response(&resp, id, rtype, domain)
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
        domain: &str,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let msg = Message::from_octets(data).map_err(|_| anyhow!("invalid DNS response"))?;
        if msg.header().id() != id {
            return Err(anyhow!(
                "DNS ID mismatch: expected {}, got {}",
                id,
                msg.header().id()
            ));
        }
        let question = msg
            .sole_question()
            .map_err(|_| anyhow!("DNS response question missing or malformed"))?;
        let name_matches = question
            .qname()
            .to_string()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(domain.trim_end_matches('.'));
        if question.qtype() != qtype || !name_matches {
            return Err(anyhow!(
                "DNS response question does not match query for {domain}"
            ));
        }
        if msg.header().tc() {
            return Err(anyhow!("DNS response truncated (TC set)"));
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
            let lo = self.config.options.min_ttl.min(self.config.options.max_ttl);
            let hi = self.config.options.min_ttl.max(self.config.options.max_ttl);
            Duration::from_secs((min_ttl as u64).clamp(lo, hi))
        };
        Ok((ips, ttl))
    }

    pub async fn resolve(self: &Arc<Self>, host: &str, ecs: Option<IpAddr>) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = IpAddr::from_str(host) {
            debug!("host is an IP address: {}, no lookup needed", ip);
            return Ok(vec![ip]);
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
        Ok(self.interleave_ips(v4, v6))
    }

    pub async fn connect(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        ecs: Option<IpAddr>,
        socks5_proxy: Option<String>,
    ) -> Result<TcpStream> {
        let sorted = self.resolve(host, ecs).await?;
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
        let mut attempts = FuturesUnordered::new();
        let mut iter = ips.into_iter();

        attempts.push(Self::connect_single(
            iter.next().unwrap(),
            port,
            proxy.as_deref(),
        ));

        let delay = Duration::from_millis(self.config.options.happy_eyeballs_delay_ms);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                Some(result) = attempts.next() => {
                    match result {
                        Ok(stream) => return Ok(stream),
                        Err(error) => debug!("connection attempt failed: {}", error),
                    }

                    if attempts.is_empty() {
                        let Some(ip) = iter.next() else { break; };
                        attempts.push(Self::connect_single(ip, port, proxy.as_deref()));
                        sleep.as_mut().reset(Instant::now() + delay);
                    }
                },
                () = &mut sleep, if iter.len() > 0 => {
                    attempts.push(Self::connect_single(iter.next().unwrap(), port, proxy.as_deref()));
                    sleep.as_mut().reset(Instant::now() + delay);
                },
                else => break,
            }
        }

        Err(anyhow!(
            "all connection attempts failed (via proxy: {:?})",
            proxy
        ))
    }

    async fn connect_single(ip: IpAddr, port: u16, proxy: Option<&str>) -> Result<TcpStream> {
        let addr = SocketAddr::new(ip, port);
        let t = Duration::from_secs(10);
        let stream = match proxy {
            Some(url) => {
                let proxy_addr = url
                    .strip_prefix("socks5://")
                    .or_else(|| url.strip_prefix("socks5h://"))
                    .unwrap_or(url);
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

pub async fn init_dns(
    config: &mut DnsConfig,
    warp: Option<&Arc<WarpClient>>,
) -> Result<Arc<DnsClient>> {
    if config.options.protocol == Protocol::Dot && config.tls_domain.is_none() {
        config.tls_domain = Some(config.upstream.ip().to_string());
    }
    if config.options.min_ttl > config.options.max_ttl {
        return Err(anyhow!(
            "dns.options.min_ttl ({}) must not exceed max_ttl ({})",
            config.options.min_ttl,
            config.options.max_ttl
        ));
    }
    let transport = transport::build_transport(config, warp)?;
    Ok(Arc::new(DnsClient::with_transport(config, transport)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::DnsOptions;
    use std::net::Ipv4Addr;

    fn make_response(id: u16, tc: bool, rcode: Rcode, ttl: u32, a_ips: &[Ipv4Addr]) -> Vec<u8> {
        make_response_for(id, tc, rcode, ttl, a_ips, "example.com", Rtype::A)
    }

    fn make_response_for(
        id: u16,
        tc: bool,
        rcode: Rcode,
        ttl: u32,
        a_ips: &[Ipv4Addr],
        qname: &str,
        qtype: Rtype,
    ) -> Vec<u8> {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(id);
        builder.header_mut().set_rcode(rcode);
        if tc {
            builder.header_mut().set_tc(true);
        }
        let mut question = builder.question();
        question
            .push(Question::new(
                Name::<Vec<u8>>::from_str(qname).unwrap(),
                qtype,
                Class::IN,
            ))
            .unwrap();
        let mut answer = question.answer();
        for ip in a_ips {
            let rec = Record::new(
                Name::<Vec<u8>>::from_str(qname).unwrap(),
                Class::IN,
                Ttl::from_secs(ttl),
                A::new(*ip),
            );
            answer.push(rec).unwrap();
        }
        answer.into_message().into_octets()
    }

    async fn test_client() -> DnsClient {
        let cfg = DnsConfig {
            upstream: "127.0.0.1:1".parse().unwrap(),
            tls_domain: None,
            options: DnsOptions::default(),
        };
        DnsClient::new(&cfg).await.unwrap()
    }

    async fn capturing_upstream() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((len, peer)) = upstream.recv_from(&mut buf).await else {
                    return;
                };
                *recorder.lock().unwrap() = buf[..len].to_vec();
                buf[2] |= 0x80;
                let _ = upstream.send_to(&buf[..len], peer).await;
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn hijacked_queries_carry_the_configured_client_subnet() {
        let (upstream, seen) = capturing_upstream().await;
        let config = DnsConfig {
            upstream,
            tls_domain: None,
            options: DnsOptions {
                client_subnet: Some("1.2.3.4".parse().unwrap()),
                ..DnsOptions::default()
            },
        };
        let client = DnsClient::new(&config).await.unwrap();
        let query = client
            .build_query("ecs.test", Rtype::A, None, 0x1111)
            .unwrap();
        client.query(&query).await.unwrap();

        let received = seen.lock().unwrap().clone();
        assert!(
            received.ends_with(&[0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3]),
            "{received:02x?}"
        );
    }

    #[tokio::test]
    async fn failed_address_does_not_delay_the_next_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = test_client().await;
        client.config.options.happy_eyeballs_delay_ms = 60_000;
        let stream = timeout(
            Duration::from_secs(10),
            client.happy_eyeballs_connect(
                vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
                listener.local_addr().unwrap().port(),
                None,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn parse_response_accepts_valid_a_record() {
        let c = test_client().await;
        let bytes = make_response(1, false, Rcode::NOERROR, 120, &[Ipv4Addr::new(1, 2, 3, 4)]);
        let (ips, ttl) = c
            .parse_response(&bytes, 1, Rtype::A, "example.com")
            .unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(ttl.as_secs(), 120);
    }

    #[tokio::test]
    async fn parse_response_rejects_truncated() {
        let c = test_client().await;
        let bytes = make_response(2, true, Rcode::NOERROR, 120, &[]);
        assert!(
            c.parse_response(&bytes, 2, Rtype::A, "example.com")
                .is_err()
        );
    }

    #[tokio::test]
    async fn parse_response_rejects_id_mismatch() {
        let c = test_client().await;
        let bytes = make_response(3, false, Rcode::NOERROR, 120, &[]);
        assert!(
            c.parse_response(&bytes, 99, Rtype::A, "example.com")
                .is_err()
        );
    }

    #[tokio::test]
    async fn parse_response_nxdomain_returns_empty_with_empty_ttl() {
        let c = test_client().await;
        let bytes = make_response(4, false, Rcode::NXDOMAIN, 120, &[]);
        let (ips, ttl) = c
            .parse_response(&bytes, 4, Rtype::A, "example.com")
            .unwrap();
        assert!(ips.is_empty());
        assert_eq!(ttl.as_secs(), c.config.options.empty_ttl);
    }

    #[tokio::test]
    async fn parse_response_rejects_error_rcode() {
        let c = test_client().await;
        let bytes = make_response(5, false, Rcode::SERVFAIL, 120, &[]);
        assert!(
            c.parse_response(&bytes, 5, Rtype::A, "example.com")
                .is_err()
        );
    }

    #[tokio::test]
    async fn parse_response_clamps_ttl() {
        let c = test_client().await;
        let bytes = make_response(6, false, Rcode::NOERROR, 10, &[Ipv4Addr::new(9, 9, 9, 9)]);
        let (_, ttl) = c
            .parse_response(&bytes, 6, Rtype::A, "example.com")
            .unwrap();
        assert_eq!(ttl.as_secs(), c.config.options.min_ttl);
        let bytes = make_response(
            7,
            false,
            Rcode::NOERROR,
            999_999,
            &[Ipv4Addr::new(9, 9, 9, 9)],
        );
        let (_, ttl) = c
            .parse_response(&bytes, 7, Rtype::A, "example.com")
            .unwrap();
        assert_eq!(ttl.as_secs(), c.config.options.max_ttl);
    }

    #[tokio::test]
    async fn parse_response_rejects_question_name_mismatch() {
        let c = test_client().await;
        let bytes = make_response_for(
            9,
            false,
            Rcode::NOERROR,
            120,
            &[Ipv4Addr::new(1, 2, 3, 4)],
            "evil.com",
            Rtype::A,
        );
        assert!(
            c.parse_response(&bytes, 9, Rtype::A, "example.com")
                .is_err()
        );
    }

    #[tokio::test]
    async fn init_dns_rejects_inverted_ttl_bounds() {
        let mut cfg = DnsConfig {
            upstream: "127.0.0.1:1".parse().unwrap(),
            tls_domain: None,
            options: DnsOptions {
                min_ttl: 5000,
                max_ttl: 100,
                ..DnsOptions::default()
            },
        };
        assert!(init_dns(&mut cfg, None).await.is_err());
    }

    #[tokio::test]
    async fn parse_response_extracts_aaaa_records() {
        let c = test_client().await;
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(10);
        builder.header_mut().set_rcode(Rcode::NOERROR);
        let mut question = builder.question();
        question
            .push(Question::new(
                Name::<Vec<u8>>::from_str("example.com").unwrap(),
                Rtype::AAAA,
                Class::IN,
            ))
            .unwrap();
        let mut answer = question.answer();
        let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let rec = Record::new(
            Name::<Vec<u8>>::from_str("example.com").unwrap(),
            Class::IN,
            Ttl::from_secs(300),
            domain::rdata::Aaaa::new(v6),
        );
        answer.push(rec).unwrap();
        let bytes = answer.into_message().into_octets();
        let (ips, ttl) = c
            .parse_response(&bytes, 10, Rtype::AAAA, "example.com")
            .unwrap();
        assert_eq!(ips, vec![IpAddr::V6(v6)]);
        assert_eq!(ttl.as_secs(), 300);
    }

    #[tokio::test]
    async fn interleave_exhausts_one_side() {
        let c = test_client().await;
        let v4 = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        ];
        let v6 = vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)];
        let r = c.interleave_ips(v4.clone(), v6);
        assert_eq!(
            r,
            vec![
                v4[0],
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                v4[1],
                v4[2]
            ],
            "剩余地址必须按原顺序追加，不能只保留长度"
        );
    }
}

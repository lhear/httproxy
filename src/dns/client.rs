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
            Protocol::Udp => Transport::Udp(UdpTransport::new(config.upstream)),
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
    if config.options.min_ttl > config.options.max_ttl {
        return Err(anyhow!(
            "dns.options.min_ttl ({}) must not exceed max_ttl ({})",
            config.options.min_ttl,
            config.options.max_ttl
        ));
    }
    Ok(Arc::new(DnsClient::new(config).await?))
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
    async fn parse_response_safe_when_ttl_bounds_inverted() {
        let cfg = DnsConfig {
            upstream: "127.0.0.1:1".parse().unwrap(),
            tls_domain: None,
            options: DnsOptions {
                min_ttl: 5000,
                max_ttl: 100,
                ..DnsOptions::default()
            },
        };
        let c = DnsClient::new(&cfg).await.unwrap();
        let bytes = make_response(8, false, Rcode::NOERROR, 60, &[Ipv4Addr::new(9, 9, 9, 9)]);
        let (_, ttl) = c
            .parse_response(&bytes, 8, Rtype::A, "example.com")
            .unwrap();
        assert_eq!(
            ttl.as_secs(),
            100,
            "inverted bounds must not panic and clamp to max"
        );
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
    async fn parse_response_rejects_question_type_mismatch() {
        let c = test_client().await;
        let bytes = make_response_for(
            10,
            false,
            Rcode::NOERROR,
            120,
            &[Ipv4Addr::new(1, 2, 3, 4)],
            "example.com",
            Rtype::AAAA,
        );
        assert!(
            c.parse_response(&bytes, 10, Rtype::A, "example.com")
                .is_err()
        );
    }

    #[tokio::test]
    async fn parse_response_rejects_missing_question() {
        let c = test_client().await;
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(11);
        builder.header_mut().set_rcode(Rcode::NOERROR);
        let mut answer = builder.answer();
        answer
            .push(Record::new(
                Name::<Vec<u8>>::from_str("example.com").unwrap(),
                Class::IN,
                Ttl::from_secs(120),
                A::new(Ipv4Addr::new(1, 2, 3, 4)),
            ))
            .unwrap();
        let bytes = answer.into_message().into_octets();
        assert!(
            c.parse_response(&bytes, 11, Rtype::A, "example.com")
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
        assert!(init_dns(&mut cfg).await.is_err());
    }

    #[tokio::test]
    async fn build_query_writes_id_and_domain() {
        let c = test_client().await;
        let q = c
            .build_query("example.com", Rtype::A, None, 0x1234)
            .unwrap();
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);
        assert!(q.windows(7).any(|w| w == b"example"));
        assert_eq!(q[2] & 0x01, 0x01, "RD flag must be set");
    }

    #[tokio::test]
    async fn build_query_with_ecs_includes_opt_record() {
        let c = test_client().await;
        let plain = c.build_query("example.com", Rtype::A, None, 1).unwrap();
        let with_ecs = c
            .build_query(
                "example.com",
                Rtype::A,
                Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                1,
            )
            .unwrap();
        assert!(with_ecs.len() > plain.len());
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
    async fn interleave_prefers_ipv4_by_default() {
        let c = test_client().await;
        let v4 = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ];
        let v6 = vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)];
        let r = c.interleave_ips(v4.clone(), v6.clone());
        assert_eq!(r, vec![v4[0], v6[0], v4[1]]);
    }

    #[tokio::test]
    async fn interleave_prefers_ipv6_when_configured() {
        let cfg = DnsConfig {
            upstream: "127.0.0.1:1".parse().unwrap(),
            tls_domain: None,
            options: DnsOptions {
                prefer_ipv6: true,
                ..DnsOptions::default()
            },
        };
        let c = DnsClient::new(&cfg).await.unwrap();
        let v4 = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let v6 = vec![
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ];
        let r = c.interleave_ips(v4, v6.clone());
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], v6[0]);
    }

    #[tokio::test]
    async fn interleave_exhausts_one_side() {
        let c = test_client().await;
        let v4 = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let v6 = vec![
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ];
        let r = c.interleave_ips(v4, v6);
        assert_eq!(r.len(), 3);
    }
}

mod common;

use common::*;
use httproxy::dns::{DnsConfig, DnsOptions};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

fn extract_question(query: &[u8], mut offset: usize) -> Option<(String, u16)> {
    let mut labels = Vec::new();
    loop {
        let len = *query.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        let label = std::str::from_utf8(query.get(offset..offset + len)?).ok()?;
        labels.push(label.to_string());
        offset += len;
    }
    let qtype = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    Some((labels.join("."), qtype))
}

async fn spawn_mock_dns(
    records: HashMap<String, IpAddr>,
    query_count: Arc<AtomicUsize>,
) -> std::net::SocketAddr {
    use domain::base::iana::{Class, Rcode, Rtype};
    use domain::base::{MessageBuilder, Name, Question, Record, Ttl};
    use domain::rdata::{A, Aaaa};
    use std::str::FromStr;

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let query = &buf[..n];
            if query.len() < 12 {
                continue;
            }
            query_count.fetch_add(1, Ordering::Relaxed);
            let id = u16::from_be_bytes([query[0], query[1]]);
            let (domain, qtype_int) = extract_question(query, 12).unwrap_or_default();
            let qtype = Rtype::from_int(qtype_int);
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(id);
            if records.contains_key(&domain) {
                builder.header_mut().set_rcode(Rcode::NOERROR);
            } else {
                builder.header_mut().set_rcode(Rcode::NXDOMAIN);
            }
            let name = Name::<Vec<u8>>::from_str(&domain).unwrap_or_else(|_| Name::root());
            let mut question = builder.question();
            let _ = question.push(Question::new(name.clone(), qtype, Class::IN));
            let mut answer = question.answer();
            if let Some(ip) = records.get(&domain) {
                let _ = match ip {
                    IpAddr::V4(v4) => answer.push(Record::new(
                        name.clone(),
                        Class::IN,
                        Ttl::from_secs(60),
                        A::new(*v4),
                    )),
                    IpAddr::V6(v6) => answer.push(Record::new(
                        name.clone(),
                        Class::IN,
                        Ttl::from_secs(60),
                        Aaaa::new(*v6),
                    )),
                };
            }
            let resp = answer.into_message().into_octets();
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    addr
}

fn server_with_dns(mock_dns: std::net::SocketAddr) -> httproxy::config::ServerTopConfig {
    let mut cfg = server_config(traffic(true, None), None, None);
    cfg.dns = Some(DnsConfig {
        upstream: mock_dns,
        tls_domain: None,
        options: DnsOptions::default(),
    });
    cfg
}

#[tokio::test]
async fn server_resolves_domain_via_dns_module() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let query_count = Arc::new(AtomicUsize::new(0));
    let mut records = HashMap::new();
    records.insert("dns-test.invalid".to_string(), upstream.ip());
    let mock_dns = spawn_mock_dns(records, query_count.clone()).await;
    let dc = std::sync::Arc::new(
        httproxy::dns::DnsClient::new(&DnsConfig {
            upstream: mock_dns,
            tls_domain: None,
            options: DnsOptions::default(),
        })
        .await
        .unwrap(),
    );
    let ips = dc
        .lookup("dns-test.invalid", domain::base::iana::Rtype::A, None)
        .await;
    assert!(!ips.unwrap().is_empty(), "direct lookup must resolve");
    let server = spawn_server(server_with_dns(mock_dns)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let url = format!("http://dns-test.invalid:{}/hello", upstream.port());
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
    assert!(
        query_count.load(Ordering::Relaxed) >= 1,
        "dns module must have queried the mock server"
    );
}

#[tokio::test]
async fn dns_results_are_cached() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let query_count = Arc::new(AtomicUsize::new(0));
    let mut records = HashMap::new();
    records.insert("cached.invalid".to_string(), upstream.ip());
    let mock_dns = spawn_mock_dns(records, query_count.clone()).await;
    let server = spawn_server(server_with_dns(mock_dns)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let url = format!("http://cached.invalid:{}/hello", upstream.port());
    let request = format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    for _ in 0..3 {
        let (status, body) = raw_exchange(client, request.as_bytes()).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello upstream");
    }
    let queries = query_count.load(Ordering::Relaxed);
    assert!(
        queries <= 2,
        "cache should serve repeat lookups, got {queries} queries"
    );
}

#[tokio::test]
async fn nxdomain_fails_connection() {
    common::init_logging();
    let mock_dns = spawn_mock_dns(HashMap::new(), Arc::new(AtomicUsize::new(0))).await;
    let server = spawn_server(server_with_dns(mock_dns)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let url = format!("http://missing.invalid:{}/hello", 12345);
    let mut stream = tokio::net::TcpStream::connect(client).await.unwrap();
    stream
        .write_all(format!("GET {url} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "nxdomain should close the proxy connection");
}

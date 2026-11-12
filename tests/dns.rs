mod common;

use common::*;
use httproxy::dns::{DnsConfig, DnsOptions};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_with_dns(
    mock_dns: std::net::SocketAddr,
    keys: &TestKeys,
) -> httproxy::config::ServerTopConfig {
    let mut cfg = server_config(traffic(true, None), keys, None);
    cfg.dns = Some(DnsConfig {
        upstream: mock_dns,
        tls_domain: None,
        options: DnsOptions::default(),
    });
    cfg
}

#[tokio::test]
async fn server_resolves_domain_via_dns_module() {
    let keys = test_keys();
    common::init_logging();
    let upstream = spawn_upstream().await;
    let query_count = Arc::new(AtomicUsize::new(0));
    let mut records = HashMap::new();
    records.insert("dns-test.invalid".to_string(), upstream.ip());
    let mock_dns = spawn_dns_udp(records, query_count.clone()).await;
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
    let server = spawn_server(server_with_dns(mock_dns, &keys)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
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
    let keys = test_keys();
    common::init_logging();
    let upstream = spawn_upstream().await;
    let query_count = Arc::new(AtomicUsize::new(0));
    let mut records = HashMap::new();
    records.insert("cached.invalid".to_string(), upstream.ip());
    let mock_dns = spawn_dns_udp(records, query_count.clone()).await;
    let server = spawn_server(server_with_dns(mock_dns, &keys)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
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
    let keys = test_keys();
    common::init_logging();
    let mock_dns = spawn_dns_udp(HashMap::new(), Arc::new(AtomicUsize::new(0))).await;
    let server = spawn_server(server_with_dns(mock_dns, &keys)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
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

mod common;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn write_bypass_file(rules: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("httproxy_bypass_{}_{}.json", std::process::id(), n));
    std::fs::write(&path, rules).unwrap();
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn bypass_direct_connect_skips_tunnel() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let bypass_file = write_bypass_file(r#"{"domain_suffix": [], "ip_cidr": ["127.0.0.1/32"]}"#);
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![bypass_file]),
        server,
    )
    .await;

    let url = format!("http://{upstream}/hello");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
}

#[tokio::test]
async fn bypass_large_body_direct() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let bypass_file = write_bypass_file(r#"{"domain_suffix": [], "ip_cidr": ["127.0.0.1/32"]}"#);
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![bypass_file]),
        server,
    )
    .await;

    let url = format!("http://{upstream}/large");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn bypass_connect_direct() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let bypass_file = write_bypass_file(r#"{"domain_suffix": [], "ip_cidr": ["127.0.0.1/32"]}"#);
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![bypass_file]),
        server,
    )
    .await;

    let mut stream = proxy_connect(client, upstream).await;
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("hello upstream"));
}

#[tokio::test]
async fn non_matching_domain_still_tunneled() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let bypass_file = write_bypass_file(r#"{"domain_suffix": [], "ip_cidr": ["10.0.0.0/8"]}"#);
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![bypass_file]),
        server,
    )
    .await;

    let url = format!("http://{upstream}/hello");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
}

#[tokio::test]
async fn bypass_unreachable_target_fails_fast() {
    common::init_logging();
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let bypass_file = write_bypass_file(r#"{"domain_suffix": [], "ip_cidr": ["127.0.0.1/32"]}"#);
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![bypass_file]),
        server,
    )
    .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = listener.local_addr().unwrap();
    drop(listener);

    let url = format!("http://{dead_addr}/");
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream
        .write_all(format!("GET {url} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "bypass connection failure should close the proxy connection"
    );
}

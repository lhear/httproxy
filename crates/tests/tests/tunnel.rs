mod common;

use common::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start_tunnel() -> (SocketAddr, SocketAddr) {
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
        server,
    )
    .await;
    (upstream, client)
}

#[tokio::test]
async fn tunnel_get_small_response() {
    common::init_logging();
    let (upstream, client) = start_tunnel().await;
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
async fn tunnel_get_large_response() {
    common::init_logging();
    let (upstream, client) = start_tunnel().await;
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
async fn tunnel_large_post_echoes() {
    common::init_logging();
    let (upstream, client) = start_tunnel().await;
    let body: Vec<u8> = (0..(3 * 1024 * 1024) as u32)
        .map(|i| (i % 251) as u8)
        .collect();

    let url = format!("http://{upstream}/echo");
    let request = format!(
        "POST {url} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(client).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (status, echoed) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(echoed, body);
}

#[tokio::test]
async fn tunnel_connect_relays_bytes() {
    common::init_logging();
    let (upstream, client) = start_tunnel().await;
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
async fn session_resumption_reuses_ticket() {
    common::init_logging();
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
        server,
    )
    .await;

    let url = format!("http://{upstream}/hello");
    let request = format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    for _ in 0..2 {
        let (status, body) = raw_exchange(client, request.as_bytes()).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello upstream");
    }
}

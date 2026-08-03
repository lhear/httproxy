mod common;

use base64::Engine;
use common::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start_plain() -> (SocketAddr, SocketAddr) {
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;
    (upstream, client)
}

#[tokio::test]
async fn get_small_response_through_tunnel() {
    let (upstream, client) = start_plain().await;
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
async fn get_large_response_through_tunnel() {
    let (upstream, client) = start_plain().await;
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
async fn connect_tunnel_relays_bytes() {
    let (upstream, client) = start_plain().await;
    let mut stream = proxy_connect(client, upstream).await;
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf);
    assert!(head.contains("200 OK") || head.starts_with("HTTP/1.1 200"));
    assert!(buf.ends_with(b"hello upstream"));
}

#[tokio::test]
async fn large_post_echoes_through_tunnel() {
    let (upstream, client) = start_plain().await;
    let body: Vec<u8> = (0..(3 * 1024 * 1024) as u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let url = format!("http://{upstream}/echo");
    let request = format!(
        "POST {url} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (status, echoed) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(echoed, body);
}

#[tokio::test]
async fn bad_token_rejected() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let client = spawn_client(
        client_config(
            traffic(true, None),
            None,
            Some("bad-token".to_string()),
            vec![],
        ),
        server,
    )
    .await;
    let url = format!("http://{upstream}/hello");
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream
        .write_all(format!("GET {url} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "rejected connection should close without a response");
}

#[tokio::test]
async fn expired_token_rejected() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, Some(make_token("u", 1)), vec![]),
        server,
    )
    .await;
    let url = format!("http://{upstream}/hello");
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream
        .write_all(format!("GET {url} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "rejected connection should close without a response");
}

#[tokio::test]
async fn unreachable_upstream_yields_connection_error() {
    common::init_logging();
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
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
    assert_eq!(n, 0, "connection should close without a proxy response");
}

#[tokio::test]
async fn concurrent_tunnels_work_independently() {
    let (upstream, client) = start_plain().await;
    let url = format!("http://{upstream}/hello");
    let request = format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let request = request.clone();
        handles.push(tokio::spawn(async move {
            raw_exchange(client, request.as_bytes()).await
        }));
    }
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello upstream");
    }
}

#[tokio::test]
async fn tunnel_admission_limit_rejects_excess() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, Some(1))).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let big_url = format!("http://{upstream}/big");
    let small_url = format!("http://{upstream}/hello");
    let big_req = format!("GET {big_url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    let small_req = format!("GET {small_url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");

    let big = tokio::spawn(async move { raw_exchange(client, big_req.as_bytes()).await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream.write_all(small_req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "excess tunnel should be rejected (503 -> connection closed)"
    );

    let (status, body) = big.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body.len(), 32 * 1024 * 1024);
}

#[tokio::test]
async fn local_proxy_auth_challenges_and_accepts() {
    common::init_logging();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;
    let mut cfg = client_config(traffic(true, None), None, None, vec![]);
    cfg.client.auth = Some(httproxy::config::ClientProxyAuth {
        username: "proxyuser".to_string(),
        password: "proxypass".to_string(),
    });
    let client = spawn_client(cfg, server).await;

    let url = format!("http://{upstream}/hello");

    let mut stream = TcpStream::connect(client).await.unwrap();
    stream
        .write_all(
            format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let (status, _) = read_response(&mut stream).await;
    assert_eq!(status, 407);

    let mut stream = TcpStream::connect(client).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {url} HTTP/1.1\r\nHost: test\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
                base64::engine::general_purpose::STANDARD
                    .encode(b"proxyuser:proxypass")
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (status, body) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
}

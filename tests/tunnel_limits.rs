mod common;

use base64::Engine;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn bad_token_rejected() {
    common::init_logging();
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let client = spawn_client(
        client_config(
            traffic(true, None),
            &keys,
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
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, Some(make_token("u", 1)), vec![]),
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
    let keys = test_keys();
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
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
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, Some(1))).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
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
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), &keys, None)).await;
    let mut cfg = client_config(traffic(true, None), &keys, None, vec![]);
    cfg.client.proxy_auth = Some(httproxy::config::ClientProxyAuth {
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

//! `[[redirect]]` 本地端口转发的端到端测试：这里的目标是一个原始 TCP 回显服务，
//! 不是 HTTP —— 正好验证转发路径完全不依赖协议解析。

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 原始 TCP 回显服务（收到什么原样回什么）。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 起 server + client，并在 client 上加一条指向 echo 的 redirect。
///
/// `keys` 为 `(服务端私钥, 客户端公钥)`：两边必须用同一对密钥。
async fn spawn_redirect(
    traffic: httproxy::shaper::TrafficConfig,
    keys: Option<(String, String)>,
) -> SocketAddr {
    let echo = spawn_tcp_echo().await;
    let (server_key, client_key) = match keys {
        Some((sk, pk)) => (Some(sk), Some(pk)),
        None => (None, None),
    };
    let server =
        common::spawn_server(common::server_config(traffic.clone(), server_key, None)).await;

    let mut cfg = common::client_config(traffic, client_key, None, vec![]);
    cfg.redirect = vec![httproxy::config::RedirectSection {
        listen: "127.0.0.1:0".to_string(),
        target: echo.to_string(),
    }];

    let (_proxy, redirects) = common::spawn_client_with_redirects(cfg, server).await;
    assert_eq!(redirects.len(), 1, "one redirect listener expected");
    redirects[0]
}

#[tokio::test]
async fn redirect_forwards_raw_tcp() {
    common::init_logging();
    let redirect = spawn_redirect(common::traffic(true, None), None).await;

    let mut stream = TcpStream::connect(redirect).await.unwrap();
    stream.write_all(b"hello redirect\n").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello redirect\n");
}

#[tokio::test]
async fn redirect_handles_many_roundtrips() {
    common::init_logging();
    let redirect = spawn_redirect(common::traffic(true, None), None).await;
    let mut stream = TcpStream::connect(redirect).await.unwrap();

    // 同一条连接上来回多次，确认隧道不是一次性的
    for i in 0..8u8 {
        let payload = [i; 32];
        stream.write_all(&payload).await.unwrap();
        let mut buf = [0u8; 32];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(buf, payload);
    }
}

#[tokio::test]
async fn redirect_forwards_large_bidirectional_stream() {
    common::init_logging();
    let redirect = spawn_redirect(common::traffic(true, None), None).await;
    let stream = TcpStream::connect(redirect).await.unwrap();

    // 256 KiB 上行 + 256 KiB 下行，覆盖多次封帧/轮转
    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (mut read_half, mut write_half) = stream.into_split();

    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.unwrap();
        write_half.shutdown().await.unwrap();
    });

    let mut got = Vec::with_capacity(expected.len());
    let mut buf = [0u8; 16 * 1024];
    while got.len() < expected.len() {
        let n = tokio::time::timeout(Duration::from_secs(10), read_half.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    writer.await.unwrap();

    assert_eq!(got.len(), expected.len());
    assert_eq!(got, expected);
}

#[tokio::test]
async fn redirect_works_over_encrypted_tunnel() {
    common::init_logging();
    let (sk, pk) = httproxy::crypto::generate_keypair();
    let redirect = spawn_redirect(
        common::traffic(true, Some(2 * 1024 * 1024)),
        Some((
            httproxy::crypto::private_key_to_b64(&sk),
            httproxy::crypto::public_key_to_b64(&pk),
        )),
    )
    .await;

    let mut stream = TcpStream::connect(redirect).await.unwrap();
    let payload: Vec<u8> = (0..128 * 1024u32).map(|i| (i % 241) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut got = Vec::with_capacity(payload.len());
    let mut buf = [0u8; 16 * 1024];
    while got.len() < payload.len() {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload);
}

//! 虚拟内网（`[client] virtual_ip` + `virtual_ports`）的端到端测试。
//!
//! 拓扑：`虚拟内网节点` 与 `普通客户端` 共用同一个服务端；前者把本机
//! `upstream` 的端口挂在自己的虚拟 IP 上，后者用普通代理的方式访问这个
//! 虚拟地址，请求应该经服务端中继给前者、再由它连本机的最终服务。

mod common;

use common::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 故意选一个本机没有监听的地址：节点要先连它失败、再回退到 127.0.0.1。
const VIRTUAL_IP: &str = "127.0.0.9";

struct Env {
    upstream: SocketAddr,
    /// 声明虚拟 IP 的那个客户端（自身也是个代理，但这里只用它的虚拟内网能力）
    _tunnel: SocketAddr,
    /// 访问方：普通客户端
    proxy: SocketAddr,
}

async fn start() -> Env {
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;

    let mut tunnel_cfg = client_config(traffic(true, None), None, None, vec![]);
    with_vnet(&mut tunnel_cfg, VIRTUAL_IP, &[upstream.port()]);
    let tunnel = spawn_client(tunnel_cfg, server).await;

    let proxy = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    Env {
        upstream,
        _tunnel: tunnel,
        proxy,
    }
}

/// 走一次代理请求，失败（连接被关闭 / 早退）时返回 `None`。
async fn fetch(proxy: SocketAddr, request: &str) -> Option<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(proxy).await.ok()?;
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut buf))
        .await
        .ok()?
        .ok()?;
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let status: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, buf[head_end + 4..].to_vec()))
}

/// 注册是异步的：请求发早会连不到，这里轮询到成功为止。
async fn fetch_until_ok(proxy: SocketAddr, request: &str) -> (u16, Vec<u8>) {
    for _ in 0..100 {
        if let Some((status, body)) = fetch(proxy, request).await
            && status == 200
        {
            return (status, body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("virtual network target never became reachable: {request}");
}

#[tokio::test]
async fn vnet_get_reaches_local_service() {
    init_logging();
    let env = start().await;
    let url = format!("http://{VIRTUAL_IP}:{}/hello", env.upstream.port());
    let (status, body) = fetch_until_ok(
        env.proxy,
        &format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
}

#[tokio::test]
async fn vnet_large_response_is_intact() {
    let env = start().await;
    let url = format!("http://{VIRTUAL_IP}:{}/large", env.upstream.port());
    let (status, body) = fetch_until_ok(
        env.proxy,
        &format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn vnet_post_echoes_uploaded_bytes() {
    let env = start().await;
    let url = format!("http://{VIRTUAL_IP}:{}/echo", env.upstream.port());
    let payload: Vec<u8> = (0..(256 * 1024) as u32).map(|i| (i % 251) as u8).collect();
    let request = format!(
        "POST {url} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );

    // 先等节点上线，避免大 body 在失败重试里被反复发送
    fetch_until_ok(
        env.proxy,
        &format!(
            "GET http://{VIRTUAL_IP}:{}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            env.upstream.port()
        ),
    )
    .await;

    let mut stream = TcpStream::connect(env.proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
    assert_eq!(&buf[head_end + 4..], &payload[..], "echoed body must match");
}

#[tokio::test]
async fn vnet_connect_relays_raw_bytes() {
    let env = start().await;
    let url = format!("http://{VIRTUAL_IP}:{}/hello", env.upstream.port());
    fetch_until_ok(
        env.proxy,
        &format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await;

    let target: SocketAddr = format!("{VIRTUAL_IP}:{}", env.upstream.port())
        .parse()
        .unwrap();
    let mut stream = proxy_connect(env.proxy, target).await;
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(
        buf.starts_with(b"HTTP/1.1 200"),
        "got: {}",
        String::from_utf8_lossy(&buf[..buf.len().min(64)])
    );
    assert!(buf.ends_with(b"hello upstream"));
}

#[tokio::test]
async fn unexposed_port_on_virtual_ip_is_rejected() {
    init_logging();
    let env = start().await;
    let ready = format!(
        "GET http://{VIRTUAL_IP}:{}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        env.upstream.port()
    );
    fetch_until_ok(env.proxy, &ready).await;

    // 同一个虚拟地址上没声明的端口必须被服务端挡掉
    let blocked_port = env.upstream.port().wrapping_add(1).max(1);
    let request = format!(
        "GET http://{VIRTUAL_IP}:{blocked_port}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    );
    for _ in 0..5 {
        if let Some((status, _)) = fetch(env.proxy, &request).await {
            panic!("exposed port check failed: got status {status}");
        }
    }
}

#[tokio::test]
async fn normal_targets_still_work_while_vnet_is_active() {
    let env = start().await;
    // 另一个服务，不在这个节点的端口列表里：应该照旧直连
    let direct = spawn_upstream().await;
    let ready = format!(
        "GET http://{VIRTUAL_IP}:{}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        env.upstream.port()
    );
    fetch_until_ok(env.proxy, &ready).await;

    let (status, body) = fetch(
        env.proxy,
        &format!("GET http://{direct}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await
    .expect("direct target must still be reachable");
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
}

/// 配置了 `public_key` 时虚拟内网帧也走端到端加密（密钥由会话主密钥派生）。
#[tokio::test]
async fn encrypted_vnet_relays_traffic() {
    let upstream = spawn_upstream().await;
    let (sk, pk) = httproxy::crypto::generate_keypair();
    let server = spawn_server(server_config(
        traffic(true, None),
        Some(httproxy::crypto::private_key_to_b64(&sk)),
        None,
    ))
    .await;

    let mut tunnel_cfg = client_config(
        traffic(true, None),
        Some(httproxy::crypto::public_key_to_b64(&pk)),
        None,
        vec![],
    );
    with_vnet(&mut tunnel_cfg, VIRTUAL_IP, &[upstream.port()]);
    let _tunnel = spawn_client(tunnel_cfg, server).await;

    // 访问方仍然走普通（明文）隧道，只有虚拟内网那一跳是加密的
    let proxy = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let url = format!("http://{VIRTUAL_IP}:{}/hello", upstream.port());
    let (status, body) = fetch_until_ok(
        proxy,
        &format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");

    let url = format!("http://{VIRTUAL_IP}:{}/large", upstream.port());
    let (status, body) = fetch_until_ok(
        proxy,
        &format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

/// 端口被声明了、但本机没人监听：请求必须快速失败，不能挂在一条不会再有
/// 数据的连接上（`OPEN` 是单向的，服务端不等回执就放行数据，所以这条路径
/// 靠节点的 `OPEN_FAIL` 收尾）。
#[tokio::test]
async fn dead_local_port_fails_fast() {
    init_logging();
    let server = spawn_server(server_config(traffic(true, None), None, None)).await;

    let upstream = spawn_upstream().await;
    // 占一个空闲端口再立刻放掉：节点会把它声明出去，但那里没人监听
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = probe.local_addr().unwrap().port();
    drop(probe);

    let mut tunnel_cfg = client_config(traffic(true, None), None, None, vec![]);
    with_vnet(&mut tunnel_cfg, VIRTUAL_IP, &[upstream.port(), dead_port]);
    let _tunnel = spawn_client(tunnel_cfg, server).await;
    let proxy = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    // 先用活着的端口确认节点已经上线，否则下面测到的是「地址还没注册」
    fetch_until_ok(
        proxy,
        &format!(
            "GET http://{VIRTUAL_IP}:{}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            upstream.port()
        ),
    )
    .await;

    let request = format!(
        "GET http://{VIRTUAL_IP}:{dead_port}/ HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    );
    // 断言的是「不会挂住」：节点先拨回环、再拨虚拟地址，两次都被拒，
    // 于是回 OPEN_FAIL、服务端撤掉连接、访问方立刻读到 EOF。两次被拒的
    // connect 在部分平台上要 ~2s（本机实测 2060ms），所以给两倍余量。
    let outcome = tokio::time::timeout(Duration::from_secs(6), fetch(proxy, &request))
        .await
        .expect("dead port must not hang the request");
    match outcome {
        None => {}
        Some((status, body)) => {
            assert_eq!(status, 200, "dead port must not turn into a 5xx payload");
            assert!(body.is_empty(), "dead port must not emit a body");
        }
    }
}

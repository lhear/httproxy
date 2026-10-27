use bytes::{Buf, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::client::constants::{
    AUTH_REJECT_DRAIN_WINDOW, CONNECT_RESPONSE, EARLY_READ_CHUNK, EARLY_READ_WINDOW,
    PROXY_AUTH_REQUIRED_RESPONSE, PROXY_BUF_INITIAL_CAPACITY, PROXY_REQUEST_PARSE_TIMEOUT,
};
use crate::client::proxy;
use crate::client::state::SharedState;

pub struct ClientConnectionActor {
    socket: Option<TcpStream>,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
}

impl ClientConnectionActor {
    pub fn new(socket: TcpStream, http_client: Arc<wreq::Client>, state: Arc<SharedState>) -> Self {
        socket.set_nodelay(true).ok();
        Self {
            socket: Some(socket),
            http_client,
            state,
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let socket = self
            .socket
            .take()
            .expect("connection actor can only run once");
        let http_client = Arc::clone(&self.http_client);
        let state = Arc::clone(&self.state);
        let (mut read_half, mut write_half) = socket.into_split();
        // 浏览器 CONNECT 头通常只有几百字节，先给小缓冲，按需增长
        let mut buf = BytesMut::with_capacity(PROXY_BUF_INITIAL_CAPACITY);

        let Some((method, header_len, url)) =
            read_request_head(&mut read_half, &mut write_half, &mut buf, &state).await?
        else {
            // 已回过 407 并关闭连接，等客户端带认证头重连
            return Ok(());
        };

        if method == "CONNECT" {
            buf.advance(header_len);
            write_half.write_all(CONNECT_RESPONSE).await?;
            read_early_data(&mut read_half, &mut buf).await;
        }

        // 只解析一次请求目标：同时得到上游地址和需要写回请求行的 origin-form
        let (target_host, origin_form) = proxy::resolve_request(&method, &url)?;
        tracing::Span::current().record("target", target_host.as_str());

        if let Some(origin_path) = origin_form {
            proxy::rewrite_request_line(&mut buf, header_len, &method, &origin_path)?;
        }

        let payload = buf.split().freeze();
        crate::client::connection::open_tunnel(
            read_half,
            write_half,
            http_client,
            state,
            payload,
            &target_host,
        )
        .await
    }
}

/// 读取并校验代理请求头。
///
/// 入站代理连接不做 keep-alive：认证失败时回一个 `Connection: close` 的 407 并
/// 关闭连接，客户端自然会带认证头重开一条，因此这里不需要在同一条 TCP 上循环
/// 等待下一个请求。返回 `Ok(None)` 表示已经拒绝并关闭。
async fn read_request_head(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
    buf: &mut BytesMut,
    state: &Arc<SharedState>,
) -> anyhow::Result<Option<(String, usize, String)>> {
    let expected_auth = state
        .proxy_auth
        .as_ref()
        .map(|(expected, _)| expected.as_str());

    let request = tokio::time::timeout(
        PROXY_REQUEST_PARSE_TIMEOUT,
        proxy::parse_proxy_request(read_half, buf, expected_auth),
    )
    .await
    .map_err(|_| anyhow::anyhow!("proxy request parse timeout"))??;

    if !request.authorized {
        reject_unauthorized(read_half, write_half).await?;
        return Ok(None);
    }

    Ok(Some((request.method, request.header_len, request.target)))
}

/// 回 407 并优雅关闭连接。
async fn reject_unauthorized(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
) -> anyhow::Result<()> {
    write_half.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await?;
    let _ = write_half.shutdown().await;

    // 先发 FIN，再把对端已经在途的数据读掉：直接 close 往往触发 RST，
    // 客户端可能还没读到 407 就收到连接重置。
    let _ = tokio::time::timeout(AUTH_REJECT_DRAIN_WINDOW, async {
        let mut sink = [0u8; 512];
        loop {
            match read_half.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    Ok(())
}

/// CONNECT 之后浏览器往往已经把 TLS ClientHello 发过来了，先尽力读一段，
/// 让上游建连与首包发送重叠。
async fn read_early_data(read_half: &mut OwnedReadHalf, buf: &mut BytesMut) {
    let deadline = tokio::time::Instant::now() + EARLY_READ_WINDOW;
    loop {
        let remaining = crate::shaper::MAX_RAW_PAYLOAD.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        // read_buf 在空闲容量为 0 时会返回 0（伪 EOF），必须显式预留；
        // 分块预留，避免为一个只发了几字节的连接一次性吃掉 16 KiB。
        buf.reserve(remaining.min(EARLY_READ_CHUNK));
        match tokio::time::timeout_at(deadline, read_half.read_buf(buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::{BypassRules, BypassRulesBuilder};
    use crate::shaper::{EncodingType, PaddingConfig, ResolvedShaperConfig, TrafficConfig};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        (server.await.unwrap(), client)
    }

    fn test_state(
        proxy_auth: Option<(String, String)>,
        bypass: Option<Arc<BypassRules>>,
    ) -> Arc<SharedState> {
        let traffic = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        Arc::new(SharedState {
            remote_str: "http://127.0.0.1:1/".to_string(),
            auth_header: "Bearer test".to_string(),
            traffic_config: traffic.clone(),
            resolved_traffic: Arc::new(ResolvedShaperConfig::resolve(&traffic)),
            bypass,
            server_public_key: None,
            proxy_auth,
            initial_master: Mutex::new(None),
            handshake_lock: Mutex::new(()),
            max_download_bytes: None,
            max_connections: 8,
            max_in_flight_bytes: 1024 * 1024,
            upload_concurrency: 4,
        })
    }

    fn bypass_loopback() -> Arc<BypassRules> {
        let mut b = BypassRulesBuilder::new();
        b.add_cidr("127.0.0.1/32").unwrap();
        Arc::new(b.build().unwrap())
    }

    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    fn test_client() -> Arc<wreq::Client> {
        Arc::new(wreq::Client::builder().no_proxy().build().unwrap())
    }

    #[tokio::test]
    async fn auth_challenge_closes_connection_then_reconnect_succeeds() {
        let echo = spawn_echo().await;
        let state = test_state(
            Some(("Basic dXNlcjpwYXNz".to_string(), "user".to_string())),
            Some(bypass_loopback()),
        );

        // 第一次：不带认证头，应该只收到 407 + Connection: close，然后连接被关闭
        let (server_side, mut client) = tcp_pair().await;
        let http_client = test_client();
        let state1 = Arc::clone(&state);
        let actor = tokio::spawn(async move {
            ClientConnectionActor::new(server_side, http_client, state1)
                .run()
                .await
        });

        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\n\r\n",
                    echo.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(
            head.starts_with("HTTP/1.1 407"),
            "expected 407, got: {head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("connection: close"),
            "got: {head}"
        );

        let mut tail = [0u8; 64];
        let n = client.read(&mut tail).await.unwrap();
        assert_eq!(n, 0, "407 之后必须关闭连接，不能在同一条连接上等待");

        let joined = tokio::time::timeout(Duration::from_secs(5), actor)
            .await
            .expect("actor must finish after 407")
            .expect("actor task must not panic");
        assert!(joined.is_ok(), "407 是正常流程，不应上报错误");

        // 第二次：新连接带上认证头，请求应被正常转发
        let (server_side, mut client) = tcp_pair().await;
        let http_client = test_client();
        let actor = tokio::spawn(async move {
            ClientConnectionActor::new(server_side, http_client, state)
                .run()
                .await
        });

        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
                    echo.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        let echoed_str = String::from_utf8_lossy(&echoed);
        assert!(
            echoed_str.contains("GET / "),
            "expected rewritten request echoed, got: {echoed_str}"
        );
        assert!(echoed_str.contains("Host: x"));

        let _ = tokio::time::timeout(Duration::from_secs(5), actor).await;
    }

    #[tokio::test]
    async fn connect_early_data_buffered_and_forwarded() {
        let echo = spawn_echo().await;
        let (server_side, mut client) = tcp_pair().await;
        let state = test_state(None, Some(bypass_loopback()));
        let http_client = test_client();
        let actor = tokio::spawn(async move {
            let actor = ClientConnectionActor::new(server_side, http_client, state);
            actor.run().await
        });

        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
            echo.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
            "expected 200"
        );

        client.write_all(b"early-data-bytes").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        client.write_all(b"post-window-bytes").await.unwrap();
        client.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        let echoed_str = String::from_utf8_lossy(&echoed);
        assert!(
            echoed_str.contains("early-data-bytes"),
            "early data must be forwarded, got: {echoed_str}"
        );
        assert!(echoed_str.contains("post-window-bytes"));

        let _ = tokio::time::timeout(Duration::from_secs(5), actor).await;
    }

    #[tokio::test]
    async fn request_parse_timeout_errors() {
        tokio::time::pause();
        let (server_side, mut client) = tcp_pair().await;
        let state = test_state(None, None);
        let http_client = test_client();
        let actor = tokio::spawn(async move {
            let actor = ClientConnectionActor::new(server_side, http_client, state);
            actor.run().await
        });

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();

        tokio::task::yield_now().await;
        tokio::time::advance(PROXY_REQUEST_PARSE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();

        let res = tokio::time::timeout(Duration::from_secs(5), actor).await;
        let joined = res
            .expect("actor must finish after parse timeout")
            .expect("actor task must not panic");
        let err = joined.unwrap_err();
        assert!(err.to_string().contains("parse timeout"), "got: {err}");
    }

    #[tokio::test]
    async fn unauthenticated_connections_do_not_linger() {
        let state = test_state(
            Some(("Basic dXNlcjpwYXNz".to_string(), "user".to_string())),
            None,
        );
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n";

        // 连续多条未认证连接都应该被立刻关闭，不会被留在这里反复占用
        for _ in 0..3 {
            let (server_side, mut client) = tcp_pair().await;
            let http_client = test_client();
            let state = Arc::clone(&state);
            let actor = tokio::spawn(async move {
                ClientConnectionActor::new(server_side, http_client, state)
                    .run()
                    .await
            });

            client.write_all(req).await.unwrap();
            let mut sink = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut sink))
                .await
                .expect("server must close after 407")
                .unwrap();
            assert!(sink.starts_with(b"HTTP/1.1 407"));

            let result = tokio::time::timeout(Duration::from_secs(5), actor)
                .await
                .expect("actor must stop after 407")
                .expect("actor task must not panic");
            assert!(result.is_ok());
        }
    }
}

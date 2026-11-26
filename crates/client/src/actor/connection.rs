use bytes::{Buf, BytesMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::constants::{
    AUTH_REJECT_DRAIN_WINDOW, CONNECT_RESPONSE, EARLY_READ_CHUNK, EARLY_READ_WINDOW,
    PROXY_AUTH_REQUIRED_RESPONSE, PROXY_BUF_INITIAL_CAPACITY, PROXY_REQUEST_PARSE_TIMEOUT,
};
use crate::cronet::Client;
use crate::proxy;
use crate::state::SharedState;

pub struct ClientConnectionActor {
    socket: Option<TcpStream>,
    http_client: Arc<Client>,
    state: Arc<SharedState>,
}

impl ClientConnectionActor {
    pub fn new(socket: TcpStream, http_client: Arc<Client>, state: Arc<SharedState>) -> Self {
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
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;
        let (mut read_half, mut write_half) = socket.into_split();
        let mut buf = BytesMut::with_capacity(PROXY_BUF_INITIAL_CAPACITY);

        let mut first = [0; 1];
        let n = tokio::time::timeout(PROXY_REQUEST_PARSE_TIMEOUT, read_half.read(&mut first))
            .await
            .map_err(|_| anyhow::anyhow!("proxy protocol detection timeout"))??;
        if n == 0 {
            return Ok(());
        }
        if first[0] == 5 {
            return run_socks5(
                first[0],
                read_half,
                write_half,
                http_client,
                state,
                local_addr,
                peer_addr,
            )
            .await;
        }
        buf.extend_from_slice(&first);

        let Some((method, header_len, url)) =
            read_request_head(&mut read_half, &mut write_half, &mut buf, &state).await?
        else {
            return Ok(());
        };

        if method == "CONNECT" {
            buf.advance(header_len);
            write_half.write_all(CONNECT_RESPONSE).await?;
            read_early_data(&mut read_half, &mut buf).await;
        }

        let (target_host, origin_form) = proxy::resolve_request(&method, &url)?;
        tracing::Span::current().record("target", target_host.as_str());

        let header_len = if origin_form.is_some() {
            proxy::strip_proxy_headers(&mut buf, header_len)
        } else {
            header_len
        };

        if let Some(origin_path) = origin_form {
            proxy::rewrite_request_line(&mut buf, header_len, &method, &origin_path)?;
        }

        let payload = buf.split().freeze();
        crate::connection::open_tunnel(
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

async fn run_socks5(
    version: u8,
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    http_client: Arc<Client>,
    state: Arc<SharedState>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let command = tokio::time::timeout(
        PROXY_REQUEST_PARSE_TIMEOUT,
        crate::socks5::server_handshake(
            version,
            &mut read_half,
            &mut write_half,
            state.proxy_auth.as_ref(),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timeout"))??;

    match command {
        crate::socks5::Command::Connect(target) => {
            crate::socks5::write_reply(&mut write_half, 0, None).await?;
            let target_host = target.tunnel_target();
            tracing::Span::current().record("target", target_host.as_str());
            crate::connection::open_tunnel(
                read_half,
                write_half,
                http_client,
                state,
                bytes::Bytes::new(),
                &target_host,
            )
            .await
        }
        crate::socks5::Command::UdpAssociate(requested) => {
            let requested = requested.map(|endpoint| {
                SocketAddr::new(
                    if endpoint.ip().is_unspecified() {
                        peer_addr.ip()
                    } else {
                        endpoint.ip()
                    },
                    endpoint.port(),
                )
            });
            let bind_addr = SocketAddr::new(local_addr.ip(), 0);
            let relay = Arc::new(UdpSocket::bind(bind_addr).await?);
            tracing::debug!(relay = %relay.local_addr()?, "SOCKS5 UDP association started");
            crate::socks5::write_reply(&mut write_half, 0, Some(relay.local_addr()?)).await?;
            relay_udp_dns(
                &mut read_half,
                write_half,
                relay,
                requested,
                peer_addr.ip(),
                local_addr,
                state,
            )
            .await
        }
        crate::socks5::Command::Unsupported => Ok(()),
    }
}

async fn relay_udp_dns(
    control: &mut tokio::net::tcp::OwnedReadHalf,
    _control_write: tokio::net::tcp::OwnedWriteHalf,
    relay: Arc<UdpSocket>,
    requested: Option<SocketAddr>,
    client_ip: IpAddr,
    local_addr: SocketAddr,
    state: Arc<SharedState>,
) -> anyhow::Result<()> {
    let concurrency = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    let mut control_buf = [0; 1024];
    let mut packet = vec![0; u16::MAX as usize];

    loop {
        tokio::select! {
            control_read = control.read(&mut control_buf) => {
                if control_read? == 0 {
                    break;
                }
            }
            received = relay.recv_from(&mut packet) => {
                let (length, peer) = received?;
                if peer.ip() != client_ip
                    || requested.is_some_and(|endpoint| endpoint.ip() != peer.ip() || (endpoint.port() != 0 && endpoint.port() != peer.port()))
                {
                    tracing::debug!(%peer, %client_ip, ?requested, "SOCKS5 UDP packet rejected by client endpoint check");
                    continue;
                }
                let Some((target, query)) = crate::socks5::parse_udp_packet(&packet[..length]) else {
                    tracing::debug!(length, "invalid SOCKS5 UDP packet");
                    continue;
                };
                if target.port() != 53 || query.len() < 12 {
                    tracing::debug!(?target, query_len = query.len(), "SOCKS5 UDP packet rejected");
                    continue;
                }
                tracing::debug!(%peer, ?target, query_len = query.len(), "SOCKS5 DNS UDP query received");
                let Ok(permit) = Arc::clone(&concurrency).try_acquire_owned() else {
                    continue;
                };
                let relay = Arc::clone(&relay);
                let state = Arc::clone(&state);
                let query = bytes::Bytes::copy_from_slice(query);
                tasks.spawn(async move {
                    let _permit = permit;
                    let response = match tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        relay_dns_query(local_addr, target.clone(), &query, &state),
                    ).await {
                        Ok(Ok(response)) => response,
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "SOCKS5 DNS relay failed");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!("SOCKS5 DNS relay timed out");
                            return;
                        }
                    };
                    let packet = crate::socks5::encode_udp_packet(&target, &response);
                    let _ = relay.send_to(&packet, peer).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn relay_dns_query(
    local_addr: SocketAddr,
    target: crate::socks5::Target,
    query: &[u8],
    state: &SharedState,
) -> anyhow::Result<Vec<u8>> {
    if let Some(response) = state.dns_cache.response(query).await {
        return Ok(response);
    }
    let mut stream = TcpStream::connect(local_addr).await?;
    crate::socks5::client_connect(&mut stream, &target, state.proxy_auth.as_ref()).await?;
    let length = u16::try_from(query.len())?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut response_len = [0; 2];
    stream.read_exact(&mut response_len).await?;
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len < 12 {
        anyhow::bail!("invalid DNS response length");
    }
    let mut response = vec![0; response_len];
    stream.read_exact(&mut response).await?;
    state.dns_cache.store(query, &response).await;
    Ok(response)
}

async fn read_request_head(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
    buf: &mut BytesMut,
    state: &Arc<SharedState>,
) -> anyhow::Result<Option<(String, usize, String)>> {
    let expected_auth = state
        .proxy_auth
        .as_ref()
        .map(|auth| auth.http_header.as_str());

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

async fn reject_unauthorized(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
) -> anyhow::Result<()> {
    write_half.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await?;
    let _ = write_half.shutdown().await;

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

async fn read_early_data(read_half: &mut OwnedReadHalf, buf: &mut BytesMut) {
    let deadline = tokio::time::Instant::now() + EARLY_READ_WINDOW;
    loop {
        let remaining = httproxy_core::shaper::MAX_RAW_PAYLOAD.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
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
    use httproxy_core::bypass::{BypassRules, BypassRulesBuilder};
    use httproxy_core::test_support::connected_pair as tcp_pair;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn test_state(
        proxy_auth: Option<crate::state::ProxyAuth>,
        bypass: Option<Arc<BypassRules>>,
    ) -> Arc<SharedState> {
        let mut state = SharedState::for_test("http://127.0.0.1:1/");
        state.proxy_auth = proxy_auth;
        state.bypass = bypass;
        Arc::new(state)
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

    fn test_client() -> Arc<Client> {
        Client::new(None).unwrap()
    }

    #[tokio::test]
    async fn auth_challenge_closes_connection_then_reconnect_succeeds() {
        let echo = spawn_echo().await;
        let state = test_state(
            Some(crate::state::ProxyAuth {
                http_header: "Basic dXNlcjpwYXNz".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
            Some(bypass_loopback()),
        );

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
        assert!(
            !echoed_str
                .to_ascii_lowercase()
                .contains("proxy-authorization"),
            "proxy credentials must never reach the target, got: {echoed_str}"
        );

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
}

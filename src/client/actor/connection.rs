use bytes::{Buf, Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::client::constants::{
    CONNECT_RESPONSE, EARLY_READ_WINDOW, PROXY_AUTH_REQUIRED_RESPONSE, PROXY_REQUEST_PARSE_TIMEOUT,
};
use crate::client::proxy;
use crate::client::state::ClientPqFsm;
use crate::client::state::SharedState;

pub enum ClientConnState {
    Parsing {
        socket: TcpStream,
        buf: BytesMut,
        http_client: Arc<wreq::Client>,
        state: Arc<SharedState>,
    },
    Active,
    Closed,
}

pub struct ClientConnectionActor {
    state: ClientConnState,
}

impl ClientConnectionActor {
    pub fn new(socket: TcpStream, http_client: Arc<wreq::Client>, state: Arc<SharedState>) -> Self {
        socket.set_nodelay(true).ok();
        Self {
            state: ClientConnState::Parsing {
                socket,
                buf: BytesMut::with_capacity(16 * 1024),
                http_client,
                state,
            },
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.state = match std::mem::replace(&mut self.state, ClientConnState::Closed) {
                ClientConnState::Parsing {
                    socket,
                    mut buf,
                    http_client,
                    state,
                } => {
                    self.do_parsing(socket, &mut buf, http_client, state)
                        .await?
                }
                ClientConnState::Active => return Ok(()),
                ClientConnState::Closed => return Ok(()),
            };
        }
    }

    async fn do_parsing(
        &mut self,
        socket: TcpStream,
        buf: &mut BytesMut,
        http_client: Arc<wreq::Client>,
        state: Arc<SharedState>,
    ) -> anyhow::Result<ClientConnState> {
        let (mut read_half, mut write_half) = socket.into_split();

        let (method, header_len, url) = loop {
            let (method, header_len, url, proxy_auth_header) = tokio::time::timeout(
                PROXY_REQUEST_PARSE_TIMEOUT,
                proxy::parse_proxy_request(&mut read_half, buf, state.proxy_auth.is_some()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("proxy request parse timeout"))??;

            if let Some((ref expected_auth, _)) = state.proxy_auth
                && proxy_auth_header
                    .as_ref()
                    .is_none_or(|h| h.trim() != expected_auth.as_str())
            {
                write_half.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await?;
                write_half.flush().await?;
                buf.advance(header_len);
                continue;
            }
            break (method, header_len, url);
        };

        if method == "CONNECT" {
            buf.advance(header_len);
            write_half.write_all(CONNECT_RESPONSE).await?;
            let deadline = tokio::time::Instant::now() + EARLY_READ_WINDOW;
            loop {
                let remaining = crate::shaper::MAX_RAW_PAYLOAD.saturating_sub(buf.len());
                if remaining == 0 {
                    break;
                }
                match tokio::time::timeout_at(deadline, read_half.read_buf(buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {}
                }
            }
        }

        let target_host = proxy::resolve_target_host(&method, &url)?;
        tracing::Span::current().record("target", target_host.as_str());

        if method != "CONNECT" {
            proxy::rewrite_absolute_url(buf, &method, &url)?;
        }

        if let Some(ref bypass) = state.bypass
            && bypass.should_bypass(&target_host)
        {
            info!(mode = "bypass", "direct connect");
            let payload = buf.split().freeze();
            return handle_bypass_direct(read_half, write_half, &target_host, payload).await;
        }

        let payload = buf.split().freeze();
        info!(mode = "proxy", "connecting");

        if let Some(ref server_pk) = state.server_public_key {
            let fsm = ClientPqFsm::new(
                target_host,
                payload,
                read_half,
                write_half,
                *server_pk,
                &state,
            )
            .await;
            fsm.run(http_client, state).await?;
        } else {
            crate::client::connection::handle_plain_proxy(
                read_half,
                write_half,
                http_client,
                state,
                payload,
                &target_host,
            )
            .await?;
        }

        Ok(ClientConnState::Active)
    }
}

async fn handle_bypass_direct(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    initial_payload: Bytes,
) -> anyhow::Result<ClientConnState> {
    use anyhow::Context;
    use tokio::io::AsyncWriteExt;
    let mut remote = TcpStream::connect(target)
        .await
        .with_context(|| format!("bypass connect to {target} failed"))?;
    remote.set_nodelay(true)?;

    info!(target = %target, initial_bytes = %initial_payload.len(), "bypass connected");

    if !initial_payload.is_empty() {
        remote.write_all(&initial_payload).await?;
    }
    let (mut remote_read, mut remote_write) = remote.into_split();
    let up = async {
        let res = tokio::io::copy(&mut read_half, &mut remote_write).await;
        let _ = remote_write.shutdown().await;
        res
    };
    let down = async {
        let res = tokio::io::copy(&mut remote_read, &mut write_half).await;
        let _ = write_half.shutdown().await;
        res
    };
    let (up_res, down_res) = tokio::join!(up, down);
    up_res.context("bypass client->remote")?;
    down_res.context("bypass remote->client")?;
    info!(target = %target, "bypass connection closed");
    Ok(ClientConnState::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::{BypassRules, BypassRulesBuilder};
    use crate::shaper::{EncodingType, PaddingConfig, ResolvedShaperConfig, TrafficConfig};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
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
    async fn auth_retry_on_same_connection() {
        let echo = spawn_echo().await;
        let (server_side, mut client) = tcp_pair().await;
        let state = test_state(
            Some(("Basic dXNlcjpwYXNz".to_string(), "user".to_string())),
            Some(bypass_loopback()),
        );
        let http_client = test_client();
        let actor = tokio::spawn(async move {
            let mut actor = ClientConnectionActor::new(server_side, http_client, state);
            actor.run().await
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
            let mut actor = ClientConnectionActor::new(server_side, http_client, state);
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
            let mut actor = ClientConnectionActor::new(server_side, http_client, state);
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

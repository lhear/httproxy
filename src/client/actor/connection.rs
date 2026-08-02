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

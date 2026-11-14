use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::info;

use crate::client::state::ClientPqFsm;
use crate::client::{constants::WRITE_STALL_TIMEOUT, state::SharedState};
use crate::cronet::Client;

pub(crate) async fn open_tunnel(
    read_half: OwnedReadHalf,
    write_half: OwnedWriteHalf,
    http_client: Arc<Client>,
    state: Arc<SharedState>,
    payload: Bytes,
    target_host: &str,
) -> Result<()> {
    if let Some(ref bypass) = state.bypass
        && bypass.should_bypass(target_host)
    {
        info!(mode = "bypass", "direct connect");
        return handle_bypass_direct(read_half, write_half, target_host, payload).await;
    }

    info!(mode = "proxy", "connecting");
    let fsm = ClientPqFsm::new(
        target_host.to_owned(),
        payload,
        read_half,
        write_half,
        Arc::clone(&state.server_public_key),
        &state,
    )
    .await;
    fsm.run(http_client, state).await
}

pub async fn handle_connection_actor(
    socket: TcpStream,
    http_client: Arc<Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    use crate::client::actor::connection::ClientConnectionActor;
    let actor = ClientConnectionActor::new(socket, http_client, state);
    actor.run().await
}

async fn handle_bypass_direct(
    mut read_half: OwnedReadHalf,
    mut write_half: OwnedWriteHalf,
    target: &str,
    initial_payload: Bytes,
) -> Result<()> {
    let mut remote = TcpStream::connect(target)
        .await
        .with_context(|| format!("bypass connect to {target} failed"))?;
    remote.set_nodelay(true)?;

    info!(target = %target, initial_bytes = %initial_payload.len(), "bypass connected");

    if !initial_payload.is_empty() {
        write_with_timeout(&mut remote, &initial_payload).await?;
    }
    drop(initial_payload);
    let (mut remote_read, mut remote_write) = remote.into_split();
    let up = async {
        let res = copy_with_write_timeout(&mut read_half, &mut remote_write).await;
        let _ = remote_write.shutdown().await;
        res
    };
    let down = async {
        let res = copy_with_write_timeout(&mut remote_read, &mut write_half).await;
        let _ = write_half.shutdown().await;
        res
    };
    let (up_res, down_res) = tokio::join!(up, down);
    up_res.context("bypass client->remote")?;
    down_res.context("bypass remote->client")?;
    info!(target = %target, "bypass connection closed");
    Ok(())
}

const COPY_BUF_SIZE: usize = 64 * 1024;

#[inline]
async fn write_with_timeout<W>(writer: &mut W, data: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut off = 0;
    while off < data.len() {
        match tokio::time::timeout(WRITE_STALL_TIMEOUT, writer.write(&data[off..])).await {
            Ok(Ok(0)) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(Ok(n)) => off += n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "write stalled",
                ));
            }
        }
    }
    Ok(())
}

async fn copy_with_write_timeout<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    let mut copied = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        write_with_timeout(writer, &buf[..n]).await?;
        copied += n as u64;
    }
    Ok(copied)
}

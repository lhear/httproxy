use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{Instrument, info};

use crate::client::state::ClientPqFsm;
use crate::client::{
    actor::{download_loop::DownloadLoopActor, upload_loop::UploadLoopActor},
    constants::DOWNLOAD_CONNECT_TIMEOUT,
    state::SharedState,
    utils,
};

/// 建立一条到 `target_host` 的隧道，并把 `payload`（可能为空）作为首包发出去。
///
/// HTTP 代理入站（解析出 CONNECT/绝对 URI 之后）和 `[[redirect]]` 端口转发
/// 共用这一条路径：差別只在于前者带着已读到的请求字节，后者什么都不带。
pub(crate) async fn open_tunnel(
    read_half: OwnedReadHalf,
    write_half: OwnedWriteHalf,
    http_client: Arc<wreq::Client>,
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
    let server_pk = state.server_public_key;
    match server_pk {
        Some(pk) => {
            let fsm = ClientPqFsm::new(
                target_host.to_owned(),
                payload,
                read_half,
                write_half,
                pk,
                &state,
            )
            .await;
            fsm.run(http_client, state).await
        }
        None => {
            handle_plain_proxy(
                read_half,
                write_half,
                http_client,
                state,
                payload,
                target_host,
            )
            .await
        }
    }
}

pub(crate) async fn handle_plain_proxy(
    read_half: OwnedReadHalf,
    write_half: OwnedWriteHalf,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    payload: Bytes,
    target_host: &str,
) -> Result<()> {
    let stream_id = uuid::Uuid::new_v4();
    let mut cookie = String::new();
    utils::build_stream_cookie(&mut cookie, stream_id);

    let (early_data, remaining_payload, frames_sent) = utils::encode_initial_payload(
        &payload,
        crate::shaper::MAX_RAW_PAYLOAD,
        None,
        &state.traffic_config,
    )?;

    info!(stream_id = %stream_id, target = %target_host, "connection initiated");

    let response = tokio::time::timeout(
        DOWNLOAD_CONNECT_TIMEOUT,
        http_client
            .post(state.remote_str.as_str())
            .header("Authorization", state.auth_header.as_str())
            .header("X-Target", target_host)
            .header("Cookie", cookie)
            .body(wreq::Body::from(early_data))
            .send(),
    )
    .await
    .context("download connect timed out")?
    .context("download request failed")?;

    let response = utils::check_response_status(response, "upstream rejected download").await?;

    let upload_actor = UploadLoopActor::new(
        Arc::clone(&http_client),
        Arc::clone(&state),
        remaining_payload,
        read_half,
        None,
        stream_id,
        frames_sent,
    );
    let upload_task =
        tokio::spawn(async move { upload_actor.run().await }.instrument(tracing::Span::current()));

    let download_actor = DownloadLoopActor::new(
        response,
        write_half,
        None,
        stream_id,
        Arc::clone(&http_client),
        Arc::clone(&state),
    );

    utils::race_upload_download(upload_task, download_actor.run(), None).await
}

pub async fn handle_connection_actor(
    socket: TcpStream,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    use crate::client::actor::connection::ClientConnectionActor;
    let actor = ClientConnectionActor::new(socket, http_client, state);
    actor.run().await
}

/// 直接连目标（bypass 命中时），双向原样搬运。
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
        remote.write_all(&initial_payload).await?;
    }
    drop(initial_payload);
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
    Ok(())
}

use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{Instrument, info};

use crate::client::{
    actor::{download_loop::DownloadLoopActor, upload_loop::UploadLoopActor},
    constants::DOWNLOAD_CONNECT_TIMEOUT,
    state::SharedState,
    utils,
};

pub(crate) async fn handle_plain_proxy(
    read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    payload: Bytes,
    target_host: &str,
) -> Result<()> {
    let stream_id = uuid::Uuid::new_v4().to_string();
    let mut cookie = String::new();
    utils::build_tunnel_cookie(&mut cookie, &stream_id);

    let (early_data, remaining_payload, frames_sent) = utils::encode_initial_payload(
        &payload,
        crate::shaper::MAX_RAW_PAYLOAD,
        None,
        &state.traffic_config,
    )?;

    info!(target = %target_host, "connection initiated");

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
        stream_id.clone(),
        frames_sent,
    );
    let upload_task =
        tokio::spawn(async move { upload_actor.run().await }.instrument(tracing::Span::current()));

    let download_actor = DownloadLoopActor::new(
        response,
        write_half,
        None,
        stream_id.to_owned(),
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
    let mut actor = ClientConnectionActor::new(socket, http_client, state);
    actor.run().await
}

mod log;
mod shaper;

use anyhow::{Context, Ok, Result, anyhow};
use bytes::{Buf, BytesMut};
use clap::Parser;
use futures::StreamExt;
use http::uri::Authority;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use rand::Rng;
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{Instrument, error_span, info, warn};
use url::Url;
use wreq::{Body, Client};
use wreq_util::Emulation;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static PADDING_POOL: [u8; 32] = [b'X'; 32];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    client: ClientConfig,
    auth: AuthConfig,
    log: Option<log::LogConfig>,
    traffic_shaping: shaper::TrafficConfig,
}

#[derive(Deserialize, Debug)]
struct ClientConfig {
    listen: String,
    remote: String,
}

#[derive(Deserialize, Debug)]
struct AuthConfig {
    token: String,
}

struct StateConfig {
    remote: Url,
    token: String,
    traffic_config: shaper::TrafficConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_content = fs::read_to_string(&cli.config)?;
    let config: Config = toml::from_str(&config_content)?;
    let _guard = log::init_tracing(&config.log.clone().unwrap_or_default());

    run_server(&config.client.listen, create_proxy_config(&config).await?).await
}

async fn create_proxy_config(cfg: &Config) -> anyhow::Result<Arc<StateConfig>> {
    Ok(Arc::new(StateConfig {
        remote: cfg.client.remote.parse().context("invalid server URL")?,
        token: format!("Bearer {}", cfg.auth.token),
        traffic_config: cfg.traffic_shaping.clone(),
    }))
}

async fn run_server(listen: &str, config: Arc<StateConfig>) -> anyhow::Result<()> {
    let addr: SocketAddr = listen.parse().context("invalid bind address")?;
    let listener = TcpListener::bind(addr).await?;
    let listener_stream = TcpListenerStream::new(listener);

    let http_client = Arc::new(
        Client::builder()
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(45))
            .tcp_keepalive_interval(Duration::from_secs(45))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(6)
            .emulation(Emulation::Chrome143)
            .build()?,
    );
    info!(listen = %addr, "server started");

    listener_stream
        .filter_map(|res| async move { res.ok() })
        .for_each_concurrent(1000, |socket| {
            let (http_client, config) = (Arc::clone(&http_client), Arc::clone(&config));
            let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
            let client = socket
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "-".into());
            async move {
                if let Err(e) = handle_connection(socket, http_client, config).await {
                    if !is_silent_error(e.root_cause()) {
                        warn!(reason = %e, "connection aborted");
                    }
                }
            }
            .instrument(error_span!(
                "session",
                id,
                client,
                target = tracing::field::Empty
            ))
        })
        .await;
    Ok(())
}

fn is_silent_error(root: &(dyn std::error::Error + 'static)) -> bool {
    use std::io::ErrorKind::*;
    if let Some(e) = root.downcast_ref::<h2::Error>() {
        return e.is_reset() || e.is_library();
    }
    if let Some(e) = root.downcast_ref::<std::io::Error>() {
        return matches!(e.kind(), ConnectionReset | UnexpectedEof | NotConnected);
    }
    root.to_string()
        .contains("connection closed during header parsing")
}

async fn parse_proxy_request(
    read_half: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
) -> Result<(String, usize, String)> {
    loop {
        if read_half.read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(amt) = req.parse(buffer)? {
            let method = req.method.context("no method")?.to_string();
            let path = req.path.context("no path")?.to_string();
            return Ok((method, amt, path));
        }
        if buffer.len() > 16384 {
            return Err(anyhow!("header too large"));
        }
    }
}

fn resolve_target_host(method: &str, url_str: &str) -> Result<String> {
    let auth_str = if method == "CONNECT" {
        url_str.to_string()
    } else {
        let url = Url::parse(url_str).context("invalid proxy URL")?;
        let host = url.host_str().context("URL has no host")?;
        let port = url.port_or_known_default().context("port required")?;
        format!("{}:{}", host, port)
    };
    let auth = auth_str
        .parse::<Authority>()
        .map_err(|_| anyhow!("invalid target format: {}", auth_str))?;
    let host = auth.host();
    let port = auth
        .port_u16()
        .ok_or_else(|| anyhow!("port required for target: {}", auth_str))?;
    Ok(format!("{}:{}", host, port))
}

async fn handle_connection(
    socket: TcpStream,
    http_client: Arc<Client>,
    config: Arc<StateConfig>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut read_half, mut write_half) = socket.into_split();

    let (payload, target_host) = {
        let mut buffer = BytesMut::with_capacity(8192);
        let (method, len, url) = parse_proxy_request(&mut read_half, &mut buffer).await?;
        if method == "CONNECT" {
            buffer.advance(len);
            write_half
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        let target = resolve_target_host(&method, &url)?;
        tracing::Span::current().record("target", target.as_str());
        Ok((buffer.split().freeze(), target))
    }?;

    info!("connecting");

    let response = {
        let mut url = config.remote.clone();
        url.query_pairs_mut().append_pair("target", &target_host);
        let reader = AsyncReadExt::chain(std::io::Cursor::new(payload), read_half);
        let body_stream =
            shaper::TrafficShaper::new(reader, 16 * 1024, config.traffic_config.clone())
                .map(|item| item.map(Frame::data));
        let padding_len = rand::rng().random_range(16..PADDING_POOL.len());

        http_client
            .post(url.as_str())
            .header("Authorization", &config.token)
            .header("X-Padding", &PADDING_POOL[..padding_len])
            .body(Body::wrap(StreamBody::new(body_stream)))
            .send()
            .await
            .context("http post failed")
    }?;

    if !response.status().is_success() {
        return Err(anyhow!("upstream rejected status: {}", response.status()));
    }

    let mut remote_stream = response.into_data_stream();
    let mut buffer = BytesMut::new();

    while let Some(chunk) = remote_stream.next().await {
        let data = chunk.context("stream read error")?;
        buffer.extend_from_slice(&data);
        while let Some(decoded_data) = shaper::TrafficShaper::decode_from_buffer(&mut buffer)? {
            write_half.write_all(&decoded_data).await?;
        }
    }
    write_half.shutdown().await?;

    Ok(())
}

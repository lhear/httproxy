mod log;
mod shaper;

use anyhow::{Context, Result, anyhow};
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
use tracing::{Instrument, error_span, info, warn};
use url::Url;
use wreq::{Body, Client};
use wreq_util::Emulation;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

const CONNECT_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const MAX_HEADER_LEN: usize = 16 * 1024;
const INITIAL_BUF_CAP: usize = 16 * 1024;
const PADDING: [u8; 32] = [b'X'; 32];
const MIN_PADDING: usize = 16;

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

struct SharedState {
    remote: Url,
    auth_header: String,
    traffic_config: shaper::TrafficConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config: Config = toml::from_str(&fs::read_to_string(&cli.config)?)?;
    let _guard = log::init_tracing(&config.log.clone().unwrap_or_default());

    run_server(&config.client.listen, Arc::new(build_state(&config)?)).await
}

fn build_state(cfg: &Config) -> Result<SharedState> {
    Ok(SharedState {
        remote: cfg.client.remote.parse().context("invalid server URL")?,
        auth_header: format!("Bearer {}", cfg.auth.token),
        traffic_config: cfg.traffic_shaping.clone(),
    })
}

async fn run_server(listen: &str, state: Arc<SharedState>) -> Result<()> {
    let addr: SocketAddr = listen.parse().context("invalid bind address")?;
    let listener = TcpListener::bind(addr).await?;

    let http_client = Arc::new(
        Client::builder()
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(45))
            .tcp_keepalive_interval(Duration::from_secs(45))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(6)
            .emulation(Emulation::Chrome143)
            .no_proxy()
            .build()?,
    );
    info!(listen = %addr, "server started");

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(reason = %e, "accept failed");
                continue;
            }
        };

        let http_client = Arc::clone(&http_client);
        let state = Arc::clone(&state);
        let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(
            async move {
                if let Err(e) = handle_connection(socket, http_client, state).await {
                    if !is_silent_error(e.root_cause()) {
                        warn!(reason = %e, "connection aborted");
                    }
                }
            }
            .instrument(error_span!(
                "session",
                id,
                client = %peer,
                target = tracing::field::Empty,
            )),
        );
    }
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
    reader: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
) -> Result<(String, usize, String)> {
    loop {
        if reader.read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(amt) = req.parse(buffer)? {
            return Ok((
                req.method.context("no method")?.to_owned(),
                amt,
                req.path.context("no path")?.to_owned(),
            ));
        }
        if buffer.len() > MAX_HEADER_LEN {
            return Err(anyhow!("header too large"));
        }
    }
}

fn resolve_target_host(method: &str, url_str: &str) -> Result<String> {
    if method == "CONNECT" {
        let auth: Authority = url_str
            .parse()
            .map_err(|_| anyhow!("invalid target: {url_str}"))?;
        let port = auth
            .port_u16()
            .ok_or_else(|| anyhow!("port required: {url_str}"))?;
        return Ok(format!("{}:{port}", auth.host()));
    }

    let url = Url::parse(url_str).context("invalid proxy URL")?;
    let host = url.host_str().context("URL has no host")?;
    let port = url.port_or_known_default().context("port required")?;
    Ok(format!("{host}:{port}"))
}

async fn handle_connection(
    socket: TcpStream,
    http_client: Arc<Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut read_half, mut write_half) = socket.into_split();

    let mut buffer = BytesMut::with_capacity(INITIAL_BUF_CAP);
    let (method, header_len, url) = parse_proxy_request(&mut read_half, &mut buffer).await?;

    if method == "CONNECT" {
        buffer.advance(header_len);
        write_half.write_all(CONNECT_RESPONSE).await?;
    }

    let target_host = resolve_target_host(&method, &url)?;
    tracing::Span::current().record("target", target_host.as_str());
    let payload = buffer.split().freeze();

    info!("connecting");

    let mut remote_url = state.remote.clone();
    remote_url
        .query_pairs_mut()
        .append_pair("target", &target_host);

    let reader = AsyncReadExt::chain(std::io::Cursor::new(payload), read_half);
    let body_stream = shaper::TrafficShaper::new(reader, state.traffic_config.clone())
        .map(|item| item.map(Frame::data));

    let padding_len = rand::rng().random_range(MIN_PADDING..PADDING.len());

    let response = http_client
        .post(remote_url.as_str())
        .header("Authorization", state.auth_header.as_str())
        .header("X-Padding", &PADDING[..padding_len])
        .body(Body::wrap(StreamBody::new(body_stream)))
        .send()
        .await
        .context("http post failed")?;

    if !response.status().is_success() {
        return Err(anyhow!("upstream rejected: {}", response.status()));
    }

    let mut data_stream = response.into_data_stream();

    while let Some(chunk) = data_stream.next().await {
        buffer.extend_from_slice(&chunk.context("stream read error")?);
        while let Some(frame) = shaper::TrafficShaper::decode_from_buffer(&mut buffer)? {
            write_half.write_all(&frame).await?;
        }
    }

    write_half.shutdown().await?;
    Ok(())
}

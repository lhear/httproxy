mod shaper;

use anyhow::{Context, Ok, Result, anyhow};
use bytes::{Buf, BytesMut};
use clap::Parser;
use futures::StreamExt;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
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
use tracing::{Instrument, info, warn};
use url::Url;
use wreq::{Body, Client};
use wreq_util::Emulation;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.json")]
    config: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    listen: String,
    remote: String,
    token: String,
    #[serde(default = "default_log_level")]
    log_level: String,
    traffic_shaping: shaper::TrafficConfig,
}

struct ProxyConfig {
    remote: Url,
    token: String,
    traffic_config: shaper::TrafficConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_content = fs::read_to_string(&cli.config)?;
    let json_config: Config = serde_json::from_str(&config_content)?;

    init_tracing(&json_config.log_level);
    run_server(
        &json_config.listen,
        create_proxy_config(&json_config).await?,
    )
    .await
}

fn init_tracing(log_level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::new(
            "%Y-%m-%dT%H:%M:%S%.6f%:z".to_string(),
        ))
        .init();
}

async fn create_proxy_config(json_config: &Config) -> anyhow::Result<Arc<ProxyConfig>> {
    Ok(Arc::new(ProxyConfig {
        remote: json_config.remote.parse().context("invalid server URL")?,
        token: format!("Bearer {}", json_config.token),
        traffic_config: json_config.traffic_shaping.clone(),
    }))
}

async fn run_server(listen: &str, config: Arc<ProxyConfig>) -> anyhow::Result<()> {
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

    info!("listening on {}", addr);

    listener_stream
        .for_each_concurrent(1000, |res| {
            let http_client = Arc::clone(&http_client);
            let config = Arc::clone(&config);

            async move {
                if let std::result::Result::Ok(socket) = res {
                    let addr = socket
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "-".to_string());
                    let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
                    let span = tracing::info_span!("", id, addr);
                    async move {
                        if let Err(e) = handle_connection(socket, http_client, config).await {
                            warn!("connection error: {}", e.root_cause());
                        }
                    }
                    .instrument(span)
                    .await;
                }
            }
        })
        .await;
    Ok(())
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
    if method == "CONNECT" {
        Ok(url_str.to_string())
    } else {
        let url = Url::parse(url_str).context("invalid proxy URL")?;
        let host = url.host_str().context("URL has no host")?;
        let port = url.port_or_known_default().unwrap_or(80);
        Ok(format!("{}:{}", host, port))
    }
}

async fn handle_connection(
    socket: TcpStream,
    http_client: Arc<Client>,
    config: Arc<ProxyConfig>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut read_half, mut write_half) = socket.into_split();

    let (payload, target_host) = {
        let mut buffer = BytesMut::with_capacity(8192);
        let (method, header_size, url_str) =
            parse_proxy_request(&mut read_half, &mut buffer).await?;
        if method == "CONNECT" {
            buffer.advance(header_size);
            write_half
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        let target_host = resolve_target_host(&method, &url_str)?;
        (buffer.split().freeze(), target_host)
    };

    info!("connecting to {}", target_host);

    let request_stream_reader = AsyncReadExt::chain(std::io::Cursor::new(payload), read_half);
    let shaper_stream = shaper::TrafficShaper::new(
        request_stream_reader,
        16 * 1024,
        config.traffic_config.clone(),
    );
    let body_stream = shaper_stream.map(|item| item.map(Frame::data));

    let mut remote_url = config.remote.clone();
    remote_url
        .query_pairs_mut()
        .append_pair("target", &target_host);

    let response = http_client
        .post(remote_url.as_str())
        .header("Authorization", &config.token)
        .body(Body::wrap(StreamBody::new(body_stream)))
        .send()
        .await
        .context("upstream request failed")?;

    if !response.status().is_success() {
        return Err(anyhow!("upstream rejected: {}", response.status()));
    }
    let mut remote_stream = response.into_data_stream();
    let mut buffer = BytesMut::new();

    while let Some(chunk) = remote_stream.next().await {
        let data = chunk.context("stream error")?;
        buffer.extend_from_slice(&data);
        while let Some(decoded_data) = shaper::TrafficShaper::decode_from_buffer(&mut buffer)? {
            write_half.write_all(&decoded_data).await?;
        }
    }
    write_half.shutdown().await?;

    Ok(())
}

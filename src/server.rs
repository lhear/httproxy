mod dns;
mod log;
mod shaper;

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::BytesMut;
use clap::Parser;
use jsonwebtoken::{DecodingKey, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_socks::tcp::Socks5Stream;
use tokio_stream::StreamExt;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{Instrument, info, warn};

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

const PADDING_POOL: [u8; 62] = [b'X'; 62];
const DECODE_BUF_CAPACITY: usize = 16 * 1024;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    #[command(about = "Generate a JWT token")]
    GenToken {
        #[arg(short, long, help = "Secret key for signing")]
        secret: String,
        #[arg(short, long, help = "Username or Subject")]
        user: String,
        #[arg(short, long, help = "Expiration timestamp (Unix)")]
        exp: u64,
    },
}

#[derive(Deserialize, Debug)]
struct Config {
    server: ServerConfig,
    auth: AuthConfig,
    proxy: Option<ProxyConfig>,
    log: Option<log::LogConfig>,
    dns: Option<dns::DnsConfig>,
    traffic_shaping: shaper::TrafficConfig,
}

#[derive(Deserialize, Debug)]
struct ServerConfig {
    listen: String,
    path: String,
}

#[derive(Deserialize, Debug)]
struct AuthConfig {
    secret: String,
}

#[derive(Deserialize, Debug)]
struct ProxyConfig {
    socks5: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

#[derive(Clone)]
struct AppState {
    decoding_key: DecodingKey,
    jwt_validation: Validation,
    socks5_proxy: Option<Arc<str>>,
    dns_client: Option<Arc<dns::DnsClient>>,
    client_subnet: Option<IpAddr>,
    traffic_config: shaper::TrafficConfig,
}

#[derive(Deserialize)]
struct TunnelQuery {
    target: String,
}

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl AppError {
    #[inline]
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    #[inline]
    fn bad_gateway(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_GATEWAY, msg.into())
    }

    #[inline]
    fn gateway_timeout(msg: impl Into<String>) -> Self {
        Self(StatusCode::GATEWAY_TIMEOUT, msg.into())
    }

    #[inline]
    fn unauthorized(msg: impl Into<String>) -> Self {
        Self(StatusCode::UNAUTHORIZED, msg.into())
    }

    #[inline]
    fn internal(msg: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

impl<E: std::error::Error> From<E> for AppError {
    fn from(err: E) -> Self {
        Self::internal(err.to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::GenToken { secret, user, exp }) = cli.command {
        return gen_token(&secret, user, exp);
    }

    let mut config: Config = toml::from_str(&fs::read_to_string(&cli.config)?)?;
    let _guard = log::init_tracing(&config.log.as_ref().cloned().unwrap_or_default());
    let state = build_state(&mut config).await?;

    run_server(
        build_router(state, &config.server.path),
        &config.server.listen,
    )
    .await
}

fn gen_token(secret: &str, user: String, exp: u64) -> anyhow::Result<()> {
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &Claims { sub: user, exp },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?;
    println!("{token}");
    Ok(())
}

async fn build_state(config: &mut Config) -> anyhow::Result<Arc<AppState>> {
    let (dns_client, client_subnet) = match config.dns {
        Some(ref mut dc) => {
            let mut dc = dc.clone();
            let client = dns::init_dns(&mut dc).await?;
            (Some(client), dc.options.client_subnet)
        }
        None => (None, None),
    };

    Ok(Arc::new(AppState {
        decoding_key: DecodingKey::from_secret(config.auth.secret.as_bytes()),
        jwt_validation: Validation::default(),
        socks5_proxy: config
            .proxy
            .as_ref()
            .and_then(|p| p.socks5.as_deref())
            .map(Arc::from),
        dns_client,
        client_subnet,
        traffic_config: config.traffic_shaping.clone(),
    }))
}

fn build_router(state: Arc<AppState>, path: &str) -> Router {
    use tracing::field::Empty;

    Router::new()
        .route(path, post(tunnel_handler))
        .layer(
            ServiceBuilder::new().layer(TraceLayer::new_for_http().make_span_with(
                |req: &axum::http::Request<Body>| {
                    let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
                    let client = req
                        .headers()
                        .get("X-Forwarded-For")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("-");
                    tracing::error_span!("session", id, client, user = Empty, target = Empty)
                },
            )),
        )
        .with_state(state)
}

async fn run_server(app: Router, listen: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    if listen.contains('/') || listen.ends_with(".sock") {
        let path = std::path::Path::new(listen);
        if path.exists() {
            fs::remove_file(path)?;
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        info!("listening on unix:{listen}");
        return Ok(axum::serve(listener, app.into_make_service()).await?);
    }

    let addr: SocketAddr = listen.parse().context("invalid bind address")?;
    info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[inline]
fn validate_jwt(
    headers: &HeaderMap,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<String, AppError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            warn!("rejected: missing or invalid authorization header");
            AppError::unauthorized("invalid header")
        })?;

    jsonwebtoken::decode::<Claims>(token, key, validation)
        .map(|td| td.claims.sub)
        .map_err(|_| {
            warn!("rejected: invalid token");
            AppError::unauthorized("invalid token")
        })
}

async fn connect_upstream(
    dns_client: Option<&Arc<dns::DnsClient>>,
    client_subnet: Option<IpAddr>,
    socks5_proxy: Option<&Arc<str>>,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    if let Some(client) = dns_client {
        return client
            .connect(
                host,
                port,
                client_subnet,
                socks5_proxy.map(|s| s.to_string()),
            )
            .await
            .map_err(|e| format!("dns error: {e}"));
    }

    match socks5_proxy {
        Some(p) => Socks5Stream::connect(p.as_ref(), (host, port))
            .await
            .map(Socks5Stream::into_inner)
            .map_err(|e| e.to_string()),
        None => TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string()),
    }
}

async fn tunnel_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TunnelQuery>,
    body: Body,
) -> Result<impl IntoResponse, AppError> {
    let span = tracing::Span::current();
    span.record(
        "user",
        validate_jwt(&headers, &state.decoding_key, &state.jwt_validation)?,
    );
    span.record("target", &query.target);

    let auth = query
        .target
        .parse::<axum::http::uri::Authority>()
        .map_err(|_| AppError::bad_request("invalid target format"))?;

    let host = auth.host();
    let port = auth
        .port_u16()
        .ok_or_else(|| AppError::bad_request("port required"))?;

    info!("connecting");

    let upstream = tokio::time::timeout(
        Duration::from_secs(10),
        connect_upstream(
            state.dns_client.as_ref(),
            state.client_subnet,
            state.socks5_proxy.as_ref(),
            host,
            port,
        ),
    )
    .await
    .map_err(|_| AppError::gateway_timeout("connect timeout"))?
    .map_err(AppError::bad_gateway)?;

    upstream.set_nodelay(true)?;

    let (upstream_read, mut upstream_write) = upstream.into_split();

    tokio::spawn(
        async move {
            let mut stream = body.into_data_stream();
            let mut buf = BytesMut::with_capacity(DECODE_BUF_CAPACITY);
            while let Some(chunk) = stream.next().await {
                let data = chunk.context("stream error")?;
                buf.extend_from_slice(&data);
                while let Some(decoded) = shaper::TrafficShaper::decode_from_buffer(&mut buf)? {
                    upstream_write.write_all(&decoded).await?;
                }
            }
            upstream_write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    let shaper_stream = shaper::TrafficShaper::new(upstream_read, state.traffic_config.clone());
    let padding_len = rand::rng().random_range(30..=PADDING_POOL.len());

    Ok((
        [
            ("Cache-Control", b"no-store" as &[u8]),
            ("X-Padding", &PADDING_POOL[..padding_len]),
        ],
        Body::from_stream(shaper_stream),
    ))
}

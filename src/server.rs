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
static PADDING_POOL: [u8; 62] = [b'X'; 62];

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
struct StateConfig {
    decoding_key: DecodingKey,
    socks5_proxy: Option<String>,
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

impl<E> From<E> for AppError
where
    E: std::error::Error,
{
    fn from(err: E) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::GenToken { secret, user, exp }) = cli.command {
        return handle_gen_token(secret, user, exp);
    }

    let config_content = fs::read_to_string(&cli.config)?;
    let mut config: Config = toml::from_str(&config_content)?;
    let _guard = log::init_tracing(&config.log.clone().unwrap_or_default());
    let proxy_config = create_proxy_config(&mut config).await?;

    run_server(
        build_router(proxy_config, &config.server.path),
        &config.server.listen,
    )
    .await
}

fn handle_gen_token(secret: String, user: String, exp: u64) -> anyhow::Result<()> {
    let claims = Claims { sub: user, exp };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?;
    println!("{}", token);
    Ok(())
}

async fn create_proxy_config(config: &mut Config) -> anyhow::Result<Arc<StateConfig>> {
    let mut dns_client = None;
    let mut client_subnet = None;

    if let Some(ref mut dc) = config.dns {
        dns_client = Some(dns::init_dns(dc).await?);
        client_subnet = dc.options.client_subnet;
    }

    let mut socks5_proxy = None;

    if let Some(proxy) = &config.proxy {
        socks5_proxy = proxy.socks5.clone();
    }

    Ok(Arc::new(StateConfig {
        decoding_key: DecodingKey::from_secret(config.auth.secret.as_bytes()),
        socks5_proxy,
        dns_client,
        client_subnet,
        traffic_config: config.traffic_shaping.clone(),
    }))
}

fn build_router(config: Arc<StateConfig>, path: &str) -> Router {
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
        .with_state(config)
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
        info!("listening on unix:{}", listen);
        return Ok(axum::serve(listener, app.into_make_service()).await?);
    }

    let addr: SocketAddr = listen.parse().context("invalid bind address")?;
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn validate_jwt(headers: &HeaderMap, key: &DecodingKey) -> Result<String, AppError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            warn!("rejected: missing or invalid authorization header");
            AppError(StatusCode::UNAUTHORIZED, "invalid header".into())
        })?;

    let token_data = jsonwebtoken::decode::<Claims>(auth_header, key, &Validation::default())
        .map_err(|_| {
            warn!("rejected: invalid token");
            AppError(StatusCode::UNAUTHORIZED, "invalid token".into())
        })?;

    Ok(token_data.claims.sub)
}

async fn connect_upstream(state: &StateConfig, host: &str, port: u16) -> Result<TcpStream, String> {
    if let Some(ref client) = state.dns_client {
        return client
            .connect(host, port, state.client_subnet, state.socks5_proxy.clone())
            .await
            .map_err(|e| format!("dns error: {e}"));
    }
    match state.socks5_proxy.as_deref() {
        Some(p) => Socks5Stream::connect(p, (host, port))
            .await
            .map(|s| s.into_inner())
            .map_err(|e| e.to_string()),
        None => TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string()),
    }
}

async fn tunnel_handler(
    State(state): State<Arc<StateConfig>>,
    headers: HeaderMap,
    Query(query): Query<TunnelQuery>,
    body: Body,
) -> Result<impl IntoResponse, AppError> {
    tracing::Span::current().record("user", &validate_jwt(&headers, &state.decoding_key)?);
    tracing::Span::current().record("target", &query.target);

    let auth = query
        .target
        .parse::<axum::http::uri::Authority>()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "invalid target format".into()))?;

    let host = auth.host();
    let port = auth
        .port_u16()
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "port required".into()))?;

    info!("connecting");

    let upstream_conn = tokio::time::timeout(
        Duration::from_secs(10),
        connect_upstream(&state, host, port),
    )
    .await
    .map_err(|_| AppError(StatusCode::GATEWAY_TIMEOUT, "connect timeout".into()))?
    .map_err(|e| AppError(StatusCode::BAD_GATEWAY, e))?;

    upstream_conn.set_nodelay(true)?;

    let (upstream_read, mut upstream_write) = upstream_conn.into_split();

    tokio::spawn(
        async move {
            let mut body_stream = body.into_data_stream();
            let mut buffer = BytesMut::new();
            while let Some(chunk) = body_stream.next().await {
                let data = chunk.context("stream error")?;
                buffer.extend_from_slice(&data);
                while let Some(decoded_data) =
                    shaper::TrafficShaper::decode_from_buffer(&mut buffer)?
                {
                    upstream_write.write_all(&decoded_data).await?;
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

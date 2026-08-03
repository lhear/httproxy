use httproxy::config::{
    AuthSection, BypassConfig, ClientAuthSection, ClientSection, ClientTopConfig, ServerSection,
    ServerTopConfig,
};
use httproxy::shaper::{EncodingType, PaddingConfig, TrafficConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SECRET: &str = "integration_test_secret";
pub const PATH: &str = "/integration_path";

pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

pub fn traffic(binary: bool, max_download_bytes: Option<u64>) -> TrafficConfig {
    TrafficConfig {
        global: PaddingConfig {
            padding_threshold: 0,
            padding_range: [0, 0],
        },
        stages: vec![],
        encoding_type: if binary {
            EncodingType::Binary
        } else {
            EncodingType::Json
        },
        max_download_bytes,
    }
}

pub fn make_token(user: &str, exp: u64) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &httproxy::server::Claims {
            sub: user.to_string(),
            exp,
        },
        &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

pub fn valid_token() -> String {
    make_token("test-user", 4_102_444_800)
}

pub fn server_config(
    traffic: TrafficConfig,
    private_key: Option<String>,
    max_tunnels: Option<usize>,
) -> ServerTopConfig {
    ServerTopConfig {
        server: ServerSection {
            listen: "127.0.0.1:0".to_string(),
            path: PATH.to_string(),
            private_key,
            max_tunnels,
        },
        auth: AuthSection {
            secret: SECRET.to_string(),
        },
        proxy: None,
        log: None,
        dns: None,
        traffic_shaping: traffic,
    }
}

pub fn client_config(
    traffic: TrafficConfig,
    public_key: Option<String>,
    token: Option<String>,
    bypass_files: Vec<String>,
) -> ClientTopConfig {
    ClientTopConfig {
        client: ClientSection {
            listen: "127.0.0.1:0".to_string(),
            remote: format!("http://proxy-host.invalid{PATH}"),
            address: None,
            public_key,
            auth: None,
            max_connections: None,
            max_in_flight_bytes: None,
            upload_concurrency: None,
        },
        auth: ClientAuthSection {
            token: token.unwrap_or_else(valid_token),
        },
        log: None,
        traffic_shaping: traffic,
        bypass: BypassConfig { bypass_files },
    }
}

pub async fn spawn_upstream() -> SocketAddr {
    let app = axum::Router::new()
        .route("/hello", axum::routing::get(|| async { "hello upstream" }))
        .route(
            "/large",
            axum::routing::get(|| async { vec![0xABu8; 512 * 1024] }),
        )
        .route(
            "/big",
            axum::routing::get(|| async { vec![0xCDu8; 32 * 1024 * 1024] }),
        )
        .route(
            "/echo",
            axum::routing::post(|body: axum::body::Bytes| async move { body }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    addr
}

pub async fn spawn_server(cfg: ServerTopConfig) -> SocketAddr {
    let mut cfg = cfg;
    let state = httproxy::server::build_state(&mut cfg).await.unwrap();
    let path = cfg.server.path.clone();
    let router = httproxy::server::build_router(state, &path);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });
    addr
}

pub async fn spawn_client(mut cfg: ClientTopConfig, server_addr: SocketAddr) -> SocketAddr {
    cfg.client.remote = format!("http://127.0.0.1:{}{}", server_addr.port(), PATH);
    let state = httproxy::client::build_state(&cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let http_client = Arc::new(
        wreq::Client::builder()
            .tcp_nodelay(true)
            .emulation(wreq_util::Emulation::Chrome143)
            .no_proxy()
            .dns_resolver(Arc::new(httproxy::client::state::ManualResolver {
                target_addr: server_addr.ip().to_string(),
            }))
            .build()
            .unwrap(),
    );
    let sem = Arc::new(tokio::sync::Semaphore::new(state.max_connections));
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let sem = sem.clone();
            let http_client = http_client.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire_owned().await;
                if let Err(e) = httproxy::client::connection::handle_connection_actor(
                    socket,
                    http_client,
                    state,
                )
                .await
                {
                    eprintln!("client connection error: {e:?}");
                }
            });
        }
    });
    proxy_addr
}

pub async fn raw_exchange(proxy: SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    read_response(&mut stream).await
}

pub async fn read_response(stream: &mut TcpStream) -> (u16, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            eprintln!("DBG read_response EOF after {} bytes", buf.len());
        }
        assert!(n > 0, "connection closed before headers");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        assert!(buf.len() < 64 * 1024, "headers too large");
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let status: u16 = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    let content_length = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok());
    match content_length {
        Some(len) => {
            while buf.len() - header_end < len {
                let n = stream.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            (status, buf[header_end..header_end + len].to_vec())
        }
        None => {
            loop {
                let n = stream.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            (status, buf[header_end..].to_vec())
        }
    }
}

#[allow(dead_code)]
pub async fn proxy_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT failed: {head}");
    stream
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

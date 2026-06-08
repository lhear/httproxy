pub mod actor;
pub mod connection;
pub mod constants;
pub mod handlers;
pub mod janitor;
pub mod stream;
pub mod stream_registry;
pub mod utils;

use crate::config::ServerTopConfig;
use crate::crypto;
use crate::dns::{self, DnsClient};
use crate::shaper::{EncodingType, FrameCipher, TrafficConfig};

use anyhow::Context;
use axum::serve::ListenerExt;
use axum::{Router, body::Body, routing::post};
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use stream_registry::StreamRegistry;
use tokio::sync::mpsc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use zeroize::Zeroizing;

use crate::server::actor::tunnel::TunnelCmd;

pub type MasterStoreEntry = (String, Zeroizing<[u8; 32]>, u64);

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}

#[derive(Clone)]
pub struct SessionHandle {
    pub cmd_tx: mpsc::Sender<TunnelCmd>,
    pub upload_cipher: Option<Arc<dyn FrameCipher>>,
    pub encoding: EncodingType,
}

#[derive(Clone)]
pub struct AppState {
    pub decoding_key: DecodingKey,
    pub jwt_validation: Validation,
    pub socks5_proxy: Option<Arc<str>>,
    pub dns_client: Option<Arc<DnsClient>>,
    pub client_subnet: Option<IpAddr>,
    pub traffic_config: Arc<TrafficConfig>,
    pub private_key: Option<x25519_dalek::StaticSecret>,
    pub master_store: Arc<DashMap<String, MasterStoreEntry>>,
    pub stream_registry: Arc<StreamRegistry>,
    pub actors: Arc<DashMap<String, SessionHandle>>,
    pub stream_id_counter: Arc<AtomicU64>,
}

pub async fn build_state(config: &mut ServerTopConfig) -> anyhow::Result<Arc<AppState>> {
    config
        .traffic_shaping
        .validate()
        .context("invalid traffic_shaping config")?;

    let (dns_client, client_subnet) = match config.dns {
        Some(ref mut dc) => {
            let mut dc = dc.clone();
            let client = dns::init_dns(&mut dc).await?;
            (Some(client), dc.options.client_subnet)
        }
        None => (None, None),
    };

    let private_key = config
        .server
        .private_key
        .as_deref()
        .map(crypto::b64_to_private_key)
        .transpose()?;

    Ok(Arc::new(AppState {
        decoding_key: DecodingKey::from_secret(config.auth.secret.as_bytes()),
        jwt_validation: {
            let mut v = Validation::new(Algorithm::HS256);
            v.validate_exp = true;
            v
        },
        socks5_proxy: config
            .proxy
            .as_ref()
            .and_then(|p| p.socks5.as_deref())
            .map(Arc::from),
        dns_client,
        client_subnet,
        traffic_config: Arc::new(config.traffic_shaping.clone()),
        private_key,
        master_store: Arc::new(DashMap::new()),
        stream_registry: Arc::new(StreamRegistry::new()),
        actors: Arc::new(DashMap::new()),
        stream_id_counter: Arc::new(AtomicU64::new(1)),
    }))
}

pub fn build_router(state: Arc<AppState>, path: &str) -> Router {
    use tracing::field::Empty;
    let span_state = Arc::clone(&state);
    Router::new()
        .route(path, post(handlers::dispatch))
        .layer(
            ServiceBuilder::new().layer(TraceLayer::new_for_http().make_span_with(
                move |req: &axum::http::Request<Body>| {
                    let id = span_state.stream_id_counter.fetch_add(1, Ordering::Relaxed);
                    let client = req
                        .headers()
                        .get("X-Forwarded-For")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("-");
                    tracing::info_span!("session", id, client, user = Empty, target = Empty)
                },
            )),
        )
        .with_state(state)
}

pub async fn run_server(app: Router, listen: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    if listen.contains('/') || listen.ends_with(".sock") {
        let path = std::path::Path::new(listen);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        info!("listening on unix:{listen}");
        return Ok(axum::serve(listener, app.into_make_service()).await?);
    }
    let addr: SocketAddr = listen.parse().context("invalid bind address")?;
    info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await?
        .tap_io(|tcp_stream| {
            let _ = tcp_stream.set_nodelay(true);
        });
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn spawn_janitors(
    state: &Arc<AppState>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let master_jh = tokio::spawn(janitor::master_and_stream_janitor(
        Arc::clone(&state.master_store),
        Arc::clone(&state.stream_registry),
    ));
    let stream_jh = tokio::spawn(janitor::stream_janitor(Arc::clone(&state.actors)));
    (master_jh, stream_jh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthSection, ServerSection};
    use crate::shaper;

    #[test]
    fn build_state_with_minimal_config() {
        let mut cfg = ServerTopConfig {
            server: ServerSection {
                listen: "0.0.0.0:0".into(),
                path: "/t".into(),
                private_key: None,
            },
            auth: AuthSection {
                secret: "test-key".into(),
            },
            proxy: None,
            log: None,
            dns: None,
            traffic_shaping: TrafficConfig {
                global: shaper::PaddingConfig {
                    padding_threshold: 100,
                    padding_range: [0, 50],
                },
                stages: vec![],
                encoding_type: Default::default(),
                max_download_bytes: None,
            },
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let state = rt.block_on(build_state(&mut cfg)).unwrap();
        assert!(state.private_key.is_none());
        assert!(state.dns_client.is_none());
    }
}

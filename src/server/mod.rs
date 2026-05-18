pub mod connection;
pub mod constants;
pub mod handlers;
pub mod janitor;
pub mod state;
pub mod utils;

use crate::config::ServerTopConfig;
use crate::crypto;
use crate::dns::{self, DnsClient};
use crate::shaper::TrafficConfig;

use anyhow::Context;
use axum::{Router, body::Body, routing::post};
use dashmap::{DashMap, DashSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use zeroize::Zeroizing;

pub type MasterStoreEntry = (String, Zeroizing<[u8; 32]>, u64);

pub static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub decoding_key: DecodingKey,
    pub jwt_validation: Validation,
    pub socks5_proxy: Option<Arc<str>>,
    pub dns_client: Option<Arc<DnsClient>>,
    pub client_subnet: Option<IpAddr>,
    pub traffic_config: Arc<TrafficConfig>,
    pub streams: Arc<DashMap<String, Arc<state::StreamBundle>>>,
    pub private_key: Option<x25519_dalek::StaticSecret>,
    pub master_store: Arc<DashMap<String, MasterStoreEntry>>,
    pub used_nonces: Arc<DashMap<String, DashSet<[u8; 16]>>>,
}

pub async fn build_state(config: &mut ServerTopConfig) -> anyhow::Result<Arc<AppState>> {
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
        streams: Arc::new(DashMap::new()),
        private_key,
        master_store: Arc::new(DashMap::new()),
        used_nonces: Arc::new(DashMap::new()),
    }))
}

pub fn build_router(state: Arc<AppState>, path: &str) -> Router {
    use tracing::field::Empty;
    Router::new()
        .route(path, post(handlers::dispatch))
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
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn spawn_janitors(
    state: &Arc<AppState>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let stream_handle = tokio::spawn(janitor::stream_janitor(Arc::clone(&state.streams)));
    let master_handle = tokio::spawn(janitor::master_and_nonce_janitor(
        Arc::clone(&state.master_store),
        Arc::clone(&state.used_nonces),
    ));
    (stream_handle, master_handle)
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

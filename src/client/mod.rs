pub mod actor;
pub mod connection;
pub mod constants;
pub mod handshake;
pub mod proxy;
pub mod state;
pub mod utils;

use crate::client::constants::{MAX_IN_FLIGHT_BYTES, MAX_LOCAL_CONNECTIONS, UPLOAD_CONCURRENCY};
use crate::config::ClientTopConfig;
use crate::crypto;
use crate::shaper::ResolvedShaperConfig;

use anyhow::{Context, Result};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn build_state(cfg: &ClientTopConfig) -> Result<Arc<state::SharedState>> {
    cfg.traffic_shaping
        .validate()
        .context("invalid traffic_shaping config")?;

    let max_in_flight_bytes = cfg
        .client
        .max_in_flight_bytes
        .unwrap_or(MAX_IN_FLIGHT_BYTES);
    let upload_concurrency = cfg.client.upload_concurrency.unwrap_or(UPLOAD_CONCURRENCY);
    if max_in_flight_bytes < crate::client::constants::MIN_IN_FLIGHT_BYTES {
        return Err(anyhow::anyhow!(
            "max_in_flight_bytes ({max_in_flight_bytes}) must be at least {} (one maximum-size encoded frame)",
            crate::client::constants::MIN_IN_FLIGHT_BYTES
        ));
    }
    if upload_concurrency == 0 {
        return Err(anyhow::anyhow!("upload_concurrency must be at least 1"));
    }

    let bypass = if cfg.bypass.bypass_files.is_empty() {
        None
    } else {
        let rules =
            crate::bypass::BypassRules::load(&cfg.bypass).context("failed to load bypass rules")?;
        if rules.is_empty() {
            None
        } else {
            Some(Arc::new(rules))
        }
    };

    let server_public_key = cfg
        .client
        .public_key
        .as_deref()
        .map(crypto::b64_to_public_key)
        .transpose()?;

    let remote: url::Url = cfg.client.remote.parse().context("invalid server URL")?;
    let remote_str = remote.as_str().to_owned();

    let proxy_auth = cfg.client.auth.as_ref().map(|a| {
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", a.username, a.password))
        );
        (expected, a.username.clone())
    });

    Ok(Arc::new(state::SharedState {
        remote_str,
        auth_header: format!("Bearer {}", cfg.auth.token),
        traffic_config: cfg.traffic_shaping.clone(),
        resolved_traffic: Arc::new(ResolvedShaperConfig::resolve(&cfg.traffic_shaping)),
        bypass,
        server_public_key,
        proxy_auth,
        initial_master: Mutex::new(None),
        handshake_lock: Mutex::new(()),
        max_download_bytes: cfg.traffic_shaping.max_download_bytes,
        max_connections: cfg.client.max_connections.unwrap_or(MAX_LOCAL_CONNECTIONS),
        max_in_flight_bytes,
        upload_concurrency,
    }))
}

pub mod connection;
pub mod constants;
pub mod handshake;
pub mod proxy;
pub mod state;
pub mod tunnel;
pub mod utils;

use crate::config::ClientTopConfig;
use crate::crypto;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

pub fn build_state(cfg: &ClientTopConfig) -> Result<Arc<state::SharedState>> {
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

    Ok(Arc::new(state::SharedState {
        remote_str,
        auth_header: format!("Bearer {}", cfg.auth.token),
        traffic_config: cfg.traffic_shaping.clone(),
        bypass,
        server_public_key,
        initial_master: Mutex::new(None),
        handshake_lock: OnceCell::new(),
    }))
}

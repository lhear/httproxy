pub mod actor;
pub mod connection;
pub mod constants;
pub mod cronet;
pub mod dns_cache;
pub mod handshake;
pub mod proxy;
pub mod redirect;
pub mod socks5;
pub mod state;
pub mod utils;

use crate::constants::{MAX_IN_FLIGHT_BYTES, MAX_LOCAL_CONNECTIONS, UPLOAD_CONCURRENCY};
use crate::cronet::Client;
use httproxy_core::config::ClientTopConfig;
use httproxy_core::crypto;
use httproxy_core::shaper::ResolvedShaperConfig;

use anyhow::{Context, Result, bail};
use base64::Engine;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

pub fn build_http_client(
    cfg: &ClientTopConfig,
    trusted_cert: Option<&Path>,
) -> Result<Arc<Client>> {
    let trusted_pem = trusted_cert.map(read_trusted_cert).transpose()?;
    if let Some(path) = trusted_cert {
        warn!(
            path = %path.display(),
            "trusting only the supplied certificate; the built-in Mozilla roots are disabled"
        );
    }
    if cfg.client.disable_http3 && cfg.client.http3_hint {
        bail!("client.disable_http3 and client.http3_hint cannot both be enabled");
    }
    let http3_hint = if cfg.client.http3_hint {
        let remote: url::Url = cfg.client.remote.parse().context("invalid client.remote")?;
        if remote.scheme() != "https" {
            bail!("client.http3_hint requires an https client.remote");
        }
        Some((
            remote
                .host_str()
                .context("client.remote has no host")?
                .to_owned(),
            remote
                .port_or_known_default()
                .context("client.remote has no port")?,
        ))
    } else {
        None
    };
    Client::with_http3_options(
        cfg.client.address.as_deref(),
        trusted_pem.as_deref(),
        cfg.client.disable_http3,
        http3_hint
            .as_ref()
            .map(|(host, port)| (host.as_str(), *port)),
    )
    .context("failed to start cronet engine")
}

fn read_trusted_cert(path: &Path) -> Result<Vec<u8>> {
    let pem = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if pem.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(pem)
}

pub fn build_state(cfg: &ClientTopConfig) -> Result<Arc<state::SharedState>> {
    cfg.traffic_shaping
        .validate()
        .context("invalid traffic_shaping config")?;

    if let Some(auth) = &cfg.client.proxy_auth {
        if auth.username.is_empty() || auth.username.len() > u8::MAX as usize {
            bail!("client.proxy_auth.username must be 1 to 255 bytes");
        }
        if auth.password.is_empty() || auth.password.len() > u8::MAX as usize {
            bail!("client.proxy_auth.password must be 1 to 255 bytes");
        }
    }

    let bypass = if cfg.bypass.bypass_files.is_empty() {
        None
    } else {
        let rules = httproxy_core::bypass::BypassRules::load(&cfg.bypass)
            .context("failed to load bypass rules")?;
        if rules.is_empty() {
            None
        } else {
            Some(Arc::new(rules))
        }
    };

    let server_public_key =
        crypto::b64_to_public_key(&cfg.client.public_key).context("invalid client.public_key")?;

    let remote: url::Url = cfg.client.remote.parse().context("invalid server URL")?;
    let remote_str = remote.as_str().to_owned();

    let proxy_auth = cfg.client.proxy_auth.as_ref().map(|a| {
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", a.username, a.password))
        );
        state::ProxyAuth {
            http_header: expected,
            username: a.username.clone(),
            password: a.password.clone(),
        }
    });

    Ok(Arc::new(state::SharedState {
        remote_str,
        auth_token: cfg.auth.token.clone(),
        traffic_config: cfg.traffic_shaping.clone(),
        resolved_traffic: Arc::new(ResolvedShaperConfig::resolve(&cfg.traffic_shaping)),
        bypass,
        server_public_key: Arc::new(server_public_key),
        proxy_auth,
        initial_master: Mutex::new(None),
        handshake_lock: Mutex::new(()),
        max_download_bytes: cfg.traffic_shaping.max_download_bytes,
        max_connections: MAX_LOCAL_CONNECTIONS,
        max_in_flight_bytes: MAX_IN_FLIGHT_BYTES,
        upload_concurrency: UPLOAD_CONCURRENCY,
        dns_cache: crate::dns_cache::DnsCache::default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_client_cfg() -> httproxy_core::config::ClientTopConfig {
        let (_, public_key) = crypto::generate_keypair();
        let public_key = crypto::public_key_to_b64(&public_key);
        toml::from_str(&format!(
            r#"
[client]
listen = "127.0.0.1:8080"
remote = "https://example.com/secret"
public_key = "{public_key}"

[auth]
token = "tok"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50
"#,
        ))
        .unwrap()
    }

    #[test]
    fn build_http_client_reports_a_missing_certificate() {
        let cfg = minimal_client_cfg();
        let error = build_http_client(&cfg, Some(Path::new("no-such-certificate.pem")))
            .err()
            .expect("a missing certificate file must be reported");
        assert!(
            format!("{error:#}").contains("no-such-certificate.pem"),
            "{error:#}"
        );
    }

    #[test]
    fn http3_hint_requires_https_and_conflicts_with_disable_http3() {
        let mut cfg = minimal_client_cfg();
        cfg.client.remote = "http://example.com/secret".to_owned();
        cfg.client.http3_hint = true;
        assert!(build_http_client(&cfg, None).is_err());

        cfg.client.remote = "https://example.com/secret".to_owned();
        cfg.client.disable_http3 = true;
        assert!(build_http_client(&cfg, None).is_err());
    }
}

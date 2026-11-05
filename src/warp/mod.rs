pub(crate) mod h3;
pub(crate) mod masque;
pub(crate) mod register;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use masque::{MasqueConfig, MasqueConn, MasqueStream};

const DEFAULT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
const DEFAULT_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(25);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const FALLBACK_ENDPOINT: &str = "162.159.192.1";

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WarpSection {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub endpoint_v6: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub keepalive_secs: Option<u64>,
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub register_model: Option<String>,
    #[serde(default)]
    pub register_locale: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default = "yes")]
    pub bypass_private: bool,
    #[serde(default)]
    pub bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub bypass_suffixes: Vec<String>,
}

fn yes() -> bool {
    true
}

pub struct WarpClient {
    endpoint: quinn::Endpoint,
    masque: MasqueConfig,
    cached: RwLock<Option<Arc<MasqueConn>>>,
    establishing: Mutex<()>,
    bypass: Bypass,
}

impl WarpClient {
    pub async fn init(section: &WarpSection) -> Result<Arc<Self>> {
        let path = section
            .config_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(register::default_path);
        let opts = register::RegisterOptions {
            model: section
                .register_model
                .as_deref()
                .unwrap_or(register::DEFAULT_MODEL),
            locale: section
                .register_locale
                .as_deref()
                .unwrap_or(register::DEFAULT_LOCALE),
        };

        let creds = register::load_or_register(&path, &opts)
            .await
            .context("warp: cannot obtain credentials")?;
        let signing_key = creds.signing_key()?;

        let pin = if section.insecure_skip_verify {
            warn!("warp: endpoint certificate pinning is disabled");
            None
        } else {
            Some(creds.endpoint_spki()?)
        };
        let tls = masque::build_tls_config(&signing_key, pin)?;

        let addr = resolve_endpoint(section, &creds)?;
        let port = section.port.unwrap_or(DEFAULT_PORT);

        let keepalive = Duration::from_secs(section.keepalive_secs.unwrap_or(KEEPALIVE.as_secs()));
        let idle_timeout =
            Duration::from_secs(section.idle_timeout_secs.unwrap_or(IDLE_TIMEOUT.as_secs()));

        let masque = MasqueConfig {
            endpoint: SocketAddr::new(addr, port),
            sni: section
                .sni
                .clone()
                .unwrap_or_else(|| DEFAULT_SNI.to_string()),
            connect_timeout: Duration::from_secs(
                section
                    .connect_timeout_secs
                    .unwrap_or(CONNECT_TIMEOUT.as_secs()),
            ),
            keepalive,
            idle_timeout,
            tls,
        };

        let bind: SocketAddr = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .with_context(|| format!("warp: cannot bind UDP socket {bind}"))?;
        endpoint.set_default_client_config(masque.client_config()?);

        info!(
            endpoint = %masque.endpoint,
            sni = %masque.sni,
            "warp: outbound enabled"
        );

        Ok(Arc::new(Self {
            endpoint,
            masque,
            cached: RwLock::new(None),
            establishing: Mutex::new(()),
            bypass: Bypass::new(section)?,
        }))
    }

    pub(crate) fn is_direct_ip(&self, ip: IpAddr) -> bool {
        self.bypass.contains(ip)
    }

    pub(crate) fn is_direct_name(&self, host: &str) -> bool {
        self.bypass.name_is_direct(host)
    }

    pub(crate) async fn dial(&self, ip: IpAddr, port: u16) -> Result<MasqueStream> {
        let authority = authority(ip, port);
        let mut last_error = None;
        for attempt in 0..2 {
            let conn = self.connection().await?;
            match conn.open(&authority).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    let stale = !conn.is_usable();
                    if stale {
                        self.invalidate(&conn).await;
                    }
                    debug!(
                        authority = %authority,
                        attempt,
                        stale,
                        error = %e,
                        "warp: CONNECT failed"
                    );
                    last_error = Some(e);
                    if !stale {
                        break;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("warp: CONNECT failed")))
    }

    async fn connection(&self) -> Result<Arc<MasqueConn>> {
        if let Some(conn) = self.cached.read().await.as_ref()
            && conn.is_usable()
        {
            return Ok(Arc::clone(conn));
        }

        let _guard = self.establishing.lock().await;
        if let Some(conn) = self.cached.read().await.as_ref()
            && conn.is_usable()
        {
            return Ok(Arc::clone(conn));
        }

        let conn = Arc::new(MasqueConn::establish(&self.endpoint, &self.masque).await?);
        *self.cached.write().await = Some(Arc::clone(&conn));
        Ok(conn)
    }

    async fn invalidate(&self, stale: &Arc<MasqueConn>) {
        let mut guard = self.cached.write().await;
        if guard
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, stale))
        {
            stale.close();
            *guard = None;
        }
    }
}

fn resolve_endpoint(section: &WarpSection, creds: &register::WarpCredentials) -> Result<IpAddr> {
    let raw = section
        .endpoint_v6
        .as_deref()
        .or(section.endpoint.as_deref())
        .filter(|s| !s.is_empty())
        .or_else(|| (!creds.endpoint_v4.is_empty()).then_some(creds.endpoint_v4.as_str()))
        .or_else(|| (!creds.endpoint_v6.is_empty()).then_some(creds.endpoint_v6.as_str()))
        .unwrap_or(FALLBACK_ENDPOINT);

    let trimmed = raw.trim_start_matches('[').trim_end_matches(']');
    IpAddr::from_str(trimmed).with_context(|| format!("warp: invalid endpoint address `{raw}`"))
}

fn authority(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

struct Bypass {
    private: bool,
    networks: Vec<ip_network::IpNetwork>,
    suffixes: Vec<String>,
}

impl Bypass {
    fn new(section: &WarpSection) -> Result<Self> {
        let mut networks = Vec::with_capacity(section.bypass_cidrs.len());
        for cidr in &section.bypass_cidrs {
            let network = ip_network::IpNetwork::from_str(cidr)
                .with_context(|| format!("warp: invalid bypass_cidrs entry `{cidr}`"))?;
            networks.push(network);
        }
        Ok(Self {
            private: section.bypass_private,
            networks,
            suffixes: section
                .bypass_suffixes
                .iter()
                .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    fn name_is_direct(&self, host: &str) -> bool {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if bare.eq_ignore_ascii_case("localhost") {
            return true;
        }
        let lower = bare.to_ascii_lowercase();
        self.suffixes.iter().any(|s| {
            lower == *s
                || lower
                    .strip_suffix(s.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        if self.networks.iter().any(|n| n.contains(ip)) {
            return true;
        }
        if !self.private {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => is_private_v4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => is_private_v4(v4),
                None => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_unique_local()
                        || v6.is_unicast_link_local()
                        || v6.is_multicast()
                }
            },
        }
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass(private: bool, cidrs: &[&str]) -> Bypass {
        Bypass {
            private,
            networks: cidrs
                .iter()
                .map(|c| ip_network::IpNetwork::from_str(c).unwrap())
                .collect(),
            suffixes: Vec::new(),
        }
    }

    fn direct(b: &Bypass, host: &str) -> bool {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match IpAddr::from_str(bare) {
            Ok(ip) => b.contains(ip),
            Err(_) => b.name_is_direct(host),
        }
    }

    fn bypass_with_suffixes(suffixes: &[&str]) -> Bypass {
        Bypass {
            private: true,
            networks: Vec::new(),
            suffixes: suffixes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn private_targets_are_direct() {
        let b = bypass(true, &[]);
        for host in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.7",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "localhost",
            "[::1]",
        ] {
            assert!(direct(&b, host), "{host} should bypass WARP");
        }
    }

    #[test]
    fn public_targets_go_through_warp() {
        let b = bypass(true, &[]);
        for host in ["1.1.1.1", "2606:4700::1111", "example.com", "8.8.8.8"] {
            assert!(!direct(&b, host), "{host} should use WARP");
        }
    }

    #[test]
    fn bypass_private_can_be_disabled() {
        let b = bypass(false, &[]);
        assert!(!direct(&b, "10.0.0.1"));
        assert!(direct(&b, "localhost"));
    }

    #[test]
    fn bypass_suffixes_match_only_full_labels() {
        let b = bypass_with_suffixes(&["corp.local"]);
        assert!(direct(&b, "db.corp.local"));
        assert!(direct(&b, "CORP.LOCAL"));
        assert!(!direct(&b, "evilcorp.local"));
        assert!(!direct(&b, "corp.local.example.com"));
    }

    #[test]
    fn extra_cidrs_are_honoured() {
        let b = bypass(false, &["203.0.113.0/24"]);
        assert!(direct(&b, "203.0.113.9"));
        assert!(!direct(&b, "203.0.114.9"));
    }

    #[test]
    fn ipv4_mapped_addresses_are_classified_by_their_v4_form() {
        let b = bypass(true, &[]);
        assert!(direct(&b, "::ffff:10.0.0.1"));
        assert!(!direct(&b, "::ffff:1.1.1.1"));
    }

    #[test]
    fn authority_is_always_ip_literal() {
        assert_eq!(authority("1.1.1.1".parse().unwrap(), 80), "1.1.1.1:80");
        assert_eq!(
            authority("2606:4700::1".parse().unwrap(), 443),
            "[2606:4700::1]:443"
        );
    }

    fn creds(v4: &str, v6: &str) -> register::WarpCredentials {
        register::WarpCredentials {
            id: "id".into(),
            access_token: "t".into(),
            private_key: "x".into(),
            endpoint_pub_key: "y".into(),
            ipv4: String::new(),
            ipv6: String::new(),
            endpoint_v4: v4.into(),
            endpoint_v6: v6.into(),
        }
    }

    fn section() -> WarpSection {
        WarpSection {
            enabled: true,
            config_path: None,
            endpoint: None,
            endpoint_v6: None,
            port: None,
            sni: None,
            connect_timeout_secs: None,
            keepalive_secs: None,
            idle_timeout_secs: None,
            register_model: None,
            register_locale: None,
            insecure_skip_verify: false,
            bypass_private: true,
            bypass_cidrs: vec![],
            bypass_suffixes: vec![],
        }
    }

    #[test]
    fn endpoint_prefers_config_then_credentials() {
        let c = creds("162.159.192.7", "");
        assert_eq!(
            resolve_endpoint(&section(), &c).unwrap(),
            "162.159.192.7".parse::<IpAddr>().unwrap()
        );

        let explicit = WarpSection {
            endpoint: Some("162.159.192.9".into()),
            ..section()
        };
        assert_eq!(
            resolve_endpoint(&explicit, &c).unwrap(),
            "162.159.192.9".parse::<IpAddr>().unwrap()
        );

        let c = creds("162.159.192.7", "2606:4700:d0::1");
        assert_eq!(
            resolve_endpoint(&section(), &c).unwrap(),
            "162.159.192.7".parse::<IpAddr>().unwrap()
        );

        let explicit_v6 = WarpSection {
            endpoint_v6: Some("2606:4700:d0::9".into()),
            ..section()
        };
        assert_eq!(
            resolve_endpoint(&explicit_v6, &c).unwrap(),
            "2606:4700:d0::9".parse::<IpAddr>().unwrap()
        );

        let c = creds("", "");
        assert_eq!(
            resolve_endpoint(&section(), &c).unwrap(),
            FALLBACK_ENDPOINT.parse::<IpAddr>().unwrap()
        );
    }
}

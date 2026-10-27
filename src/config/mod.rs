use serde::Deserialize;

use crate::log::LogConfig;

pub use crate::bypass::BypassConfig;
pub use crate::shaper::TrafficConfig;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServerTopConfig {
    pub server: ServerSection,
    pub auth: AuthSection,
    pub proxy: Option<ProxySection>,
    pub log: Option<LogConfig>,
    pub dns: Option<crate::dns::DnsConfig>,
    pub traffic_shaping: TrafficConfig,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClientTopConfig {
    pub client: ClientSection,
    pub auth: ClientAuthSection,
    pub log: Option<LogConfig>,
    pub traffic_shaping: TrafficConfig,
    #[serde(default)]
    pub bypass: BypassConfig,
    /// `[[redirect]]` 本地端口转发（等价于 ssh -L）
    #[serde(default)]
    pub redirect: Vec<RedirectSection>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RedirectSection {
    /// 本地监听地址，必须是 `ip:port`
    pub listen: String,
    /// 隧道另一端的 `host:port`
    pub target: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    pub secret: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ProxySection {
    pub socks5: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub listen: String,
    pub path: String,
    pub private_key: Option<String>,
    #[serde(default)]
    pub max_tunnels: Option<usize>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub listen: String,
    pub remote: String,
    pub address: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub auth: Option<ClientProxyAuth>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default)]
    pub max_in_flight_bytes: Option<usize>,
    #[serde(default)]
    pub upload_concurrency: Option<usize>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthSection {
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_server_config() {
        let toml_str = r#"
[server]
listen = "127.0.0.1:3000"
path = "/secret"

[auth]
secret = "key"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50
"#;
        let cfg: ServerTopConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1:3000");
        assert_eq!(cfg.server.path, "/secret");
        assert!(cfg.proxy.is_none());
    }

    #[test]
    fn parse_minimal_client_config() {
        let toml_str = r#"
[client]
listen = "127.0.0.1:8080"
remote = "https://example.com/secret"

[auth]
token = "mytoken"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50
"#;
        let cfg: ClientTopConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.client.listen, "127.0.0.1:8080");
        assert_eq!(cfg.auth.token, "mytoken");
    }

    #[test]
    fn parse_client_redirect_rules() {
        let toml_str = r#"
[client]
listen = "127.0.0.1:8080"
remote = "https://example.com/secret"

[auth]
token = "mytoken"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50

[[redirect]]
listen = "127.0.0.1:2222"
target = "172.16.0.207:22"

[[redirect]]
listen = "127.0.0.1:2223"
target = "example.com:443"
"#;
        let cfg: ClientTopConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.redirect.len(), 2);
        assert_eq!(cfg.redirect[0].listen, "127.0.0.1:2222");
        assert_eq!(cfg.redirect[0].target, "172.16.0.207:22");
        assert_eq!(cfg.redirect[1].target, "example.com:443");
    }
}

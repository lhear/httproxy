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
    /// 上传侧合并窗口（毫秒）。默认 0，表示一凑够就发；设成 1~2 可以把
    /// 先后到达的几个小帧并进同一个 POST，代价是每批最多多等这么久。
    #[serde(default)]
    pub upload_coalesce_ms: Option<u64>,
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
        assert_eq!(cfg.client.upload_coalesce_ms, None);
    }

    #[test]
    fn parse_client_upload_coalesce() {
        let toml_str = r#"
[client]
listen = "127.0.0.1:8080"
remote = "https://example.com/secret"
upload_coalesce_ms = 2

[auth]
token = "mytoken"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50
"#;
        let cfg: ClientTopConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.client.upload_coalesce_ms, Some(2));
    }
}

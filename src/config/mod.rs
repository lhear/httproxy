use serde::Deserialize;
use std::fmt::Write as _;

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
    /// 虚拟 IP：声明本机在这张虚拟内网里的地址。
    ///
    /// 它只是一个会合地址——服务端不会去连它，而是在自己的注册表里查“谁持有
    /// 这个地址”，再把流量沿该客户端的长连接送过去。
    #[serde(default)]
    pub virtual_ip: Option<String>,
    /// 在虚拟 IP 上响应哪些本地端口，必须是数组或范围（可混写），
    /// 与 `virtual_ip` 同配同缺。
    #[serde(default)]
    pub virtual_ports: Option<PortSet>,
}

/// 一组端口。
///
/// 配置里支持三种写法（也可以混写）：
///
/// ```toml
/// virtual_ports = 8080
/// virtual_ports = "8000-8100"
/// virtual_ports = [80, 443, "8000-8100"]
/// ```
///
/// 内部按升序去重保存，`contains` 走二分查找。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortSet(Vec<u16>);

impl PortSet {
    pub fn new(mut ports: Vec<u16>) -> Self {
        ports.retain(|p| *p != 0);
        ports.sort_unstable();
        ports.dedup();
        Self(ports)
    }

    #[inline]
    pub fn contains(&self, port: u16) -> bool {
        self.0.binary_search(&port).is_ok()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 线上格式：连续的端口压缩成区间，例如 `80,443,8000-8100`。
    ///
    /// 服务端收到后用 [`PortSet::parse_list`] 还原成同一个集合，因此端口白名单
    /// 的判定基准始终是客户端配置里声明的那一份。
    pub fn to_header(&self) -> String {
        let mut out = String::new();
        let mut i = 0;
        while i < self.0.len() {
            let start = self.0[i];
            let mut end = start;
            while i + 1 < self.0.len() && self.0[i + 1] == end + 1 {
                i += 1;
                end = self.0[i];
            }
            if !out.is_empty() {
                out.push(',');
            }
            if start == end {
                let _ = write!(out, "{start}");
            } else {
                let _ = write!(out, "{start}-{end}");
            }
            i += 1;
        }
        out
    }

    /// 解析 `80,443,8000-8100` 形式的端口列表（逗号分隔，允许区间）。
    pub fn parse_list(list: &str) -> Result<Self, String> {
        let mut ports = Vec::new();
        for item in list.split(',') {
            ports.extend(parse_port_item(item)?);
        }
        let set = Self::new(ports);
        if set.is_empty() {
            return Err("port list is empty".to_string());
        }
        Ok(set)
    }
}

fn parse_port_number(raw: &str) -> Result<u16, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty port number".to_string());
    }
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("invalid port number: {raw}"))?;
    if value == 0 || value > u16::MAX as u32 {
        return Err(format!("port out of range (1-65535): {raw}"));
    }
    Ok(value as u16)
}

/// 解析单个条目：`80` 或 `8000-8100`（闭区间）。
fn parse_port_item(item: &str) -> Result<Vec<u16>, String> {
    let item = item.trim();
    if item.is_empty() {
        return Err("empty port entry".to_string());
    }
    match item.split_once('-') {
        Some((lo, hi)) => {
            let lo = parse_port_number(lo)?;
            let hi = parse_port_number(hi)?;
            if lo > hi {
                return Err(format!("invalid port range (low > high): {item}"));
            }
            Ok((lo..=hi).collect())
        }
        None => Ok(vec![parse_port_number(item)?]),
    }
}

impl<'de> Deserialize<'de> for PortSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PortItem {
            Num(i64),
            Text(String),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            One(PortItem),
            Many(Vec<PortItem>),
        }

        let repr = Repr::deserialize(deserializer)?;
        let items = match repr {
            Repr::One(item) => vec![item],
            Repr::Many(items) => items,
        };

        let mut ports = Vec::new();
        for item in items {
            match item {
                PortItem::Num(n) => {
                    if n <= 0 || n > u16::MAX as i64 {
                        return Err(serde::de::Error::custom(format!(
                            "port out of range (1-65535): {n}"
                        )));
                    }
                    ports.push(n as u16);
                }
                PortItem::Text(text) => {
                    ports.extend(parse_port_item(&text).map_err(serde::de::Error::custom)?);
                }
            }
        }

        let set = PortSet::new(ports);
        if set.is_empty() {
            return Err(serde::de::Error::custom(
                "virtual_ports must list at least one port",
            ));
        }
        Ok(set)
    }
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

    fn client_with_vnet(extra: &str) -> Result<ClientTopConfig, toml::de::Error> {
        toml::from_str(&format!(
            r#"
[client]
listen = "127.0.0.1:8080"
remote = "https://example.com/secret"
{extra}

[auth]
token = "mytoken"

[traffic_shaping.global]
padding_range = [0, 100]
padding_threshold = 50
"#
        ))
    }

    #[test]
    fn virtual_ports_accepts_array_and_range() {
        let cfg = client_with_vnet(
            r#"virtual_ip = "10.0.0.5"
virtual_ports = [80, 443, "8000-8002"]"#,
        )
        .unwrap();
        assert_eq!(cfg.client.virtual_ip.as_deref(), Some("10.0.0.5"));
        let ports = cfg.client.virtual_ports.unwrap();
        assert_eq!(ports.as_slice(), &[80, 443, 8000, 8001, 8002]);
        assert!(ports.contains(8001));
        assert!(!ports.contains(8003));

        let cfg = client_with_vnet(
            r#"virtual_ip = "10.0.0.5"
virtual_ports = "7000-7003""#,
        )
        .unwrap();
        assert_eq!(
            cfg.client.virtual_ports.unwrap().as_slice(),
            &[7000, 7001, 7002, 7003]
        );

        let cfg = client_with_vnet(
            r#"virtual_ip = "10.0.0.5"
virtual_ports = 22"#,
        )
        .unwrap();
        assert_eq!(cfg.client.virtual_ports.unwrap().as_slice(), &[22]);
    }

    #[test]
    fn virtual_ports_sorts_and_dedups() {
        let cfg = client_with_vnet(
            r#"virtual_ip = "10.0.0.5"
virtual_ports = [443, 80, "80-81"]"#,
        )
        .unwrap();
        assert_eq!(cfg.client.virtual_ports.unwrap().as_slice(), &[80, 81, 443]);
    }

    #[test]
    fn virtual_ports_rejects_bad_values() {
        for bad in [
            r#"virtual_ports = []"#,
            r#"virtual_ports = 0"#,
            r#"virtual_ports = 70000"#,
            r#"virtual_ports = "9000-8000""#,
            r#"virtual_ports = "abc""#,
            r#"virtual_ports = ["80", "x-y"]"#,
        ] {
            let extra = format!("virtual_ip = \"10.0.0.5\"\n{bad}");
            assert!(client_with_vnet(&extra).is_err(), "must reject: {bad}");
        }
    }

    #[test]
    fn vnet_fields_are_optional() {
        let cfg = client_with_vnet("").unwrap();
        assert!(cfg.client.virtual_ip.is_none());
        assert!(cfg.client.virtual_ports.is_none());
    }

    #[test]
    fn port_set_header_roundtrip() {
        let set = PortSet::new(vec![80, 81, 82, 443, 8000, 8001]);
        assert_eq!(set.to_header(), "80-82,443,8000-8001");
        assert_eq!(PortSet::parse_list(&set.to_header()).unwrap(), set);

        let single = PortSet::new(vec![22]);
        assert_eq!(single.to_header(), "22");
        assert_eq!(PortSet::parse_list("22").unwrap(), single);
    }

    #[test]
    fn port_set_parse_list_rejects_garbage() {
        assert!(PortSet::parse_list("").is_err());
        assert!(PortSet::parse_list("80,,443").is_err());
        assert!(PortSet::parse_list("0").is_err());
        assert!(PortSet::parse_list("65536").is_err());
        assert!(PortSet::parse_list("100-99").is_err());
        assert_eq!(
            PortSet::parse_list(" 80 , 443 ").unwrap().as_slice(),
            &[80, 443]
        );
    }
}

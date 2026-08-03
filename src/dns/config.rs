use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

fn deserialize_upstream<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
    String::deserialize(d)?
        .parse()
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Deserialize, Debug)]
pub struct DnsConfig {
    #[serde(deserialize_with = "deserialize_upstream")]
    pub upstream: SocketAddr,
    pub tls_domain: Option<String>,
    #[serde(flatten, default)]
    pub options: DnsOptions,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(default)]
pub struct DnsOptions {
    #[serde(rename = "protocol")]
    pub protocol: Protocol,
    pub prefer_ipv6: bool,
    pub cache_size: u64,
    pub client_subnet: Option<IpAddr>,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub swr_ttl: u64,
    pub empty_ttl: u64,
    pub happy_eyeballs_delay_ms: u64,
    pub max_concurrent_queries: usize,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            protocol: Protocol::Udp,
            prefer_ipv6: false,
            cache_size: 1024,
            client_subnet: None,
            min_ttl: 30,
            max_ttl: 3600,
            swr_ttl: 3600,
            empty_ttl: 300,
            happy_eyeballs_delay_ms: 250,
            max_concurrent_queries: 1024,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Dot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_parsed_from_string() {
        let cfg: DnsConfig = toml::from_str("upstream = \"8.8.8.8:53\"\n").unwrap();
        assert_eq!(cfg.upstream, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
        assert!(cfg.tls_domain.is_none());
    }

    #[test]
    fn defaults_applied() {
        let cfg: DnsConfig = toml::from_str("upstream = \"8.8.8.8:53\"\n").unwrap();
        assert_eq!(cfg.options.protocol, Protocol::Udp);
        assert!(!cfg.options.prefer_ipv6);
        assert_eq!(cfg.options.cache_size, 1024);
        assert_eq!(cfg.options.min_ttl, 30);
        assert_eq!(cfg.options.max_ttl, 3600);
        assert_eq!(cfg.options.empty_ttl, 300);
        assert_eq!(cfg.options.max_concurrent_queries, 1024);
    }

    #[test]
    fn explicit_fields_override_defaults() {
        let cfg: DnsConfig =
            toml::from_str("upstream = \"1.1.1.1:853\"\nprotocol = \"dot\"\ncache_size = 64\n")
                .unwrap();
        assert_eq!(cfg.options.protocol, Protocol::Dot);
        assert_eq!(cfg.options.cache_size, 64);
    }

    #[test]
    fn invalid_upstream_rejected() {
        let r: Result<DnsConfig, _> = toml::from_str("upstream = \"not-an-address\"\n");
        assert!(r.is_err());
    }
}

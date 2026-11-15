use anyhow::{Context, Result};
use fst::{Set, SetBuilder};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use serde::Deserialize;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[derive(Deserialize, Debug, Clone, Default)]
pub struct BypassConfig {
    #[serde(default)]
    pub bypass_files: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
struct BypassFile {
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    ip_cidr: Vec<String>,
}

const MAX_DOMAIN_LEN: usize = 253;

#[inline]
fn domain_to_fst_key(domain: &str) -> Option<Box<[u8]>> {
    let domain = domain.trim_matches('.');
    if domain.is_empty() {
        return None;
    }

    let bytes = domain.as_bytes();
    let mut buf = Vec::with_capacity(bytes.len());

    let mut end = bytes.len();
    let mut first = true;
    while end > 0 {
        let mut start = end;
        while start > 0 && bytes[start - 1] != b'.' {
            start -= 1;
        }

        if !first {
            buf.push(b'\x00');
        }
        first = false;

        buf.extend(bytes[start..end].iter().map(|b| b.to_ascii_lowercase()));

        end = if start > 0 { start - 1 } else { 0 };
    }

    Some(buf.into_boxed_slice())
}

struct DomainFst {
    set: Set<Vec<u8>>,
}

impl DomainFst {
    fn from_sorted_keys(keys: Vec<Box<[u8]>>) -> Result<Self> {
        let mut builder = SetBuilder::memory();
        for key in &keys {
            builder.insert(key).context("fst insert domain key")?;
        }

        drop(keys);

        let fst_bytes = builder.into_inner().context("fst finalize")?;
        let set = Set::new(fst_bytes).context("fst build set")?;
        Ok(Self { set })
    }

    #[inline]
    fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_matches('.');
        if domain.is_empty() {
            return false;
        }

        let bytes = domain.as_bytes();
        let mut buf = Vec::with_capacity(bytes.len().min(MAX_DOMAIN_LEN));
        let mut end = bytes.len();
        let mut first = true;

        while end > 0 {
            let mut start = end;
            while start > 0 && bytes[start - 1] != b'.' {
                start -= 1;
            }

            if !first {
                buf.push(b'\x00');
            }
            first = false;

            buf.extend(bytes[start..end].iter().map(|b| b.to_ascii_lowercase()));

            if self.set.contains(&buf) {
                return true;
            }

            end = if start > 0 { start - 1 } else { 0 };
        }

        false
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

struct IpCidrTable {
    table: IpNetworkTable<()>,
}

impl IpCidrTable {
    fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }

    fn insert_v4(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let net = IpNetwork::new(IpAddr::V4(addr), prefix_len)
            .with_context(|| format!("invalid IPv4 CIDR {addr}/{prefix_len}"))?;
        self.table.insert(net, ());
        Ok(())
    }

    fn insert_v6(&mut self, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let net = IpNetwork::new(IpAddr::V6(addr), prefix_len)
            .with_context(|| format!("invalid IPv6 CIDR {addr}/{prefix_len}"))?;
        self.table.insert(net, ());
        Ok(())
    }

    #[inline]
    fn contains(&self, ip: IpAddr) -> bool {
        self.table.longest_match(ip).is_some()
    }

    fn is_empty(&self) -> bool {
        let (v4len, v6len) = self.table.len();
        v4len == 0 && v6len == 0
    }
}

pub struct BypassRulesBuilder {
    domain_keys: Vec<Box<[u8]>>,
    ip_table: IpCidrTable,
}

impl Default for BypassRulesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassRulesBuilder {
    pub fn new() -> Self {
        Self {
            domain_keys: Vec::new(),
            ip_table: IpCidrTable::new(),
        }
    }

    pub fn add_domain(&mut self, domain: &str) {
        if let Some(key) = domain_to_fst_key(domain) {
            self.domain_keys.push(key);
        }
    }

    pub fn add_cidr(&mut self, cidr: &str) -> Result<()> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .with_context(|| format!("missing '/' in CIDR `{cidr}`"))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix length in `{cidr}`"))?;

        match IpAddr::from_str(addr_str)
            .with_context(|| format!("invalid IP address in `{cidr}`"))?
        {
            IpAddr::V4(addr) => {
                anyhow::ensure!(prefix_len <= 32, "IPv4 prefix > 32 in `{cidr}`");
                self.ip_table.insert_v4(addr, prefix_len)?;
            }
            IpAddr::V6(addr) => {
                anyhow::ensure!(prefix_len <= 128, "IPv6 prefix > 128 in `{cidr}`");
                self.ip_table.insert_v6(addr, prefix_len)?;
            }
        }
        Ok(())
    }

    pub fn build(mut self) -> Result<BypassRules> {
        self.domain_keys.sort_unstable();
        self.domain_keys.dedup();

        let domain_fst = DomainFst::from_sorted_keys(self.domain_keys)?;

        Ok(BypassRules {
            domain_fst,
            ip_table: self.ip_table,
        })
    }
}

pub struct BypassRules {
    domain_fst: DomainFst,
    ip_table: IpCidrTable,
}

impl BypassRules {
    pub fn load(cfg: &BypassConfig) -> Result<Self> {
        let mut builder = BypassRulesBuilder::new();

        for path in &cfg.bypass_files {
            let content =
                fs::read_to_string(path).with_context(|| format!("read bypass file: {path}"))?;
            let file: BypassFile = serde_json::from_str(&content)
                .with_context(|| format!("parse bypass file: {path}"))?;

            for domain in &file.domain_suffix {
                builder.add_domain(domain);
            }
            for cidr in &file.ip_cidr {
                builder
                    .add_cidr(cidr)
                    .with_context(|| format!("in file {path}"))?;
            }
        }

        builder.build()
    }

    #[inline]
    pub fn match_domain(&self, domain: &str) -> bool {
        self.domain_fst.matches(domain)
    }

    #[inline]
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.ip_table.contains(ip)
    }

    pub fn should_bypass(&self, target: &str) -> bool {
        let host = extract_host(target);
        if let Ok(ip) = IpAddr::from_str(host) {
            return self.match_ip(ip);
        }
        self.match_domain(host)
    }

    pub fn is_empty(&self) -> bool {
        self.domain_fst.is_empty() && self.ip_table.is_empty()
    }
}

#[inline]
fn extract_host(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(target);
    }
    target.split(':').next().unwrap_or(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rules(domains: &[&str], cidrs: &[&str]) -> BypassRules {
        let mut b = BypassRulesBuilder::new();
        for d in domains {
            b.add_domain(d);
        }
        for c in cidrs {
            b.add_cidr(c).unwrap();
        }
        b.build().unwrap()
    }

    #[test]
    fn domain_exact_match() {
        let r = make_rules(&["example.com"], &[]);
        assert!(r.match_domain("example.com"));
        assert!(r.match_domain("sub.example.com"));
        assert!(r.match_domain("deep.sub.example.com"));
        assert!(!r.match_domain("notexample.com"));
        assert!(!r.match_domain("com"));
    }

    #[test]
    fn domain_tld_wildcard() {
        let r = make_rules(&["com"], &[]);
        assert!(r.match_domain("anything.com"));
        assert!(r.match_domain("a.b.c.com"));
        assert!(!r.match_domain("anything.net"));
    }

    #[test]
    fn domain_case_insensitive() {
        let r = make_rules(&["Example.COM"], &[]);
        assert!(r.match_domain("example.com"));
        assert!(r.match_domain("Sub.Example.Com"));
        assert!(!r.match_domain("other.net"));
    }

    #[test]
    fn domain_dedup() {
        let r = make_rules(&["example.com", "example.com", ".example.com"], &[]);
        assert!(r.match_domain("example.com"));
        assert!(r.match_domain("sub.example.com"));
    }

    #[test]
    fn ip_exact() {
        let r = make_rules(&[], &["1.1.1.1/32"]);
        assert!(r.match_ip("1.1.1.1".parse().unwrap()));
        assert!(!r.match_ip("1.1.1.2".parse().unwrap()));
    }

    #[test]
    fn ip_subnet() {
        let r = make_rules(&[], &["8.8.8.0/24"]);
        assert!(r.match_ip("8.8.8.1".parse().unwrap()));
        assert!(r.match_ip("8.8.8.254".parse().unwrap()));
        assert!(!r.match_ip("8.8.9.1".parse().unwrap()));
    }

    #[test]
    fn ip_default_route() {
        let r = make_rules(&[], &["0.0.0.0/0"]);
        assert!(r.match_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(r.match_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn ipv6_cidr() {
        let r = make_rules(&[], &["2001:db8::/32"]);
        assert!(r.match_ip("2001:db8::1".parse().unwrap()));
        assert!(!r.match_ip("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn should_bypass_host_port() {
        let r = make_rules(&["example.com"], &["1.1.1.1/32"]);
        assert!(r.should_bypass("example.com:443"));
        assert!(r.should_bypass("sub.example.com:80"));
        assert!(r.should_bypass("1.1.1.1:53"));
        assert!(!r.should_bypass("other.com:443"));
        assert!(!r.should_bypass("1.1.1.2:53"));
    }

    #[test]
    fn should_bypass_ipv6_bracket() {
        let r = make_rules(&[], &["::1/128"]);
        assert!(r.should_bypass("[::1]:80"));
        assert!(!r.should_bypass("[::2]:80"));
    }

    #[test]
    fn extract_host_cases() {
        assert_eq!(extract_host("example.com:443"), "example.com");
        assert_eq!(extract_host("[::1]:80"), "::1");
        assert_eq!(extract_host("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(extract_host("example.com"), "example.com");
    }
}

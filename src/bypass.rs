use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    collections::HashMap,
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

#[derive(Default)]
struct DomainTrieNode {
    children: HashMap<Box<str>, DomainTrieNode>,

    is_terminal: bool,
}

impl DomainTrieNode {
    fn insert(&mut self, domain: &str) {
        let domain = domain.strip_prefix('.').unwrap_or(domain);

        let mut node = self;
        for label in domain.split('.').rev() {
            node = node
                .children
                .entry(label.into())
                .or_insert_with(DomainTrieNode::default);
        }
        node.is_terminal = true;
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        let labels: Vec<&str> = domain.split('.').collect();
        Self::search(self, &labels, labels.len())
    }

    fn search(node: &DomainTrieNode, labels: &[&str], idx: usize) -> bool {
        if node.is_terminal {
            return true;
        }
        if idx == 0 {
            return false;
        }
        let label = labels[idx - 1];

        if let Some(child) = node.children.get(label) {
            if Self::search(child, labels, idx - 1) {
                return true;
            }
        }
        false
    }
}

#[derive(Default)]
struct IpTrieNode {
    children: [Option<Box<IpTrieNode>>; 2],
    is_terminal: bool,
}

impl IpTrieNode {
    fn insert_bits(&mut self, bits: &[u8]) {
        let mut node = self;
        for &bit in bits {
            let idx = bit as usize;
            node = node.children[idx].get_or_insert_with(|| Box::new(IpTrieNode::default()));

            if node.is_terminal {
                return;
            }
        }
        node.is_terminal = true;

        node.children = [None, None];
    }

    fn match_bits(&self, bits: &[u8]) -> bool {
        let mut node = self;
        for &bit in bits {
            if node.is_terminal {
                return true;
            }
            match &node.children[bit as usize] {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.is_terminal
    }
}

fn ipv4_to_bits(addr: Ipv4Addr, prefix_len: u8) -> Vec<u8> {
    let n = u32::from(addr);
    (0..prefix_len)
        .map(|i| ((n >> (31 - i)) & 1) as u8)
        .collect()
}

fn ipv6_to_bits(addr: Ipv6Addr, prefix_len: u8) -> Vec<u8> {
    let n = u128::from(addr);
    (0..prefix_len)
        .map(|i| ((n >> (127 - i)) & 1) as u8)
        .collect()
}

pub struct BypassRules {
    domain_trie: DomainTrieNode,
    ipv4_trie: IpTrieNode,
    ipv6_trie: IpTrieNode,
}

impl BypassRules {
    pub fn load(cfg: &BypassConfig) -> Result<Self> {
        let mut rules = Self {
            domain_trie: DomainTrieNode::default(),
            ipv4_trie: IpTrieNode::default(),
            ipv6_trie: IpTrieNode::default(),
        };

        for path in &cfg.bypass_files {
            let content =
                fs::read_to_string(path).with_context(|| format!("read bypass file: {path}"))?;
            let file: BypassFile = serde_json::from_str(&content)
                .with_context(|| format!("parse bypass file: {path}"))?;

            for domain in &file.domain_suffix {
                rules.domain_trie.insert(domain);
            }
            for cidr in &file.ip_cidr {
                rules
                    .insert_cidr(cidr)
                    .with_context(|| format!("invalid cidr `{cidr}` in {path}"))?;
            }
        }

        Ok(rules)
    }

    fn insert_cidr(&mut self, cidr: &str) -> Result<()> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .with_context(|| "missing '/' in cidr")?;
        let prefix_len: u8 = prefix_str.parse().context("invalid prefix length")?;

        match IpAddr::from_str(addr_str).context("invalid IP address")? {
            IpAddr::V4(addr) => {
                anyhow::ensure!(prefix_len <= 32, "IPv4 prefix length > 32");
                let bits = ipv4_to_bits(addr, prefix_len);
                self.ipv4_trie.insert_bits(&bits);
            }
            IpAddr::V6(addr) => {
                anyhow::ensure!(prefix_len <= 128, "IPv6 prefix length > 128");
                let bits = ipv6_to_bits(addr, prefix_len);
                self.ipv6_trie.insert_bits(&bits);
            }
        }
        Ok(())
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        self.domain_trie.matches(domain)
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => {
                let bits = ipv4_to_bits(addr, 32);
                self.ipv4_trie.match_bits(&bits)
            }
            IpAddr::V6(addr) => {
                let bits = ipv6_to_bits(addr, 128);
                self.ipv6_trie.match_bits(&bits)
            }
        }
    }

    pub fn should_bypass(&self, target: &str) -> bool {
        let host = extract_host(target);
        if let Ok(ip) = IpAddr::from_str(host) {
            return self.match_ip(ip);
        }
        self.match_domain(host)
    }

    pub fn is_empty(&self) -> bool {
        self.domain_trie.children.is_empty()
            && self.ipv4_trie.children[0].is_none()
            && self.ipv4_trie.children[1].is_none()
            && self.ipv6_trie.children[0].is_none()
            && self.ipv6_trie.children[1].is_none()
    }
}

fn extract_host(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(target);
    }

    target.split(':').next().unwrap_or(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_rules(domains: &[&str], cidrs: &[&str]) -> BypassRules {
        let mut rules = BypassRules {
            domain_trie: DomainTrieNode::default(),
            ipv4_trie: IpTrieNode::default(),
            ipv6_trie: IpTrieNode::default(),
        };
        for d in domains {
            rules.domain_trie.insert(d);
        }
        for c in cidrs {
            rules.insert_cidr(c).unwrap();
        }
        rules
    }

    #[test]
    fn domain_exact_match() {
        let r = make_rules(&["example.com"], &[]);
        assert!(r.match_domain("example.com"));
        assert!(r.match_domain("sub.example.com"));
        assert!(!r.match_domain("notexample.com"));
        assert!(!r.match_domain("com"));
    }

    #[test]
    fn domain_leading_dot() {
        let r = make_rules(&[".example.com"], &[]);
        assert!(r.match_domain("example.com"));
        assert!(r.match_domain("a.b.example.com"));
        assert!(!r.match_domain("fakeexample.com"));
    }

    #[test]
    fn domain_nested() {
        let r = make_rules(&["google.com"], &[]);
        assert!(r.match_domain("mail.google.com"));
        assert!(r.match_domain("deep.nested.google.com"));
        assert!(!r.match_domain("notgoogle.com"));
    }

    #[test]
    fn domain_tld_wildcard() {
        let r = make_rules(&["com"], &[]);
        assert!(r.match_domain("anything.com"));
        assert!(r.match_domain("a.b.c.com"));
        assert!(!r.match_domain("anything.net"));
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

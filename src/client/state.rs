use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

use crate::bypass::BypassRules;
use crate::shaper::TrafficConfig;

pub type InitialMasterEntry = (String, Zeroizing<[u8; 32]>, Instant);

pub struct ManualResolver {
    pub target_addr: String,
}

impl wreq::dns::Resolve for ManualResolver {
    fn resolve(&self, _name: wreq::dns::Name) -> wreq::dns::Resolving {
        let target = self.target_addr.clone();
        Box::pin(async move {
            let mut lookup_str = String::with_capacity(target.len() + 2);
            lookup_str.push_str(&target);
            lookup_str.push_str(":0");
            let addrs = tokio::net::lookup_host(lookup_str)
                .await?
                .map(|mut s| {
                    s.set_port(0);
                    s
                })
                .collect::<Vec<_>>();
            Ok(Box::new(addrs.into_iter())
                as Box<dyn Iterator<Item = SocketAddr> + Send + 'static>)
        })
    }
}

pub struct SharedState {
    pub remote_str: String,
    pub auth_header: String,
    pub traffic_config: TrafficConfig,
    pub bypass: Option<Arc<BypassRules>>,
    pub server_public_key: Option<x25519_dalek::PublicKey>,
    pub proxy_auth: Option<(String, String)>,
    pub initial_master: Mutex<Option<InitialMasterEntry>>,
    pub handshake_lock: OnceCell<tokio::sync::Mutex<()>>,
}

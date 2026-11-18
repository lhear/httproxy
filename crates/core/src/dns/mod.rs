mod client;
mod config;
mod ecs;
mod transport;

pub use client::{DnsClient, init_dns};
pub use config::{DnsConfig, DnsOptions, Protocol};

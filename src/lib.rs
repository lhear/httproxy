use std::{sync::LazyLock, time::Instant};

pub static START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline(always)]
pub fn now_secs() -> u64 {
    START.elapsed().as_secs()
}

pub mod bypass;
pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod log;
pub mod server;
pub mod shaper;

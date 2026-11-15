use std::{sync::LazyLock, time::Instant};

pub static START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline]
pub fn now_secs() -> u64 {
    START.elapsed().as_secs()
}

#[inline]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub mod bypass;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod http;
pub mod log;
pub mod shaper;
pub mod warp;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

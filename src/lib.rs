use std::{sync::LazyLock, time::Instant};

pub static START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline]
pub fn now_secs() -> u64 {
    START.elapsed().as_secs()
}

/// 真正的 Unix 时间戳（秒）。`now_secs()` 是进程启动后的相对时间，
/// 判断 JWT 的 `exp` 必须用这个。
#[inline]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

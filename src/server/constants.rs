use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

pub const MAX_UPLOAD_BODY_SIZE: usize = 1024 * 1024;

pub const MAX_PENDING_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PENDING_FRAMES: usize = 8 * 1024;
pub const MAX_REORDER_SECS: u64 = 10;

pub const STREAM_IDLE_TIMEOUT_SECS: u64 = 120;

pub const JANITOR_INTERVAL: Duration = Duration::from_secs(30);
pub const NONCE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub const MASTER_EXPIRY: Duration = Duration::from_secs(1200);

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

pub static START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline(always)]
pub fn now_secs() -> u64 {
    START.elapsed().as_secs()
}

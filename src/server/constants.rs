use std::time::Duration;

pub const MAX_UPLOAD_BODY_SIZE: usize = 1024 * 1024;

pub const MAX_PENDING_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PENDING_FRAMES: usize = 8 * 1024;
pub const MAX_REORDER_SECS: u64 = 10;

pub const STREAM_IDLE_TIMEOUT_SECS: u64 = 120;

pub const ROTATION_TIMEOUT_SECS: u64 = 30;

pub const UPLOAD_DONE_TIMEOUT: Duration = Duration::from_secs(30);

pub const JANITOR_INTERVAL: Duration = Duration::from_secs(30);
pub const NONCE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub const UPLOAD_CHANNEL_CAPACITY: usize = 16;

pub const MASTER_EXPIRY: Duration = Duration::from_secs(1200);

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

pub use crate::now_secs;

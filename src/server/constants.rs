use std::time::Duration;

pub const MAX_FRAME_BUF_SIZE: usize = 18781;

pub const MAX_PENDING_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PENDING_FRAMES: usize = 8 * 1024;
pub const MAX_EOS_WAITERS: usize = 256;
pub const MAX_REORDER_SECS: u64 = 10;

pub const STREAM_IDLE_TIMEOUT_SECS: u64 = 120;

pub const ROTATION_STALENESS: Duration = Duration::from_secs(10);

pub const UPLOAD_DONE_TIMEOUT: Duration = Duration::from_secs(30);

pub const JANITOR_INTERVAL: Duration = Duration::from_secs(30);
pub const NONCE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub const DOWNLOAD_CHANNEL_CAPACITY: usize = 1;
pub const TUNNEL_CMD_CHANNEL_CAPACITY: usize = 32;
pub const UPLOAD_CMD_CHANNEL_CAPACITY: usize = 8;

pub const MASTER_EXPIRY: Duration = Duration::from_secs(1200);

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

pub use crate::now_secs;

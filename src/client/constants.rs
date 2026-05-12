use std::time::Duration;

pub const CONNECT_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
pub const PROXY_AUTH_REQUIRED_RESPONSE: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"httproxy\"\r\nContent-Length: 0\r\n\r\n";
pub const EARLY_READ_WINDOW: Duration = Duration::from_millis(2);

pub const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const PROXY_REQUEST_PARSE_TIMEOUT: Duration = Duration::from_secs(10);
pub const UPLOAD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_IN_FLIGHT_BYTES: usize = 2 * 1024 * 1024;
pub const UPLOAD_CONCURRENCY: usize = 128;

pub const DECODE_BUF_CAPACITY: usize = 16 * 1024 + 2396;

pub const MASTER_RESUME_WINDOW_SECS: u64 = 1170;

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXX";
pub const MIN_PADDING: usize = 16;

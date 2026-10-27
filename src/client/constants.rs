use std::time::Duration;

pub const CONNECT_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// 认证失败直接关闭连接：入站代理连接不复用，客户端会带认证头重连。
pub const PROXY_AUTH_REQUIRED_RESPONSE: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"httproxy\"\r\nProxy-Connection: close\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// 回完 407 后短暂排空对端数据的时间窗口，避免带着未读数据 close 触发 RST、
/// 把 407 响应冲掉。
pub const AUTH_REJECT_DRAIN_WINDOW: Duration = Duration::from_millis(250);
pub const EARLY_READ_WINDOW: Duration = Duration::from_millis(2);

pub const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const PROXY_REQUEST_PARSE_TIMEOUT: Duration = Duration::from_secs(10);
pub const UPLOAD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 代理请求头解析缓冲的初始容量；头部通常只有几百字节，按需增长到 16 KiB。
pub const PROXY_BUF_INITIAL_CAPACITY: usize = 2048;
/// CONNECT 之后预读早期数据时每次预留的容量（最多预读一个最大帧）。
pub const EARLY_READ_CHUNK: usize = 2048;

pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const BATCH_BUF_INITIAL_CAPACITY: usize = 8192;
pub const MAX_IN_FLIGHT_BYTES: usize = 2 * 1024 * 1024;
pub const UPLOAD_CONCURRENCY: usize = 128;
pub const MIN_IN_FLIGHT_BYTES: usize = 20 * 1024;

pub const MAX_LOCAL_CONNECTIONS: usize = 1024;
pub const PREFETCH_LEAD_BYTES: u64 = 20 * 1024 * 1024;

pub const PREFETCH_ROTATE_TIMEOUT: Duration = Duration::from_secs(5);

pub const DECODE_BUF_CAPACITY: usize = 16 * 1024 + 2396;

pub const WRITE_BUF_CAPACITY: usize = 64 * 1024;
pub const WRITE_FLUSH_TIMEOUT: Duration = Duration::from_millis(2);

pub const MASTER_RESUME_WINDOW_SECS: u64 = 1170;

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXX";
pub const MIN_PADDING: usize = 16;

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
/// 批处理缓冲的初始容量约等于一个最大帧，避免从 8 KiB 起反复翻倍扩容拷贝。
pub const BATCH_BUF_INITIAL_CAPACITY: usize = 32 * 1024;
pub const MAX_IN_FLIGHT_BYTES: usize = 2 * 1024 * 1024;
pub const UPLOAD_CONCURRENCY: usize = 128;
pub const MIN_IN_FLIGHT_BYTES: usize = 20 * 1024;

pub const MAX_LOCAL_CONNECTIONS: usize = 1024;
pub const PREFETCH_LEAD_BYTES: u64 = 20 * 1024 * 1024;

pub const PREFETCH_ROTATE_TIMEOUT: Duration = Duration::from_secs(5);

pub const DECODE_BUF_CAPACITY: usize = 16 * 1024 + 2396;

pub const WRITE_BUF_CAPACITY: usize = 64 * 1024;
/// 单次 write_vectored 最多带多少块明文（Linux IOV_MAX=1024，留足余量）
pub const MAX_WRITE_IOV: usize = 64;
pub const WRITE_FLUSH_TIMEOUT: Duration = Duration::from_millis(2);

pub const MASTER_RESUME_WINDOW_SECS: u64 = 1170;

/// 虚拟内网：通道断开后的重连退避区间。
pub const VNET_RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const VNET_RECONNECT_MAX: Duration = Duration::from_secs(30);
/// 虚拟内网：连本机服务的超时（先试回环，失败再试虚拟 IP）。
///
/// 两次都是**本机**拨号：要么毫秒级连上，要么立刻被拒，唯一会挂住的情形是
/// 「那个地址不属于本机」——SYN 被发到网卡外面再也没人应答。1s 足够覆盖正常
/// 情况，同时把这种黑洞情形从 5s 压到 1s。
pub const VNET_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// 虚拟内网：单个上行 POST 最多攒多少已编码字节。
///
/// 上行吞吐 ≈（批次 × 在飞数）/ RTT，所以这个上限直接决定链路带宽延迟积：
/// 256 KiB × 4 在飞 = 1 MiB，约为服务端重排序窗口的一半，给乱序留出余量。
/// 批次只在队列里已有数据时才攒，攒不满也照样立刻发，因此不影响延迟。
pub const VNET_BATCH_BYTES: usize = 256 * 1024;
/// 虚拟内网：并发上行 POST 数量。
pub const VNET_UPLINK_CONCURRENCY: usize = 4;
/// 虚拟内网：单条逻辑连接待写字节的队列容量。
pub const VNET_CONN_CAPACITY: usize = 32;
/// 虚拟内网：等待发送的 mux 帧队列容量。
pub const VNET_UPLINK_QUEUE: usize = 1024;
/// 虚拟内网：下行解码缓冲上限（一个最大帧 + 余量）。
pub const VNET_DECODE_BUF: usize = 16 * 1024 + 2396;

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXX";
pub const MIN_PADDING: usize = 16;

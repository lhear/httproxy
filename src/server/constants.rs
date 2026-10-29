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
pub const MASTER_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 一次向量写最多带多少帧（补齐空档时把连续帧合并成少数几次系统调用）
pub const MAX_WRITE_IOV: usize = 64;
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// 每个下载段结束时通知隧道 actor 的通道容量（每段一条消息）
pub const SEGMENT_DONE_CHANNEL_CAPACITY: usize = 2;
pub const TUNNEL_CMD_CHANNEL_CAPACITY: usize = 32;
pub const UPLOAD_CMD_CHANNEL_CAPACITY: usize = 8;

pub const MAX_TUNNELS: usize = 1024;

pub const MASTER_EXPIRY: Duration = Duration::from_secs(1200);

/// 已校验通过的 JWT 缓存时长。只在 `exp` 还够远时才写入缓存，因此缓存
/// 永远不会让过期 token 通过校验。
pub const JWT_CACHE_TTL: Duration = Duration::from_secs(60);
pub const JWT_CACHE_CAPACITY: u64 = 2048;

pub const PADDING_POOL: &[u8] = b"padding=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

/// 虚拟内网：服务端向下行通道发心跳的间隔。
pub const VNET_HEARTBEAT: Duration = Duration::from_secs(20);
/// 虚拟内网：超过这么久没有上行数据就认为该节点已经失联。
pub const VNET_STALE_SECS: u64 = 75;
/// 虚拟内网：同一地址的旧注册在这段时间内刷新过就拒绝顶替，避免相互抢占。
pub const VNET_REPLACE_GUARD_SECS: u64 = 5;
/// 虚拟内网：等待节点回执「本地端口连上了」的上限。
pub const VNET_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// 虚拟内网：下行帧通道容量（背压直接作用在对端本地服务的读取速度上）。
pub const VNET_DOWNLINK_CAPACITY: usize = 512;
/// 虚拟内网：上行帧通道容量。
pub const VNET_UPLINK_FRAMES: usize = 1024;
/// 虚拟内网：单条逻辑连接待写字节的队列容量。
pub const VNET_CONN_CAPACITY: usize = 32;
/// 虚拟内网：上行重排序缓冲允许积压的字节数。
pub const VNET_UPLINK_PENDING_BYTES: usize = 2 * 1024 * 1024;

pub use crate::now_secs;

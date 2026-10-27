use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard};
use std::task::{Context, Poll};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{Instrument, info, warn};
use uuid::Uuid;

use crate::now_secs;
use crate::server::actor::upload::{UploadActor, UploadCmd};
use crate::server::constants::{
    ROTATION_STALENESS, SEGMENT_DONE_CHANNEL_CAPACITY, STREAM_IDLE_TIMEOUT_SECS,
    UPLOAD_CMD_CHANNEL_CAPACITY,
};
use crate::server::stream_registry::StreamRegistry;
use crate::shaper::{FrameCipher, ResolvedShaperConfig, TrafficShaper};

/// 隧道控制面命令。
///
/// 上传数据帧不从这里过：请求处理器拿着 `SessionHandle::upload_tx` 直接投递给
/// `UploadActor`，少一次 channel 跳转和一次任务唤醒，也避免隧道 actor 成为
/// 同一条流上所有并发上传 POST 的串行瓶颈。
pub enum TunnelCmd {
    Continue {
        reply: oneshot::Sender<Option<SegmentStream>>,
    },
    Shutdown,
}

enum Phase {
    Connecting,
    Active,
    Rotating,
    Draining,
    Closed,
}

type ShaperStream = Pin<Box<TrafficShaper<OwnedReadHalf>>>;
/// shaper 的交接槽：同一时刻只有一个下载段持有 shaper。
type ShaperSlot = Arc<StdMutex<Option<ShaperStream>>>;

/// 一段下载响应体：直接由 hyper 从 shaper 拉取，不再经过"额外任务 + 每帧 mpsc 投递"。
pub type SegmentStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

#[inline]
fn slot_lock(slot: &ShaperSlot) -> MutexGuard<'_, Option<ShaperStream>> {
    // 槽位只做"取/放"，临界区里不会 panic；中毒就直接取回内部值
    slot.lock().unwrap_or_else(|e| e.into_inner())
}

/// 一段下载：持有 shaper，按 `max_bytes` 停下来把 shaper 还给槽位。
struct Segment {
    slot: ShaperSlot,
    shaper: Option<ShaperStream>,
    sent: u64,
    max_bytes: Option<u64>,
    activity: Arc<AtomicU64>,
    /// 本段结束（正常/异常/被丢弃）时通知隧道 actor
    done_tx: Option<mpsc::Sender<()>>,
    cancelled: Arc<AtomicBool>,
    /// 到达 `max_bytes`：shaper 要还给下一段，而不是丢弃
    pause_on_drop: bool,
    ended: bool,
}

impl Segment {
    fn new(
        slot: ShaperSlot,
        max_bytes: Option<u64>,
        activity: Arc<AtomicU64>,
        done_tx: mpsc::Sender<()>,
        cancelled: Arc<AtomicBool>,
    ) -> Option<Self> {
        let shaper = slot_lock(&slot).take()?;
        Some(Self {
            slot,
            shaper: Some(shaper),
            sent: 0,
            max_bytes,
            activity,
            done_tx: Some(done_tx),
            cancelled,
            pause_on_drop: false,
            ended: false,
        })
    }

    fn release(&mut self) {
        let Some(shaper) = self.shaper.take() else {
            return;
        };
        if self.pause_on_drop {
            *slot_lock(&self.slot) = Some(shaper);
        }
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        // 先把 shaper 交还，再通知 actor，保证 actor 看到的是一个自洽的槽位
        self.release();
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

impl Stream for Segment {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        if this.cancelled.load(Ordering::Acquire) {
            this.ended = true;
            return Poll::Ready(None);
        }
        let Some(shaper) = this.shaper.as_mut() else {
            this.ended = true;
            return Poll::Ready(None);
        };

        match shaper.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok((_seq, data)))) => {
                this.sent += data.len() as u64;
                this.activity.store(now_secs(), Ordering::Relaxed);
                if this.max_bytes.is_some_and(|m| this.sent >= m) {
                    this.pause_on_drop = true;
                    this.ended = true;
                }
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct TunnelActor {
    rx: mpsc::Receiver<TunnelCmd>,
    phase: Phase,
    upload_tx: Option<mpsc::Sender<UploadCmd>>,
    upload_handle: Option<tokio::task::JoinHandle<()>>,
    shaper_slot: Option<ShaperSlot>,
    /// 是否有一段响应体正被 hyper 拉取（shaper 被它持有）
    segment_active: bool,
    pending_continue: Vec<oneshot::Sender<Option<SegmentStream>>>,
    segment_done_tx: mpsc::Sender<()>,
    segment_done_rx: mpsc::Receiver<()>,
    cancelled: Arc<AtomicBool>,
    stream_id: Uuid,
    stream_registry: Arc<StreamRegistry>,
    shutdown_signal: Arc<Notify>,
    max_download_bytes: Option<u64>,
    pending_write_half: Option<OwnedWriteHalf>,
    pending_initial_seq: u64,
    last_activity: Arc<AtomicU64>,
}

impl TunnelActor {
    pub fn new(
        rx: mpsc::Receiver<TunnelCmd>,
        stream_id: Uuid,
        stream_registry: Arc<StreamRegistry>,
        max_download_bytes: Option<u64>,
        last_activity: Arc<AtomicU64>,
    ) -> Self {
        let (seg_tx, seg_rx) = mpsc::channel::<()>(SEGMENT_DONE_CHANNEL_CAPACITY);
        Self {
            rx,
            phase: Phase::Connecting,
            upload_tx: None,
            upload_handle: None,
            shaper_slot: None,
            segment_active: false,
            pending_continue: Vec::new(),
            segment_done_tx: seg_tx,
            segment_done_rx: seg_rx,
            cancelled: Arc::new(AtomicBool::new(false)),
            stream_id,
            stream_registry,
            shutdown_signal: Arc::new(Notify::new()),
            max_download_bytes,
            pending_write_half: None,
            pending_initial_seq: 0,
            last_activity,
        }
    }

    pub fn shutdown_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown_signal)
    }

    pub fn set_upload_channel(
        &mut self,
        upload_tx: mpsc::Sender<UploadCmd>,
        upload_handle: tokio::task::JoinHandle<()>,
    ) {
        self.upload_tx = Some(upload_tx);
        self.upload_handle = Some(upload_handle);
    }

    pub fn on_upstream_connected(
        &mut self,
        read_half: OwnedReadHalf,
        write_half: Option<OwnedWriteHalf>,
        config: &ResolvedShaperConfig,
        download_cipher: Option<Arc<dyn FrameCipher>>,
        initial_seq: u64,
    ) {
        let shaper = TrafficShaper::with_seq(read_half, config, download_cipher, initial_seq);
        self.shaper_slot = Some(Arc::new(StdMutex::new(Some(Box::pin(shaper)))));

        if let Some(wh) = write_half {
            self.pending_write_half = Some(wh);
            self.pending_initial_seq = initial_seq;
        }
        self.phase = Phase::Active;
    }

    /// 取出一段可以直接交给 hyper 的响应体；槽位为空（上游已结束）时返回 `None`。
    pub fn take_segment(&mut self) -> Option<SegmentStream> {
        let slot = Arc::clone(self.shaper_slot.as_ref()?);
        let segment = Segment::new(
            slot,
            self.max_download_bytes,
            Arc::clone(&self.last_activity),
            self.segment_done_tx.clone(),
            Arc::clone(&self.cancelled),
        )?;
        self.segment_active = true;
        Some(Box::pin(segment))
    }

    pub async fn run(mut self) {
        if self.upload_tx.is_none() {
            let write_half = self
                .pending_write_half
                .take()
                .expect("upstream write half must be provided before run");
            let (upload_tx, upload_rx) = mpsc::channel::<UploadCmd>(UPLOAD_CMD_CHANNEL_CAPACITY);
            self.upload_tx = Some(upload_tx);
            let upload_actor = UploadActor::new(upload_rx, write_half, self.pending_initial_seq);
            self.upload_handle = Some(tokio::spawn(
                async move { upload_actor.run().await }.instrument(tracing::Span::current()),
            ));
        }

        let segmented = self.shaper_slot.is_some();

        let rotation_timeout = tokio::time::sleep(ROTATION_STALENESS);
        tokio::pin!(rotation_timeout);

        let idle_sleep =
            tokio::time::sleep(std::time::Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS));
        tokio::pin!(idle_sleep);

        loop {
            tokio::select! {
                biased;
                done = self.segment_done_rx.recv(), if segmented => {
                    if done.is_none() {
                        break;
                    }
                    self.segment_active = false;
                    // 本段结束：shaper 还在槽位里说明只是到达轮转阈值，可以继续
                    let alive = self.shaper_alive();
                    if alive {
                        self.phase = Phase::Rotating;
                        rotation_timeout.as_mut().reset(Instant::now() + ROTATION_STALENESS);
                    } else {
                        self.phase = Phase::Draining;
                    }
                    self.serve_pending_continue(alive);
                }
                cmd = self.rx.recv() => {
                    self.last_activity.store(now_secs(), Ordering::Relaxed);
                    match cmd {
                        Some(TunnelCmd::Shutdown) | None => break,
                        Some(cmd) => self.dispatch_cmd(cmd),
                    }
                }
                _ = &mut rotation_timeout, if matches!(self.phase, Phase::Rotating) => {
                    warn!(stream_id = %self.stream_id, "rotation staleness timeout");
                    break;
                }
                _ = self.shutdown_signal.notified() => {
                    break;
                }
                _ = &mut idle_sleep => {
                    let idle_secs = now_secs()
                        .saturating_sub(self.last_activity.load(Ordering::Relaxed));
                    if idle_secs >= STREAM_IDLE_TIMEOUT_SECS {
                        warn!(
                            stream_id = %self.stream_id,
                            "stream idle timeout, closing tunnel"
                        );
                        break;
                    }
                    let remaining = STREAM_IDLE_TIMEOUT_SECS.saturating_sub(idle_secs);
                    idle_sleep.as_mut().reset(
                        Instant::now() + std::time::Duration::from_secs(remaining),
                    );
                }
            }

            if matches!(self.phase, Phase::Closed | Phase::Draining) {
                break;
            }
        }

        self.cleanup().await;
    }

    fn shaper_alive(&self) -> bool {
        self.shaper_slot
            .as_ref()
            .is_some_and(|slot| slot_lock(slot).is_some())
    }

    /// 把排队中的 `Continue` 尽量都兑现。
    fn serve_pending_continue(&mut self, alive: bool) {
        let pending = std::mem::take(&mut self.pending_continue);
        for reply in pending {
            if !alive {
                let _ = reply.send(None);
                continue;
            }
            // 请求方可能已经放弃（预取超时/连接断开），别为它把 shaper 取出来
            if reply.is_closed() {
                continue;
            }
            match self.take_segment() {
                Some(segment) => {
                    self.phase = Phase::Active;
                    let _ = reply.send(Some(segment));
                }
                None => {
                    self.phase = Phase::Draining;
                    let _ = reply.send(None);
                }
            }
        }
    }

    fn dispatch_cmd(&mut self, cmd: TunnelCmd) {
        match cmd {
            TunnelCmd::Continue { reply } => match self.phase {
                Phase::Rotating => {
                    self.phase = Phase::Active;
                    if reply.is_closed() {
                        return;
                    }
                    match self.take_segment() {
                        Some(segment) => {
                            let _ = reply.send(Some(segment));
                        }
                        None => {
                            self.phase = Phase::Draining;
                            let _ = reply.send(None);
                        }
                    }
                }
                Phase::Active if self.segment_active => {
                    // 预取提前到达：等本段结束后再兑现
                    self.pending_continue.push(reply);
                }
                _ => {
                    let _ = reply.send(None);
                }
            },
            TunnelCmd::Shutdown => {}
        }
    }

    async fn cleanup(&mut self) {
        self.phase = Phase::Closed;
        self.consume_stream();
        // 让仍在被 hyper 拉取的段立刻收尾
        self.cancelled.store(true, Ordering::Release);
        if let Some(slot) = self.shaper_slot.take() {
            slot_lock(&slot).take();
        }
        if let Some(handle) = self.upload_handle.take() {
            if let Some(ref tx) = self.upload_tx {
                let _ = tx.send(UploadCmd::Shutdown).await;
            }
            self.upload_tx = None;
            if let Err(join_err) = handle.await {
                warn!(stream_id = %self.stream_id, error = %join_err, "upload actor panicked");
            }
        }
        info!(stream_id = %self.stream_id, "tunnel actor closed");
    }

    fn consume_stream(&mut self) {
        self.stream_registry.mark_consumed(self.stream_id);
    }
}

impl Drop for TunnelActor {
    fn drop(&mut self) {
        self.consume_stream();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaper::{EncodingType, PaddingConfig, TrafficConfig};
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn tcp_pair() -> (OwnedReadHalf, OwnedWriteHalf, OwnedWriteHalf) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        let (client_read, client_write) = client.into_split();
        let (_server_read, server_write) = server_stream.into_split();
        (client_read, client_write, server_write)
    }

    fn resolved_config() -> Arc<ResolvedShaperConfig> {
        let cfg = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        Arc::new(ResolvedShaperConfig::resolve(&cfg))
    }

    fn new_rotating_actor(rx: mpsc::Receiver<TunnelCmd>, max_download_bytes: u64) -> TunnelActor {
        TunnelActor::new(
            rx,
            Uuid::new_v4(),
            Arc::new(StreamRegistry::new()),
            Some(max_download_bytes),
            Arc::new(AtomicU64::new(crate::now_secs())),
        )
    }

    /// 把一段响应体读干净，返回收到的字节数。
    async fn drain_segment(mut segment: SegmentStream) -> usize {
        let mut total = 0;
        while let Some(item) = segment.next().await {
            total += item.expect("segment must not error").len();
        }
        total
    }

    /// 只取第一块数据（段还没到轮转阈值时不能读到结束）。
    async fn first_chunk_len(segment: &mut SegmentStream) -> usize {
        match segment.next().await {
            Some(Ok(data)) => data.len(),
            Some(Err(e)) => panic!("segment errored: {e}"),
            None => panic!("segment ended before producing data"),
        }
    }

    #[tokio::test]
    async fn segment_stops_at_rotation_limit_and_keeps_shaper() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = new_rotating_actor(cmd_rx, 1000);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let first = actor.take_segment().expect("first segment");
        let handle = tokio::spawn(async move { actor.run().await });

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        let sent = drain_segment(first).await;
        assert!(
            sent >= 1000,
            "first segment must stop at the limit, got {sent}"
        );

        // 到达阈值后 shaper 应该还在，Continue 能接着开下一段
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        let mut second = reply_rx
            .await
            .unwrap()
            .expect("rotating continue must restart");
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(first_chunk_len(&mut second).await > 0);

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn prefetched_continue_is_queued_and_served() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = new_rotating_actor(cmd_rx, 1000);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let first = actor.take_segment().expect("first segment");
        let handle = tokio::spawn(async move { actor.run().await });

        // 本段还在读的时候就来 Continue（预取），应该被排队
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        tokio::task::yield_now().await;

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        assert!(drain_segment(first).await >= 1000);

        let mut second = reply_rx
            .await
            .unwrap()
            .expect("queued continue must be served after rotation");
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(first_chunk_len(&mut second).await > 0);

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn continue_in_direct_mode_returns_none() {
        let (read_half, client_write, _upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = TunnelActor::new(
            cmd_rx,
            Uuid::new_v4(),
            Arc::new(StreamRegistry::new()),
            None,
            Arc::new(AtomicU64::new(crate::now_secs())),
        );
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        assert!(reply_rx.await.unwrap().is_none());

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_continue_skips_segment_restart() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = new_rotating_actor(cmd_rx, 1000);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let first = actor.take_segment().expect("first segment");
        let handle = tokio::spawn(async move { actor.run().await });

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        drop(reply_rx);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        let _ = drain_segment(first).await;

        let (reply2_tx, reply2_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply2_tx })
            .await
            .unwrap();
        let mut second = reply2_rx
            .await
            .unwrap()
            .expect("fresh continue must restart");
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(first_chunk_len(&mut second).await > 0);

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_segment_ends_the_tunnel() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = new_rotating_actor(cmd_rx, u64::MAX);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let segment = actor.take_segment().expect("first segment");
        let handle = tokio::spawn(async move { actor.run().await });

        upstream_write.write_all(&[0u8; 100]).await.unwrap();
        tokio::task::yield_now().await;
        // 模拟客户端中断：直接丢掉响应体
        drop(segment);

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("tunnel must close when the response body is dropped")
            .unwrap();
        drop(cmd_tx);
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crate::server::constants::ROTATION_STALENESS;
    use crate::shaper::{EncodingType, PaddingConfig, TrafficConfig};
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn tcp_pair() -> (OwnedReadHalf, OwnedWriteHalf, OwnedWriteHalf) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        let (client_read, client_write) = client.into_split();
        let (_server_read, server_write) = server_stream.into_split();
        (client_read, client_write, server_write)
    }

    #[tokio::test]
    async fn rotation_staleness_timeout_closes_tunnel() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let cfg = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        let mut actor = TunnelActor::new(
            cmd_rx,
            Uuid::new_v4(),
            Arc::new(StreamRegistry::new()),
            Some(1000),
            Arc::new(AtomicU64::new(crate::now_secs())),
        );
        actor.on_upstream_connected(
            read_half,
            Some(client_write),
            &Arc::new(ResolvedShaperConfig::resolve(&cfg)),
            None,
            0,
        );
        let mut segment = actor.take_segment().expect("first segment");
        let handle = tokio::spawn(async move { actor.run().await });

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        let mut total = 0;
        while let Some(item) = segment.next().await {
            total += item.unwrap().len();
        }
        assert!(total >= 1000);
        drop(segment);

        tokio::time::pause();
        tokio::time::advance(ROTATION_STALENESS + std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();

        let _ = cmd_tx.send(TunnelCmd::Shutdown).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("tunnel must close after rotation staleness")
            .unwrap();
    }
}

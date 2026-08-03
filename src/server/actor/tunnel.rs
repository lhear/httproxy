use bytes::Bytes;
use futures::StreamExt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{Instrument, info, warn};
use uuid::Uuid;

use crate::now_secs;
use crate::server::actor::upload::{UploadActor, UploadCmd};
use crate::server::constants::{
    DOWNLOAD_CHANNEL_CAPACITY, ROTATION_STALENESS, STREAM_IDLE_TIMEOUT_SECS,
    UPLOAD_CMD_CHANNEL_CAPACITY,
};
use crate::server::stream_registry::StreamRegistry;
use crate::shaper::{FrameCipher, ResolvedShaperConfig, TrafficShaper};

pub enum TunnelCmd {
    UploadFrame {
        seq: u64,
        data: Bytes,
    },
    UploadEos {
        max_seq: u64,
        ack: oneshot::Sender<Result<(), crate::error::ServerError>>,
    },
    Continue {
        reply: oneshot::Sender<Option<mpsc::Receiver<std::io::Result<Bytes>>>>,
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

pub struct TunnelActor {
    rx: mpsc::Receiver<TunnelCmd>,
    phase: Phase,
    upload_tx: Option<mpsc::Sender<UploadCmd>>,
    upload_handle: Option<tokio::task::JoinHandle<()>>,
    download_handle: Option<tokio::task::JoinHandle<()>>,
    shaper: Option<ShaperStream>,
    download_tx: Option<mpsc::Sender<std::io::Result<Bytes>>>,
    pending_continue: Vec<oneshot::Sender<Option<mpsc::Receiver<std::io::Result<Bytes>>>>>,
    segment_done_tx: mpsc::Sender<Option<ShaperStream>>,
    segment_done_rx: mpsc::Receiver<Option<ShaperStream>>,
    stream_id: Uuid,
    stream_registry: Arc<StreamRegistry>,
    shutdown_signal: Arc<Notify>,
    max_download_bytes: Option<u64>,
    pending_write_half: Option<OwnedWriteHalf>,
    pending_initial_seq: u64,
    last_activity: Arc<AtomicU64>,
}

impl TunnelActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rx: mpsc::Receiver<TunnelCmd>,
        download_tx: Option<mpsc::Sender<std::io::Result<Bytes>>>,
        stream_id: Uuid,
        stream_registry: Arc<StreamRegistry>,
        max_download_bytes: Option<u64>,
        last_activity: Arc<AtomicU64>,
    ) -> Self {
        let (seg_tx, seg_rx) = mpsc::channel::<Option<ShaperStream>>(2);
        Self {
            rx,
            phase: Phase::Connecting,
            upload_tx: None,
            upload_handle: None,
            download_handle: None,
            shaper: None,
            download_tx,
            pending_continue: Vec::new(),
            segment_done_tx: seg_tx,
            segment_done_rx: seg_rx,
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
        let shaper = TrafficShaper::with_seq(read_half, config, download_cipher, 0);
        self.shaper = Some(Box::pin(shaper));

        if let Some(wh) = write_half {
            self.pending_write_half = Some(wh);
            self.pending_initial_seq = initial_seq;
        }
        self.phase = Phase::Active;
    }

    fn spawn_download_segment(&mut self, max_bytes: Option<u64>) {
        let mut shaper = self
            .shaper
            .take()
            .expect("shaper must exist for download segment");
        let download_tx = self
            .download_tx
            .clone()
            .expect("download_tx must exist for download segment");
        let done_tx = self.segment_done_tx.clone();
        let activity = Arc::clone(&self.last_activity);

        self.download_handle = Some(tokio::spawn(
            async move {
                let mut bytes_sent: u64 = 0;
                loop {
                    match shaper.as_mut().next().await {
                        Some(Ok((_seq, data))) => {
                            bytes_sent += data.len() as u64;
                            activity.store(now_secs(), Ordering::Relaxed);
                            if download_tx.send(Ok(data)).await.is_err() {
                                break;
                            }
                            if max_bytes.is_some_and(|m| bytes_sent >= m) {
                                let _ = done_tx.send(Some(shaper)).await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            let _ = download_tx.send(Err(e)).await;
                            break;
                        }
                        None => break,
                    }
                }
                let _ = done_tx.send(None).await;
            }
            .instrument(tracing::Span::current()),
        ));
    }

    pub async fn run(mut self) {
        let max_bytes = self.max_download_bytes;

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

        let direct_mode = self.download_tx.is_none();
        if !direct_mode {
            self.spawn_download_segment(max_bytes);
        }

        let rotation_timeout = tokio::time::sleep(ROTATION_STALENESS);
        tokio::pin!(rotation_timeout);

        let idle_sleep =
            tokio::time::sleep(std::time::Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS));
        tokio::pin!(idle_sleep);

        loop {
            tokio::select! {
                biased;
                returned = self.segment_done_rx.recv(), if !direct_mode => {
                    self.download_tx = None;

                    match returned {
                        Some(Some(s)) => {
                            self.shaper = Some(s);
                    self.phase = Phase::Rotating;
                            rotation_timeout.as_mut().reset(Instant::now() + ROTATION_STALENESS);
                        }
                        Some(None) => {
                            self.shaper = None;
                    self.phase = Phase::Draining;
                        }
                        None => {
                    self.phase = Phase::Draining;
                        }
                    }

                    let pending = std::mem::take(&mut self.pending_continue);
                    for reply in pending {
                        if self.shaper.is_some() {
                            let (new_tx, new_rx) =
                                mpsc::channel::<std::io::Result<Bytes>>(DOWNLOAD_CHANNEL_CAPACITY);
                            if reply.send(Some(new_rx)).is_err() {
                                continue;
                            }
                            self.download_tx = Some(new_tx);
                            self.spawn_download_segment(self.max_download_bytes);
                            self.phase = Phase::Active;
                        } else {
                            let _ = reply.send(None);
                        }
                    }
                }
                cmd = self.rx.recv() => {
                    self.last_activity.store(now_secs(), Ordering::Relaxed);
                    match cmd {
                        Some(TunnelCmd::Shutdown) => {
                            break;
                        }
                        None => {
                            break;
                        }
                        Some(cmd) => {
                            self.dispatch_cmd(cmd).await;
                        }
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

    async fn dispatch_cmd(&mut self, cmd: TunnelCmd) {
        let upload_tx = self.upload_tx.as_ref().expect("upload_tx not initialized");

        match cmd {
            TunnelCmd::UploadFrame { seq, data } => {
                if upload_tx
                    .send(UploadCmd::Frame { seq, data })
                    .await
                    .is_err()
                {
                    warn!("upload actor channel closed during frame send");
                    self.phase = Phase::Draining;
                }
            }
            TunnelCmd::UploadEos { max_seq, ack } => {
                if upload_tx
                    .send(UploadCmd::Eos { max_seq, ack })
                    .await
                    .is_err()
                {
                    warn!("upload actor closed before EOS");
                }
            }
            TunnelCmd::Continue { reply } => match self.phase {
                Phase::Rotating => {
                    let (new_tx, new_rx) =
                        mpsc::channel::<std::io::Result<Bytes>>(DOWNLOAD_CHANNEL_CAPACITY);
                    self.download_tx = Some(new_tx);
                    self.spawn_download_segment(self.max_download_bytes);
                    self.phase = Phase::Active;
                    let _ = reply.send(Some(new_rx));
                }
                Phase::Active if self.shaper.is_none() => {
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
        if let Some(handle) = self.download_handle.take() {
            handle.abort();
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

    fn new_rotating_actor(
        rx: mpsc::Receiver<TunnelCmd>,
        download_tx: mpsc::Sender<std::io::Result<Bytes>>,
    ) -> TunnelActor {
        TunnelActor::new(
            rx,
            Some(download_tx),
            Uuid::new_v4(),
            Arc::new(StreamRegistry::new()),
            Some(1000),
            Arc::new(AtomicU64::new(crate::now_secs())),
        )
    }

    #[tokio::test]
    async fn continue_in_rotating_restarts_download() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let (dl_tx, mut dl_rx) = mpsc::channel::<std::io::Result<Bytes>>(2);
        let mut actor = new_rotating_actor(cmd_rx, dl_tx);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        assert!(dl_rx.recv().await.is_some());
        assert!(dl_rx.recv().await.is_none());

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        let mut new_rx = reply_rx
            .await
            .unwrap()
            .expect("rotating continue must restart");
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(new_rx.recv().await.is_some());

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn continue_during_active_segment_is_queued_and_served() {
        let (read_half, client_write, mut upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let (dl_tx, mut dl_rx) = mpsc::channel::<std::io::Result<Bytes>>(2);
        let mut actor = new_rotating_actor(cmd_rx, dl_tx);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        let mut new_rx = reply_rx
            .await
            .unwrap()
            .expect("queued continue must be served");
        assert!(dl_rx.recv().await.is_some());
        assert!(dl_rx.recv().await.is_none());
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(new_rx.recv().await.is_some());

        drop(cmd_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn continue_in_direct_mode_returns_none() {
        let (read_half, client_write, _upstream_write) = tcp_pair().await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCmd>(16);
        let mut actor = TunnelActor::new(
            cmd_rx,
            None,
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
        let (dl_tx, mut dl_rx) = mpsc::channel::<std::io::Result<Bytes>>(2);
        let mut actor = new_rotating_actor(cmd_rx, dl_tx);
        actor.on_upstream_connected(read_half, Some(client_write), &resolved_config(), None, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply_tx })
            .await
            .unwrap();
        drop(reply_rx);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        upstream_write.write_all(&[0u8; 2000]).await.unwrap();

        let (reply2_tx, reply2_rx) = oneshot::channel();
        cmd_tx
            .send(TunnelCmd::Continue { reply: reply2_tx })
            .await
            .unwrap();
        let mut new_rx = reply2_rx
            .await
            .unwrap()
            .expect("fresh continue must restart");
        upstream_write.write_all(&[0u8; 500]).await.unwrap();
        assert!(new_rx.recv().await.is_some());
        assert!(dl_rx.recv().await.is_some());
        assert!(dl_rx.recv().await.is_none());

        drop(cmd_tx);
        handle.await.unwrap();
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crate::server::constants::ROTATION_STALENESS;
    use crate::shaper::{EncodingType, PaddingConfig, TrafficConfig};
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
        let (dl_tx, mut dl_rx) = mpsc::channel::<std::io::Result<Bytes>>(2);
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
            Some(dl_tx),
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
        let handle = tokio::spawn(async move { actor.run().await });

        upstream_write.write_all(&[0u8; 2000]).await.unwrap();
        assert!(dl_rx.recv().await.is_some());
        assert!(dl_rx.recv().await.is_none());

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

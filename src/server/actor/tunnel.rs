use bytes::Bytes;
use futures::StreamExt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{Instrument, info, warn};

use crate::error::ServerError;
use crate::now_secs;
use crate::server::actor::upload::{UploadActor, UploadCmd};
use crate::server::constants::{
    DOWNLOAD_CHANNEL_CAPACITY, ROTATION_STALENESS, STREAM_IDLE_TIMEOUT_SECS,
    UPLOAD_CMD_CHANNEL_CAPACITY, UPLOAD_DONE_TIMEOUT,
};
use crate::server::nonce_registry::NonceRegistry;
use crate::shaper::{FrameCipher, TrafficConfig, TrafficShaper};

pub enum TunnelCmd {
    UploadFrame {
        seq: u64,
        data: Bytes,
    },
    UploadEos {
        max_seq: u64,
        ack: oneshot::Sender<Result<(), ServerError>>,
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
    session_id: String,
    conn_nonce: Option<[u8; 16]>,
    nonce_registry: Arc<NonceRegistry>,
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
        download_tx: mpsc::Sender<std::io::Result<Bytes>>,
        session_id: String,
        conn_nonce: Option<[u8; 16]>,
        nonce_registry: Arc<NonceRegistry>,
        max_download_bytes: Option<u64>,
    ) -> Self {
        let (seg_tx, seg_rx) = mpsc::channel::<Option<ShaperStream>>(2);
        Self {
            rx,
            phase: Phase::Connecting,
            upload_tx: None,
            upload_handle: None,
            download_handle: None,
            shaper: None,
            download_tx: Some(download_tx),
            pending_continue: Vec::new(),
            segment_done_tx: seg_tx,
            segment_done_rx: seg_rx,
            session_id,
            conn_nonce,
            nonce_registry,
            shutdown_signal: Arc::new(Notify::new()),
            max_download_bytes,
            pending_write_half: None,
            pending_initial_seq: 0,
            last_activity: Arc::new(AtomicU64::new(now_secs())),
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
        config: TrafficConfig,
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
                while let Some(result) = shaper.as_mut().next().await {
                    match result {
                        Ok((_seq, data)) => {
                            bytes_sent += data.len() as u64;
                            if download_tx.send(Ok(data)).await.is_err() {
                                break;
                            }
                            activity.store(now_secs(), Ordering::Relaxed);
                            if max_bytes.is_some_and(|m| bytes_sent >= m) {
                                let _ = done_tx.send(Some(shaper)).await;
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = download_tx.send(Err(e)).await;
                            break;
                        }
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
            let write_half = self.pending_write_half.take().expect(
                "on_upstream_connected must provide write_half when upload channel not pre-set",
            );
            let (upload_tx, upload_rx) = mpsc::channel::<UploadCmd>(UPLOAD_CMD_CHANNEL_CAPACITY);
            self.upload_tx = Some(upload_tx);
            let upload_actor = UploadActor::new(upload_rx, write_half, self.pending_initial_seq);
            self.upload_handle = Some(tokio::spawn(
                async move { upload_actor.run().await }.instrument(tracing::Span::current()),
            ));
        }

        self.spawn_download_segment(max_bytes);

        let rotation_timeout = tokio::time::sleep(ROTATION_STALENESS);
        tokio::pin!(rotation_timeout);

        let idle_sleep =
            tokio::time::sleep(std::time::Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS));
        tokio::pin!(idle_sleep);

        loop {
            tokio::select! {
                biased;
                returned = self.segment_done_rx.recv() => {
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
                            self.download_tx = Some(new_tx);
                            self.spawn_download_segment(self.max_download_bytes);
                            self.phase = Phase::Active;
                            let _ = reply.send(Some(new_rx));
                        } else {
                            let _ = reply.send(None);
                        }
                    }
                }
                cmd = self.rx.recv() => {
                    self.last_activity.store(now_secs(), Ordering::Relaxed);
                    match cmd {
                        Some(TunnelCmd::Shutdown) | None => break,
                        Some(cmd) => {
                            self.dispatch_cmd(cmd).await;
                        }
                    }
                }
                _ = &mut rotation_timeout, if matches!(self.phase, Phase::Rotating) => {
                    warn!(session_id = %self.session_id, "rotation staleness timeout");
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
                            session_id = %self.session_id,
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
                let (done_tx, done_rx) = oneshot::channel();
                if upload_tx
                    .send(UploadCmd::Eos {
                        max_seq,
                        done: done_tx,
                    })
                    .await
                    .is_err()
                {
                    warn!("upload actor closed before EOS");
                    let _ = ack.send(Err(ServerError::bad_gateway("upload actor closed")));
                    return;
                }
                let upload_done_timeout = UPLOAD_DONE_TIMEOUT;
                tokio::spawn(
                    async move {
                        let confirmed = tokio::time::timeout(upload_done_timeout, done_rx)
                            .await
                            .map(|r| r.is_ok())
                            .unwrap_or(false);
                        if confirmed {
                            let _ = ack.send(Ok(()));
                        } else {
                            warn!("upload EOS ack timed out or upload actor closed");
                            let _ =
                                ack.send(Err(ServerError::gateway_timeout("upload drain timeout")));
                        }
                    }
                    .instrument(tracing::Span::current()),
                );
            }
            TunnelCmd::Continue { reply } => {
                if self.shaper.is_some() {
                    let (new_tx, new_rx) =
                        mpsc::channel::<std::io::Result<Bytes>>(DOWNLOAD_CHANNEL_CAPACITY);
                    self.download_tx = Some(new_tx);
                    self.spawn_download_segment(self.max_download_bytes);
                    self.phase = Phase::Active;
                    let _ = reply.send(Some(new_rx));
                } else {
                    self.pending_continue.push(reply);
                }
            }
            TunnelCmd::Shutdown => {}
        }
    }

    async fn cleanup(&mut self) {
        self.phase = Phase::Closed;
        self.consume_nonce();
        if let Some(handle) = self.download_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.upload_handle.take() {
            if let Some(ref tx) = self.upload_tx {
                let _ = tx.send(UploadCmd::Shutdown).await;
            }
            self.upload_tx = None;
            if let Err(join_err) = handle.await {
                warn!(session_id = %self.session_id, error = %join_err, "upload actor panicked");
            }
        }
        info!(session_id = %self.session_id, "tunnel actor closed");
    }

    fn consume_nonce(&mut self) {
        if let Some(nonce) = self.conn_nonce.take() {
            self.nonce_registry.mark_consumed(&self.session_id, &nonce);
        }
    }
}

impl Drop for TunnelActor {
    fn drop(&mut self) {
        self.consume_nonce();
    }
}

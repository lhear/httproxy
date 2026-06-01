use bytes::Bytes;
use dashmap::DashMap;
use futures::{Future, Stream};
use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::crypto::AesFrameCipher;
use crate::server::constants::{ROTATION_TIMEOUT_SECS, STREAM_IDLE_TIMEOUT_SECS, now_secs};
use crate::shaper::FrameCipher;

pub enum FrameOrEos {
    Data {
        seq: u64,
        data: Bytes,
    },
    Eos {
        max_seq: u64,
        done: oneshot::Sender<()>,
    },
}

pub struct UploadStream {
    last_activity: AtomicU64,
    pub(crate) tx: mpsc::Sender<FrameOrEos>,
    pub(crate) upload_cipher: Option<Arc<AesFrameCipher>>,
    pub(crate) shutdown: Arc<Notify>,
    shutdown_flag: AtomicBool,
    rotation_at: AtomicU64,
}

impl UploadStream {
    #[inline]
    pub fn new(tx: mpsc::Sender<FrameOrEos>, upload_cipher: Option<Arc<AesFrameCipher>>) -> Self {
        Self {
            last_activity: AtomicU64::new(now_secs()),
            tx,
            upload_cipher,
            shutdown: Arc::new(Notify::new()),
            shutdown_flag: AtomicBool::new(false),
            rotation_at: AtomicU64::new(0),
        }
    }
    #[inline]
    pub fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }
    #[inline]
    pub fn is_idle(&self) -> bool {
        now_secs().saturating_sub(self.last_activity.load(Ordering::Relaxed))
            > STREAM_IDLE_TIMEOUT_SECS
    }
    #[inline]
    pub fn do_shutdown(&self) -> bool {
        if self.shutdown_flag.swap(true, Ordering::AcqRel) {
            false
        } else {
            self.shutdown.notify_one();
            true
        }
    }
    #[inline]
    pub fn mark_rotation(&self) {
        self.rotation_at.store(now_secs(), Ordering::Relaxed);
    }
    #[inline]
    pub fn clear_rotation(&self) {
        self.rotation_at.store(0, Ordering::Relaxed);
    }
    #[inline]
    pub fn is_rotation_stale(&self) -> bool {
        let at = self.rotation_at.load(Ordering::Relaxed);
        at != 0 && now_secs().saturating_sub(at) > ROTATION_TIMEOUT_SECS
    }
}

pub type ShaperStream = Pin<Box<dyn Stream<Item = std::io::Result<(u64, Bytes)>> + Send>>;

pub struct StreamBundle {
    pub upload: Arc<UploadStream>,
    pub(crate) upstream_reader: Mutex<Option<ShaperStream>>,
    pub download_cipher: Option<Arc<dyn FrameCipher>>,
    pub max_download_bytes: Option<u64>,
    pub(crate) handoff_tx: Mutex<Option<oneshot::Sender<()>>>,
    pub(crate) handoff_done: AtomicBool,
}

impl StreamBundle {
    fn take_upstream_reader(&self) -> Result<Option<ShaperStream>, ()> {
        self.upstream_reader
            .lock()
            .map(|mut g| g.take())
            .map_err(|_| ())
    }
    fn restore_upstream_reader(&self, reader: Option<ShaperStream>) {
        if let Ok(mut g) = self.upstream_reader.lock() {
            *g = reader;
        }
    }
}

pub struct DownloadStream {
    pub bundle: Arc<StreamBundle>,
    pub streams: Arc<DashMap<String, Arc<StreamBundle>>>,
    pub map_key: String,
    pub log_key: String,
    pub shutdown_fut: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    pub done: bool,
    pub rotated: bool,
    pub bytes_sent: u64,
    pub handoff_rx: Option<Pin<Box<oneshot::Receiver<()>>>>,
}

impl DownloadStream {
    fn release_upstream(&self) {
        self.bundle.handoff_done.store(true, Ordering::Release);
        if let Ok(mut guard) = self.bundle.handoff_tx.lock()
            && let Some(tx) = guard.take()
        {
            let _ = tx.send(());
        }
    }
}

impl Stream for DownloadStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(rx) = &mut this.handoff_rx {
            match rx.as_mut().poll(cx) {
                Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                    this.bundle.handoff_done.store(false, Ordering::Release);
                    this.handoff_rx = None;
                }
                Poll::Pending => {
                    if this.bundle.handoff_done.load(Ordering::Acquire) {
                        this.bundle.handoff_done.store(false, Ordering::Release);
                        this.handoff_rx = None;
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }

        if this.done {
            return Poll::Ready(None);
        }

        if let Some(fut) = this.shutdown_fut.as_mut()
            && fut.as_mut().poll(cx).is_ready()
        {
            info!(stream_id = %this.log_key, reason = "shutdown signal", "download stream ended");
            this.done = true;
            this.shutdown_fut = None;
            this.release_upstream();
            return Poll::Ready(None);
        }

        let threshold = this.bundle.max_download_bytes;

        let mut shaper_opt = match this.bundle.take_upstream_reader() {
            Ok(opt) => opt,
            Err(()) => {
                info!(stream_id = %this.log_key, reason = "upstream reader mutex poisoned", "download stream ended");
                this.done = true;
                return Poll::Ready(None);
            }
        };

        let shaper = match shaper_opt.as_mut() {
            Some(s) => s,
            None => {
                info!(stream_id = %this.log_key, reason = "upstream reader already taken", "download stream ended");
                this.done = true;
                this.release_upstream();
                return Poll::Ready(None);
            }
        };

        match shaper.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok((_seq, data)))) => {
                this.bundle.upload.touch();
                let frame_len = data.len() as u64;
                this.bytes_sent += frame_len;

                if let Some(max) = threshold
                    && this.bytes_sent >= max
                {
                    this.done = true;
                    this.rotated = true;
                    this.bundle.upload.mark_rotation();
                    this.bundle.restore_upstream_reader(shaper_opt.take());
                    this.release_upstream();
                    debug!(
                        stream_id = %this.log_key,
                        bytes_sent = this.bytes_sent,
                        "download stream rotated"
                    );
                    return Poll::Ready(Some(Ok(data)));
                }
                this.bundle.restore_upstream_reader(shaper_opt.take());
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Some(Err(e))) => {
                warn!(stream_id = %this.log_key, error = %e, "upstream read error");
                this.done = true;
                this.release_upstream();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                info!(stream_id = %this.log_key, reason = "upstream closed", "download stream ended");
                this.done = true;
                this.release_upstream();
                Poll::Ready(None)
            }
            Poll::Pending => {
                this.bundle.restore_upstream_reader(shaper_opt.take());
                Poll::Pending
            }
        }
    }
}

impl Drop for DownloadStream {
    fn drop(&mut self) {
        if !self.done {
            info!(stream_id = %self.log_key, reason = "client disconnected", "download stream ended");
        }

        self.release_upstream();

        if self.rotated {
            debug!(stream_id = %self.log_key, reason = "rotated", "download stream dropped after rotation");
            return;
        }

        self.bundle.upload.do_shutdown();
        self.streams.remove(&self.map_key);

        if let Ok(mut guard) = self.bundle.upstream_reader.lock() {
            *guard = None;
        }
    }
}

use bytes::Bytes;
use dashmap::DashMap;
use futures::{Future, Stream};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{info, warn};

use crate::crypto::AesFrameCipher;
use crate::server::constants::{STREAM_IDLE_TIMEOUT_SECS, now_secs};

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
    pub last_activity: AtomicU64,
    pub tx: mpsc::Sender<FrameOrEos>,
    pub upload_cipher: Option<Arc<AesFrameCipher>>,
    pub shutdown: Arc<Notify>,
    shutdown_flag: AtomicBool,
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
        }
    }
    #[inline(always)]
    pub fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        now_secs().saturating_sub(self.last_activity.load(Ordering::Relaxed))
            > STREAM_IDLE_TIMEOUT_SECS
    }
    #[inline(always)]
    pub fn do_shutdown(&self) -> bool {
        if self.shutdown_flag.swap(true, Ordering::AcqRel) {
            false
        } else {
            self.shutdown.notify_one();
            true
        }
    }
}

type ShaperStream = Pin<Box<dyn Stream<Item = std::io::Result<(u64, Bytes)>> + Send>>;

pub struct DownloadStream {
    pub shaper: ShaperStream,
    pub stream: Arc<UploadStream>,
    pub streams: Arc<DashMap<String, Arc<UploadStream>>>,
    pub map_key: String,
    pub log_key: String,
    pub shutdown_fut: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    pub done: bool,
}

impl Stream for DownloadStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        if let Some(fut) = this.shutdown_fut.as_mut()
            && fut.as_mut().poll(cx).is_ready()
        {
            info!(stream_id = %this.log_key, reason = "shutdown signal", "download stream ended");
            this.done = true;
            this.shutdown_fut = None;
            return Poll::Ready(None);
        }

        match this.shaper.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok((_seq, data)))) => {
                this.stream.touch();
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Some(Err(e))) => {
                warn!(stream_id = %this.log_key, error = %e, "upstream read error");
                this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                info!(stream_id = %this.log_key, reason = "upstream closed", "download stream ended");
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DownloadStream {
    fn drop(&mut self) {
        if !self.done {
            info!(stream_id = %self.log_key, reason = "client disconnected", "download stream ended");
        }
        self.stream.do_shutdown();
        self.streams.remove(&self.map_key);
    }
}

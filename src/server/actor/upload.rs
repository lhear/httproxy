use bytes::Bytes;
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::warn;

use crate::server::constants::{
    MAX_EOS_WAITERS, MAX_PENDING_BYTES, MAX_PENDING_FRAMES, MAX_REORDER_SECS, WRITE_TIMEOUT,
};

pub enum UploadCmd {
    Frame {
        seq: u64,
        data: Bytes,
    },
    Eos {
        max_seq: u64,
        done: oneshot::Sender<()>,
    },
    Shutdown,
}

enum UploadPhase {
    Reordering {
        next_seq: u64,
        pending: BTreeMap<u64, Bytes>,
        pending_bytes: usize,
        eos_waiters: Vec<(u64, oneshot::Sender<()>)>,
    },
    Draining {
        eos_waiters: Vec<oneshot::Sender<()>>,
    },
    Closed,
}

pub struct UploadActor {
    rx: mpsc::Receiver<UploadCmd>,
    phase: UploadPhase,
    upstream: Option<OwnedWriteHalf>,
    last_activity: Instant,
}

impl UploadActor {
    pub fn new(rx: mpsc::Receiver<UploadCmd>, upstream: OwnedWriteHalf, initial_seq: u64) -> Self {
        Self {
            rx,
            phase: UploadPhase::Reordering {
                next_seq: initial_seq,
                pending: BTreeMap::new(),
                pending_bytes: 0,
                eos_waiters: Vec::new(),
            },
            upstream: Some(upstream),
            last_activity: Instant::now(),
        }
    }

    pub async fn run(mut self) {
        loop {
            let has_pending = matches!(&self.phase, UploadPhase::Reordering { pending, eos_waiters, .. }
                if !pending.is_empty() || !eos_waiters.is_empty());
            let idle_deadline = self.last_activity + Duration::from_secs(MAX_REORDER_SECS);

            tokio::select! {
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(cmd) => { if self.dispatch(cmd).await { break; } }
                        None => {
                            self.shutdown_and_drain().await;
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep_until(idle_deadline), if has_pending => {
                    warn!("reorder timeout, shutting down upload actor");
                    self.shutdown_and_drain().await;
                    break;
                }
            }
        }
        self.ack_all_waiters();
    }

    async fn dispatch(&mut self, cmd: UploadCmd) -> bool {
        self.last_activity = Instant::now();
        match cmd {
            UploadCmd::Shutdown => {
                self.shutdown_and_drain().await;
                true
            }
            UploadCmd::Frame { seq, data } => self.handle_frame(seq, data).await,
            UploadCmd::Eos { max_seq, done } => self.handle_eos(max_seq, done),
        }
    }

    async fn handle_frame(&mut self, seq: u64, data: Bytes) -> bool {
        match &mut self.phase {
            UploadPhase::Reordering {
                next_seq,
                pending,
                pending_bytes,
                eos_waiters,
            } => {
                if seq < *next_seq {
                    warn!(seq, next_seq = %*next_seq, "stale frame discarded");
                    return false;
                }
                if seq == *next_seq {
                    if let Some(ref mut upstream) = self.upstream
                        && tokio::time::timeout(WRITE_TIMEOUT, upstream.write_all(&data))
                            .await
                            .is_err()
                    {
                        self.shutdown_and_drain().await;
                        return true;
                    }
                    *next_seq += 1;
                    while let Some(pending_data) = pending.remove(next_seq) {
                        *pending_bytes -= pending_data.len();
                        if let Some(ref mut upstream) = self.upstream
                            && tokio::time::timeout(
                                WRITE_TIMEOUT,
                                upstream.write_all(&pending_data),
                            )
                            .await
                            .is_err()
                        {
                            self.shutdown_and_drain().await;
                            return true;
                        }
                        *next_seq += 1;
                    }
                    let mut i = 0;
                    while i < eos_waiters.len() {
                        if *next_seq > eos_waiters[i].0 {
                            let (_, done) = eos_waiters.swap_remove(i);
                            let _ = done.send(());
                        } else {
                            i += 1;
                        }
                    }
                    return false;
                }
                if pending.contains_key(&seq) {
                    warn!(seq, "duplicate pending frame discarded");
                    return false;
                }
                let len = data.len();
                if pending.len() >= MAX_PENDING_FRAMES || *pending_bytes + len > MAX_PENDING_BYTES {
                    warn!(
                        seq,
                        pending_frames = pending.len(),
                        pending_bytes,
                        max_pending_frames = MAX_PENDING_FRAMES,
                        max_pending_bytes = MAX_PENDING_BYTES,
                        "reorder buffer overflow, discarding frame"
                    );
                    return false;
                }
                pending.insert(seq, data);
                *pending_bytes += len;
                false
            }
            UploadPhase::Draining { .. } | UploadPhase::Closed => false,
        }
    }

    fn handle_eos(&mut self, max_seq: u64, done: oneshot::Sender<()>) -> bool {
        match &mut self.phase {
            UploadPhase::Reordering {
                next_seq,
                eos_waiters,
                ..
            } => {
                if *next_seq > max_seq {
                    let _ = done.send(());
                } else if eos_waiters.len() >= MAX_EOS_WAITERS {
                    warn!(
                        max_seq,
                        eos_waiters = eos_waiters.len(),
                        "EOS waiters overflow, shutting down upload actor"
                    );
                    return true;
                } else {
                    eos_waiters.push((max_seq, done));
                }
                false
            }
            UploadPhase::Draining { eos_waiters } => {
                eos_waiters.push(done);
                false
            }
            UploadPhase::Closed => {
                let _ = done.send(());
                true
            }
        }
    }

    async fn shutdown_and_drain(&mut self) {
        if let Some(ref mut upstream) = self.upstream {
            let _ = upstream.shutdown().await;
        }
        self.upstream = None;
        self.phase = match std::mem::replace(&mut self.phase, UploadPhase::Closed) {
            UploadPhase::Reordering { eos_waiters, .. } => UploadPhase::Draining {
                eos_waiters: eos_waiters.into_iter().map(|(_, done)| done).collect(),
            },
            other @ UploadPhase::Draining { .. } => other,
            UploadPhase::Closed => UploadPhase::Closed,
        };
    }

    fn ack_all_waiters(&mut self) {
        let phase = std::mem::replace(&mut self.phase, UploadPhase::Closed);
        match phase {
            UploadPhase::Reordering { eos_waiters, .. } => {
                for (_, waiter) in eos_waiters {
                    let _ = waiter.send(());
                }
            }
            UploadPhase::Draining { eos_waiters } => {
                for waiter in eos_waiters {
                    let _ = waiter.send(());
                }
            }
            UploadPhase::Closed => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::net::tcp::OwnedReadHalf;

    async fn tcp_pair() -> (OwnedReadHalf, OwnedWriteHalf) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        let (client_read, _client_write) = client.into_split();
        let (_server_read, server_write) = server_stream.into_split();
        (client_read, server_write)
    }

    #[tokio::test]
    async fn frames_delivered_in_order() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        tx.send(UploadCmd::Frame {
            seq: 0,
            data: Bytes::from_static(b"hello"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 1,
            data: Bytes::from_static(b"world"),
        })
        .await
        .unwrap();
        let (done_tx, done_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 1,
            done: done_tx,
        })
        .await
        .unwrap();
        done_rx.await.unwrap();

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn reorder_buffer_drains_on_consecutive_arrival() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        tx.send(UploadCmd::Frame {
            seq: 2,
            data: Bytes::from_static(b"c"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 0,
            data: Bytes::from_static(b"a"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 1,
            data: Bytes::from_static(b"b"),
        })
        .await
        .unwrap();
        let (done_tx, done_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 2,
            done: done_tx,
        })
        .await
        .unwrap();
        done_rx.await.unwrap();

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn eos_acked_immediately_when_next_seq_exceeds_max() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 5);
        let handle = tokio::spawn(async move { actor.run().await });

        let (done_tx, done_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 3,
            done: done_tx,
        })
        .await
        .unwrap();
        done_rx.await.unwrap();

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_and_acks_waiters() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        tx.send(UploadCmd::Frame {
            seq: 5,
            data: Bytes::from_static(b"far"),
        })
        .await
        .unwrap();
        let (done_tx, done_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 5,
            done: done_tx,
        })
        .await
        .unwrap();

        tx.send(UploadCmd::Shutdown).await.unwrap();
        drop(tx);
        done_rx.await.unwrap();
        handle.await.unwrap();
    }
}

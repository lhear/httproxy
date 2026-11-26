use bytes::Bytes;
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::warn;

use crate::constants::{
    MAX_EOS_WAITERS, MAX_PENDING_BYTES, MAX_PENDING_FRAMES, MAX_REORDER_SECS, MAX_WRITE_IOV,
    WRITE_TIMEOUT,
};
use crate::error::ServerError;
use crate::upstream::UpstreamWrite;

pub enum UploadCmd {
    Frame {
        seq: u64,
        data: Bytes,
    },
    Eos {
        max_seq: u64,
        ack: oneshot::Sender<Result<(), ServerError>>,
    },
    Shutdown,
}

enum UploadPhase {
    Reordering {
        next_seq: u64,
        pending: BTreeMap<u64, Bytes>,
        pending_bytes: usize,
        eos_waiters: Vec<(u64, oneshot::Sender<Result<(), ServerError>>)>,
    },
    Draining {
        eos_waiters: Vec<oneshot::Sender<Result<(), ServerError>>>,
    },
    Closed,
}

pub struct UploadActor {
    rx: mpsc::Receiver<UploadCmd>,
    phase: UploadPhase,
    upstream: Option<UpstreamWrite>,
    last_activity: Instant,
    run_buf: Vec<Bytes>,
}

impl UploadActor {
    pub(crate) fn new(
        rx: mpsc::Receiver<UploadCmd>,
        upstream: UpstreamWrite,
        initial_seq: u64,
    ) -> Self {
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
            run_buf: Vec::with_capacity(MAX_WRITE_IOV),
        }
    }

    pub async fn run(mut self) {
        let mut commands = Vec::with_capacity(MAX_WRITE_IOV);
        'running: loop {
            let has_pending = matches!(&self.phase, UploadPhase::Reordering { pending, eos_waiters, .. }
                if !pending.is_empty() || !eos_waiters.is_empty());
            let idle_deadline = self.last_activity + Duration::from_secs(MAX_REORDER_SECS);

            tokio::select! {
                count = self.rx.recv_many(&mut commands, MAX_WRITE_IOV) => {
                    if count == 0 {
                        self.shutdown_and_drain().await;
                        break;
                    }
                    self.last_activity = Instant::now();
                    for cmd in commands.drain(..) {
                        if self.dispatch(cmd).await {
                            break 'running;
                        }
                    }
                    if !self.flush_run().await {
                        break;
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
        match cmd {
            UploadCmd::Shutdown => {
                self.flush_run().await;
                self.shutdown_and_drain().await;
                true
            }
            UploadCmd::Frame { seq, data } => self.handle_frame(seq, data).await,
            UploadCmd::Eos { max_seq, ack } => {
                if !self.flush_run().await {
                    return true;
                }
                self.handle_eos(max_seq, ack)
            }
        }
    }

    async fn handle_frame(&mut self, seq: u64, data: Bytes) -> bool {
        match &mut self.phase {
            UploadPhase::Reordering {
                next_seq,
                pending,
                pending_bytes,
                ..
            } => {
                if seq < *next_seq {
                    warn!(seq, next_seq = %*next_seq, "stale frame discarded");
                    return false;
                }
                if seq == *next_seq {
                    let mut head = data;
                    loop {
                        if !head.is_empty() {
                            self.run_buf.push(head);
                        }
                        *next_seq += 1;
                        while self.run_buf.len() < MAX_WRITE_IOV {
                            let Some(next_data) = pending.remove(next_seq) else {
                                break;
                            };
                            *pending_bytes -= next_data.len();
                            if !next_data.is_empty() {
                                self.run_buf.push(next_data);
                            }
                            *next_seq += 1;
                        }
                        if self.run_buf.len() == MAX_WRITE_IOV {
                            let written = write_run(&mut self.upstream, &self.run_buf).await;
                            self.run_buf.clear();
                            if !written {
                                self.shutdown_and_drain().await;
                                return true;
                            }
                        }
                        match pending.remove(next_seq) {
                            Some(next_data) => {
                                *pending_bytes -= next_data.len();
                                head = next_data;
                            }
                            None => break,
                        }
                    }
                    return false;
                }
                let len = data.len();
                let pending_frames = pending.len();
                let std::collections::btree_map::Entry::Vacant(entry) = pending.entry(seq) else {
                    warn!(seq, "duplicate pending frame discarded");
                    return false;
                };
                if pending_frames >= MAX_PENDING_FRAMES || *pending_bytes + len > MAX_PENDING_BYTES
                {
                    warn!(
                        seq,
                        pending_frames,
                        pending_bytes,
                        max_pending_frames = MAX_PENDING_FRAMES,
                        max_pending_bytes = MAX_PENDING_BYTES,
                        "reorder buffer overflow, aborting upload"
                    );
                    self.shutdown_and_drain().await;
                    return true;
                }
                entry.insert(data);
                *pending_bytes += len;
                false
            }
            UploadPhase::Draining { .. } | UploadPhase::Closed => false,
        }
    }

    async fn flush_run(&mut self) -> bool {
        if !self.run_buf.is_empty() {
            let written = write_run(&mut self.upstream, &self.run_buf).await;
            self.run_buf.clear();
            if !written {
                self.shutdown_and_drain().await;
                return false;
            }
        }
        if let UploadPhase::Reordering {
            next_seq,
            eos_waiters,
            ..
        } = &mut self.phase
        {
            let mut index = 0;
            while index < eos_waiters.len() {
                if *next_seq > eos_waiters[index].0 {
                    let (_, ack) = eos_waiters.swap_remove(index);
                    let _ = ack.send(Ok(()));
                } else {
                    index += 1;
                }
            }
        }
        true
    }

    fn handle_eos(&mut self, max_seq: u64, ack: oneshot::Sender<Result<(), ServerError>>) -> bool {
        match &mut self.phase {
            UploadPhase::Reordering {
                next_seq,
                eos_waiters,
                ..
            } => {
                if *next_seq > max_seq {
                    let _ = ack.send(Ok(()));
                } else if eos_waiters.len() >= MAX_EOS_WAITERS {
                    warn!(
                        max_seq,
                        eos_waiters = eos_waiters.len(),
                        "EOS waiters overflow, shutting down upload actor"
                    );
                    let _ = ack.send(Err(ServerError::bad_gateway("upload EOS waiters overflow")));
                    return true;
                } else {
                    eos_waiters.push((max_seq, ack));
                }
                false
            }
            UploadPhase::Draining { .. } => {
                let _ = ack.send(Err(ServerError::bad_gateway("upload actor is draining")));
                false
            }
            UploadPhase::Closed => {
                let _ = ack.send(Err(ServerError::bad_gateway("upload actor closed")));
                true
            }
        }
    }

    async fn shutdown_and_drain(&mut self) {
        self.run_buf.clear();
        if let Some(ref mut upstream) = self.upstream {
            let _ = upstream.shutdown().await;
        }
        self.upstream = None;
        self.phase = match std::mem::replace(&mut self.phase, UploadPhase::Closed) {
            UploadPhase::Reordering { eos_waiters, .. } => UploadPhase::Draining {
                eos_waiters: eos_waiters.into_iter().map(|(_, ack)| ack).collect(),
            },
            other @ UploadPhase::Draining { .. } => other,
            UploadPhase::Closed => UploadPhase::Closed,
        };
    }

    fn ack_all_waiters(&mut self) {
        let phase = std::mem::replace(&mut self.phase, UploadPhase::Closed);
        let err = ServerError::gateway_timeout("upload drain timeout");
        match phase {
            UploadPhase::Reordering { eos_waiters, .. } => {
                for (_, ack) in eos_waiters {
                    let _ = ack.send(Err(err.clone()));
                }
            }
            UploadPhase::Draining { eos_waiters } => {
                for ack in eos_waiters {
                    let _ = ack.send(Err(err.clone()));
                }
            }
            UploadPhase::Closed => {}
        }
    }
}

async fn write_run(upstream: &mut Option<UpstreamWrite>, frames: &[Bytes]) -> bool {
    let Some(upstream) = upstream.as_mut() else {
        return false;
    };
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, upstream.write_frames(frames)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use httproxy_core::test_support::connected_pair;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::OwnedReadHalf;

    async fn tcp_pair() -> (OwnedReadHalf, UpstreamWrite) {
        let (server_stream, client) = connected_pair().await;
        let (client_read, _client_write) = client.into_split();
        let (_server_read, server_write) = server_stream.into_split();
        (client_read, server_write.into())
    }

    #[tokio::test]
    async fn contiguous_frames_are_batched_and_released_before_ack() {
        let (mut reader, writer) = tcp_pair().await;
        let (_sender, receiver) = mpsc::channel(8);
        let mut actor = UploadActor::new(receiver, writer, 0);
        assert!(!actor.handle_frame(0, Bytes::from_static(b"first")).await);
        assert!(!actor.handle_frame(1, Bytes::from_static(b"second")).await);
        assert_eq!(actor.run_buf.len(), 2);
        let mut output = [0; 11];
        assert_eq!(
            reader.try_read(&mut output).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        let (ack, result) = oneshot::channel();
        assert!(!actor.dispatch(UploadCmd::Eos { max_seq: 1, ack }).await);
        result.await.unwrap().unwrap();
        reader.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"firstsecond");
        assert!(actor.run_buf.is_empty());
    }

    #[tokio::test]
    async fn empty_frames_advance_sequence_without_empty_writes() {
        let (mut reader, writer) = tcp_pair().await;
        let (_sender, receiver) = mpsc::channel(8);
        let mut actor = UploadActor::new(receiver, writer, 0);
        assert!(!actor.handle_frame(0, Bytes::new()).await);
        assert!(!actor.handle_frame(2, Bytes::new()).await);
        assert!(!actor.handle_frame(1, Bytes::from_static(b"x")).await);
        let (ack, result) = oneshot::channel();
        assert!(!actor.dispatch(UploadCmd::Eos { max_seq: 2, ack }).await);
        result.await.unwrap().unwrap();
        assert_eq!(reader.read_u8().await.unwrap(), b'x');
        assert!(actor.run_buf.is_empty());
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
        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 2,
            ack: ack_tx,
        })
        .await
        .unwrap();
        assert!(ack_rx.await.unwrap().is_ok());

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
        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 5,
            ack: ack_tx,
        })
        .await
        .unwrap();

        tx.send(UploadCmd::Shutdown).await.unwrap();
        drop(tx);
        assert!(ack_rx.await.unwrap().is_err());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn draining_eos_waiters_are_bounded() {
        let (_rx, server_write) = tcp_pair().await;
        let (_tx, rx) = mpsc::channel::<UploadCmd>(MAX_EOS_WAITERS + 2);
        let mut actor = UploadActor::new(rx, server_write, 0);
        actor.phase = UploadPhase::Draining {
            eos_waiters: Vec::new(),
        };

        for _ in 0..=MAX_EOS_WAITERS {
            let (ack_tx, mut ack_rx) = oneshot::channel();
            actor.handle_eos(0, ack_tx);
            assert!(ack_rx.try_recv().unwrap().is_err());
        }

        let UploadPhase::Draining { eos_waiters } = &actor.phase else {
            panic!("actor must remain draining");
        };
        assert!(eos_waiters.is_empty());
    }

    #[tokio::test]
    async fn channel_close_acks_waiters_with_error() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 5,
            ack: ack_tx,
        })
        .await
        .unwrap();

        drop(tx);
        assert!(ack_rx.await.unwrap().is_err());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_write_error_acks_eos_with_error() {
        let (_server_side, client) = connected_pair().await;
        let (_cr, mut write_half) = client.into_split();
        write_half.shutdown().await.unwrap();
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, write_half.into(), 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 2,
            ack: ack_tx,
        })
        .await
        .unwrap();
        for seq in 0..3 {
            tx.send(UploadCmd::Frame {
                seq,
                data: Bytes::from_static(b"hello"),
            })
            .await
            .unwrap();
        }
        drop(tx);

        assert!(ack_rx.await.unwrap().is_err());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn reorder_buffer_overflow_aborts_upload() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        let big = Bytes::from(vec![0u8; MAX_PENDING_BYTES + 1]);
        tx.send(UploadCmd::Frame { seq: 1, data: big })
            .await
            .unwrap();
        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 1,
            ack: ack_tx,
        })
        .await
        .unwrap();
        drop(tx);
        assert!(ack_rx.await.is_err());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn large_gap_fill_keeps_order_across_write_runs() {
        let (mut client_read, server_write) = tcp_pair().await;
        let total = MAX_WRITE_IOV * 3 + 5;
        let (tx, rx) = mpsc::channel::<UploadCmd>(total + 16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        for seq in 1..total as u64 {
            tx.send(UploadCmd::Frame {
                seq,
                data: Bytes::from(vec![seq as u8; 64]),
            })
            .await
            .unwrap();
        }
        tx.send(UploadCmd::Frame {
            seq: 0,
            data: Bytes::from(vec![0u8; 64]),
        })
        .await
        .unwrap();

        let mut got = vec![0u8; total * 64];
        client_read.read_exact(&mut got).await.unwrap();
        for seq in 0..total {
            assert_eq!(
                got[seq * 64],
                seq as u8,
                "frame {seq} arrived out of order after a multi-run drain"
            );
        }

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn stale_and_duplicate_frames_discarded() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        tx.send(UploadCmd::Frame {
            seq: 0,
            data: Bytes::from_static(b"a"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 0,
            data: Bytes::from_static(b"stale"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 3,
            data: Bytes::from_static(b"d"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 3,
            data: Bytes::from_static(b"dup"),
        })
        .await
        .unwrap();
        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 3,
            ack: ack_tx,
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 1,
            data: Bytes::from_static(b"b"),
        })
        .await
        .unwrap();
        tx.send(UploadCmd::Frame {
            seq: 2,
            data: Bytes::from_static(b"c"),
        })
        .await
        .unwrap();
        assert!(ack_rx.await.unwrap().is_ok());
        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn reorder_timeout_shuts_down_actor() {
        tokio::time::pause();
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        tx.send(UploadCmd::Frame {
            seq: 5,
            data: Bytes::from_static(b"gap"),
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(MAX_REORDER_SECS + 1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();

        let (ack_tx, _ack_rx) = oneshot::channel();
        let send_result = tx
            .send(UploadCmd::Eos {
                max_seq: 5,
                ack: ack_tx,
            })
            .await;
        assert!(send_result.is_err());
        handle.await.unwrap();
    }
}

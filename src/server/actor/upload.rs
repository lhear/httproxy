use bytes::Bytes;
use std::collections::BTreeMap;
use std::io::IoSlice;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::warn;

use crate::error::ServerError;
use crate::server::constants::{
    MAX_EOS_WAITERS, MAX_PENDING_BYTES, MAX_PENDING_FRAMES, MAX_REORDER_SECS, MAX_WRITE_IOV,
    WRITE_TIMEOUT,
};

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
    upstream: Option<OwnedWriteHalf>,
    last_activity: Instant,
    /// 复用的一次性写批次，避免每次补齐空档都分配
    run_buf: Vec<Bytes>,
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
            run_buf: Vec::with_capacity(MAX_WRITE_IOV),
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
                        Some(cmd) => { if self.dispatch(cmd).await {
                            break;
                        } }
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
            UploadCmd::Eos { max_seq, ack } => self.handle_eos(max_seq, ack),
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
                    // 「刚到的这一帧 + 重排序缓冲里紧随其后的连续帧」合成一段，
                    // 用向量写一次吐出去：补齐空档时原来是每帧一次系统调用。
                    let mut head = data;
                    loop {
                        self.run_buf.clear();
                        self.run_buf.push(head);
                        *next_seq += 1;
                        while self.run_buf.len() < MAX_WRITE_IOV {
                            let Some(next_data) = pending.remove(next_seq) else {
                                break;
                            };
                            *pending_bytes -= next_data.len();
                            self.run_buf.push(next_data);
                            *next_seq += 1;
                        }
                        if !write_run(&mut self.upstream, &self.run_buf).await {
                            self.shutdown_and_drain().await;
                            return true;
                        }
                        match pending.remove(next_seq) {
                            Some(next_data) => {
                                *pending_bytes -= next_data.len();
                                head = next_data;
                            }
                            None => break,
                        }
                    }
                    let mut i = 0;
                    while i < eos_waiters.len() {
                        if *next_seq > eos_waiters[i].0 {
                            let (_, ack) = eos_waiters.swap_remove(i);
                            let _ = ack.send(Ok(()));
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
                        "reorder buffer overflow, aborting upload"
                    );
                    self.shutdown_and_drain().await;
                    return true;
                }
                pending.insert(seq, data);
                *pending_bytes += len;
                false
            }
            UploadPhase::Draining { .. } | UploadPhase::Closed => false,
        }
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
            UploadPhase::Draining { eos_waiters } => {
                eos_waiters.push(ack);
                false
            }
            UploadPhase::Closed => {
                let _ = ack.send(Err(ServerError::bad_gateway("upload actor closed")));
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

/// 把一段连续帧写进上游。返回 `false` 表示写失败/超时，调用方需要收尾。
async fn write_run(upstream: &mut Option<OwnedWriteHalf>, frames: &[Bytes]) -> bool {
    let Some(upstream) = upstream.as_mut() else {
        return false;
    };
    let written = if frames.len() == 1 {
        // 单帧是常态，走普通 write，省掉 iov 装配
        tokio::time::timeout(WRITE_TIMEOUT, upstream.write_all(&frames[0])).await
    } else {
        tokio::time::timeout(WRITE_TIMEOUT, write_vectored_all(upstream, frames)).await
    };
    matches!(written, Ok(Ok(())))
}

/// 一段连续帧一次系统调用写出去；部分写时按帧/帧内偏移推进。
async fn write_vectored_all(
    upstream: &mut OwnedWriteHalf,
    frames: &[Bytes],
) -> std::io::Result<()> {
    let mut first = 0usize;
    let mut skip = 0usize;
    while first < frames.len() {
        let written = {
            let mut slices: [IoSlice<'_>; MAX_WRITE_IOV] =
                std::array::from_fn(|_| IoSlice::new(&[]));
            let mut count = 0;
            for (i, frame) in frames[first..].iter().enumerate().take(MAX_WRITE_IOV) {
                let slice: &[u8] = if i == 0 { &frame[skip..] } else { &frame[..] };
                slices[count] = IoSlice::new(slice);
                count += 1;
            }
            upstream.write_vectored(&slices[..count]).await?
        };
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        let mut left = written;
        while left > 0 && first < frames.len() {
            let remain = frames[first].len() - skip;
            if left >= remain {
                left -= remain;
                first += 1;
                skip = 0;
            } else {
                skip += left;
                left = 0;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
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
        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 1,
            ack: ack_tx,
        })
        .await
        .unwrap();
        assert!(ack_rx.await.unwrap().is_ok());

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
    async fn eos_acked_immediately_when_next_seq_exceeds_max() {
        let (_rx, server_write) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, server_write, 5);
        let handle = tokio::spawn(async move { actor.run().await });

        let (ack_tx, ack_rx) = oneshot::channel();
        tx.send(UploadCmd::Eos {
            max_seq: 3,
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_stream = server.await.unwrap();
        drop(server_stream);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (_cr, write_half) = client.into_split();
        let (tx, rx) = mpsc::channel::<UploadCmd>(16);
        let actor = UploadActor::new(rx, write_half, 0);
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

    /// 一次补齐跨越多次向量写的大空档：帧顺序必须完全保持。
    #[tokio::test]
    async fn large_gap_fill_keeps_order_across_write_runs() {
        let (mut client_read, server_write) = tcp_pair().await;
        let total = MAX_WRITE_IOV * 3 + 5;
        let (tx, rx) = mpsc::channel::<UploadCmd>(total + 16);
        let actor = UploadActor::new(rx, server_write, 0);
        let handle = tokio::spawn(async move { actor.run().await });

        // 先发 1..total，最后补上 0：一次补齐整段，超过单次向量写上限
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

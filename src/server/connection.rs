use bytes::Bytes;
use std::{cmp::Ordering, collections::BTreeMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_socks::tcp::Socks5Stream;
use tracing::{info, warn};

use tokio::io::AsyncWriteExt;

use crate::dns::DnsClient;
use crate::server::constants::{
    MAX_PENDING_BYTES, MAX_PENDING_FRAMES, MAX_REORDER_SECS, WRITE_TIMEOUT,
};
use crate::server::state::{FrameOrEos, UploadStream};

pub async fn connect_upstream(
    dns_client: Option<&Arc<DnsClient>>,
    client_subnet: Option<IpAddr>,
    socks5_proxy: Option<&Arc<str>>,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    if let Some(client) = dns_client {
        return client
            .connect(
                host,
                port,
                client_subnet,
                socks5_proxy.map(|s| s.to_string()),
            )
            .await
            .map_err(|e| format!("dns error: {e}"));
    }
    match socks5_proxy {
        Some(p) => Socks5Stream::connect(p.as_ref(), (host, port))
            .await
            .map(Socks5Stream::into_inner)
            .map_err(|e| e.to_string()),
        None => TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string()),
    }
}

pub async fn ordered_frame_writer(
    mut rx: mpsc::Receiver<FrameOrEos>,
    mut upstream_write: tokio::net::tcp::OwnedWriteHalf,
    stream_key: String,
    stream: Arc<UploadStream>,
    initial_seq: u64,
) {
    let mut next_seq: u64 = initial_seq;
    let mut pending: BTreeMap<u64, Bytes> = BTreeMap::new();
    let mut pending_bytes: usize = 0;
    let mut eos_waiters: BTreeMap<u64, Vec<oneshot::Sender<()>>> = BTreeMap::new();

    'main: loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(FrameOrEos::Data { seq, data }) => {
                        match seq.cmp(&next_seq) {
                            Ordering::Less => {
                                warn!(stream_id = %stream_key, seq, "stale frame discarded");
                            }
                            Ordering::Equal => {
                                let mut expected = next_seq + 1;
                                let mut run = vec![data];

                                while let Some(d) = pending.remove(&expected) {
                                    pending_bytes -= d.len();
                                    run.push(d);
                                    expected += 1;
                                }
                                next_seq = expected;

                                for buf in run {
                                    if let Err(e) = tokio::time::timeout(WRITE_TIMEOUT, upstream_write.write_all(&buf)).await {
                                        warn!(stream_id = %stream_key, reason = %e, "upstream write failed");
                                        break 'main;
                                    }
                                }
                                notify_eos(&mut eos_waiters, next_seq);
                            }
                            Ordering::Greater => {
                                if pending.contains_key(&seq) {
                                    warn!(stream_id = %stream_key, seq, "duplicate pending frame discarded");
                                    continue;
                                }
                                let data_len = data.len();
                                if pending.len() >= MAX_PENDING_FRAMES ||
                                   pending_bytes + data_len > MAX_PENDING_BYTES {
                                    warn!(stream_id = %stream_key, "reorder buffer full");
                                    break;
                                }
                                pending.insert(seq, data);
                                pending_bytes += data_len;
                            }
                        }
                    }
                    Some(FrameOrEos::Eos { max_seq, done }) => {
                        if next_seq > max_seq {
                            let _ = done.send(());
                        } else {
                            eos_waiters.entry(max_seq)
                                .or_default()
                                .push(done);
                        }
                    }
                    None => break
                }
            }
             _ = stream.shutdown.notified() => {
                info!(stream_id = %stream_key, "shutdown received, exiting");
                break;
            },
            _ = tokio::time::sleep(Duration::from_secs(MAX_REORDER_SECS)), if !pending.is_empty() || !eos_waiters.is_empty() => {
                warn!(stream_id = %stream_key, next_seq,
                      pending_frames = pending.len(), eos_waiters = eos_waiters.len(),
                      "reorder timeout");
                break;
            }
        }
    }

    stream.do_shutdown();

    while let Ok(cmd) = rx.try_recv() {
        if let FrameOrEos::Eos { done, .. } = cmd {
            let _ = done.send(());
        }
    }

    for (_, waiters) in eos_waiters {
        for sender in waiters {
            let _ = sender.send(());
        }
    }

    let _ = upstream_write.shutdown().await;
    info!(stream_id = %stream_key, "frame writer exited");
}

#[inline]
fn notify_eos(eos_waiters: &mut BTreeMap<u64, Vec<oneshot::Sender<()>>>, next_seq: u64) {
    while let Some(entry) = eos_waiters.first_entry() {
        if *entry.key() >= next_seq {
            break;
        }
        let (_, senders) = entry.remove_entry();
        for sender in senders {
            let _ = sender.send(());
        }
    }
}

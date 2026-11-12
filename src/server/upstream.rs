use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::server::constants::MAX_WRITE_IOV;
use crate::warp::masque::{KeepAlive, MasqueRecv, MasqueSend, MasqueStream};

pub(crate) enum Upstream {
    Direct(TcpStream),
    Warp(MasqueStream),
}

impl Upstream {
    pub fn into_split(self) -> (UpstreamRead, UpstreamWrite) {
        match self {
            Upstream::Direct(stream) => {
                let (read, write) = stream.into_split();
                (UpstreamRead::Direct(read), UpstreamWrite::Direct(write))
            }
            Upstream::Warp(stream) => (
                UpstreamRead::Warp {
                    read: stream.recv,
                    _guard: stream.guard.clone(),
                },
                UpstreamWrite::Warp {
                    write: stream.send,
                    _guard: stream.guard,
                },
            ),
        }
    }
}

pub(crate) enum UpstreamRead {
    Direct(OwnedReadHalf),
    Warp { read: MasqueRecv, _guard: KeepAlive },
}

impl AsyncRead for UpstreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamRead::Direct(read) => Pin::new(read).poll_read(cx, buf),
            UpstreamRead::Warp { read, .. } => Pin::new(read).poll_read(cx, buf),
        }
    }
}

impl From<OwnedReadHalf> for UpstreamRead {
    fn from(value: OwnedReadHalf) -> Self {
        Self::Direct(value)
    }
}

pub(crate) enum UpstreamWrite {
    Direct(OwnedWriteHalf),
    Warp {
        write: MasqueSend,
        _guard: KeepAlive,
    },
}

impl UpstreamWrite {
    pub async fn write_frames(&mut self, frames: &[Bytes]) -> io::Result<()> {
        match self {
            UpstreamWrite::Direct(write) => write_tcp_frames(write, frames).await,
            UpstreamWrite::Warp { write, .. } => write.write_frames(frames).await,
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            UpstreamWrite::Direct(write) => write.shutdown().await,
            UpstreamWrite::Warp { write, .. } => write.shutdown().await,
        }
    }
}

impl From<OwnedWriteHalf> for UpstreamWrite {
    fn from(value: OwnedWriteHalf) -> Self {
        Self::Direct(value)
    }
}

async fn write_tcp_frames(write: &mut OwnedWriteHalf, frames: &[Bytes]) -> io::Result<()> {
    if frames.len() == 1 {
        return write.write_all(&frames[0]).await;
    }
    write_vectored_all(write, frames).await
}

async fn write_vectored_all(write: &mut OwnedWriteHalf, frames: &[Bytes]) -> io::Result<()> {
    use std::io::IoSlice;

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
            write.write_vectored(&slices[..count]).await?
        };
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
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
    use crate::test_support::connected_pair;
    use tokio::io::AsyncReadExt;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let (server_side, client) = connected_pair().await;
        (client, server_side)
    }

    #[tokio::test]
    async fn direct_write_preserves_frame_order() {
        let (client, mut server) = tcp_pair().await;
        let (_, mut write) = Upstream::Direct(client).into_split();

        let frames: Vec<Bytes> = (0..MAX_WRITE_IOV as u8)
            .map(|i| Bytes::from(vec![i; 32]))
            .collect();
        write.write_frames(&frames).await.unwrap();
        write.shutdown().await.unwrap();

        let mut got = vec![0u8; frames.len() * 32];
        server.read_exact(&mut got).await.unwrap();
        for (i, chunk) in got.chunks(32).enumerate() {
            assert!(
                chunk.iter().all(|&b| b == i as u8),
                "frame {i} out of order"
            );
        }
    }

    #[tokio::test]
    async fn direct_read_delegates() {
        let (client, mut server) = tcp_pair().await;
        let (mut read, _write) = Upstream::Direct(client).into_split();
        server.write_all(b"upstream bytes").await.unwrap();
        let mut buf = [0u8; 14];
        read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"upstream bytes");
    }
}

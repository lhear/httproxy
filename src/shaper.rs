use bytes::BufMut;
use bytes::{Bytes, BytesMut};
use futures::Stream;
use pin_project_lite::pin_project;
use rand::RngCore;
use rand::seq::SliceRandom;
use rand_distr::{Distribution, Normal};
use std::sync::OnceLock;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::{Instant, Sleep};

static JITTER_TABLE: OnceLock<Vec<u64>> = OnceLock::new();
const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;

pin_project! {
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,
        pending_data: BytesMut,
        chunk_size: usize,
        #[pin]
        flush_timer: Sleep,
        jitter_table: &'static [u64],
        cursor: usize,
    }
}

fn get_jitter_table(avg_latency: Duration) -> &'static [u64] {
    return JITTER_TABLE.get_or_init(|| {
        let mean = avg_latency.as_micros() as f64;
        let std_dev = mean / 3.0;
        let normal = Normal::new(mean, std_dev).unwrap();
        let mut rng = rand::rng();
        let upper_limit = mean * 2.0;

        let mut table = (0..TABLE_SIZE)
            .map(|_| {
                let sample = normal.sample(&mut rng);
                sample.clamp(0.0, upper_limit) as u64
            })
            .collect::<Vec<_>>();

        table.shuffle(&mut rng);
        table
    });
}

impl<R> TrafficShaper<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        let start_cursor = (rand::rng().next_u64() as usize) & TABLE_MASK;

        Self {
            reader,
            pending_data: BytesMut::with_capacity(chunk_size),
            chunk_size,
            flush_timer: tokio::time::sleep_until(Instant::now()),
            jitter_table: get_jitter_table(Duration::from_millis(5)),
            cursor: start_cursor,
        }
    }
}

impl<R> Stream for TrafficShaper<R>
where
    R: AsyncRead,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let has_data = !this.pending_data.is_empty();
            let rem = *this.chunk_size - this.pending_data.len();

            if has_data && (rem == 0 || this.flush_timer.as_mut().poll(cx).is_ready()) {
                let chunk = this.pending_data.split();
                return Poll::Ready(Some(Ok(chunk.freeze())));
            }

            this.pending_data.reserve(rem);

            let dst = this.pending_data.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(dst);

            match this.reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();

                    if n == 0 {
                        return if !has_data {
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Ok(this.pending_data.split().freeze())))
                        };
                    }

                    if !has_data {
                        let idx = *this.cursor;
                        let delay_micros = this.jitter_table[idx];
                        *this.cursor = (idx + 13) & TABLE_MASK;

                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay_micros));

                        let _ = this.flush_timer.as_mut().poll(cx);
                    }

                    unsafe {
                        this.pending_data.advance_mut(n);
                    }
                    continue;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            }
        }
    }
}

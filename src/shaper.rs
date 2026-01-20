use bytes::{Buf, BufMut, Bytes, BytesMut};
use pin_project_lite::pin_project;
use rand::{Rng, RngCore};
use rand_distr::{Distribution, Normal};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    time::{Instant, Sleep},
};
use tokio_stream::StreamExt;

static JITTER_TABLE: OnceLock<Vec<u64>> = OnceLock::new();
const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const CHUNK_SIZE: usize = 16 * 1024;
const AVG_LATENCY: u128 = Duration::from_millis(5).as_micros();

#[derive(Debug, Deserialize, Clone)]
pub struct PaddingConfig {
    pub padding_threshold: usize,
    pub padding_range: [usize; 2],
}

#[derive(Debug, Deserialize, Clone)]
pub struct StageConfig {
    pub count: Option<usize>,
    pub count_range: Option<[usize; 2]>,
    pub padding_threshold: usize,
    pub padding_range: [usize; 2],
}

#[derive(Debug, Deserialize, Clone)]
pub struct TrafficConfig {
    pub global: PaddingConfig,
    pub stages: Vec<StageConfig>,
}

pin_project! {
    #[project = TrafficShaperProj]
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,
        frame_buffer: BytesMut,
        #[pin]
        flush_timer: Sleep,
        cursor: usize,
        config: TrafficConfig,
        packet_count: usize,
        current_stage_idx: usize,
    }
}

struct MultiBuf(VecDeque<Bytes>);

impl Buf for MultiBuf {
    fn remaining(&self) -> usize {
        self.0.iter().map(|b| b.len()).sum()
    }
    fn chunk(&self) -> &[u8] {
        self.0.front().map(|b| b.as_ref()).unwrap_or(&[])
    }
    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            if let Some(front) = self.0.front_mut() {
                if front.len() <= cnt {
                    cnt -= front.len();
                    self.0.pop_front();
                } else {
                    front.advance(cnt);
                    cnt = 0;
                }
            } else {
                break;
            }
        }
    }
    fn chunks_vectored<'a>(&'a self, dst: &mut [std::io::IoSlice<'a>]) -> usize {
        let mut n = 0;
        for (chunk, slot) in self.0.iter().zip(dst.iter_mut()) {
            *slot = std::io::IoSlice::new(chunk.as_ref());
            n += 1;
        }
        n
    }
}

impl TrafficShaper<()> {
    pub async fn decode_to_writer<S, W, E>(mut reader: S, writer: &mut W) -> std::io::Result<()>
    where
        S: futures::Stream<Item = Result<Bytes, E>> + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
        E: std::fmt::Display,
    {
        let mut queue = MultiBuf(VecDeque::new());

        while let Some(chunk) = reader.next().await {
            let data =
                chunk.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            queue.0.push_back(data);

            while queue.remaining() >= 4 {
                let header = {
                    let mut head_bytes = [0u8; 4];
                    let mut temp_cursor = 0;
                    for b in &queue.0 {
                        let take = (4 - temp_cursor).min(b.len());
                        head_bytes[temp_cursor..temp_cursor + take].copy_from_slice(&b[..take]);
                        temp_cursor += take;
                        if temp_cursor == 4 {
                            break;
                        }
                    }
                    u32::from_be_bytes(head_bytes)
                };

                let actual_data_len = (header >> 16) as usize;
                let total_frame_payload = (header & 0xFFFF) as usize;

                if total_frame_payload > CHUNK_SIZE - 4 || actual_data_len > total_frame_payload {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "corrupt frame",
                    ));
                }

                if queue.remaining() < 4 + total_frame_payload {
                    break;
                }

                queue.advance(4);

                let mut to_write = actual_data_len;
                while to_write > 0 {
                    let mut slices = [std::io::IoSlice::new(&[]); 16];
                    let cnt = queue.chunks_vectored(&mut slices);

                    let mut batch_size = 0;
                    let mut take_cnt = 0;
                    for (i, chunk) in queue.0.iter().enumerate().take(cnt) {
                        let s_len = chunk.len();
                        if batch_size + s_len > to_write {
                            let rem = to_write - batch_size;
                            slices[i] = std::io::IoSlice::new(&chunk[..rem]);
                            take_cnt = i + 1;
                            break;
                        }
                        batch_size += s_len;
                        take_cnt = i + 1;
                    }
                    let n = writer.write_vectored(&slices[..take_cnt]).await?;
                    queue.advance(n);
                    to_write -= n;
                }
                let padding = total_frame_payload - actual_data_len;
                if padding > 0 {
                    queue.advance(padding);
                }
            }
        }
        Ok(())
    }
}

impl<R> TrafficShaper<R> {
    pub fn new(reader: R, mut config: TrafficConfig) -> Self {
        let start_cursor = (rand::rng().next_u64() as usize) & TABLE_MASK;
        let mut frame_buffer = BytesMut::with_capacity(CHUNK_SIZE);

        unsafe { frame_buffer.advance_mut(4) }

        config.stages.sort_by_key(|s| {
            s.count
                .or_else(|| s.count_range.map(|[_, b]| b))
                .unwrap_or(0)
        });

        Self {
            reader,
            frame_buffer,
            flush_timer: tokio::time::sleep_until(Instant::now()),
            config,
            packet_count: 0,
            cursor: start_cursor,
            current_stage_idx: 0,
        }
    }

    fn seal_and_reset(this: &mut TrafficShaperProj<'_, R>, actual_len: usize) -> Bytes {
        let current_packet = *this.packet_count + 1;

        if let Some(stage) = this.config.stages.get(*this.current_stage_idx) {
            let end = stage
                .count
                .or_else(|| stage.count_range.map(|r| r[1]))
                .unwrap_or(0);
            if current_packet > end {
                *this.current_stage_idx += 1;
            }
        }

        let (threshold, range) = this
            .config
            .stages
            .get(*this.current_stage_idx)
            .map(|s| (s.padding_threshold, s.padding_range))
            .unwrap_or((
                this.config.global.padding_threshold,
                this.config.global.padding_range,
            ));

        let padding_len = if actual_len < threshold {
            rand::rng()
                .random_range(range[0]..=range[1])
                .min(CHUNK_SIZE - 4 - actual_len)
        } else {
            0
        };

        let total_payload_len = actual_len + padding_len;
        let header_bytes = ((actual_len as u32) << 16) | (total_payload_len as u32);
        unsafe {
            let ptr = this.frame_buffer.as_mut_ptr();
            std::ptr::copy_nonoverlapping(header_bytes.to_be_bytes().as_ptr(), ptr, 4);
        }

        if padding_len > 0 {
            this.frame_buffer.put_bytes(0, padding_len);
        }

        let frame = this.frame_buffer.split().freeze();
        *this.packet_count += 1;

        this.frame_buffer.reserve(CHUNK_SIZE);
        unsafe { this.frame_buffer.advance_mut(4) }

        frame
    }
}

impl<R> tokio_stream::Stream for TrafficShaper<R>
where
    R: AsyncRead,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let actual_len = this.frame_buffer.len() - 4;
            let is_full = actual_len == CHUNK_SIZE - 4;

            if is_full || (actual_len > 0 && this.flush_timer.as_mut().poll(cx).is_ready()) {
                return Poll::Ready(Some(Ok(Self::seal_and_reset(&mut this, actual_len))));
            }

            let dst = this.frame_buffer.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(dst);

            match this.reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if actual_len == 0 {
                            return Poll::Ready(None);
                        }
                        return Poll::Ready(Some(Ok(Self::seal_and_reset(&mut this, actual_len))));
                    }

                    if actual_len == 0 && n < CHUNK_SIZE - 4 {
                        let idx = *this.cursor;
                        let delay = jitter_table()[idx];
                        *this.cursor = (idx + 1) & TABLE_MASK;
                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay));
                        let _ = this.flush_timer.as_mut().poll(cx);
                    }

                    unsafe {
                        this.frame_buffer.advance_mut(n);
                    }
                    continue;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            }
        }
    }
}

fn jitter_table() -> &'static [u64] {
    JITTER_TABLE.get_or_init(|| {
        let mean = AVG_LATENCY as f64;
        let std_dev = mean / 3.0;
        let normal = Normal::new(mean, std_dev).unwrap();
        let mut rng = rand::rng();
        let mut table = (0..TABLE_SIZE)
            .map(|_| normal.sample(&mut rng).clamp(0.0, mean * 2.0) as u64)
            .collect::<Vec<_>>();
        use rand::seq::SliceRandom;
        table.shuffle(&mut rng);
        table
    })
}

use bytes::{Buf, BufMut, Bytes, BytesMut};
use pin_project_lite::pin_project;
use rand::{Rng, RngCore};
use rand_distr::{Distribution, Normal};
use serde::Deserialize;
use std::{
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};

static JITTER_TABLE: OnceLock<Vec<u64>> = OnceLock::new();
const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;

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

struct FlattenedStage {
    end_at: usize,
    threshold: usize,
    range: [usize; 2],
}

pin_project! {
    #[project = TrafficShaperProj]
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,
        frame_buffer: BytesMut,
        chunk_size: usize,
        #[pin]
        flush_timer: Sleep,
        jitter_table: &'static [u64],
        cursor: usize,
        config: TrafficConfig,
        packet_count: usize,
        current_data_len: usize,
        stages_cache: Vec<FlattenedStage>,
        current_stage_idx: usize,
        max_data_allowed: usize,
    }
}

impl TrafficShaper<()> {
    pub fn decode_from_buffer(src: &mut BytesMut) -> Result<Option<Bytes>, std::io::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let header = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let actual_len = (header >> 16) as usize;
        let total_len = (header & 0xFFFF) as usize;
        let full_frame_len = 4 + total_len;

        if src.len() < full_frame_len {
            return Ok(None);
        }

        let mut frame = src.split_to(full_frame_len);
        frame.advance(4);
        Ok(Some(frame.split_to(actual_len).freeze()))
    }
}

impl<R> TrafficShaper<R> {
    pub fn new(reader: R, chunk_size: usize, config: TrafficConfig) -> Self {
        let start_cursor = (rand::rng().next_u64() as usize) & TABLE_MASK;
        let mut frame_buffer = BytesMut::with_capacity(chunk_size);
        frame_buffer.put_u32(0);

        let mut stages_cache: Vec<FlattenedStage> = config
            .stages
            .iter()
            .map(|s| {
                let end_at = s
                    .count
                    .unwrap_or_else(|| s.count_range.map(|[_, b]| b).unwrap_or(0));
                FlattenedStage {
                    end_at,
                    threshold: s.padding_threshold,
                    range: s.padding_range,
                }
            })
            .collect();
        stages_cache.sort_by_key(|s| s.end_at);

        Self {
            reader,
            frame_buffer,
            chunk_size,
            flush_timer: tokio::time::sleep_until(Instant::now()),
            config,
            packet_count: 0,
            jitter_table: get_jitter_table(Duration::from_millis(5)),
            cursor: start_cursor,
            current_data_len: 0,
            stages_cache,
            current_stage_idx: 0,
            max_data_allowed: chunk_size.saturating_sub(4),
        }
    }

    fn seal_and_reset(this: &mut TrafficShaperProj<'_, R>) -> Bytes {
        let actual_len = *this.current_data_len;
        let current_packet = *this.packet_count + 1;
        if *this.current_stage_idx < this.stages_cache.len()
            && current_packet > this.stages_cache[*this.current_stage_idx].end_at
        {
            *this.current_stage_idx += 1;
        }

        let (threshold, range) = if let Some(s) = this.stages_cache.get(*this.current_stage_idx) {
            if current_packet <= s.end_at {
                (s.threshold, s.range)
            } else {
                (
                    this.config.global.padding_threshold,
                    this.config.global.padding_range,
                )
            }
        } else {
            (
                this.config.global.padding_threshold,
                this.config.global.padding_range,
            )
        };

        let padding_len = if actual_len < threshold {
            rand::rng()
                .random_range(range[0]..=range[1])
                .min(this.chunk_size.saturating_sub(4 + actual_len))
        } else {
            0
        };

        let total_payload_len = actual_len + padding_len;
        let header_bytes = ((actual_len as u32) << 16) | (total_payload_len as u32);
        this.frame_buffer[0..4].copy_from_slice(&header_bytes.to_be_bytes());

        if padding_len > 0 {
            this.frame_buffer.put_bytes(0, padding_len);
        }

        let frame = this.frame_buffer.split().freeze();
        *this.packet_count += 1;

        this.frame_buffer.clear();
        this.frame_buffer.reserve(*this.chunk_size);
        this.frame_buffer.put_u32(0);
        *this.current_data_len = 0;

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
            let current_len = *this.current_data_len;
            let is_full = current_len == *this.max_data_allowed;

            if is_full || (current_len > 0 && this.flush_timer.as_mut().poll(cx).is_ready()) {
                return Poll::Ready(Some(Ok(Self::seal_and_reset(&mut this))));
            }

            let remaining_space = this.max_data_allowed.saturating_sub(current_len);
            let dst = this.frame_buffer.spare_capacity_mut();
            let read_limit = remaining_space.min(dst.len());
            let mut read_buf = ReadBuf::uninit(&mut dst[..read_limit]);

            match this.reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if *this.current_data_len == 0 {
                            return Poll::Ready(None);
                        }
                        return Poll::Ready(Some(Ok(Self::seal_and_reset(&mut this))));
                    }

                    if *this.current_data_len == 0 && n < *this.max_data_allowed {
                        let idx = *this.cursor;
                        let delay = this.jitter_table[idx];
                        *this.cursor = (idx + 1) & TABLE_MASK;
                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay));
                        let _ = this.flush_timer.as_mut().poll(cx);
                    }

                    unsafe {
                        this.frame_buffer.advance_mut(n);
                    }
                    *this.current_data_len += n;
                    continue;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            }
        }
    }
}

fn get_jitter_table(avg_latency: Duration) -> &'static [u64] {
    JITTER_TABLE.get_or_init(|| {
        let mean = avg_latency.as_micros() as f64;
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

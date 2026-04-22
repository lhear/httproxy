use bytes::{Buf, BufMut, Bytes, BytesMut};
use pin_project_lite::pin_project;
use rand::{Rng, RngExt, seq::SliceRandom};
use rand_distr::{Distribution, Normal};
use serde::Deserialize;
use std::{
    io::{Error, ErrorKind},
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};

const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const CHUNK_SIZE: usize = 16 * 1024;
const HEADER_SIZE: usize = 4;
const MAX_PAYLOAD: usize = CHUNK_SIZE - HEADER_SIZE;
const AVG_LATENCY_MICROS: f64 = 5_000.0;

static JITTER_TABLE: OnceLock<Box<[u64; TABLE_SIZE]>> = OnceLock::new();

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

#[derive(Debug, Clone, Copy)]
struct ResolvedStage {
    end_count: usize,
    padding_threshold: usize,
    padding_range: [usize; 2],
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
        stages: Vec<ResolvedStage>,
        global_threshold: usize,
        global_range: [usize; 2],
        packet_count: usize,
        stage_idx: usize,
    }
}

impl TrafficShaper<()> {
    pub fn decode_from_buffer(src: &mut BytesMut) -> Result<Option<Bytes>, Error> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        let header = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let actual_len = (header >> 16) as usize;
        let total_len = (header & 0xFFFF) as usize;

        if total_len > MAX_PAYLOAD || actual_len > total_len {
            return Err(Error::new(ErrorKind::InvalidData, "invalid frame size"));
        }

        let full_frame_len = HEADER_SIZE + total_len;
        if src.len() < full_frame_len {
            return Ok(None);
        }

        let mut frame = src.split_to(full_frame_len);
        frame.advance(HEADER_SIZE);
        frame.truncate(actual_len);
        Ok(Some(frame.freeze()))
    }
}

impl<R> TrafficShaper<R> {
    pub fn new(reader: R, config: TrafficConfig) -> Self {
        let cursor = (rand::rng().next_u64() as usize) & TABLE_MASK;

        let mut stages: Vec<ResolvedStage> = config
            .stages
            .iter()
            .map(|s| ResolvedStage {
                end_count: s
                    .count
                    .or_else(|| s.count_range.map(|[_, hi]| hi))
                    .unwrap_or(0),
                padding_threshold: s.padding_threshold,
                padding_range: s.padding_range,
            })
            .collect();
        stages.sort_unstable_by_key(|s| s.end_count);

        let mut frame_buffer = BytesMut::with_capacity(CHUNK_SIZE);
        unsafe { frame_buffer.advance_mut(HEADER_SIZE) }

        Self {
            reader,
            frame_buffer,
            flush_timer: tokio::time::sleep_until(Instant::now()),
            stages,
            global_threshold: config.global.padding_threshold,
            global_range: config.global.padding_range,
            packet_count: 0,
            cursor,
            stage_idx: 0,
        }
    }

    #[inline(always)]
    fn prepare_next_frame(buf: &mut BytesMut) {
        buf.reserve(CHUNK_SIZE);
        unsafe { buf.advance_mut(HEADER_SIZE) }
    }

    fn seal_and_emit(this: &mut TrafficShaperProj<'_, R>, actual_len: usize) -> Bytes {
        *this.packet_count += 1;

        while let Some(stage) = this.stages.get(*this.stage_idx) {
            if *this.packet_count <= stage.end_count {
                break;
            }
            *this.stage_idx += 1;
        }

        let (threshold, range) = match this.stages.get(*this.stage_idx) {
            Some(s) => (s.padding_threshold, s.padding_range),
            None => (*this.global_threshold, *this.global_range),
        };

        let padding_len = if actual_len < threshold {
            rand::rng()
                .random_range(range[0]..=range[1])
                .min(MAX_PAYLOAD - actual_len)
        } else {
            0
        };

        let total_payload = actual_len + padding_len;
        let header = ((actual_len as u32) << 16) | (total_payload as u32);
        unsafe {
            std::ptr::copy_nonoverlapping(
                header.to_be_bytes().as_ptr(),
                this.frame_buffer.as_mut_ptr(),
                HEADER_SIZE,
            );
        }

        if padding_len > 0 {
            this.frame_buffer.put_bytes(0, padding_len);
        }

        let frame = this.frame_buffer.split().freeze();
        Self::prepare_next_frame(this.frame_buffer);
        frame
    }
}

impl<R: AsyncRead> tokio_stream::Stream for TrafficShaper<R> {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let actual_len = this.frame_buffer.len() - HEADER_SIZE;
            let remaining = MAX_PAYLOAD - actual_len;

            if remaining == 0 {
                return Poll::Ready(Some(Ok(Self::seal_and_emit(&mut this, actual_len))));
            }

            if actual_len > 0 && this.flush_timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Some(Ok(Self::seal_and_emit(&mut this, actual_len))));
            }

            let spare = this.frame_buffer.spare_capacity_mut();
            let read_limit = spare.len().min(remaining);
            let mut read_buf = ReadBuf::uninit(&mut spare[..read_limit]);

            match this.reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return if actual_len == 0 {
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Ok(Self::seal_and_emit(&mut this, actual_len))))
                        };
                    }

                    if actual_len == 0 && n < MAX_PAYLOAD {
                        let idx = *this.cursor;
                        let delay_us = jitter_table()[idx];
                        *this.cursor = (idx + 1) & TABLE_MASK;
                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay_us));
                        let _ = this.flush_timer.as_mut().poll(cx);
                    }

                    unsafe { this.frame_buffer.advance_mut(n) }
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            }
        }
    }
}

fn jitter_table() -> &'static [u64; TABLE_SIZE] {
    JITTER_TABLE.get_or_init(|| {
        let std_dev = AVG_LATENCY_MICROS / 3.0;
        let normal = Normal::new(AVG_LATENCY_MICROS, std_dev).unwrap();
        let mut rng = rand::rng();
        let max_val = AVG_LATENCY_MICROS * 2.0;

        let mut table = Box::new([0u64; TABLE_SIZE]);
        for slot in table.iter_mut() {
            *slot = normal.sample(&mut rng).clamp(0.0, max_val) as u64;
        }
        table.shuffle(&mut rng);
        table
    })
}

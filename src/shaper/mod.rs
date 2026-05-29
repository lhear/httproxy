use bytes::{Buf, BufMut, Bytes, BytesMut};
use pin_project_lite::pin_project;
use rand::rngs::SmallRng;
use rand::{Rng, RngExt, SeedableRng, seq::SliceRandom};
use rand_distr::{Distribution, LogNormal};
use serde::Deserialize;
use std::{
    io::{Error, ErrorKind},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};

pub const MAX_RAW_PAYLOAD: usize = 16 * 1024;

const TABLE_SIZE: usize = 8192;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const DELIMITER: u8 = b'\n';
const AVG_LATENCY_MICROS: f64 = 5_000.0;
const MAX_BINARY_FRAME_LEN: usize = MAX_RAW_PAYLOAD + 38;
const MAX_JSON_LINE_LEN: usize = MAX_RAW_PAYLOAD + 2396;
const HEADER_LEN: usize = 10;

static JITTER_TABLE: OnceLock<Box<[u64; TABLE_SIZE]>> = OnceLock::new();

fn generate_jitter_table(mut rng: impl Rng) -> Box<[u64; TABLE_SIZE]> {
    let sigma = 0.5;
    let avg = AVG_LATENCY_MICROS;
    let mu = avg.ln() - (sigma * sigma) * 0.5;
    let log_normal = LogNormal::new(mu, sigma).expect("Invalid parameters");
    let mut table = Box::new([0u64; TABLE_SIZE]);
    for slot in table.iter_mut() {
        *slot = log_normal.sample(&mut rng).round() as u64;
    }
    table.shuffle(&mut rng);
    table
}

#[inline]
fn jitter_table() -> &'static [u64; TABLE_SIZE] {
    JITTER_TABLE.get_or_init(|| generate_jitter_table(rand::rng()))
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PaddingConfig {
    pub padding_threshold: usize,
    pub padding_range: [usize; 2],
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StageConfig {
    pub count: Option<usize>,
    pub count_range: Option<[usize; 2]>,
    pub padding_threshold: usize,
    pub padding_range: [usize; 2],
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum EncodingType {
    Json,
    Binary,
}

impl Default for EncodingType {
    #[inline]
    fn default() -> Self {
        EncodingType::Binary
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrafficConfig {
    pub global: PaddingConfig,
    #[serde(default)]
    pub stages: Vec<StageConfig>,
    #[serde(default)]
    pub encoding_type: EncodingType,
    #[serde(default)]
    pub max_download_bytes: Option<u64>,
}

impl TrafficConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::anyhow;
        if self.global.padding_range[0] > self.global.padding_range[1] {
            return Err(anyhow!(
                "traffic_shaping.global.padding_range low ({}) > high ({})",
                self.global.padding_range[0],
                self.global.padding_range[1]
            ));
        }
        for (i, stage) in self.stages.iter().enumerate() {
            if stage.padding_range[0] > stage.padding_range[1] {
                return Err(anyhow!(
                    "traffic_shaping.stages[{}].padding_range low ({}) > high ({})",
                    i,
                    stage.padding_range[0],
                    stage.padding_range[1]
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolvedStage {
    end_count: usize,
    padding_threshold: usize,
    padding_range: [usize; 2],
}

pub trait FrameCipher: Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

#[inline]
fn read_u64_be(data: &[u8]) -> u64 {
    u64::from_be_bytes(data[..8].try_into().unwrap())
}

#[inline]
fn read_u16_be(data: &[u8]) -> u16 {
    u16::from_be_bytes(data[..2].try_into().unwrap())
}

#[inline]
fn extract_frame(payload: &[u8]) -> Result<(u64, Bytes), Error> {
    if payload.len() < HEADER_LEN {
        return Err(Error::new(ErrorKind::InvalidData, "payload too short"));
    }
    let seq = read_u64_be(&payload[..8]);
    let orig_len = read_u16_be(&payload[8..10]) as usize;
    let total = HEADER_LEN + orig_len;
    if payload.len() < total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "payload shorter than declared original length",
        ));
    }
    Ok((seq, Bytes::copy_from_slice(&payload[HEADER_LEN..total])))
}

#[inline]
fn trim_bytes(mut b: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = b.split_first() {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = b.split_last() {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

#[inline]
fn parse_json_payload(json: &[u8]) -> Result<Vec<u8>, Error> {
    let json = trim_bytes(json);
    let err = |msg: &str| Error::new(ErrorKind::InvalidData, msg);

    const PREFIX: &[u8] = b"\"data\":\"";
    static DATA_FINDER: OnceLock<memchr::memmem::Finder<'static>> = OnceLock::new();

    let finder = DATA_FINDER.get_or_init(|| memchr::memmem::Finder::new(PREFIX));
    let start = finder
        .find(json)
        .ok_or_else(|| err("missing 'data' field"))?;
    let data_start = start + PREFIX.len();

    let remaining = &json[data_start..];
    let data_end =
        memchr::memchr(b'"', remaining).ok_or_else(|| err("malformed JSON structure"))?;

    let enc_str_bytes = &remaining[..data_end];
    let enc_str =
        std::str::from_utf8(enc_str_bytes).map_err(|_| err("payload is not valid UTF-8"))?;

    base122_fast::decode(enc_str).map_err(err)
}

#[inline]
fn write_encoded_frame(buf: &mut BytesMut, data: &[u8], encoding: EncodingType) {
    match encoding {
        EncodingType::Binary => {
            buf.put_u16(data.len() as u16);
            buf.put_slice(data);
        }
        EncodingType::Json => {
            let enc_str = base122_fast::encode(data);
            buf.put_slice(b"{\"data\":\"");
            buf.put_slice(enc_str.as_bytes());
            buf.put_slice(b"\"}\n");
        }
    }
}

pub fn encode_frame(
    data: &[u8],
    seq: u64,
    cipher: Option<&dyn FrameCipher>,
    padding_threshold: usize,
    padding_range: [usize; 2],
    encoding: EncodingType,
) -> std::io::Result<Vec<u8>> {
    let raw_len = data.len();

    let padding_len = if raw_len < padding_threshold {
        let max_pad = MAX_RAW_PAYLOAD - raw_len;
        let wanted = rand::rng().random_range(padding_range[0]..=padding_range[1]);
        wanted.min(max_pad)
    } else {
        0
    };

    let payload_len = HEADER_LEN + raw_len + padding_len;
    let mut payload = Vec::with_capacity(payload_len);
    payload.put_u64(seq);
    payload.put_u16(raw_len as u16);
    payload.extend_from_slice(data);
    if padding_len > 0 {
        payload.resize(payload_len, 0u8);
    }

    if let Some(cipher) = cipher {
        payload = cipher.encrypt(&payload)?;
    }

    let mut frame = BytesMut::new();
    write_encoded_frame(&mut frame, &payload, encoding);
    Ok(frame.to_vec())
}

pub fn decode_from_buffer(
    src: &mut BytesMut,
    cipher: Option<&dyn FrameCipher>,
    encoding: EncodingType,
) -> Result<Option<(u64, Bytes)>, Error> {
    match encoding {
        EncodingType::Binary => {
            if src.len() < 2 {
                return Ok(None);
            }
            let frame_len = read_u16_be(&src[..2]) as usize;

            if frame_len > MAX_BINARY_FRAME_LEN {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "binary frame length exceeds limit",
                ));
            }
            if src.len() < 2 + frame_len {
                return Ok(None);
            }
            src.advance(2);
            let frame_data = src.split_to(frame_len);

            if let Some(c) = cipher {
                let decrypted = c.decrypt(&frame_data)?;
                Ok(Some(extract_frame(&decrypted)?))
            } else {
                Ok(Some(extract_frame(&frame_data)?))
            }
        }

        EncodingType::Json => {
            let newline_pos = memchr::memchr(DELIMITER, src);

            match newline_pos {
                Some(pos) => {
                    if pos > MAX_JSON_LINE_LEN {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "JSON line exceeds maximum allowed length",
                        ));
                    }

                    let line = src.split_to(pos);
                    src.advance(1);

                    if line.is_empty() {
                        return Err(Error::new(ErrorKind::InvalidData, "empty frame line"));
                    }

                    let encoded_payload = parse_json_payload(&line)?;

                    if let Some(c) = cipher {
                        let decrypted = c.decrypt(&encoded_payload)?;
                        Ok(Some(extract_frame(&decrypted)?))
                    } else {
                        Ok(Some(extract_frame(&encoded_payload)?))
                    }
                }
                None => {
                    if src.len() > MAX_JSON_LINE_LEN {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "incomplete JSON line is too long",
                        ));
                    }
                    Ok(None)
                }
            }
        }
    }
}

pin_project! {
    #[project = Proj]
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,

        raw_buf: BytesMut,
        out_buf: BytesMut,

        #[pin]
        flush_timer: Sleep,
        timer_armed: bool,
        cursor: usize,
        stages: Vec<ResolvedStage>,
        global_threshold: usize,
        global_range: [usize; 2],
        packet_count: usize,
        stage_idx: usize,
        rng: SmallRng,
        cipher: Option<Arc<dyn FrameCipher>>,
        encoding: EncodingType,
        seq: u64,
    }
}

impl<R> TrafficShaper<R> {
    pub fn with_seq(
        reader: R,
        config: TrafficConfig,
        cipher: Option<Arc<dyn FrameCipher>>,
        start_seq: u64,
    ) -> Self {
        let mut base_rng = rand::rng();
        let cursor = (base_rng.next_u64() as usize) & TABLE_MASK;

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

        let out_capacity = match config.encoding_type {
            EncodingType::Binary => MAX_BINARY_FRAME_LEN + 2,
            EncodingType::Json => MAX_JSON_LINE_LEN + 1,
        };

        Self {
            reader,
            raw_buf: BytesMut::with_capacity(MAX_RAW_PAYLOAD),
            out_buf: BytesMut::with_capacity(out_capacity),
            flush_timer: tokio::time::sleep_until(Instant::now()),
            timer_armed: false,
            stages,
            global_threshold: config.global.padding_threshold,
            global_range: config.global.padding_range,
            packet_count: 0,
            cursor,
            stage_idx: 0,
            rng: SmallRng::from_rng(&mut base_rng),
            cipher,
            encoding: config.encoding_type,
            seq: start_seq,
        }
    }

    #[inline]
    fn seal_and_emit(this: &mut Proj<'_, R>) -> Result<(u64, Bytes), Error> {
        let raw_len = this.raw_buf.len();
        debug_assert!(raw_len > 0);
        debug_assert!(raw_len <= MAX_RAW_PAYLOAD);

        *this.timer_armed = false;

        *this.packet_count += 1;
        let seq = *this.seq;
        *this.seq = seq + 1;

        let stages = &this.stages;
        let pc = *this.packet_count;
        let mut si = *this.stage_idx;
        while si < stages.len() && pc > stages[si].end_count {
            si += 1;
        }
        *this.stage_idx = si;

        let (threshold, range) = if si < stages.len() {
            (stages[si].padding_threshold, stages[si].padding_range)
        } else {
            (*this.global_threshold, *this.global_range)
        };

        let padding_len = if raw_len < threshold {
            let max_pad = MAX_RAW_PAYLOAD - raw_len;
            let wanted = this.rng.random_range(range[0]..=range[1]);
            wanted.min(max_pad)
        } else {
            0
        };

        let payload_len = HEADER_LEN + raw_len + padding_len;

        if let Some(cipher) = this.cipher {
            this.out_buf.clear();
            this.out_buf.reserve(payload_len);
            this.out_buf.put_u64(seq);
            this.out_buf.put_u16(raw_len as u16);
            this.out_buf.put_slice(&this.raw_buf[..raw_len]);
            if padding_len > 0 {
                this.out_buf.put_bytes(0u8, padding_len);
            }

            let encrypted = cipher.encrypt(&this.out_buf[..payload_len])?;
            this.out_buf.clear();
            write_encoded_frame(this.out_buf, &encrypted, *this.encoding);
        } else {
            this.out_buf.clear();

            match *this.encoding {
                EncodingType::Binary => {
                    this.out_buf.reserve(2 + payload_len);
                    this.out_buf.put_u16(payload_len as u16);
                    this.out_buf.put_u64(seq);
                    this.out_buf.put_u16(raw_len as u16);
                    this.out_buf.put_slice(&this.raw_buf[..raw_len]);
                    if padding_len > 0 {
                        this.out_buf.put_bytes(0u8, padding_len);
                    }
                }
                EncodingType::Json => {
                    this.out_buf.put_u64(seq);
                    this.out_buf.put_u16(raw_len as u16);
                    this.out_buf.put_slice(&this.raw_buf[..raw_len]);
                    if padding_len > 0 {
                        this.out_buf.put_bytes(0u8, padding_len);
                    }
                    let payload = this.out_buf.split();
                    write_encoded_frame(this.out_buf, &payload[..payload_len], EncodingType::Json);
                }
            }
        }

        this.raw_buf.clear();
        let result = this.out_buf.split().freeze();
        Ok((seq, result))
    }
}

impl<R: AsyncRead> tokio_stream::Stream for TrafficShaper<R> {
    type Item = Result<(u64, Bytes), Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let raw_len = this.raw_buf.len();
            let remaining = MAX_RAW_PAYLOAD - raw_len;

            if remaining == 0 {
                return Poll::Ready(Some(Self::seal_and_emit(&mut this)));
            }

            if *this.timer_armed && raw_len > 0 {
                if this.flush_timer.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Self::seal_and_emit(&mut this)));
                } else {
                    return Poll::Pending;
                }
            }

            this.raw_buf.reserve(remaining);
            let spare = this.raw_buf.spare_capacity_mut();
            let read_limit = spare.len().min(remaining);
            let mut rb = ReadBuf::uninit(&mut spare[..read_limit]);

            match this.reader.as_mut().poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return if raw_len == 0 {
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Self::seal_and_emit(&mut this)))
                        };
                    }

                    unsafe { this.raw_buf.advance_mut(n) }

                    if raw_len == 0 && this.raw_buf.len() < MAX_RAW_PAYLOAD {
                        let idx = *this.cursor;
                        let delay_us = jitter_table()[idx];
                        *this.cursor = (idx + 1) & TABLE_MASK;
                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay_us));
                        *this.timer_armed = true;

                        let _ = this.flush_timer.as_mut().poll(cx);
                    }
                }
                Poll::Pending => {
                    if *this.timer_armed
                        && raw_len > 0
                        && this.flush_timer.as_mut().poll(cx).is_ready()
                    {
                        return Poll::Ready(Some(Self::seal_and_emit(&mut this)));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TrafficConfig {
        TrafficConfig {
            encoding_type: EncodingType::Binary,
            global: PaddingConfig {
                padding_threshold: 16384,
                padding_range: [0, 16],
            },
            stages: vec![],
            max_download_bytes: None,
        }
    }

    #[test]
    fn encode_decode_roundtrip_binary_no_cipher() {
        let data = b"hello proxy frame";
        let config = test_config();
        let frame = encode_frame(
            data,
            7,
            None,
            config.global.padding_threshold,
            config.global.padding_range,
            config.encoding_type,
        )
        .unwrap();
        let mut buf = BytesMut::from(&frame[..]);
        let (seq, decoded) = decode_from_buffer(&mut buf, None, EncodingType::Binary)
            .unwrap()
            .unwrap();
        assert_eq!(seq, 7);
        assert_eq!(&decoded[..], data);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_u16(100u16);
        buf.put_u8(0xAA);
        let result = decode_from_buffer(&mut buf, None, EncodingType::Binary).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decode_too_long_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u16((MAX_RAW_PAYLOAD + 1000) as u16);
        buf.resize(2 + MAX_RAW_PAYLOAD + 1000, 0u8);
        let result = decode_from_buffer(&mut buf, None, EncodingType::Binary);
        assert!(result.is_err());
    }

    #[test]
    fn extract_frame_valid() {
        let payload = [0u8; 8]
            .iter()
            .copied()
            .chain(3u16.to_be_bytes())
            .chain(b"abc".iter().copied())
            .collect::<Vec<_>>();
        let (seq, data) = extract_frame(&payload).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&data[..], b"abc");
    }

    #[test]
    fn extract_frame_too_short() {
        assert!(extract_frame(b"short").is_err());
    }

    #[test]
    fn parse_json_payload_valid() {
        let enc = base122_fast::encode(b"hello");
        let json = format!("{{\"data\":\"{enc}\"}}");
        let result = parse_json_payload(json.as_bytes()).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn parse_json_payload_missing_field() {
        let result = parse_json_payload(b"{\"other\":\"x\"}");
        assert!(result.is_err());
    }

    #[test]
    fn jitter_table_deterministic_with_seed() {
        let table1 = generate_jitter_table(SmallRng::seed_from_u64(42));
        let table2 = generate_jitter_table(SmallRng::seed_from_u64(42));
        assert_eq!(&table1[..], &table2[..]);

        let mean = table1.iter().map(|&v| v as f64).sum::<f64>() / table1.len() as f64;
        assert!((mean - AVG_LATENCY_MICROS).abs() < AVG_LATENCY_MICROS * 0.5);
    }
}

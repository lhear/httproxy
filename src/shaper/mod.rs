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

use crate::crypto::{NONCE_LEN, TAG_LEN};

pub const MAX_RAW_PAYLOAD: usize = 16 * 1024;

const READ_HIGH_WATER: usize = 32 * 1024;

pub const JSON_PAYLOAD_CAP_PLAIN: usize = 14320 - HEADER_LEN;
pub const JSON_PAYLOAD_CAP_CIPHER: usize = 14320 - HEADER_LEN - NONCE_LEN - TAG_LEN;

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
pub(crate) struct ResolvedStage {
    end_count: usize,
    padding_threshold: usize,
    padding_range: [usize; 2],
}

#[derive(Debug, Clone)]
pub struct ResolvedShaperConfig {
    pub(crate) stages: Arc<[ResolvedStage]>,
    pub(crate) global_threshold: usize,
    pub(crate) global_range: [usize; 2],
    pub encoding: EncodingType,
}

impl ResolvedShaperConfig {
    pub fn resolve(config: &TrafficConfig) -> Self {
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
        Self {
            stages: Arc::from(stages),
            global_threshold: config.global.padding_threshold,
            global_range: config.global.padding_range,
            encoding: config.encoding_type,
        }
    }
}

pub trait FrameCipher: Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    fn encrypt_into(&self, data: &[u8], out: &mut BytesMut) -> Result<(), Error> {
        let encrypted = self.encrypt(data)?;
        out.extend_from_slice(&encrypted);
        Ok(())
    }

    fn decrypt_into(&self, data: &[u8], out: &mut BytesMut) -> Result<(), Error> {
        let decrypted = self.decrypt(data)?;
        out.extend_from_slice(&decrypted);
        Ok(())
    }

    fn seal_in_place(
        &self,
        out: &mut BytesMut,
        nonce_start: usize,
        ct_start: usize,
    ) -> Result<(), Error> {
        debug_assert!(ct_start >= nonce_start);
        let plain = out.split_off(ct_start);
        out.truncate(nonce_start);
        self.encrypt_into(&plain, out)
    }
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
fn extract_frame_range(payload: &[u8]) -> Result<(u64, usize, usize), Error> {
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
    Ok((seq, HEADER_LEN, total))
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
fn parse_json_payload_into(json: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
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

    base122_fast::decode_into(enc_str, out).map_err(err)
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
    let frame_raw_limit = match (cipher.is_some(), encoding) {
        (true, EncodingType::Json) => JSON_PAYLOAD_CAP_CIPHER,
        (false, EncodingType::Json) => JSON_PAYLOAD_CAP_PLAIN,
        _ => MAX_RAW_PAYLOAD,
    };
    if raw_len > frame_raw_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame payload too large: {raw_len} > {frame_raw_limit}"),
        ));
    }

    let padding_len = if raw_len < padding_threshold {
        let max_pad = frame_raw_limit - raw_len;
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

#[derive(Debug)]
pub enum DecodedFrame {
    InScratch { seq: u64, start: usize, end: usize },
    Owned { seq: u64, data: Bytes },
}

pub fn decode_frame(
    src: &mut BytesMut,
    scratch: &mut BytesMut,
    json_scratch: &mut Vec<u8>,
    cipher: Option<&dyn FrameCipher>,
    encoding: EncodingType,
) -> Result<Option<DecodedFrame>, Error> {
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
            let view = src.split_to(frame_len);

            if let Some(c) = cipher {
                scratch.clear();
                c.decrypt_into(&view, scratch)?;
                let (seq, start, end) = extract_frame_range(scratch)?;
                Ok(Some(DecodedFrame::InScratch { seq, start, end }))
            } else {
                let (seq, start, end) = extract_frame_range(&view)?;
                let data = view.freeze().slice(start..end);
                Ok(Some(DecodedFrame::Owned { seq, data }))
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

                    parse_json_payload_into(&line, json_scratch)?;

                    if let Some(c) = cipher {
                        scratch.clear();
                        c.decrypt_into(json_scratch, scratch)?;
                        let (seq, start, end) = extract_frame_range(scratch)?;
                        Ok(Some(DecodedFrame::InScratch { seq, start, end }))
                    } else {
                        let data = Bytes::from(std::mem::take(json_scratch));
                        let (seq, start, end) = extract_frame_range(&data)?;
                        Ok(Some(DecodedFrame::Owned {
                            seq,
                            data: data.slice(start..end),
                        }))
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

pub fn decode_from_buffer(
    src: &mut BytesMut,
    cipher: Option<&dyn FrameCipher>,
    encoding: EncodingType,
) -> Result<Option<(u64, Bytes)>, Error> {
    let mut scratch = BytesMut::new();
    let mut json_scratch = Vec::new();
    match decode_frame(src, &mut scratch, &mut json_scratch, cipher, encoding)? {
        Some(DecodedFrame::InScratch { seq, start, end }) => {
            let plain = scratch.split().freeze();
            Ok(Some((seq, plain.slice(start..end))))
        }
        Some(DecodedFrame::Owned { seq, data }) => Ok(Some((seq, data))),
        None => Ok(None),
    }
}

pub trait SealInto {
    fn poll_seal_into(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut BytesMut,
    ) -> Poll<std::io::Result<Option<u64>>>;
}

pin_project! {
    #[project = Proj]
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,

        raw_buf: BytesMut,
        out_buf: BytesMut,
        enc_buf: BytesMut,
        json_buf: Vec<u8>,

        #[pin]
        flush_timer: Sleep,
        timer_armed: bool,
        cursor: usize,
        stages: Arc<[ResolvedStage]>,
        global_threshold: usize,
        global_range: [usize; 2],
        packet_count: usize,
        stage_idx: usize,
        rng: SmallRng,
        cipher: Option<Arc<dyn FrameCipher>>,
        encoding: EncodingType,
        seal_threshold: usize,
        seq: u64,
    }
}

impl<R> TrafficShaper<R> {
    pub fn with_seq(
        reader: R,
        config: &ResolvedShaperConfig,
        cipher: Option<Arc<dyn FrameCipher>>,
        start_seq: u64,
    ) -> Self {
        let mut base_rng = rand::rng();
        let cursor = (base_rng.next_u64() as usize) & TABLE_MASK;

        let out_capacity = match config.encoding {
            EncodingType::Binary => MAX_BINARY_FRAME_LEN + 2,
            EncodingType::Json => MAX_JSON_LINE_LEN + 1,
        };

        let seal_threshold = match (cipher.is_some(), config.encoding) {
            (true, EncodingType::Binary) => {
                MAX_RAW_PAYLOAD - (NONCE_LEN + TAG_LEN + HEADER_LEN + 2)
            }
            (false, EncodingType::Binary) => MAX_RAW_PAYLOAD - (HEADER_LEN + 2),
            (true, EncodingType::Json) => JSON_PAYLOAD_CAP_CIPHER,
            (false, EncodingType::Json) => JSON_PAYLOAD_CAP_PLAIN,
        };

        Self {
            reader,
            raw_buf: BytesMut::with_capacity(READ_HIGH_WATER),
            out_buf: BytesMut::with_capacity(out_capacity),
            enc_buf: BytesMut::new(),
            json_buf: Vec::new(),
            flush_timer: tokio::time::sleep_until(Instant::now()),
            timer_armed: false,
            stages: Arc::clone(&config.stages),
            global_threshold: config.global_threshold,
            global_range: config.global_range,
            packet_count: 0,
            cursor,
            stage_idx: 0,
            rng: SmallRng::from_rng(&mut base_rng),
            cipher,
            encoding: config.encoding,
            seal_threshold,
            seq: start_seq,
        }
    }

    #[inline]
    fn resolve_padding(this: &mut Proj<'_, R>, raw_len: usize) -> (usize, usize) {
        *this.packet_count += 1;

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
            let max_pad = *this.seal_threshold - raw_len;
            let wanted = this.rng.random_range(range[0]..=range[1]);
            wanted.min(max_pad)
        } else {
            0
        };

        let payload_len = HEADER_LEN + raw_len + padding_len;
        (payload_len, padding_len)
    }

    #[inline]
    fn seal_into(this: &mut Proj<'_, R>, out: &mut BytesMut) -> Result<u64, Error> {
        let raw_len = this.raw_buf.len().min(*this.seal_threshold);
        debug_assert!(raw_len > 0);
        debug_assert!(raw_len <= MAX_RAW_PAYLOAD);

        *this.timer_armed = false;

        let seq = *this.seq;
        *this.seq = seq + 1;

        let (payload_len, padding_len) = Self::resolve_padding(this, raw_len);

        match (this.cipher.as_deref(), *this.encoding) {
            (Some(cipher), EncodingType::Binary) => {
                let enc_len = NONCE_LEN + payload_len + TAG_LEN;
                out.reserve(2 + enc_len);
                out.put_u16(enc_len as u16);
                let nonce_start = out.len();
                out.put_bytes(0u8, NONCE_LEN);
                let ct_start = out.len();
                out.put_u64(seq);
                out.put_u16(raw_len as u16);
                out.put_slice(&this.raw_buf[..raw_len]);
                if padding_len > 0 {
                    out.put_bytes(0u8, padding_len);
                }
                cipher.seal_in_place(out, nonce_start, ct_start)?;
            }
            (None, EncodingType::Binary) => {
                out.reserve(2 + payload_len);
                out.put_u16(payload_len as u16);
                out.put_u64(seq);
                out.put_u16(raw_len as u16);
                out.put_slice(&this.raw_buf[..raw_len]);
                if padding_len > 0 {
                    out.put_bytes(0u8, padding_len);
                }
            }
            (_, EncodingType::Json) => {
                this.out_buf.clear();
                this.out_buf.reserve(payload_len);
                this.out_buf.put_u64(seq);
                this.out_buf.put_u16(raw_len as u16);
                this.out_buf.put_slice(&this.raw_buf[..raw_len]);
                if padding_len > 0 {
                    this.out_buf.put_bytes(0u8, padding_len);
                }
                let payload = this.out_buf.split();
                if let Some(cipher) = this.cipher.as_deref() {
                    this.enc_buf.clear();
                    cipher.encrypt_into(&payload[..payload_len], this.enc_buf)?;
                    base122_fast::encode_into(this.enc_buf, this.json_buf);
                } else {
                    base122_fast::encode_into(&payload[..payload_len], this.json_buf);
                }
                out.reserve(9 + this.json_buf.len() + 3);
                out.put_slice(b"{\"data\":\"");
                out.put_slice(this.json_buf);
                out.put_slice(b"\"}\n");
            }
        }

        this.raw_buf.advance(raw_len);
        Ok(seq)
    }
}

impl<R: AsyncRead> TrafficShaper<R> {
    fn poll_fill_and_seal(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut BytesMut,
    ) -> Poll<std::io::Result<Option<u64>>> {
        let mut this = self.project();

        loop {
            if this.raw_buf.len() >= *this.seal_threshold {
                return Poll::Ready(Self::seal_into(&mut this, out).map(Some));
            }

            let remaining = READ_HIGH_WATER - this.raw_buf.len();
            this.raw_buf.reserve(remaining);
            let spare = this.raw_buf.spare_capacity_mut();
            let read_limit = spare.len().min(remaining);
            let mut rb = ReadBuf::uninit(&mut spare[..read_limit]);

            match this.reader.as_mut().poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return if this.raw_buf.is_empty() {
                            Poll::Ready(Ok(None))
                        } else {
                            Poll::Ready(Self::seal_into(&mut this, out).map(Some))
                        };
                    }

                    unsafe {
                        this.raw_buf.advance_mut(n);
                    }
                }
                Poll::Pending => {
                    let raw_len = this.raw_buf.len();
                    if raw_len == 0 {
                        return Poll::Pending;
                    }
                    if raw_len >= *this.seal_threshold {
                        return Poll::Ready(Self::seal_into(&mut this, out).map(Some));
                    }

                    if !*this.timer_armed {
                        let idx = *this.cursor;
                        let delay_us = jitter_table()[idx];
                        *this.cursor = (idx + 1) & TABLE_MASK;
                        this.flush_timer
                            .as_mut()
                            .reset(Instant::now() + Duration::from_micros(delay_us));
                        *this.timer_armed = true;
                    }

                    if this.flush_timer.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Self::seal_into(&mut this, out).map(Some));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<R: AsyncRead> SealInto for TrafficShaper<R> {
    fn poll_seal_into(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut BytesMut,
    ) -> Poll<std::io::Result<Option<u64>>> {
        self.poll_fill_and_seal(cx, out)
    }
}

impl<R: AsyncRead> tokio_stream::Stream for TrafficShaper<R> {
    type Item = Result<(u64, Bytes), Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut frame = BytesMut::new();
        match self.poll_fill_and_seal(cx, &mut frame) {
            Poll::Ready(Ok(Some(seq))) => Poll::Ready(Some(Ok((seq, frame.freeze())))),
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let result = decode_frame(
            &mut buf,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decode_too_long_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u16((MAX_RAW_PAYLOAD + 1000) as u16);
        buf.resize(2 + MAX_RAW_PAYLOAD + 1000, 0u8);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let result = decode_frame(
            &mut buf,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        );
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
        let (seq, start, end) = extract_frame_range(&payload).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&payload[start..end], b"abc");
    }

    #[test]
    fn extract_frame_too_short() {
        assert!(extract_frame_range(b"short").is_err());
    }

    #[test]
    fn parse_json_payload_valid() {
        let enc = base122_fast::encode(b"hello");
        let json = format!("{{\"data\":\"{enc}\"}}");
        let mut out = Vec::new();
        let n = parse_json_payload_into(json.as_bytes(), &mut out).unwrap();
        assert_eq!(&out[..n], b"hello");
    }

    #[test]
    fn parse_json_payload_missing_field() {
        let mut out = Vec::new();
        let result = parse_json_payload_into(b"{\"other\":\"x\"}", &mut out);
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

    #[test]
    fn decode_frame_plain_owned_zero_copy() {
        let data = b"plain payload";
        let frame = encode_frame(data, 9, None, 16384, [0, 0], EncodingType::Binary).unwrap();
        let mut src = BytesMut::from(&frame[..]);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        match decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        )
        .unwrap()
        .unwrap()
        {
            DecodedFrame::Owned { seq, data } => {
                assert_eq!(seq, 9);
                assert_eq!(&data[..], b"plain payload");
            }
            _ => panic!("expected Owned frame"),
        }
        assert!(src.is_empty());
    }

    #[test]
    fn decode_frame_cipher_into_scratch() {
        use crate::crypto::AesFrameCipher;
        use zeroize::Zeroizing;

        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let cipher = AesFrameCipher::new(&key);

        let frame = encode_frame(
            b"secret payload",
            42,
            Some(&cipher),
            16384,
            [0, 0],
            EncodingType::Binary,
        )
        .unwrap();
        let mut src = BytesMut::from(&frame[..]);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        match decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            Some(&cipher),
            EncodingType::Binary,
        )
        .unwrap()
        .unwrap()
        {
            DecodedFrame::InScratch { seq, start, end } => {
                assert_eq!(seq, 42);
                assert_eq!(&scratch[start..end], b"secret payload");
            }
            _ => panic!("expected InScratch frame"),
        }
        assert!(src.is_empty());
    }

    #[test]
    fn decode_frame_scratch_reused_across_frames() {
        use crate::crypto::AesFrameCipher;
        use zeroize::Zeroizing;

        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let cipher = AesFrameCipher::new(&key);

        let mut combined = BytesMut::new();
        for (i, msg) in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ]
        .iter()
        .enumerate()
        {
            let frame = encode_frame(
                msg,
                i as u64,
                Some(&cipher),
                16384,
                [0, 0],
                EncodingType::Binary,
            )
            .unwrap();
            combined.extend_from_slice(&frame);
        }

        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut expected_seq = 0u64;
        while !combined.is_empty() {
            match decode_frame(
                &mut combined,
                &mut scratch,
                &mut json_scratch,
                Some(&cipher),
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::InScratch { seq, start, end } => {
                    assert_eq!(seq, expected_seq);
                    assert_eq!(
                        &scratch[start..end],
                        [
                            b"first".as_slice(),
                            b"second".as_slice(),
                            b"third".as_slice()
                        ][expected_seq as usize]
                    );
                    expected_seq += 1;
                }
                _ => panic!("expected InScratch frame"),
            }
        }
        assert_eq!(expected_seq, 3);
    }

    #[test]
    fn decode_frame_json_roundtrip() {
        let frame =
            encode_frame(b"json payload", 3, None, 16384, [0, 0], EncodingType::Json).unwrap();
        let mut src = BytesMut::from(&frame[..]);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        match decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Json,
        )
        .unwrap()
        .unwrap()
        {
            DecodedFrame::Owned { seq, data } => {
                assert_eq!(seq, 3);
                assert_eq!(&data[..], b"json payload");
            }
            _ => panic!("expected Owned frame"),
        }
        assert!(src.is_empty());
    }

    #[test]
    fn decode_frame_json_cipher_roundtrip() {
        use crate::crypto::AesFrameCipher;
        use zeroize::Zeroizing;

        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let cipher = AesFrameCipher::new(&key);

        let frame = encode_frame(
            b"json cipher payload",
            5,
            Some(&cipher),
            16384,
            [0, 0],
            EncodingType::Json,
        )
        .unwrap();
        let mut src = BytesMut::from(&frame[..]);
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        match decode_frame(
            &mut src,
            &mut scratch,
            &mut json_scratch,
            Some(&cipher),
            EncodingType::Json,
        )
        .unwrap()
        .unwrap()
        {
            DecodedFrame::InScratch { seq, start, end } => {
                assert_eq!(seq, 5);
                assert_eq!(&scratch[start..end], b"json cipher payload");
            }
            _ => panic!("expected InScratch frame"),
        }
        assert!(src.is_empty());
    }

    #[tokio::test]
    async fn json_frames_fit_single_h2_data_frame() {
        use crate::crypto::AesFrameCipher;
        use zeroize::Zeroizing;

        let no_cipher: Option<Arc<dyn FrameCipher>> = None;
        let aes_cipher: Option<Arc<dyn FrameCipher>> =
            Some(Arc::new(AesFrameCipher::new(&Zeroizing::new([0u8; 32]))));
        for cipher in [no_cipher, aes_cipher] {
            let cipher_for_decode = cipher.clone();
            let mut config = test_config();
            config.encoding_type = EncodingType::Json;
            let resolved = ResolvedShaperConfig::resolve(&config);
            let data = vec![0xAAu8; 64 * 1024];
            let shaper = TrafficShaper::with_seq(Cursor::new(data.clone()), &resolved, cipher, 0);
            let mut out = BytesMut::new();
            seal_all(shaper, &mut out);

            let mut frames = 0;
            let mut src = &out[..];
            while !src.is_empty() {
                let newline = memchr::memchr(b'\n', src).expect("frame must end with newline");
                let line_len = newline + 1;
                assert!(line_len <= 16384, "JSON frame {line_len} B > 16384");
                src = &src[line_len..];
                frames += 1;
            }
            assert!(frames >= 4, "expected multiple frames, got {frames}");

            let mut scratch = BytesMut::new();
            let mut json_scratch = Vec::new();
            let mut decoded = Vec::new();
            let mut buf = out;
            while !buf.is_empty() {
                match decode_frame(
                    &mut buf,
                    &mut scratch,
                    &mut json_scratch,
                    cipher_for_decode.as_deref(),
                    EncodingType::Json,
                )
                .unwrap()
                .unwrap()
                {
                    DecodedFrame::InScratch { start, end, .. } => {
                        decoded.extend_from_slice(&scratch[start..end]);
                    }
                    DecodedFrame::Owned { data, .. } => decoded.extend_from_slice(&data),
                }
            }
            assert_eq!(decoded, data);
        }
    }

    fn seal_all(shaper: TrafficShaper<Cursor<Vec<u8>>>, out: &mut BytesMut) -> Vec<u64> {
        let mut shaper = std::pin::pin!(shaper);
        let mut seqs = Vec::new();
        loop {
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            match shaper.as_mut().poll_seal_into(&mut cx, out) {
                Poll::Ready(Ok(Some(seq))) => seqs.push(seq),
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Err(e)) => panic!("seal error: {e}"),
                Poll::Pending => panic!("unexpected Pending with Cursor reader"),
            }
        }
        seqs
    }

    #[tokio::test]
    async fn poll_seal_into_produces_valid_frames() {
        let config = ResolvedShaperConfig::resolve(&test_config());
        let data = vec![0xABu8; 40_000];
        let shaper = TrafficShaper::with_seq(Cursor::new(data.clone()), &config, None, 0);
        let mut out = BytesMut::new();
        let seqs = seal_all(shaper, &mut out);

        assert_eq!(seqs, vec![0, 1, 2]);

        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut decoded = Vec::new();
        let mut frame_idx = 0usize;
        while !out.is_empty() {
            match decode_frame(
                &mut out,
                &mut scratch,
                &mut json_scratch,
                None,
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::Owned { seq, data } => {
                    assert_eq!(seq, seqs[frame_idx]);
                    frame_idx += 1;
                    decoded.extend_from_slice(&data);
                }
                _ => panic!("expected Owned frame"),
            }
        }
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn poll_seal_into_cipher_matches_stream_output() {
        use crate::crypto::AesFrameCipher;
        use futures::StreamExt;
        use zeroize::Zeroizing;

        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let cipher: Arc<dyn FrameCipher> = Arc::new(AesFrameCipher::new(&key));

        let config = ResolvedShaperConfig::resolve(&test_config());
        let data = vec![0x5Cu8; 33_000];

        let cipher_for_decode = Arc::clone(&cipher);
        let decode_append = |src: &mut BytesMut, out: &mut Vec<u8>| {
            let mut scratch = BytesMut::new();
            let mut json_scratch = Vec::new();
            match decode_frame(
                src,
                &mut scratch,
                &mut json_scratch,
                Some(cipher_for_decode.as_ref()),
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::InScratch { start, end, .. } => {
                    out.extend_from_slice(&scratch[start..end]);
                }
                _ => panic!("expected InScratch frame"),
            }
        };

        let shaper_stream = TrafficShaper::with_seq(
            Cursor::new(data.clone()),
            &config,
            Some(Arc::clone(&cipher)),
            0,
        );
        let mut stream_payload = Vec::new();
        let mut stream_seqs = Vec::new();
        let mut shaper_stream = Box::pin(shaper_stream);
        while let Some(item) = shaper_stream.next().await {
            let (seq, bytes) = item.unwrap();
            stream_seqs.push(seq);
            let mut frame_buf = BytesMut::from(&bytes[..]);
            decode_append(&mut frame_buf, &mut stream_payload);
        }

        let shaper_seal =
            TrafficShaper::with_seq(Cursor::new(data.clone()), &config, Some(cipher), 0);
        let mut out = BytesMut::new();
        let seqs = seal_all(shaper_seal, &mut out);
        let mut seal_payload = Vec::new();
        while !out.is_empty() {
            decode_append(&mut out, &mut seal_payload);
        }

        assert_eq!(seqs, stream_seqs);
        assert_eq!(seal_payload, stream_payload);
        assert_eq!(seal_payload, data);
    }

    #[tokio::test]
    async fn seal_in_place_default_impl_produces_valid_frames() {
        use zeroize::Zeroizing;

        struct VecCipher(Zeroizing<[u8; 32]>);
        impl FrameCipher for VecCipher {
            fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
                crate::crypto::encrypt_bytes(&self.0, data).map_err(Error::other)
            }
            fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
                crate::crypto::decrypt_bytes(&self.0, data).map_err(Error::other)
            }
        }

        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let cipher: Arc<dyn FrameCipher> = Arc::new(VecCipher(key));
        let cipher_for_decode = Arc::clone(&cipher);

        let config = ResolvedShaperConfig::resolve(&test_config());
        let data = vec![0x3Du8; 20_000];
        let shaper = TrafficShaper::with_seq(Cursor::new(data.clone()), &config, Some(cipher), 0);
        let mut out = BytesMut::new();
        let seqs = seal_all(shaper, &mut out);

        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut decoded = Vec::new();
        let mut frame_idx = 0usize;
        while !out.is_empty() {
            match decode_frame(
                &mut out,
                &mut scratch,
                &mut json_scratch,
                Some(cipher_for_decode.as_ref()),
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::InScratch { seq, start, end } => {
                    assert_eq!(seq, seqs[frame_idx]);
                    frame_idx += 1;
                    decoded.extend_from_slice(&scratch[start..end]);
                }
                _ => panic!("expected InScratch frame"),
            }
        }
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_frame_rejects_oversized_payload() {
        let big = vec![0u8; MAX_RAW_PAYLOAD + 1];
        let r = encode_frame(&big, 0, None, 0, [0, 0], EncodingType::Binary);
        assert!(r.is_err());
        let r = encode_frame(&big, 0, None, 0, [0, 0], EncodingType::Json);
        assert!(r.is_err());
    }

    #[test]
    fn encode_frame_json_padding_stays_within_line_limit() {
        let raw = vec![0x42u8; 1000];
        let aes = crate::crypto::AesFrameCipher::new(&zeroize::Zeroizing::new([0u8; 32]));
        for cipher in [None, Some(&aes as &dyn FrameCipher)] {
            let frame =
                encode_frame(&raw, 0, cipher, 100_000, [0, 100_000], EncodingType::Json).unwrap();
            let line_len = frame.iter().position(|&b| b == b'\n').unwrap();
            assert!(line_len <= MAX_JSON_LINE_LEN);
        }
    }

    #[tokio::test]
    async fn poll_seal_into_eof_returns_none() {
        let reader = std::io::Cursor::new(Vec::<u8>::new());
        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_seq(reader, &cfg, None, 0));
        let mut out = BytesMut::new();
        let result = std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out)).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn poll_seal_into_respects_start_seq() {
        let data = vec![0x55u8; 1000];
        let reader = std::io::Cursor::new(data);
        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_seq(reader, &cfg, None, 42));
        let mut out = BytesMut::new();
        let result = std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out)).await;
        assert!(matches!(result, Ok(Some(42))));
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let frame = decode_frame(
            &mut out,
            &mut scratch,
            &mut json_scratch,
            None,
            EncodingType::Binary,
        )
        .unwrap()
        .expect("frame");
        match frame {
            DecodedFrame::Owned { seq, .. } => assert_eq!(seq, 42),
            DecodedFrame::InScratch { seq, .. } => assert_eq!(seq, 42),
        }
    }

    #[tokio::test]
    async fn poll_seal_into_pending_then_data() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(READ_HIGH_WATER);
        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_seq(reader, &cfg, None, 0));
        let mut out = BytesMut::new();

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(
            matches!(
                shaper.as_mut().poll_seal_into(&mut cx, &mut out),
                Poll::Pending
            ),
            "empty duplex must yield Pending"
        );

        writer.write_all(&[0x33u8; READ_HIGH_WATER]).await.unwrap();
        assert!(
            matches!(
                shaper.as_mut().poll_seal_into(&mut cx, &mut out),
                Poll::Ready(Ok(Some(_)))
            ),
            "data arrival must produce a frame"
        );
        assert!(!out.is_empty());
    }

    #[tokio::test]
    async fn stages_progress_and_fall_back_to_global() {
        let cfg = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 10_000,
                padding_range: [0, 0],
            },
            stages: vec![
                StageConfig {
                    count: Some(1),
                    count_range: None,
                    padding_threshold: 10_000,
                    padding_range: [100, 100],
                },
                StageConfig {
                    count: None,
                    count_range: Some([2, 3]),
                    padding_threshold: 10_000,
                    padding_range: [200, 200],
                },
            ],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        use tokio::io::AsyncWriteExt;
        let resolved = ResolvedShaperConfig::resolve(&cfg);
        let (mut writer, reader) = tokio::io::duplex(READ_HIGH_WATER);
        let mut shaper = Box::pin(TrafficShaper::with_seq(reader, &resolved, None, 0));
        let mut out = BytesMut::new();
        let mut sizes = Vec::new();
        for _ in 0..4 {
            writer.write_all(&[0x44u8; 1000]).await.unwrap();
            std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out))
                .await
                .unwrap();
            sizes.push(out.len());
            out.clear();
        }
        assert_eq!(sizes[0], 2 + 10 + 1000 + 100);
        assert_eq!(sizes[1], 2 + 10 + 1000 + 200);
        assert_eq!(sizes[2], 2 + 10 + 1000 + 200);
        assert_eq!(sizes[3], 2 + 10 + 1000);
    }

    #[test]
    fn decode_frame_json_rejects_malformed_lines() {
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut src = BytesMut::new();

        src.extend_from_slice(
            b"
",
        );
        assert!(
            decode_frame(
                &mut src,
                &mut scratch,
                &mut json_scratch,
                None,
                EncodingType::Json
            )
            .is_err()
        );

        let mut long = BytesMut::new();
        long.extend_from_slice(b"{\"data\":\"");
        long.resize(MAX_JSON_LINE_LEN + 2, b'x');
        assert!(
            decode_frame(
                &mut long,
                &mut scratch,
                &mut json_scratch,
                None,
                EncodingType::Json
            )
            .is_err()
        );

        let mut unclosed = BytesMut::new();
        unclosed.extend_from_slice(b"{\"data\":\"abc");
        unclosed.extend_from_slice(
            b"
",
        );
        assert!(
            decode_frame(
                &mut unclosed,
                &mut scratch,
                &mut json_scratch,
                None,
                EncodingType::Json
            )
            .is_err()
        );
    }

    #[test]
    fn decode_frame_json_rejects_invalid_utf8() {
        let mut scratch = BytesMut::new();
        let mut json_scratch = Vec::new();
        let mut src = BytesMut::new();
        src.extend_from_slice(b"{\"data\":\"");
        src.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        src.extend_from_slice(
            b"\"}
",
        );
        assert!(
            decode_frame(
                &mut src,
                &mut scratch,
                &mut json_scratch,
                None,
                EncodingType::Json
            )
            .is_err()
        );
    }
}

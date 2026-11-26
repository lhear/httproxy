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

use crate::crypto::{NONCE_LEN, TAG_LEN, TlsInspector};

mod bufpool;

pub use bufpool::frame_bytes as pooled_frame_bytes;
pub use bufpool::take as take_buf;

pub const MAX_RAW_PAYLOAD: usize = 16 * 1024;
const TLS_RECORD_SLACK: usize = 256;
const MAX_FRAME_PAYLOAD: usize = MAX_RAW_PAYLOAD + TLS_RECORD_SLACK;
const HEAD_BINARY: usize = 2 + NONCE_LEN + HEADER_LEN;
const HEAD_JSON: usize = NONCE_LEN + HEADER_LEN;

pub const JSON_PAYLOAD_CAP: usize = 14320 - HEADER_LEN - NONCE_LEN - TAG_LEN;

const TABLE_SIZE: usize = 8192;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const DELIMITER: u8 = b'\n';
const AVG_LATENCY_MICROS: f64 = 5_000.0;
const MAX_BINARY_FRAME_LEN: usize = MAX_FRAME_PAYLOAD + NONCE_LEN + HEADER_LEN + TAG_LEN;
const MAX_JSON_LINE_LEN: usize = MAX_RAW_PAYLOAD + 2396;
pub(crate) const HEADER_LEN: usize = 10;

#[inline]
pub fn max_encoded_frame_len(encoding: EncodingType) -> usize {
    match encoding {
        EncodingType::Binary => MAX_BINARY_FRAME_LEN + 2,
        EncodingType::Json => MAX_JSON_LINE_LEN + 1,
    }
}

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

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct HandshakePadding {
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

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
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
    pub handshake: Option<HandshakePadding>,
    #[serde(default)]
    pub stages: Vec<StageConfig>,
    #[serde(default)]
    pub encoding_type: EncodingType,
    #[serde(default)]
    pub max_download_bytes: Option<u64>,
}

impl TrafficConfig {
    #[inline]
    pub fn handshake_padding_range(&self) -> [usize; 2] {
        self.handshake.map_or([0, 0], |h| h.padding_range)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::anyhow;
        if self.global.padding_range[0] > self.global.padding_range[1] {
            return Err(anyhow!(
                "traffic_shaping.global.padding_range low ({}) > high ({})",
                self.global.padding_range[0],
                self.global.padding_range[1]
            ));
        }
        if let Some(handshake) = &self.handshake
            && handshake.padding_range[0] > handshake.padding_range[1]
        {
            return Err(anyhow!(
                "traffic_shaping.handshake.padding_range low ({}) > high ({})",
                handshake.padding_range[0],
                handshake.padding_range[1]
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

    fn decrypt_in_place(&self, buf: &mut [u8]) -> Result<std::ops::Range<usize>, Error> {
        let decrypted = self.decrypt(buf)?;
        let len = decrypted.len();
        if len > buf.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "decrypted frame too large",
            ));
        }
        buf[..len].copy_from_slice(&decrypted);
        Ok(0..len)
    }

    fn seal_in_place(
        &self,
        out: &mut Vec<u8>,
        nonce_start: usize,
        ct_start: usize,
    ) -> Result<(), Error> {
        debug_assert!(ct_start >= nonce_start);
        let plain = out.split_off(ct_start);
        out.truncate(nonce_start);
        let encrypted = self.encrypt(&plain)?;
        out.extend_from_slice(&encrypted);
        Ok(())
    }

    fn seal_frame(
        &self,
        out: &mut Vec<u8>,
        nonce_start: usize,
        ct_start: usize,
        _opaque: bool,
    ) -> Result<(), Error> {
        self.seal_in_place(out, nonce_start, ct_start)
    }

    fn open_frame(&self, buf: &mut [u8]) -> Result<std::ops::Range<usize>, Error> {
        self.decrypt_in_place(buf)
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

    if let Some(payload) = json
        .strip_prefix(b"{\"data\":\"")
        .and_then(|rest| rest.strip_suffix(b"\"}"))
    {
        return base122_fast::decode_into_bytes(payload, out).map_err(err);
    }

    const FIELD: &[u8] = b"\"data\":\"";
    static DATA_FINDER: OnceLock<memchr::memmem::Finder<'static>> = OnceLock::new();

    let finder = DATA_FINDER.get_or_init(|| memchr::memmem::Finder::new(FIELD));
    let start = finder
        .find(json)
        .ok_or_else(|| err("missing 'data' field"))?;
    let remaining = &json[start + FIELD.len()..];
    let data_end =
        memchr::memchr(b'"', remaining).ok_or_else(|| err("malformed JSON structure"))?;

    base122_fast::decode_into_bytes(&remaining[..data_end], out).map_err(err)
}

#[inline]
fn frame_raw_limit(encoding: EncodingType) -> usize {
    match encoding {
        EncodingType::Json => JSON_PAYLOAD_CAP,
        EncodingType::Binary => MAX_RAW_PAYLOAD,
    }
}

#[inline]
fn resolve_frame_padding(
    raw_len: usize,
    padding_threshold: usize,
    padding_range: [usize; 2],
    raw_limit: usize,
) -> usize {
    if raw_len < padding_threshold {
        let max_pad = raw_limit - raw_len;
        let wanted = rand::rng().random_range(padding_range[0]..=padding_range[1]);
        wanted.min(max_pad)
    } else {
        0
    }
}

pub fn encode_frame_into(
    data: &[u8],
    seq: u64,
    cipher: &dyn FrameCipher,
    padding_threshold: usize,
    padding_range: [usize; 2],
    encoding: EncodingType,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    let raw_len = data.len();
    let raw_limit = frame_raw_limit(encoding);
    if raw_len > raw_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame payload too large: {raw_len} > {raw_limit}"),
        ));
    }

    let padding_len = resolve_frame_padding(raw_len, padding_threshold, padding_range, raw_limit);
    let payload_len = HEADER_LEN + raw_len + padding_len;

    match encoding {
        EncodingType::Binary => {
            let enc_len = NONCE_LEN + payload_len + TAG_LEN;
            out.reserve(2 + enc_len);
            out.put_u16(enc_len as u16);
            let nonce_start = out.len();
            out.put_bytes(0u8, NONCE_LEN);
            let ct_start = out.len();
            out.put_u64(seq);
            out.put_u16(raw_len as u16);
            out.put_slice(data);
            if padding_len > 0 {
                out.put_bytes(0u8, padding_len);
            }
            cipher.seal_frame(out, nonce_start, ct_start, false)?;
        }
        EncodingType::Json => {
            let mut sealed = Vec::with_capacity(payload_len + NONCE_LEN + TAG_LEN);
            sealed.resize(NONCE_LEN, 0u8);
            sealed.extend_from_slice(&seq.to_be_bytes());
            sealed.extend_from_slice(&(raw_len as u16).to_be_bytes());
            sealed.extend_from_slice(data);
            sealed.resize(NONCE_LEN + payload_len, 0);
            cipher.seal_frame(&mut sealed, 0, NONCE_LEN, false)?;
            let mut encoded = Vec::with_capacity(sealed.len() + sealed.len() / 6 + 16);
            base122_fast::encode_into(&sealed, &mut encoded);
            out.reserve(9 + encoded.len() + 3);
            out.put_slice(b"{\"data\":\"");
            out.put_slice(&encoded);
            out.put_slice(b"\"}\n");
        }
    }

    Ok(())
}

pub fn encode_frame(
    data: &[u8],
    seq: u64,
    cipher: &dyn FrameCipher,
    padding_threshold: usize,
    padding_range: [usize; 2],
    encoding: EncodingType,
) -> std::io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(max_encoded_frame_len(encoding));
    encode_frame_into(
        data,
        seq,
        cipher,
        padding_threshold,
        padding_range,
        encoding,
        &mut frame,
    )?;
    Ok(frame)
}

pub fn encode_frame_padded(
    data: &[u8],
    seq: u64,
    cipher: &dyn FrameCipher,
    padding_range: [usize; 2],
    encoding: EncodingType,
) -> std::io::Result<Vec<u8>> {
    encode_frame(data, seq, cipher, usize::MAX, padding_range, encoding)
}

#[derive(Debug)]
pub enum DecodedFrame {
    InJsonScratch { seq: u64, start: usize, end: usize },
    Owned { seq: u64, data: Bytes },
}

pub fn append_frame_chunk(input: &mut BytesMut, chunk: &mut Bytes, encoding: EncodingType) {
    if input.is_empty() {
        match std::mem::take(chunk).try_into_mut() {
            Ok(owned) => *input = owned,
            Err(shared) => input.extend_from_slice(&shared),
        }
        return;
    }
    let needed = match encoding {
        EncodingType::Binary if input.len() < 2 => 2 - input.len(),
        EncodingType::Binary => (2 + read_u16_be(input) as usize).saturating_sub(input.len()),
        EncodingType::Json => memchr::memchr(DELIMITER, chunk)
            .map_or(chunk.len(), |position| position + 1)
            .min((MAX_JSON_LINE_LEN + 1).saturating_sub(input.len())),
    };
    let take = needed.min(chunk.len());
    input.extend_from_slice(&chunk[..take]);
    chunk.advance(take);
}

pub fn decode_frame(
    src: &mut BytesMut,
    json_scratch: &mut Vec<u8>,
    cipher: &dyn FrameCipher,
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
            let mut view = src.split_to(frame_len);

            let range = cipher.open_frame(&mut view)?;
            let offset = range.start;
            let (seq, start, end) = extract_frame_range(&view[range])?;
            let data = view.freeze().slice(offset + start..offset + end);
            Ok(Some(DecodedFrame::Owned { seq, data }))
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

                    if json_scratch.capacity() < line.len() {
                        *json_scratch = bufpool::take(line.len().max(1024));
                    }
                    parse_json_payload_into(&line, json_scratch)?;

                    let plain = cipher.open_frame(json_scratch)?;
                    let (seq, start, end) =
                        extract_frame_range(&json_scratch[plain.start..plain.end])?;
                    Ok(Some(DecodedFrame::InJsonScratch {
                        seq,
                        start: plain.start + start,
                        end: plain.start + end,
                    }))
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
    cipher: &dyn FrameCipher,
    encoding: EncodingType,
) -> Result<Option<(u64, Bytes)>, Error> {
    let mut json_scratch = Vec::new();
    match decode_frame(src, &mut json_scratch, cipher, encoding)? {
        Some(DecodedFrame::InJsonScratch { seq, start, end }) => {
            let plain = pooled_frame_bytes(std::mem::take(&mut json_scratch));
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
        out: &mut Vec<u8>,
    ) -> Poll<std::io::Result<Option<u64>>>;
}

pub type ShaperStream = Pin<Box<dyn SealInto + Send>>;

pin_project! {
    #[project = Proj]
    pub struct TrafficShaper<R> {
        #[pin]
        reader: R,

        frame: Vec<u8>,
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
        cipher: Arc<dyn FrameCipher>,
        encoding: EncodingType,
        head: usize,
        seal_threshold: usize,
        frame_capacity: usize,
        line_capacity: usize,
        seq: u64,
        inspector: Option<TlsInspector>,
        sealed_total: u64,
    }
}

impl<R> TrafficShaper<R> {
    #[cfg(test)]
    pub fn with_seq(
        reader: R,
        config: &ResolvedShaperConfig,
        cipher: Arc<dyn FrameCipher>,
        start_seq: u64,
    ) -> Self {
        Self::with_inspector(reader, config, cipher, start_seq, None)
    }

    pub fn with_inspector(
        reader: R,
        config: &ResolvedShaperConfig,
        cipher: Arc<dyn FrameCipher>,
        start_seq: u64,
        inspector: Option<TlsInspector>,
    ) -> Self {
        let mut base_rng = rand::rng();
        let cursor = (base_rng.next_u64() as usize) & TABLE_MASK;

        let (head, seal_threshold) = match config.encoding {
            EncodingType::Binary => (HEAD_BINARY, MAX_FRAME_PAYLOAD),
            EncodingType::Json => (HEAD_JSON, JSON_PAYLOAD_CAP),
        };
        let frame_capacity = head + seal_threshold + TAG_LEN;

        let mut frame = bufpool::take(frame_capacity);
        frame.resize(head, 0);

        let sealed_total = inspector.as_ref().map_or(0, TlsInspector::total);

        Self {
            reader,
            frame,
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
            head,
            seal_threshold,
            frame_capacity,
            line_capacity: max_encoded_frame_len(config.encoding),
            seq: start_seq,
            inspector,
            sealed_total,
        }
    }

    #[inline]
    fn resolve_padding(this: &mut Proj<'_, R>, raw_len: usize) -> usize {
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

        if raw_len < threshold {
            let max_pad = (*this.seal_threshold).saturating_sub(raw_len);
            let wanted = this.rng.random_range(range[0]..=range[1]);
            wanted.min(max_pad)
        } else {
            0
        }
    }

    #[inline]
    fn finalize(this: &mut Proj<'_, R>) -> Result<u64, Error> {
        let head = *this.head;
        let raw_len = this.frame.len() - head;
        debug_assert!(raw_len > 0);
        debug_assert!(raw_len <= *this.seal_threshold);

        let start = *this.sealed_total;
        let opaque = this
            .inspector
            .as_ref()
            .and_then(TlsInspector::opaque_at)
            .is_some_and(|at| start >= at);

        *this.timer_armed = false;

        let seq = *this.seq;
        *this.seq = seq + 1;

        let padding_len = Self::resolve_padding(this, raw_len);
        if padding_len > 0 {
            this.frame.resize(head + raw_len + padding_len, 0);
        }

        let ct = head - HEADER_LEN;
        this.frame[ct..ct + 8].copy_from_slice(&seq.to_be_bytes());
        this.frame[ct + 8..ct + 10].copy_from_slice(&(raw_len as u16).to_be_bytes());
        if *this.encoding == EncodingType::Binary {
            let wire_len = NONCE_LEN + HEADER_LEN + raw_len + padding_len + TAG_LEN;
            this.frame[head - HEAD_BINARY..head - HEAD_BINARY + 2]
                .copy_from_slice(&(wire_len as u16).to_be_bytes());
        }

        this.cipher
            .seal_frame(this.frame, ct - NONCE_LEN, ct, opaque)?;

        *this.sealed_total = start + raw_len as u64;
        Ok(seq)
    }

    #[inline]
    fn start_frame(this: &mut Proj<'_, R>) {
        this.frame.clear();
        this.frame.resize(*this.head, 0);
    }

    fn write_json(this: &mut Proj<'_, R>, out: &mut Vec<u8>) {
        base122_fast::encode_into(this.frame, this.json_buf);
        out.extend_from_slice(b"{\"data\":\"");
        out.extend_from_slice(this.json_buf);
        out.extend_from_slice(b"\"}\n");
    }

    #[inline]
    fn seal_into(this: &mut Proj<'_, R>, out: &mut Vec<u8>) -> Result<u64, Error> {
        let seq = Self::finalize(this)?;
        if *this.encoding == EncodingType::Json {
            Self::write_json(this, out);
        } else {
            out.extend_from_slice(this.frame);
        }
        Self::start_frame(this);
        Ok(seq)
    }
}

enum Fill {
    Frame,
    Eof,
}

impl<R: AsyncRead> TrafficShaper<R> {
    fn poll_fill_and_seal(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut Vec<u8>,
    ) -> Poll<std::io::Result<Option<u64>>> {
        let mut this = self.project();
        if *this.encoding == EncodingType::Binary {
            let start = out.len();
            let head = *this.head;
            out.extend_from_slice(this.frame);
            std::mem::swap(this.frame, out);
            *this.head += start;
            let result = match Self::poll_fill_proj(&mut this, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Fill::Eof)) => Poll::Ready(Ok(None)),
                Poll::Ready(Ok(Fill::Frame)) => Poll::Ready(Self::finalize(&mut this).map(Some)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            };
            *this.head = head;
            out.truncate(head);
            if result.is_pending() {
                out.extend_from_slice(&this.frame[start + head..]);
            }
            if !matches!(result, Poll::Ready(Ok(Some(_)))) {
                this.frame.truncate(start);
            }
            std::mem::swap(this.frame, out);
            return result;
        }
        match Self::poll_fill_proj(&mut this, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Fill::Eof)) => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(Fill::Frame)) => Poll::Ready(Self::seal_into(&mut this, out).map(Some)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_fill_proj(this: &mut Proj<'_, R>, cx: &mut Context<'_>) -> Poll<std::io::Result<Fill>> {
        let head = *this.head;
        let budget = head + *this.seal_threshold;
        loop {
            if this.frame.len() >= budget {
                return Poll::Ready(Ok(Fill::Frame));
            }

            let want = budget - this.frame.len();
            this.frame.reserve(want + TAG_LEN);
            let spare = this.frame.spare_capacity_mut();
            let mut rb = ReadBuf::uninit(&mut spare[..want]);

            match this.reader.as_mut().poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(if this.frame.len() == head {
                            Fill::Eof
                        } else {
                            Fill::Frame
                        }));
                    }

                    unsafe {
                        this.frame.set_len(this.frame.len() + n);
                    }

                    if let Some(inspector) = this.inspector.as_mut() {
                        inspector.feed(&this.frame[this.frame.len() - n..]);
                    }
                }
                Poll::Pending => {
                    if this.frame.len() == head {
                        return Poll::Pending;
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
                        return Poll::Ready(Ok(Fill::Frame));
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
        out: &mut Vec<u8>,
    ) -> Poll<std::io::Result<Option<u64>>> {
        self.poll_fill_and_seal(cx, out)
    }
}

impl<R: AsyncRead> tokio_stream::Stream for TrafficShaper<R> {
    type Item = Result<(u64, Bytes), Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match Self::poll_fill_proj(&mut this, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Fill::Eof)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(Fill::Frame)) => {
                let seq = match Self::finalize(&mut this) {
                    Ok(seq) => seq,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                };
                let buf = if *this.encoding == EncodingType::Json {
                    let mut line = bufpool::take(*this.line_capacity);
                    Self::write_json(&mut this, &mut line);
                    line
                } else {
                    std::mem::replace(this.frame, bufpool::take(*this.frame_capacity))
                };
                Self::start_frame(&mut this);
                Poll::Ready(Some(Ok((seq, bufpool::frame_bytes(buf)))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{stream_cipher_arc, test_cipher, test_cipher_dyn as test_cipher_arc};
    use std::io::Cursor;

    #[tokio::test(start_paused = true)]
    async fn pending_binary_frame_survives_switching_batch_buffers() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(1024);
        let cipher = test_cipher_arc();
        let config = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_seq(
            reader,
            &config,
            Arc::clone(&cipher),
            7,
        ));
        writer.write_all(b"first").await.unwrap();
        let mut original = b"previous batch".to_vec();
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(
            shaper
                .as_mut()
                .poll_seal_into(&mut context, &mut original)
                .is_pending()
        );
        assert_eq!(&original, b"previous batch");
        drop(original);
        writer.write_all(b"second").await.unwrap();
        drop(writer);
        let mut next = Vec::new();
        assert_eq!(
            std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut next))
                .await
                .unwrap(),
            Some(7)
        );
        let mut input = BytesMut::from(&next[..]);
        let (seq, decoded) = decode_from_buffer(&mut input, cipher.as_ref(), EncodingType::Binary)
            .unwrap()
            .unwrap();
        assert_eq!(seq, 7);
        assert_eq!(&decoded[..], b"firstsecond");
    }

    #[test]
    fn binary_payload_length_cannot_include_the_authentication_tag() {
        let cipher = test_cipher();
        let mut header = [0; HEADER_LEN];
        header[HEADER_LEN - 1] = 1;
        let encrypted = cipher.encrypt(&header).unwrap();
        let mut input = BytesMut::new();
        input.put_u16(encrypted.len() as u16);
        input.extend_from_slice(&encrypted);
        assert!(decode_from_buffer(&mut input, &cipher, EncodingType::Binary).is_err());
    }

    fn test_config() -> TrafficConfig {
        TrafficConfig {
            encoding_type: EncodingType::Binary,
            global: PaddingConfig {
                padding_threshold: 16384,
                padding_range: [0, 16],
            },
            handshake: None,
            stages: vec![],
            max_download_bytes: None,
        }
    }

    #[test]
    fn validate_rejects_inverted_handshake_range() {
        let cfg = TrafficConfig {
            handshake: Some(HandshakePadding {
                padding_range: [4096, 1024],
            }),
            ..test_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn padded_frame_pads_regardless_of_payload_size() {
        let cipher = test_cipher();
        let data = [0xABu8; 4096];
        let frame = encode_frame_padded(&data, 0, &cipher, [16, 16], EncodingType::Binary).unwrap();
        assert_eq!(
            frame.len(),
            2 + NONCE_LEN + HEADER_LEN + data.len() + 16 + TAG_LEN
        );

        let mut src = BytesMut::from(&frame[..]);
        let (seq, decoded) = decode_from_buffer(&mut src, &cipher, EncodingType::Binary)
            .unwrap()
            .unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&decoded[..], &data[..]);
    }

    #[test]
    fn decode_frame_roundtrips_multiple_frames() {
        let cipher = test_cipher();
        let mut combined = BytesMut::new();
        for (i, msg) in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ]
        .iter()
        .enumerate()
        {
            let frame =
                encode_frame(msg, i as u64, &cipher, 16384, [0, 0], EncodingType::Binary).unwrap();
            combined.extend_from_slice(&frame);
        }

        let mut json_scratch = Vec::new();
        let mut expected_seq = 0u64;
        while !combined.is_empty() {
            match decode_frame(
                &mut combined,
                &mut json_scratch,
                &cipher,
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::Owned { seq, data } => {
                    assert_eq!(seq, expected_seq);
                    assert_eq!(
                        &data[..],
                        [
                            b"first".as_slice(),
                            b"second".as_slice(),
                            b"third".as_slice()
                        ][expected_seq as usize]
                    );
                    expected_seq += 1;
                }
                _ => panic!("expected Owned frame"),
            }
        }
        assert_eq!(expected_seq, 3);
    }

    #[test]
    fn decode_frame_json_roundtrip() {
        let cipher = test_cipher();
        let frame = encode_frame(
            b"json payload",
            3,
            &cipher,
            16384,
            [0, 0],
            EncodingType::Json,
        )
        .unwrap();
        let mut src = BytesMut::from(&frame[..]);
        let mut json_scratch = Vec::new();
        match decode_frame(&mut src, &mut json_scratch, &cipher, EncodingType::Json)
            .unwrap()
            .unwrap()
        {
            DecodedFrame::InJsonScratch { seq, start, end } => {
                assert_eq!(seq, 3);
                assert_eq!(&json_scratch[start..end], b"json payload");
            }
            _ => panic!("expected InJsonScratch frame"),
        }
        assert!(src.is_empty());
    }

    fn seal_all(shaper: TrafficShaper<Cursor<Vec<u8>>>, out: &mut Vec<u8>) -> Vec<u64> {
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
    async fn poll_seal_into_cipher_matches_stream_output() {
        use futures::StreamExt;

        let cipher = test_cipher_arc();

        let config = ResolvedShaperConfig::resolve(&test_config());
        let data = vec![0x5Cu8; 33_000];

        let cipher_for_decode = Arc::clone(&cipher);
        let decode_append = |src: &mut BytesMut, out: &mut Vec<u8>| {
            let mut json_scratch = Vec::new();
            match decode_frame(
                src,
                &mut json_scratch,
                cipher_for_decode.as_ref(),
                EncodingType::Binary,
            )
            .unwrap()
            .unwrap()
            {
                DecodedFrame::Owned { data, .. } => out.extend_from_slice(&data),
                _ => panic!("expected Owned frame"),
            }
        };

        let shaper_stream =
            TrafficShaper::with_seq(Cursor::new(data.clone()), &config, Arc::clone(&cipher), 0);
        let mut stream_payload = Vec::new();
        let mut stream_seqs = Vec::new();
        let mut shaper_stream = Box::pin(shaper_stream);
        while let Some(item) = shaper_stream.next().await {
            let (seq, bytes) = item.unwrap();
            stream_seqs.push(seq);
            let mut frame_buf = BytesMut::from(&bytes[..]);
            decode_append(&mut frame_buf, &mut stream_payload);
        }

        let shaper_seal = TrafficShaper::with_seq(Cursor::new(data.clone()), &config, cipher, 0);
        let mut out = Vec::new();
        let seqs = seal_all(shaper_seal, &mut out);
        let mut out_buf = BytesMut::from(&out[..]);
        let mut seal_payload = Vec::new();
        while !out_buf.is_empty() {
            decode_append(&mut out_buf, &mut seal_payload);
        }

        assert!(seqs.iter().copied().eq(0..seqs.len() as u64));
        assert_eq!(seqs, stream_seqs);
        assert_eq!(seal_payload, stream_payload);
        assert_eq!(seal_payload, data);
    }

    #[test]
    fn encode_frame_rejects_oversized_payload() {
        let big = vec![0u8; MAX_RAW_PAYLOAD + 1];
        let cipher = test_cipher();
        let r = encode_frame(&big, 0, &cipher, 0, [0, 0], EncodingType::Binary);
        assert!(r.is_err());
        let r = encode_frame(&big, 0, &cipher, 0, [0, 0], EncodingType::Json);
        assert!(r.is_err());
    }

    #[test]
    fn encode_frame_json_padding_stays_within_line_limit() {
        let raw = vec![0x42u8; 1000];
        let aes = test_cipher();
        let frame = encode_frame(&raw, 0, &aes, 100_000, [0, 100_000], EncodingType::Json).unwrap();
        let line_len = frame.iter().position(|&b| b == b'\n').unwrap();
        assert!(line_len <= MAX_JSON_LINE_LEN);
    }

    #[tokio::test]
    async fn poll_seal_into_respects_start_seq() {
        let data = vec![0x55u8; 1000];
        let reader = std::io::Cursor::new(data);
        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let cipher = test_cipher();
        let mut shaper = Box::pin(TrafficShaper::with_seq(
            reader,
            &cfg,
            Arc::new(test_cipher()),
            42,
        ));
        let mut out = Vec::new();
        let result = std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out)).await;
        assert!(matches!(result, Ok(Some(42))));
        let mut out = BytesMut::from(&out[..]);
        let mut json_scratch = Vec::new();
        let frame = decode_frame(&mut out, &mut json_scratch, &cipher, EncodingType::Binary)
            .unwrap()
            .expect("frame");
        match frame {
            DecodedFrame::Owned { seq, .. } => assert_eq!(seq, 42),
            DecodedFrame::InJsonScratch { seq, .. } => assert_eq!(seq, 42),
        }
    }

    #[tokio::test]
    async fn poll_seal_into_pending_then_data() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(32 * 1024);
        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_seq(reader, &cfg, test_cipher_arc(), 0));
        let mut out = Vec::new();

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(
            matches!(
                shaper.as_mut().poll_seal_into(&mut cx, &mut out),
                Poll::Pending
            ),
            "empty duplex must yield Pending"
        );

        writer.write_all(&[0x33u8; 32 * 1024]).await.unwrap();
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
            handshake: None,
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
        let (mut writer, reader) = tokio::io::duplex(32 * 1024);
        let mut shaper = Box::pin(TrafficShaper::with_seq(
            reader,
            &resolved,
            test_cipher_arc(),
            0,
        ));
        let mut out = Vec::new();
        let mut sizes = Vec::new();
        for _ in 0..4 {
            writer.write_all(&[0x44u8; 1000]).await.unwrap();
            std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out))
                .await
                .unwrap();
            sizes.push(out.len());
            out.clear();
        }
        let overhead = 2 + NONCE_LEN + HEADER_LEN + TAG_LEN;
        assert_eq!(sizes[0], overhead + 1000 + 100);
        assert_eq!(sizes[1], overhead + 1000 + 200);
        assert_eq!(sizes[2], overhead + 1000 + 200);
        assert_eq!(sizes[3], overhead + 1000);
    }

    #[test]
    fn decode_frame_json_rejects_malformed_lines() {
        let cipher = test_cipher();
        let mut json_scratch = Vec::new();
        let mut src = BytesMut::new();

        src.extend_from_slice(
            b"
",
        );
        assert!(decode_frame(&mut src, &mut json_scratch, &cipher, EncodingType::Json).is_err());

        let mut long = BytesMut::new();
        long.extend_from_slice(b"{\"data\":\"");
        long.resize(MAX_JSON_LINE_LEN + 2, b'x');
        assert!(decode_frame(&mut long, &mut json_scratch, &cipher, EncodingType::Json).is_err());

        let mut unclosed = BytesMut::new();
        unclosed.extend_from_slice(b"{\"data\":\"abc");
        unclosed.extend_from_slice(
            b"
",
        );
        assert!(
            decode_frame(
                &mut unclosed,
                &mut json_scratch,
                &cipher,
                EncodingType::Json
            )
            .is_err()
        );
    }

    fn tls13_server_hello_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[5u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        let ext = [0x00u8, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = Vec::new();
        hs.push(2);
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    fn tls13_client_hello_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[6u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        let ext = [0x00u8, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = Vec::new();
        hs.push(1);
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[tokio::test]
    async fn shaper_continues_from_inspector_offset() {
        let cipher = stream_cipher_arc(2);
        let hello = tls13_client_hello_record();
        let mut input = hello.clone();
        input.extend_from_slice(&tls13_app_data_record(2048));
        let split = hello.len() + 5;

        let mut inspector = crate::crypto::TlsInspector::new();
        inspector.feed(&input[..split]);
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));

        let cfg = ResolvedShaperConfig::resolve(&test_config());
        let mut shaper = Box::pin(TrafficShaper::with_inspector(
            std::io::Cursor::new(input[split..].to_vec()),
            &cfg,
            Arc::clone(&cipher),
            0,
            Some(inspector),
        ));

        let mut out = Vec::new();
        std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out[2] & 0x80, 0x80);

        let mut buf = BytesMut::from(&out[..]);
        let mut json_scratch = Vec::new();
        let DecodedFrame::Owned { data, .. } = decode_frame(
            &mut buf,
            &mut json_scratch,
            cipher.as_ref(),
            EncodingType::Binary,
        )
        .unwrap()
        .expect("frame") else {
            panic!("expected owned frame");
        };
        assert_eq!(&data[..], &input[split..]);
    }

    fn tls13_app_data_record(len: usize) -> Vec<u8> {
        let mut record = vec![23u8, 0x03, 0x03];
        record.extend_from_slice(&(len as u16).to_be_bytes());
        record.extend(std::iter::repeat_n(0x5Au8, len));
        record
    }

    #[tokio::test]
    async fn json_record_fragments_stay_plaintext() {
        let cipher = stream_cipher_arc(4);
        let mut input = tls13_server_hello_record();
        for _ in 0..8 {
            input.extend_from_slice(&tls13_app_data_record(4096));
        }

        let cfg = ResolvedShaperConfig::resolve(&TrafficConfig {
            encoding_type: EncodingType::Json,
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            ..test_config()
        });
        let mut shaper = Box::pin(TrafficShaper::with_inspector(
            std::io::Cursor::new(input.clone()),
            &cfg,
            Arc::clone(&cipher),
            0,
            Some(crate::crypto::TlsInspector::new()),
        ));

        let mut out = Vec::new();
        let mut received = Vec::new();
        for expected_seq in 0..3 {
            out.clear();
            let seq = std::future::poll_fn(|cx| shaper.as_mut().poll_seal_into(cx, &mut out))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(seq, expected_seq);

            let mut sealed = Vec::new();
            parse_json_payload_into(&out, &mut sealed).unwrap();
            assert_eq!(
                sealed[0] & 0x80,
                if expected_seq == 0 { 0 } else { 0x80 },
                "frame {expected_seq}"
            );

            let mut buf = BytesMut::from(&out[..]);
            let mut scratch = Vec::new();
            let frame = decode_frame(&mut buf, &mut scratch, cipher.as_ref(), EncodingType::Json)
                .unwrap()
                .expect("frame");
            match frame {
                DecodedFrame::InJsonScratch { start, end, .. } => {
                    received.extend_from_slice(&scratch[start..end]);
                }
                DecodedFrame::Owned { data, .. } => received.extend_from_slice(&data),
            }
        }
        assert_eq!(received, input);
    }
}

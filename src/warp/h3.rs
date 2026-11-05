use bytes::{BufMut, Bytes, BytesMut};

pub(crate) const FRAME_DATA: u64 = 0x00;
pub(crate) const FRAME_HEADERS: u64 = 0x01;
pub(crate) const FRAME_SETTINGS: u64 = 0x04;

pub(crate) const STREAM_CONTROL: u64 = 0x00;
pub(crate) const STREAM_QPACK_ENCODER: u64 = 0x02;
pub(crate) const STREAM_QPACK_DECODER: u64 = 0x03;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

const INDEXED_STATIC: u8 = 0xC0;
const STATIC_METHOD_CONNECT: u8 = 15;
const STATIC_AUTHORITY: u8 = 0;

const STATIC_STATUS_FIRST: u64 = 24;
const STATIC_STATUS_VALUES: [u16; 8] = [103, 200, 204, 206, 304, 400, 404, 500];

const MAX_FIELD_SECTION: usize = 16 * 1024;

#[inline]
pub(crate) fn varint_len(value: u64) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

pub(crate) fn put_varint(out: &mut BytesMut, value: u64) {
    let len = varint_len(value);
    match len {
        1 => out.put_u8(value as u8),
        2 => out.put_u16(0x4000 | value as u16),
        4 => out.put_u32(0x8000_0000 | value as u32),
        _ => out.put_u64(0xC000_0000_0000_0000 | value),
    }
}

pub(crate) fn put_varint_slice(out: &mut [u8], value: u64) -> usize {
    match varint_len(value) {
        1 => {
            out[0] = value as u8;
            1
        }
        2 => {
            out[..2].copy_from_slice(&(0x4000 | value as u16).to_be_bytes());
            2
        }
        4 => {
            out[..4].copy_from_slice(&(0x8000_0000 | value as u32).to_be_bytes());
            4
        }
        _ => {
            out[..8].copy_from_slice(&(0xC000_0000_0000_0000 | value).to_be_bytes());
            8
        }
    }
}

#[inline]
pub(crate) fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

#[inline]
pub(crate) fn get_frame_header(buf: &[u8]) -> Option<(u64, u64, usize)> {
    let (ty, n) = get_varint(buf)?;
    let (len, m) = get_varint(&buf[n..])?;
    Some((ty, len, n + m))
}

fn put_int(out: &mut BytesMut, first: u8, prefix_bits: u8, mut value: u64) {
    let mask = ((1u16 << prefix_bits) - 1) as u64;
    if value < mask {
        out.put_u8(first | value as u8);
        return;
    }
    out.put_u8(first | mask as u8);
    value -= mask;
    while value >= 128 {
        out.put_u8((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn get_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let mut value = (first & mask) as u64;
    if value < mask as u64 {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    loop {
        let byte = *buf.get(idx)?;
        value = value.checked_add(((byte & 0x7F) as u64) << shift)?;
        idx += 1;
        if byte & 0x80 == 0 {
            return Some((value, idx));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn put_string(out: &mut BytesMut, value: &[u8]) {
    put_int(out, 0, 7, value.len() as u64);
    out.put_slice(value);
}

fn get_string(buf: &[u8]) -> Option<(&[u8], usize, bool)> {
    let huffman = *buf.first()? & 0x80 != 0;
    let (len, used) = get_int(buf, 7)?;
    let end = used.checked_add(len as usize)?;
    Some((buf.get(used..end)?, end, huffman))
}

pub(crate) fn control_stream_bytes() -> Bytes {
    let mut out = BytesMut::with_capacity(16);
    put_varint(&mut out, STREAM_CONTROL);
    put_varint(&mut out, FRAME_SETTINGS);
    let mut settings = BytesMut::with_capacity(10);
    put_varint(&mut settings, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    put_varint(&mut settings, 0);
    put_varint(&mut settings, SETTINGS_QPACK_BLOCKED_STREAMS);
    put_varint(&mut settings, 0);
    put_varint(&mut settings, SETTINGS_MAX_FIELD_SECTION_SIZE);
    put_varint(&mut settings, MAX_FIELD_SECTION as u64);
    put_varint(&mut out, settings.len() as u64);
    out.extend_from_slice(&settings);
    out.freeze()
}

pub(crate) fn encode_connect_headers(authority: &str) -> Bytes {
    let mut out = BytesMut::with_capacity(authority.len() + 16);
    out.put_u8(0);
    out.put_u8(0);
    out.put_u8(INDEXED_STATIC | STATIC_METHOD_CONNECT);
    put_int(&mut out, 0b0101_0000, 4, STATIC_AUTHORITY as u64);
    put_string(&mut out, authority.as_bytes());
    out.freeze()
}

#[inline]
fn static_status(index: u64) -> Option<u16> {
    let offset = index.checked_sub(STATIC_STATUS_FIRST)?;
    STATIC_STATUS_VALUES.get(offset as usize).copied()
}

fn parse_status_code(value: &[u8]) -> Result<u16, &'static str> {
    if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return Err("malformed :status value");
    }
    let mut code = 0u16;
    for &b in value {
        code = code * 10 + (b - b'0') as u16;
    }
    if !(100..600).contains(&code) {
        return Err(":status out of range");
    }
    Ok(code)
}

pub(crate) fn decode_status(block: &[u8]) -> Result<u16, &'static str> {
    let (insert_count, mut offset) = get_int(block, 8).ok_or("truncated field section prefix")?;
    if insert_count != 0 {
        return Err("peer referenced the QPACK dynamic table");
    }
    let (_, used) = get_int(&block[offset..], 7).ok_or("truncated delta base")?;
    offset += used;

    while offset < block.len() {
        let first = block[offset];
        if first & 0x80 != 0 {
            let (index, used) = get_int(&block[offset..], 6).ok_or("truncated indexed field")?;
            offset += used;
            if first & 0x40 == 0 {
                return Err("dynamic table reference");
            }
            if let Some(code) = static_status(index) {
                return Ok(code);
            }
        } else if first & 0x40 != 0 {
            let is_static = first & 0x10 != 0;
            let (name_index, used) = get_int(&block[offset..], 4).ok_or("truncated field name")?;
            offset += used;
            let (value, used, huffman) =
                get_string(&block[offset..]).ok_or("truncated field value")?;
            offset += used;
            if is_static && static_status(name_index).is_some() {
                if huffman {
                    return Err("huffman-coded :status");
                }
                return parse_status_code(value);
            }
        } else if first & 0x20 != 0 {
            let name_huffman = first & 0x08 != 0;
            let (name_len, used) =
                get_int(&block[offset..], 3).ok_or("truncated literal field name")?;
            let name_start = offset + used;
            let name_end = name_start
                .checked_add(name_len as usize)
                .ok_or("literal field name overflow")?;
            let name = block
                .get(name_start..name_end)
                .ok_or("truncated literal field name")?;
            let (value, used, value_huffman) =
                get_string(&block[name_end..]).ok_or("truncated literal field value")?;
            offset = name_end + used;
            if !name_huffman && name == b":status" {
                if value_huffman {
                    return Err("huffman-coded :status");
                }
                return parse_status_code(value);
            }
        } else {
            return Err("post-base index");
        }
    }
    Err(":status not found in response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_all_widths() {
        for value in [0u64, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1 << 30] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            assert_eq!(buf.len(), varint_len(value));
            assert_eq!(get_varint(&buf).unwrap(), (value, buf.len()));

            let mut slice = [0u8; 8];
            let n = put_varint_slice(&mut slice, value);
            assert_eq!(n, buf.len());
            assert_eq!(&slice[..n], &buf[..]);
        }
    }

    #[test]
    fn varint_rejects_truncated() {
        assert!(get_varint(&[]).is_none());
        assert!(get_varint(&[0x40]).is_none());
    }

    #[test]
    fn frame_header_parses_type_and_length() {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, FRAME_HEADERS);
        put_varint(&mut buf, 300);
        let (ty, len, used) = get_frame_header(&buf).unwrap();
        assert_eq!((ty, len, used), (FRAME_HEADERS, 300, buf.len()));
    }

    #[test]
    fn connect_headers_have_expected_bytes() {
        let block = encode_connect_headers("example.com:443");
        assert_eq!(block[0], 0, "Required Insert Count must be 0");
        assert_eq!(block[1], 0, "Delta Base must be 0");
        assert_eq!(block[2], 0xCF, ":method CONNECT");
        assert_eq!(block[3], 0x50, ":authority with static name reference");
        assert_eq!(block[4], 15, "authority length");
        assert_eq!(&block[5..20], b"example.com:443");
        assert_eq!(block.len(), 20, "no :scheme / :path for CONNECT");
    }

    #[test]
    fn connect_headers_encode_long_authority() {
        let authority = "a".repeat(200);
        let block = encode_connect_headers(&authority);
        assert_eq!(block[4], 0x7F);
        assert_eq!(block[5], 200 - 127);
        assert_eq!(&block[6..6 + 200], authority.as_bytes());
    }

    #[test]
    fn decode_status_from_static_index() {
        for (index, expected) in STATIC_STATUS_VALUES.iter().enumerate() {
            let block = [
                0u8,
                0u8,
                INDEXED_STATIC | (STATIC_STATUS_FIRST as u8 + index as u8),
            ];
            assert_eq!(decode_status(&block).unwrap(), *expected);
        }
    }

    #[test]
    fn decode_status_from_literal_name() {
        let mut block = BytesMut::new();
        block.put_u8(0);
        block.put_u8(0);
        put_int(&mut block, 0b0010_0000, 3, 7);
        block.put_slice(b":status");
        put_string(&mut block, b"403");
        assert_eq!(decode_status(&block).unwrap(), 403);
    }

    #[test]
    fn decode_status_skips_unrelated_fields() {
        let mut block = BytesMut::new();
        block.put_u8(0);
        block.put_u8(0);
        put_int(&mut block, INDEXED_STATIC, 6, 32);
        block.put_u8(INDEXED_STATIC | 25);
        assert_eq!(decode_status(&block).unwrap(), 200);
    }

    #[test]
    fn decode_status_rejects_dynamic_table() {
        let block = [1u8, 0u8, INDEXED_STATIC | 25];
        assert!(decode_status(&block).is_err());
        let block = [0u8, 0u8, 0x80 | 25];
        assert!(decode_status(&block).is_err());
    }

    #[test]
    fn decode_status_rejects_malformed_value() {
        let mut block = BytesMut::new();
        block.put_u8(0);
        block.put_u8(0);
        put_int(&mut block, 0b0010_0000, 3, 7);
        block.put_slice(b":status");
        put_string(&mut block, b"2x0");
        assert!(decode_status(&block).is_err());
    }

    #[test]
    fn decode_status_errors_when_absent() {
        let block = [0u8, 0u8, INDEXED_STATIC | 32];
        assert!(decode_status(&block).is_err());
    }

    #[test]
    fn control_stream_declares_zero_dynamic_table() {
        let bytes = control_stream_bytes();
        let (stream_type, used) = get_varint(&bytes).unwrap();
        assert_eq!(stream_type, STREAM_CONTROL);
        let (frame_type, len, header) = get_frame_header(&bytes[used..]).unwrap();
        assert_eq!(frame_type, FRAME_SETTINGS);
        let payload = &bytes[used + header..used + header + len as usize];
        assert_eq!(payload.len(), 9);
        let (id, n) = get_varint(payload).unwrap();
        assert_eq!(id, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        assert_eq!(get_varint(&payload[n..]).unwrap().0, 0);
    }
}

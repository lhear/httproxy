//! 最小可用的 HTTP/3 客户端编解码。
//!
//! 只实现 MASQUE TCP 转发需要的那一小部分：控制流（SETTINGS）、QPACK 单向流
//! 占位、请求 HEADERS、响应 HEADERS 以及双向的 DATA 帧。
//!
//! 字段块刻意只使用 QPACK 静态表：我们在 SETTINGS 里把动态表容量
//! （`SETTINGS_QPACK_MAX_TABLE_CAPACITY`）和阻塞流数量
//! （`SETTINGS_QPACK_BLOCKED_STREAMS`）都通告为 0，因此对端在协议上不可能
//! 引用动态表条目，解码侧也就不需要维护动态表和 Huffman 字典。

use bytes::{BufMut, Bytes, BytesMut};

/// DATA 帧：隧道载荷
pub(crate) const FRAME_DATA: u64 = 0x00;
/// HEADERS 帧：字段块
pub(crate) const FRAME_HEADERS: u64 = 0x01;
/// SETTINGS 帧：只能出现在控制流上
pub(crate) const FRAME_SETTINGS: u64 = 0x04;

/// 控制流（单向）
pub(crate) const STREAM_CONTROL: u64 = 0x00;
/// QPACK 编码器流（单向）
pub(crate) const STREAM_QPACK_ENCODER: u64 = 0x02;
/// QPACK 解码器流（单向）
pub(crate) const STREAM_QPACK_DECODER: u64 = 0x03;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// 索引字段行 + 静态表标记
const INDEXED_STATIC: u8 = 0xC0;
/// 静态表里的 `:method: CONNECT`
const STATIC_METHOD_CONNECT: u8 = 15;
/// 静态表里的 `:authority`（只有名字，值需要单独编）
const STATIC_AUTHORITY: u8 = 0;

/// 静态表里 `:status` 条目的起始下标，24..=31 依次是
/// 103 / 200 / 204 / 206 / 304 / 400 / 404 / 500。
///
/// 静态表里带名字的 `:status` 条目都自带值，所以对端要么直接命中这里的
/// 索引，要么用「字面量名字」形式（`Literal Field Line With Literal Name`），
/// 不存在「静态名字引用 + 另外给值」的写法。
const STATIC_STATUS_FIRST: u64 = 24;
const STATIC_STATUS_VALUES: [u16; 8] = [103, 200, 204, 206, 304, 400, 404, 500];

/// 响应头字段块的最大长度，防止对端用超长 HEADERS 撑爆内存。
const MAX_FIELD_SECTION: usize = 16 * 1024;

/// QUIC 变长整数（RFC 9000 §16）编码后的长度。
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

/// 把变长整数追加到缓冲区。
pub(crate) fn put_varint(out: &mut BytesMut, value: u64) {
    let len = varint_len(value);
    match len {
        1 => out.put_u8(value as u8),
        2 => out.put_u16(0x4000 | value as u16),
        4 => out.put_u32(0x8000_0000 | value as u32),
        _ => out.put_u64(0xC000_0000_0000_0000 | value),
    }
}

/// 把变长整数写进定长切片，返回写入长度。
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

/// 解析变长整数，返回（值，占用字节数）。
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

/// 解析一个帧头（类型 + 长度），返回（类型，长度，头部字节数）。
#[inline]
pub(crate) fn get_frame_header(buf: &[u8]) -> Option<(u64, u64, usize)> {
    let (ty, n) = get_varint(buf)?;
    let (len, m) = get_varint(&buf[n..])?;
    Some((ty, len, n + m))
}

/// QPACK 前缀整数（RFC 9204 §4.1.1）。
///
/// `first` 是已经置好标志位、低位留空的第一个字节。
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

/// 读取 QPACK 前缀整数，返回（值，占用字节数）。
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

/// 写一个不做 Huffman 编码的字符串字面量。
fn put_string(out: &mut BytesMut, value: &[u8]) {
    put_int(out, 0, 7, value.len() as u64);
    out.put_slice(value);
}

/// 读一个字符串字面量，返回（内容，占用字节数，是否 Huffman 编码）。
fn get_string(buf: &[u8]) -> Option<(&[u8], usize, bool)> {
    let huffman = *buf.first()? & 0x80 != 0;
    let (len, used) = get_int(buf, 7)?;
    let end = used.checked_add(len as usize)?;
    Some((buf.get(used..end)?, end, huffman))
}

/// 控制流：流类型 + SETTINGS。
///
/// 只保留「动态表容量 0」这一条真正有用的设置：它让对端的 QPACK 编码器
/// 无法向动态表插入条目，我们就不必实现动态表与 Huffman 解码。
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

/// 把 `CONNECT <authority>` 的字段块编码成 QPACK 字节串。
///
/// 只用 `:method` 与 `:authority` 两个伪首部：RFC 9114 §4.4 要求 CONNECT
/// 省略 `:scheme` / `:path`，quic-go 对非扩展 CONNECT 也确实不会写它们
/// （usque 的 `l4-*` 模式就是这么跑通的）。多带这两个伪首部会被严格的
/// H3 服务端判成 malformed。
pub(crate) fn encode_connect_headers(authority: &str) -> Bytes {
    let mut out = BytesMut::with_capacity(authority.len() + 16);
    // 字段块前缀：Required Insert Count = 0，Delta Base = 0
    out.put_u8(0);
    out.put_u8(0);
    out.put_u8(INDEXED_STATIC | STATIC_METHOD_CONNECT);
    // :authority —— 静态名字引用（N=0，T=1，4 位前缀索引）
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

/// 从一个 HEADERS 字段块里取出 `:status`。
///
/// 只接受静态表与未压缩字面量；遇到动态表引用、Post-Base 索引或
/// Huffman 编码的 `:status` 值都会报错（正常不会出现，见模块注释）。
pub(crate) fn decode_status(block: &[u8]) -> Result<u16, &'static str> {
    // 字段块前缀
    let (insert_count, mut offset) = get_int(block, 8).ok_or("truncated field section prefix")?;
    if insert_count != 0 {
        return Err("peer referenced the QPACK dynamic table");
    }
    let (_, used) = get_int(&block[offset..], 7).ok_or("truncated delta base")?;
    offset += used;

    while offset < block.len() {
        let first = block[offset];
        if first & 0x80 != 0 {
            // Indexed Field Line（T 位区分静态/动态）
            let (index, used) = get_int(&block[offset..], 6).ok_or("truncated indexed field")?;
            offset += used;
            if first & 0x40 == 0 {
                return Err("dynamic table reference");
            }
            if let Some(code) = static_status(index) {
                return Ok(code);
            }
        } else if first & 0x40 != 0 {
            // Literal Field Line With Name Reference
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
            // Literal Field Line With Literal Name：`001 N H` + 3 位名字长度
            let name_huffman = first & 0x08 != 0;
            let (name_len, used) =
                get_int(&block[offset..], 3).ok_or("truncated literal field name")?;
            let name_start = offset + used;
            let name_end = name_start
                .checked_add(name_len as usize)
                .ok_or("literal field name overflow")?;
            let name = block.get(name_start..name_end).ok_or("truncated literal field name")?;
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
            // 0001 前缀：Post-Base Indexed Field Line
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
        // 两字节编码只给了一个字节
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
        // 长度 200 需要两字节前缀整数：0x7F + 0x49
        assert_eq!(block[4], 0x7F);
        assert_eq!(block[5], 200 - 127);
        assert_eq!(&block[6..6 + 200], authority.as_bytes());
    }

    #[test]
    fn decode_status_from_static_index() {
        for (index, expected) in STATIC_STATUS_VALUES.iter().enumerate() {
            let block = [0u8, 0u8, INDEXED_STATIC | (STATIC_STATUS_FIRST as u8 + index as u8)];
            assert_eq!(decode_status(&block).unwrap(), *expected);
        }
    }

    #[test]
    fn decode_status_from_literal_name() {
        let mut block = BytesMut::new();
        block.put_u8(0);
        block.put_u8(0);
        put_int(&mut block, 0b0010_0000, 3, 7); // 字面量名字，长度 7
        block.put_slice(b":status");
        put_string(&mut block, b"403");
        assert_eq!(decode_status(&block).unwrap(), 403);
    }

    #[test]
    fn decode_status_skips_unrelated_fields() {
        let mut block = BytesMut::new();
        block.put_u8(0);
        block.put_u8(0);
        // 先来一个静态索引的 accept: */*（索引 32）
        put_int(&mut block, INDEXED_STATIC, 6, 32);
        // 再跟一个 :status 200
        block.put_u8(INDEXED_STATIC | 25);
        assert_eq!(decode_status(&block).unwrap(), 200);
    }

    #[test]
    fn decode_status_rejects_dynamic_table() {
        // Required Insert Count = 1
        let block = [1u8, 0u8, INDEXED_STATIC | 25];
        assert!(decode_status(&block).is_err());
        // 动态表索引
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

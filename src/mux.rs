//! 虚拟内网通道的多路复用帧。
//!
//! 虚拟内网节点和服务端之间只维持一条长连接（客户端发出的 POST，服务端用一条
//! 无限的响应体回推数据），所有被访问的逻辑连接都复用这条通道，因此每个
//! shaper 帧的载荷都是下面这个固定 5 字节头 + 数据：
//!
//! ```text
//! +---------+----------------+--------------------+
//! | tag: u8 | conn_id: u32BE | payload (0..n)     |
//! +---------+----------------+--------------------+
//! ```
//!
//! 头长度固定、长度由外层 shaper 帧给出，所以这里不需要再带长度字段。

use bytes::{BufMut, Bytes, BytesMut};

/// 多路复用头长度（tag + conn_id）。
pub const HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// 服务端 → 节点：在 payload 指定的端口上新建一条连接
    Open = 1,
    /// 节点 → 服务端：本地端口连上了
    OpenOk = 2,
    /// 节点 → 服务端：本地端口连不上
    OpenFail = 3,
    /// 双向：连接上的字节流
    Data = 4,
    /// 双向：半关闭（对端不再有数据）
    Close = 5,
    /// 服务端 → 节点：心跳
    Ping = 6,
    /// 节点 → 服务端：心跳应答
    Pong = 7,
}

impl Tag {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Tag::Open,
            2 => Tag::OpenOk,
            3 => Tag::OpenFail,
            4 => Tag::Data,
            5 => Tag::Close,
            6 => Tag::Ping,
            7 => Tag::Pong,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub tag: Tag,
    pub conn: u32,
    pub payload: &'a [u8],
}

/// 搬运层写向一条逻辑连接的指令，服务端与客户端共用。
pub enum ToSocket {
    Data(Bytes),
    /// 对端不再有数据：半关闭写方向，读方向继续。
    Eof,
}

pub fn encode(tag: Tag, conn: u32, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(HEADER_LEN + payload.len());
    encode_into(tag, conn, payload, &mut out);
    out.freeze()
}

pub fn encode_into(tag: Tag, conn: u32, payload: &[u8], out: &mut BytesMut) {
    out.put_u8(tag as u8);
    out.put_u32(conn);
    out.put_slice(payload);
}

pub fn parse(buf: &[u8]) -> Option<Frame<'_>> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let tag = Tag::from_byte(buf[0])?;
    let conn = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Some(Frame {
        tag,
        conn,
        payload: &buf[HEADER_LEN..],
    })
}

/// OPEN 帧的载荷：目标端口（大端）。
pub fn open_port(payload: &[u8]) -> Option<u16> {
    if payload.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_tags() {
        for tag in [
            Tag::Open,
            Tag::OpenOk,
            Tag::OpenFail,
            Tag::Data,
            Tag::Close,
            Tag::Ping,
            Tag::Pong,
        ] {
            let frame = encode(tag, 0xDEAD_BEEF, b"hello");
            let parsed = parse(&frame).expect("frame must parse");
            assert_eq!(parsed.tag, tag);
            assert_eq!(parsed.conn, 0xDEAD_BEEF);
            assert_eq!(parsed.payload, b"hello");
            assert_eq!(frame.len(), HEADER_LEN + 5);
        }
    }

    #[test]
    fn empty_payload_is_valid() {
        let frame = encode(Tag::Close, 7, &[]);
        let parsed = parse(&frame).unwrap();
        assert_eq!(parsed.tag, Tag::Close);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn short_or_invalid_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[Tag::Data as u8, 0, 0]).is_none());
        assert!(parse(&[0xFF, 0, 0, 0, 1]).is_none(), "unknown tag");
    }

    #[test]
    fn open_port_roundtrip() {
        let frame = encode(Tag::Open, 1, &8080u16.to_be_bytes());
        let parsed = parse(&frame).unwrap();
        assert_eq!(open_port(parsed.payload), Some(8080));
        assert_eq!(open_port(b"x"), None);
    }
}

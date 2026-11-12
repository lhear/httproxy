const RECORD_HANDSHAKE: u8 = 22;
const RECORD_APP_DATA: u8 = 23;
const MAX_TLS_RECORD_LEN: usize = 16 * 1024 + 2048;
const MAX_HANDSHAKE_LEN: usize = 64 * 1024;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const VERSION_TLS13: u16 = 0x0304;

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

#[inline]
fn read_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Record,
    Handshake,
    Skip,
    Done,
}

#[derive(Clone, Copy)]
enum Verdict {
    Opaque,
    Skip,
    Stop,
}

pub struct TlsInspector {
    state: State,
    buf: Vec<u8>,
    handshake: Vec<u8>,
    need: usize,
    total: u64,
    tls13: bool,
    opaque_at: Option<u64>,
}

impl Default for TlsInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsInspector {
    pub fn new() -> Self {
        Self {
            state: State::Record,
            buf: Vec::with_capacity(4096),
            handshake: Vec::new(),
            need: 0,
            total: 0,
            tls13: false,
            opaque_at: None,
        }
    }

    #[inline]
    pub fn opaque_at(&self) -> Option<u64> {
        self.opaque_at
    }

    #[inline]
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn feed(&mut self, data: &[u8]) {
        if self.state == State::Done {
            return;
        }
        self.total += data.len() as u64;
        if self.buf.len() + data.len() > MAX_HANDSHAKE_LEN {
            self.finish();
            return;
        }
        self.buf.extend_from_slice(data);
        self.advance();
        if self.state == State::Done {
            self.finish();
        }
    }

    fn finish(&mut self) {
        self.state = State::Done;
        self.buf = Vec::new();
        self.handshake = Vec::new();
        self.need = 0;
    }

    fn mark_opaque(&mut self) {
        self.opaque_at = Some(self.total - self.buf.len() as u64);
        self.state = State::Done;
    }

    fn advance(&mut self) {
        loop {
            match self.state {
                State::Record => {
                    if self.buf.len() < 5 {
                        return;
                    }
                    let kind = self.buf[0];
                    let major = self.buf[1];
                    let minor = self.buf[2];
                    let len = read_u16(&self.buf[3..5]) as usize;
                    if !(20..=23).contains(&kind)
                        || major != 3
                        || minor > 4
                        || len > MAX_TLS_RECORD_LEN
                    {
                        self.state = State::Done;
                        return;
                    }
                    if kind == RECORD_APP_DATA && self.tls13 {
                        self.mark_opaque();
                        return;
                    }
                    self.buf.drain(..5);
                    self.need = len;
                    self.state = if kind == RECORD_HANDSHAKE {
                        State::Handshake
                    } else {
                        State::Skip
                    };
                }
                State::Skip => {
                    let take = self.need.min(self.buf.len());
                    self.buf.drain(..take);
                    self.need -= take;
                    if self.need > 0 {
                        return;
                    }
                    self.state = State::Record;
                }
                State::Handshake => {
                    let take = self.need.min(self.buf.len());
                    self.handshake.extend_from_slice(&self.buf[..take]);
                    self.buf.drain(..take);
                    self.need -= take;
                    self.parse_handshake();
                    if self.state == State::Done {
                        return;
                    }
                    if self.need > 0 {
                        return;
                    }
                    self.state = State::Record;
                }
                State::Done => return,
            }
        }
    }

    fn parse_handshake(&mut self) {
        loop {
            if self.handshake.len() < 4 {
                return;
            }
            let len = ((self.handshake[1] as usize) << 16)
                | ((self.handshake[2] as usize) << 8)
                | self.handshake[3] as usize;
            if len > MAX_HANDSHAKE_LEN {
                self.state = State::Done;
                return;
            }
            if self.handshake.len() < 4 + len {
                return;
            }
            let verdict = match self.handshake[0] {
                1 => client_hello_verdict(&self.handshake[4..4 + len]),
                2 => server_hello_verdict(&self.handshake[4..4 + len]),
                _ => Verdict::Skip,
            };
            match verdict {
                Verdict::Opaque => self.tls13 = true,
                Verdict::Stop => {
                    self.state = State::Done;
                    return;
                }
                Verdict::Skip => {}
            }
            self.handshake.drain(..4 + len);
        }
    }
}

struct Extensions<'a> {
    buf: &'a [u8],
}

impl<'a> Extensions<'a> {
    fn new(body: &'a [u8], pos: usize) -> Option<Self> {
        let len = read_u16(body.get(pos..pos + 2)?) as usize;
        Some(Self {
            buf: body.get(pos + 2..pos + 2 + len)?,
        })
    }
}

impl<'a> Iterator for Extensions<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let kind = read_u16(self.buf.get(..2)?);
        let len = read_u16(self.buf.get(2..4)?) as usize;
        let data = self.buf.get(4..4 + len)?;
        self.buf = &self.buf[4 + len..];
        Some((kind, data))
    }
}

fn client_hello_verdict(body: &[u8]) -> Verdict {
    let Some(&sid_len) = body.get(34) else {
        return Verdict::Stop;
    };
    let mut pos = 35 + sid_len as usize;
    let Some(suites_len) = body.get(pos..pos + 2).map(read_u16) else {
        return Verdict::Stop;
    };
    pos += 2 + suites_len as usize;
    let Some(&comp_len) = body.get(pos) else {
        return Verdict::Stop;
    };
    pos += 1 + comp_len as usize;
    let Some(exts) = Extensions::new(body, pos) else {
        return Verdict::Stop;
    };
    for (kind, data) in exts {
        if kind == EXT_SUPPORTED_VERSIONS && offers_tls13(data) {
            return Verdict::Opaque;
        }
    }
    Verdict::Stop
}

fn offers_tls13(data: &[u8]) -> bool {
    let Some((&len, versions)) = data.split_first() else {
        return false;
    };
    let len = len as usize;
    versions.len() >= len
        && versions[..len]
            .as_chunks::<2>()
            .0
            .iter()
            .any(|v| u16::from_be_bytes(*v) == VERSION_TLS13)
}

fn server_hello_verdict(body: &[u8]) -> Verdict {
    let Some(random) = body.get(2..34) else {
        return Verdict::Stop;
    };
    let Some(&sid_len) = body.get(34) else {
        return Verdict::Stop;
    };
    let pos = 35 + sid_len as usize;
    let Some(suite) = body.get(pos..pos + 2).map(read_u16) else {
        return Verdict::Stop;
    };
    if !(0x1301..=0x1305).contains(&suite) {
        return Verdict::Stop;
    }
    let Some(exts) = Extensions::new(body, pos + 3) else {
        return Verdict::Stop;
    };
    let mut selected = None;
    for (kind, data) in exts {
        if kind == EXT_SUPPORTED_VERSIONS && data.len() == 2 {
            selected = Some(read_u16(data));
        }
    }
    if selected != Some(VERSION_TLS13) {
        return Verdict::Stop;
    }
    if random == HRR_RANDOM.as_slice() {
        return Verdict::Skip;
    }
    Verdict::Opaque
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn server_hello(version: &[u8], random: [u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        let exts = extension(EXT_SUPPORTED_VERSIONS, version);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        body
    }

    fn client_hello(offered: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[2u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        let mut versions = vec![offered.len() as u8];
        versions.extend_from_slice(offered);
        let exts = extension(EXT_SUPPORTED_VERSIONS, &versions);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        body
    }

    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(kind);
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(kind);
        let len = body.len() as u32;
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn opens_on_first_application_data_after_server_hello() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [7u8; 32])));
        inspector.feed(&hello);
        assert_eq!(inspector.opaque_at(), None);

        inspector.feed(&record(23, &[0xAAu8; 64]));
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));
    }

    #[test]
    fn opens_on_client_hello_offering_tls13() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(1, &client_hello(&[0x03, 0x04, 0x03, 0x03])));
        inspector.feed(&hello);
        assert_eq!(inspector.opaque_at(), None);

        inspector.feed(&record(23, &[0x11u8; 1024]));
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));
    }

    #[test]
    fn stays_closed_on_client_hello_without_tls13() {
        let mut inspector = TlsInspector::new();
        inspector.feed(&record(
            22,
            &handshake(1, &client_hello(&[0x03, 0x03, 0x03, 0x02])),
        ));
        inspector.feed(&record(23, &[0x11u8; 1024]));
        assert_eq!(inspector.opaque_at(), None);
    }

    #[test]
    fn opaque_offset_is_exact_for_fragmented_input() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [9u8; 32])));
        let app = record(23, &[0x55u8; 4096]);
        let stream: Vec<u8> = hello.iter().chain(app.iter()).copied().collect();
        for (i, byte) in stream.iter().enumerate() {
            inspector.feed(&[*byte]);
            if i + 1 < hello.len() {
                assert_eq!(inspector.opaque_at(), None);
            }
        }
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));
    }

    #[test]
    fn stays_closed_on_tls12_server_hello() {
        let mut inspector = TlsInspector::new();
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[1u8; 32]);
            body.push(0);
            body.extend_from_slice(&[0x13, 0x01]);
            body.push(0);
            body.extend_from_slice(&0u16.to_be_bytes());
            body
        };
        inspector.feed(&record(22, &handshake(2, &body)));
        inspector.feed(&record(23, &[0xAAu8; 64]));
        assert_eq!(inspector.opaque_at(), None);
    }

    #[test]
    fn stays_closed_on_hello_retry_request() {
        let mut inspector = TlsInspector::new();
        let hrr = record(22, &handshake(2, &server_hello(&[0x03, 0x04], HRR_RANDOM)));
        inspector.feed(&hrr);
        assert_eq!(inspector.opaque_at(), None);

        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [3u8; 32])));
        inspector.feed(&hello);
        assert_eq!(inspector.opaque_at(), None);

        inspector.feed(&record(23, &[0xAAu8; 32]));
        assert_eq!(
            inspector.opaque_at(),
            Some((hrr.len() + hello.len()) as u64)
        );
    }

    #[test]
    fn stays_closed_on_plaintext_protocol() {
        let mut inspector = TlsInspector::new();
        inspector.feed(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(inspector.opaque_at(), None);
    }

    #[test]
    fn reassembles_fragmented_server_hello() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [9u8; 32])));
        for byte in &hello {
            inspector.feed(&[*byte]);
        }
        assert_eq!(inspector.opaque_at(), None);

        let app = record(23, &[0x11u8; 1024]);
        for byte in &app {
            inspector.feed(&[*byte]);
        }
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));
    }

    #[test]
    fn small_application_data_records_still_open() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [4u8; 32])));
        inspector.feed(&hello);
        inspector.feed(&record(23, &[0x22u8; 1024]));
        assert_eq!(inspector.opaque_at(), Some(hello.len() as u64));
    }

    #[test]
    fn ignores_application_data_before_hello() {
        let mut inspector = TlsInspector::new();
        inspector.feed(&record(23, &[0xAAu8; 512]));
        assert_eq!(inspector.opaque_at(), None);
    }

    #[test]
    fn tracks_total_bytes_fed() {
        let mut inspector = TlsInspector::new();
        let hello = record(22, &handshake(2, &server_hello(&[0x03, 0x04], [8u8; 32])));
        inspector.feed(&hello);
        inspector.feed(&[0u8; 7]);
        assert_eq!(inspector.total(), hello.len() as u64 + 7);
    }
}

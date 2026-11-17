use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BytesMut};
use http::uri::Authority;
use tokio::io::AsyncReadExt;
use url::Url;

const MAX_HEADER_LEN: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const READ_RESERVE: usize = 4 * 1024;
const MAX_VERSION_LEN: usize = 16;

pub struct ProxyRequest {
    pub method: String,
    pub header_len: usize,
    pub target: String,
    pub authorized: bool,
}

pub async fn parse_proxy_request(
    reader: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
    expected_auth: Option<&str>,
) -> Result<ProxyRequest> {
    loop {
        if let Some(request) = try_parse_head(buffer, expected_auth)? {
            return Ok(request);
        }
        if buffer.len() >= MAX_HEADER_LEN {
            return Err(anyhow!("header too large"));
        }

        let remaining = MAX_HEADER_LEN - buffer.len();
        buffer.reserve(READ_RESERVE.min(remaining));
        if reader.take(remaining as u64).read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
    }
}

fn try_parse_head(buffer: &BytesMut, expected_auth: Option<&str>) -> Result<Option<ProxyRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buffer)? {
        httparse::Status::Complete(amt) => {
            anyhow::ensure!(amt <= MAX_HEADER_LEN, "header too large");
            let method = req.method.context("no method")?;
            let target = req.path.context("no path")?;
            let authorized = match expected_auth {
                None => true,
                Some(expected) => auth_matches(req.headers, expected),
            };
            Ok(Some(ProxyRequest {
                method: method.to_owned(),
                header_len: amt,
                target: target.to_owned(),
                authorized,
            }))
        }
        httparse::Status::Partial => Ok(None),
    }
}

fn auth_matches(headers: &[httparse::Header<'_>], expected: &str) -> bool {
    let Some(header) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
    else {
        return false;
    };
    trim_ascii(header.value) == expected.as_bytes()
}

#[inline]
fn trim_ascii(mut b: &[u8]) -> &[u8] {
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
fn resolve_connect_host(authority: &str) -> Result<String> {
    let auth: Authority = authority
        .parse()
        .map_err(|_| anyhow!("invalid target: {authority}"))?;
    let port = auth
        .port_u16()
        .ok_or_else(|| anyhow!("port required: {authority}"))?;
    let host = auth.host();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok(format!("{host}:{port}"))
}

fn origin_form(url: &Url) -> String {
    let path = url.path();
    let query_len = url.query().map_or(0, |q| q.len() + 1);
    let mut s = String::with_capacity(path.len() + query_len + 1);
    if path.is_empty() {
        s.push('/');
    } else {
        s.push_str(path);
    }
    if let Some(q) = url.query() {
        s.push('?');
        s.push_str(q);
    }
    s
}

pub fn resolve_request(method: &str, target: &str) -> Result<(String, Option<String>)> {
    if method == "CONNECT" {
        return Ok((resolve_connect_host(target)?, None));
    }
    let url = Url::parse(target).context("invalid proxy URL")?;
    let host = url.host_str().context("URL has no host")?;
    let port = url.port_or_known_default().context("port required")?;
    Ok((format!("{host}:{port}"), Some(origin_form(&url))))
}

pub fn rewrite_request_line(
    buf: &mut BytesMut,
    header_len: usize,
    method: &str,
    origin_path: &str,
) -> Result<()> {
    let scan_len = header_len.min(buf.len());
    let line_end = memchr::memchr(b'\n', &buf[..scan_len])
        .ok_or_else(|| anyhow!("request line has no newline"))?;
    let old_line_len = line_end + 1;

    let first_line = std::str::from_utf8(&buf[..line_end])
        .map_err(|_| anyhow!("request line is not valid UTF-8"))?;
    let first_line_trimmed = first_line.trim_end_matches('\r');
    let version = first_line_trimmed
        .rsplit_once(' ')
        .map(|(_, v)| v)
        .ok_or_else(|| anyhow!("malformed request line: {first_line_trimmed}"))?;
    let version_bytes = version.as_bytes();
    if version_bytes.len() > MAX_VERSION_LEN {
        return Err(anyhow!("unsupported HTTP version: {version}"));
    }
    let mut version_buf = [0u8; MAX_VERSION_LEN];
    version_buf[..version_bytes.len()].copy_from_slice(version_bytes);
    let version = &version_buf[..version_bytes.len()];

    let new_line_len = method.len() + 1 + origin_path.len() + 1 + version.len() + 2;
    if new_line_len <= old_line_len {
        buf.advance(old_line_len - new_line_len);
        write_request_line(&mut buf[..new_line_len], method, origin_path, version);
        return Ok(());
    }

    let total = buf.len();
    buf.resize(total + new_line_len - old_line_len, 0);
    buf.copy_within(old_line_len..total, new_line_len);
    write_request_line(&mut buf[..new_line_len], method, origin_path, version);

    Ok(())
}

const PROXY_ONLY_HEADERS: [&[u8]; 2] = [b"proxy-authorization", b"proxy-connection"];

#[inline]
fn is_proxy_only_header(line: &[u8]) -> bool {
    let Some(colon) = memchr::memchr(b':', line) else {
        return false;
    };
    let name = trim_ascii(&line[..colon]);
    PROXY_ONLY_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
}

pub fn strip_proxy_headers(buf: &mut BytesMut, header_len: usize) -> usize {
    let head_end = header_len.min(buf.len());
    let Some(request_line_end) = memchr::memchr(b'\n', &buf[..head_end]).map(|pos| pos + 1) else {
        return header_len;
    };

    let mut written = request_line_end;
    let mut dropping = false;
    let mut cursor = request_line_end;
    while cursor < head_end {
        let rest = &buf[cursor..head_end];
        let Some(rel) = memchr::memchr(b'\n', rest) else {
            buf.copy_within(cursor..head_end, written);
            written += head_end - cursor;
            break;
        };
        let line_end = cursor + rel + 1;
        let line = &buf[cursor..line_end];
        if !matches!(line.first(), Some(b' ') | Some(b'\t')) {
            dropping = is_proxy_only_header(line);
        }
        if !dropping {
            if written != cursor {
                buf.copy_within(cursor..line_end, written);
            }
            written += line_end - cursor;
        }
        cursor = line_end;
    }

    if written == head_end {
        return header_len;
    }

    let tail_len = buf.len() - head_end;
    if tail_len > written {
        let removed = head_end - written;
        buf.copy_within(..written, removed);
        buf.advance(removed);
    } else {
        buf.copy_within(head_end.., written);
        buf.truncate(written + tail_len);
    }
    written
}

#[inline]
fn write_request_line(dst: &mut [u8], method: &str, origin_path: &str, version: &[u8]) {
    let mut pos = 0;
    let n = method.len();
    dst[pos..pos + n].copy_from_slice(method.as_bytes());
    pos += n;
    dst[pos] = b' ';
    pos += 1;
    let n = origin_path.len();
    dst[pos..pos + n].copy_from_slice(origin_path.as_bytes());
    pos += n;
    dst[pos] = b' ';
    pos += 1;
    let n = version.len();
    dst[pos..pos + n].copy_from_slice(version);
    pos += n;
    dst[pos] = b'\r';
    dst[pos + 1] = b'\n';
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_request(buf: &mut BytesMut, method: &str, target: &str) -> Result<()> {
        let (_, origin_path) = resolve_request(method, target)?;
        let Some(origin_path) = origin_path else {
            return Ok(());
        };
        let header_len = head_len(buf);
        let header_len = strip_proxy_headers(buf, header_len);
        rewrite_request_line(buf, header_len, method, &origin_path)
    }

    fn head_len(buf: &[u8]) -> usize {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(buf.len(), |pos| pos + 4)
    }

    #[test]
    fn resolve_connect_no_port_fails() {
        assert!(resolve_request("CONNECT", "example.com").is_err());
    }

    #[test]
    fn rewrite_absolute_to_origin() {
        for (authority, path) in [
            ("example.com", "/path"),
            ("example.com", "/search?q=rust&lang=en"),
            ("example.com", "/"),
            ("example.com:8080", "/path"),
        ] {
            let target = format!("http://{authority}{path}");
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
            );
            let mut buf = BytesMut::from(request.as_bytes());
            handle_request(&mut buf, "GET", &target).unwrap();
            assert_eq!(
                &buf[..],
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
                "{target}"
            );
        }
    }

    #[test]
    fn origin_form_target_is_rejected() {
        assert!(resolve_request("GET", "/path").is_err());
    }

    #[test]
    fn rewrite_post_body_intact() {
        let body = b"{\"key\":\"value\"}";
        let mut request = Vec::new();
        request.extend_from_slice(b"POST http://example.com/api HTTP/1.1\r\n");
        request.extend_from_slice(b"Host: example.com\r\n");
        request.extend_from_slice(b"Content-Type: application/json\r\n");
        request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);

        let mut buf = BytesMut::from(&request[..]);
        let body_pointer = buf.as_ptr().wrapping_add(buf.len() - body.len());
        handle_request(&mut buf, "POST", "http://example.com/api").unwrap();
        assert_eq!(
            buf.as_ptr().wrapping_add(buf.len() - body.len()),
            body_pointer
        );
        let result = buf.to_vec();

        let result_str = String::from_utf8(result.clone()).unwrap();
        assert!(
            result_str.starts_with("POST /api HTTP/1.1\r\n"),
            "got: {result_str}"
        );
        assert!(result.ends_with(body), "POST body was modified");
        assert!(result_str.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn rewrite_longer_request_line_preserves_headers_and_body() {
        for path in ["/", "/a/longer/path?key=value"] {
            let mut buf = BytesMut::from(&b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"[..]);
            let header_len = head_len(&buf);
            rewrite_request_line(&mut buf, header_len, "POST", path).unwrap();
            assert_eq!(
                &buf[..],
                format!("POST {path} HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody").as_bytes()
            );
        }
    }

    #[test]
    fn resolve_connect_ipv6_brackets_stripped() {
        let (host, path) = resolve_request("CONNECT", "[::1]:443").unwrap();
        assert_eq!(host, "::1:443");
        assert!(path.is_none());
        assert!(resolve_request("CONNECT", "[::1]").is_err());
    }

    #[test]
    fn resolve_request_returns_origin_form() {
        for (target, expected_host, expected_path) in [
            ("http://example.com/path", "example.com:80", "/path"),
            ("https://example.com/path", "example.com:443", "/path"),
            (
                "http://example.com:8080/a/b?q=1&r=2",
                "example.com:8080",
                "/a/b?q=1&r=2",
            ),
            ("http://example.com/a#frag", "example.com:80", "/a"),
            ("http://example.com", "example.com:80", "/"),
        ] {
            let (host, path) = resolve_request("GET", target).unwrap();
            assert_eq!(host, expected_host, "{target}");
            assert_eq!(path.as_deref(), Some(expected_path), "{target}");
        }

        let (host, path) = resolve_request("CONNECT", "example.com:443").unwrap();
        assert_eq!(host, "example.com:443");
        assert!(path.is_none());
    }

    #[tokio::test]
    async fn parse_proxy_request_reports_auth() {
        use bytes::BytesMut;
        let expected = "Basic dXNlcjpwYXNz";
        let ok =
            b"GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
                [..]
                .to_vec();
        let mut buf = BytesMut::new();
        let mut reader = &ok[..];
        let req = parse_proxy_request(&mut reader, &mut buf, Some(expected))
            .await
            .unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "http://example.com/");
        assert!(req.authorized);
        assert_eq!(&buf[..req.header_len], &ok[..]);

        let bad = b"GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic AAA\r\n\r\n"[..]
            .to_vec();
        let mut buf = BytesMut::new();
        let mut reader = &bad[..];
        let req = parse_proxy_request(&mut reader, &mut buf, Some(expected))
            .await
            .unwrap();
        assert!(!req.authorized);

        let mut buf = BytesMut::new();
        let mut reader = &bad[..];
        let req = parse_proxy_request(&mut reader, &mut buf, None)
            .await
            .unwrap();
        assert!(req.authorized);
    }

    #[tokio::test]
    async fn parse_proxy_request_handles_split_reads() {
        use bytes::BytesMut;
        struct Choppy(Vec<u8>, usize);
        impl tokio::io::AsyncRead for Choppy {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let remaining = self.0.len() - self.1;
                let n = remaining.min(8).min(buf.remaining());
                let start = self.1;
                buf.put_slice(&self.0[start..start + n]);
                self.1 += n;
                std::task::Poll::Ready(Ok(()))
            }
        }

        let raw = b"GET http://example.com/very/long/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = Choppy(raw.to_vec(), 0);
        let mut buf = BytesMut::new();
        let req = parse_proxy_request(&mut reader, &mut buf, None)
            .await
            .unwrap();
        assert_eq!(req.target, "http://example.com/very/long/path");
        assert_eq!(&buf[..req.header_len], &raw[..]);
    }

    #[tokio::test]
    async fn proxy_header_limit_excludes_the_body() {
        let mut header = b"POST http://example.com/ HTTP/1.1\r\nX-Pad: ".to_vec();
        header.resize(MAX_HEADER_LEN - 4, b'x');
        header.extend_from_slice(b"\r\n\r\n");
        let mut buffered = BytesMut::from(&header[..]);
        buffered.extend_from_slice(&vec![0; MAX_HEADER_LEN]);
        let request = parse_proxy_request(&mut tokio::io::empty(), &mut buffered, None)
            .await
            .unwrap();
        assert_eq!(request.header_len, MAX_HEADER_LEN);

        header.insert(MAX_HEADER_LEN - 4, b'x');
        for prebuffered in [false, true] {
            let mut buffer = if prebuffered {
                BytesMut::from(&header[..])
            } else {
                BytesMut::new()
            };
            let mut reader = &header[..];
            let error = parse_proxy_request(&mut reader, &mut buffer, None)
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains("header too large"));
            if !prebuffered {
                assert_eq!(buffer.len(), MAX_HEADER_LEN);
            }
        }
    }

    #[test]
    fn strip_proxy_headers_drops_credentials() {
        let raw = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let new_len = strip_proxy_headers(&mut buf, raw.len());

        let head = String::from_utf8(buf[..new_len].to_vec()).unwrap();
        assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!head.to_ascii_lowercase().contains("proxy-connection"));
        assert!(head.contains("Host: example.com\r\n"));
        assert!(head.contains("Accept: */*\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert_eq!(new_len, buf.len());
    }

    #[test]
    fn strip_proxy_headers_keeps_body() {
        for body_len in [4, 8192] {
            let head = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic YQ==\r\nContent-Length: {body_len}\r\n\r\n"
            );
            let body = vec![b'x'; body_len];
            let mut buf = BytesMut::new();
            buf.extend_from_slice(head.as_bytes());
            buf.extend_from_slice(&body);
            let body_pointer = buf.as_ptr().wrapping_add(head.len());
            let new_len = strip_proxy_headers(&mut buf, head.len());
            assert!(
                !String::from_utf8_lossy(&buf[..new_len])
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
            assert_eq!(&buf[new_len..], &body);
            if body_len == 8192 {
                assert_eq!(buf.as_ptr().wrapping_add(new_len), body_pointer);
            }
        }
    }

    #[test]
    fn strip_proxy_headers_is_noop_without_them() {
        let raw = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let new_len = strip_proxy_headers(&mut buf, raw.len());
        assert_eq!(new_len, raw.len());
        assert_eq!(&buf[..], &raw[..]);
    }

    #[test]
    fn strip_proxy_headers_drops_folded_continuation() {
        let raw = b"GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic\r\n dXNlcjpwYXNz\r\nHost: x\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let new_len = strip_proxy_headers(&mut buf, raw.len());

        let head = String::from_utf8(buf[..new_len].to_vec()).unwrap();
        assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!head.contains("dXNlcjpwYXNz"));
        assert!(head.contains("Host: x\r\n"));
    }
}

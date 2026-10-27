use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, BytesMut};
use http::uri::Authority;
use tokio::io::AsyncReadExt;
use url::Url;

/// 头部解析上限，同时也是缓冲区允许增长的上限。
const MAX_HEADER_LEN: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// 每次读之前先保证有这么多空闲容量：`AsyncReadExt::read_buf` 在缓冲区剩余
/// 可变容量为 0 时会直接返回 0（看起来像对端关闭），必须提前 reserve。
const READ_RESERVE: usize = 4 * 1024;
/// `HTTP/1.1` 走的是 8 字节，留出余量给少见版本号，超出则直接拒绝。
const MAX_VERSION_LEN: usize = 16;

/// 解析完成的一个代理请求。
pub struct ProxyRequest {
    pub method: String,
    /// 请求头（含空行）在缓冲区中的长度。
    pub header_len: usize,
    /// CONNECT 的 authority，或普通请求的绝对 URI。
    pub target: String,
    /// 代理认证是否通过（未开启认证时恒为 true）。
    pub authorized: bool,
}

pub async fn parse_proxy_request(
    reader: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
    expected_auth: Option<&str>,
) -> Result<ProxyRequest> {
    loop {
        // 先解析已缓冲的数据：认证失败重试时下一个请求往往已经在缓冲区里，
        // 先读会白白阻塞到客户端再发一次。
        if let Some(request) = try_parse_head(buffer, expected_auth)? {
            return Ok(request);
        }
        if buffer.len() > MAX_HEADER_LEN {
            return Err(anyhow!("header too large"));
        }

        buffer.reserve(READ_RESERVE);
        if reader.read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
    }
}

/// 尝试解析已缓冲的请求头；数据还不完整时返回 `Ok(None)`。
fn try_parse_head(buffer: &BytesMut, expected_auth: Option<&str>) -> Result<Option<ProxyRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buffer)? {
        httparse::Status::Complete(amt) => {
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

/// 直接在字节层面比对 `Proxy-Authorization`，避免为每个请求分配一个 String。
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

/// 从绝对 URI 中提取 origin-form（`/path?query`）。
///
/// 请求行里的 fragment 按 RFC 7230 不应转发给上游，这里直接丢弃。
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

/// 解析一次请求目标，同时得到上游 `host:port` 和需要写回请求行的 origin-form。
///
/// 非 CONNECT 请求只做一次 `Url::parse`，避免“解析目标 + 重写请求行”各解析一遍。
pub fn resolve_request(method: &str, target: &str) -> Result<(String, Option<String>)> {
    if method == "CONNECT" {
        return Ok((resolve_connect_host(target)?, None));
    }
    let url = Url::parse(target).context("invalid proxy URL")?;
    let host = url.host_str().context("URL has no host")?;
    let port = url.port_or_known_default().context("port required")?;
    Ok((format!("{host}:{port}"), Some(origin_form(&url))))
}

#[inline]
pub fn resolve_target_host(method: &str, url_str: &str) -> Result<String> {
    resolve_request(method, url_str).map(|(host, _)| host)
}

/// 就地把请求行改写成 origin-form，不产生临时 `String`。
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

    // origin-form 一定是绝对 URI 的子串，所以新请求行不会比旧的长；
    // 此时把尾部整体前移即可，避免 split_off/unsplit 拷贝整个头部和 body。
    let new_line_len = method.len() + 1 + origin_path.len() + 1 + version.len() + 2;
    if new_line_len <= old_line_len {
        let total = buf.len();
        let delta = old_line_len - new_line_len;
        buf.copy_within(old_line_len..total, new_line_len);
        write_request_line(&mut buf[..new_line_len], method, origin_path, version);
        buf.truncate(total - delta);
        return Ok(());
    }

    // 兜底路径：URL 被规范化后变长时走原来的拼接方式
    let mut new_line = Vec::with_capacity(new_line_len);
    new_line.extend_from_slice(method.as_bytes());
    new_line.push(b' ');
    new_line.extend_from_slice(origin_path.as_bytes());
    new_line.push(b' ');
    new_line.extend_from_slice(version);
    new_line.extend_from_slice(b"\r\n");

    let rest = buf.split_off(old_line_len);
    buf.clear();
    buf.put_slice(&new_line);
    buf.unsplit(rest);

    Ok(())
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

pub fn rewrite_absolute_url(buf: &mut BytesMut, method: &str, url_str: &str) -> Result<()> {
    let Ok(url) = Url::parse(url_str) else {
        return Ok(());
    };
    let header_len = buf.len();
    rewrite_request_line(buf, header_len, method, &origin_form(&url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_connect_host() {
        let target = resolve_target_host("CONNECT", "example.com:443").unwrap();
        assert_eq!(target, "example.com:443");
    }

    #[test]
    fn resolve_http_url() {
        let target = resolve_target_host("GET", "http://example.com/path").unwrap();
        assert_eq!(target, "example.com:80");
    }

    #[test]
    fn resolve_https_url() {
        let target = resolve_target_host("GET", "https://example.com/path").unwrap();
        assert_eq!(target, "example.com:443");
    }

    #[test]
    fn resolve_connect_no_port_fails() {
        assert!(resolve_target_host("CONNECT", "example.com").is_err());
    }

    #[test]
    fn rewrite_absolute_to_origin() {
        let mut buf = BytesMut::from(
            &b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        );
        rewrite_absolute_url(&mut buf, "GET", "http://example.com/path").unwrap();
        let result = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            result.starts_with("GET /path HTTP/1.1\r\n"),
            "got: {result}"
        );
        assert!(result.contains("Host: example.com"));
    }

    #[test]
    fn rewrite_with_query_string() {
        let mut buf = BytesMut::from(
            &b"GET http://example.com/search?q=rust&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n"
                [..],
        );
        rewrite_absolute_url(&mut buf, "GET", "http://example.com/search?q=rust&lang=en").unwrap();
        let result = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            result.starts_with("GET /search?q=rust&lang=en HTTP/1.1\r\n"),
            "got: {result}"
        );
    }

    #[test]
    fn rewrite_root_path() {
        let mut buf =
            BytesMut::from(&b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"[..]);
        rewrite_absolute_url(&mut buf, "GET", "http://example.com/").unwrap();
        let result = String::from_utf8(buf.to_vec()).unwrap();
        assert!(result.starts_with("GET / HTTP/1.1\r\n"), "got: {result}");
    }

    #[test]
    fn rewrite_strips_port() {
        let mut buf = BytesMut::from(
            &b"GET http://example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"[..],
        );
        rewrite_absolute_url(&mut buf, "GET", "http://example.com:8080/path").unwrap();
        let result = String::from_utf8(buf.to_vec()).unwrap();
        assert!(
            result.starts_with("GET /path HTTP/1.1\r\n"),
            "got: {result}"
        );
        assert!(result.contains("Host: example.com:8080"));
    }

    #[test]
    fn rewrite_already_origin_form_noop() {
        let original = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut buf = BytesMut::from(&original[..]);
        rewrite_absolute_url(&mut buf, "GET", "/path").unwrap();
        assert_eq!(&buf[..], &original[..]);
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
        rewrite_absolute_url(&mut buf, "POST", "http://example.com/api").unwrap();
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
    fn resolve_connect_ipv6_brackets_stripped() {
        let t = resolve_target_host("CONNECT", "[::1]:443").unwrap();
        assert_eq!(t, "::1:443");
        assert!(resolve_target_host("CONNECT", "[::1]").is_err());
    }

    #[test]
    fn resolve_request_returns_origin_form() {
        let (host, path) = resolve_request("GET", "http://example.com:8080/a/b?q=1&r=2").unwrap();
        assert_eq!(host, "example.com:8080");
        assert_eq!(path.as_deref(), Some("/a/b?q=1&r=2"));

        let (host, path) = resolve_request("CONNECT", "example.com:443").unwrap();
        assert_eq!(host, "example.com:443");
        assert!(path.is_none());
    }

    #[test]
    fn resolve_request_drops_fragment() {
        let (_, path) = resolve_request("GET", "http://example.com/a#frag").unwrap();
        assert_eq!(path.as_deref(), Some("/a"));
    }

    #[test]
    fn resolve_request_defaults_empty_path_to_slash() {
        let (_, path) = resolve_request("GET", "http://example.com").unwrap();
        assert_eq!(path.as_deref(), Some("/"));
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

        // 未开启认证时不需要头
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
        // 一次只吐 8 字节的读取器，模拟头部跨多次 read 到达
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
}

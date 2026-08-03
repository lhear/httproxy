use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use http::uri::Authority;
use tokio::io::AsyncReadExt;
use url::Url;

pub async fn parse_proxy_request(
    reader: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
    need_proxy_auth: bool,
) -> Result<(String, usize, String, Option<String>)> {
    const MAX_HEADER_LEN: usize = 16 * 1024;

    loop {
        if reader.read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(amt) = req.parse(buffer)? {
            let proxy_auth = if need_proxy_auth {
                extract_header(req.headers, "proxy-authorization")
            } else {
                None
            };
            return Ok((
                req.method.context("no method")?.to_owned(),
                amt,
                req.path.context("no path")?.to_owned(),
                proxy_auth,
            ));
        }
        if buffer.len() > MAX_HEADER_LEN {
            return Err(anyhow!("header too large"));
        }
    }
}

fn extract_header(headers: &[httparse::Header<'_>], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| String::from_utf8_lossy(h.value).into_owned())
}

#[inline]
pub fn resolve_target_host(method: &str, url_str: &str) -> Result<String> {
    if method == "CONNECT" {
        let auth: Authority = url_str
            .parse()
            .map_err(|_| anyhow!("invalid target: {url_str}"))?;
        let port = auth
            .port_u16()
            .ok_or_else(|| anyhow!("port required: {url_str}"))?;
        let host = auth.host();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        return Ok(format!("{host}:{port}"));
    }

    let url = Url::parse(url_str).context("invalid proxy URL")?;
    let host = url.host_str().context("URL has no host")?;
    let port = url.port_or_known_default().context("port required")?;
    Ok(format!("{host}:{port}"))
}

pub fn rewrite_absolute_url(buf: &mut BytesMut, method: &str, url_str: &str) -> Result<()> {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let origin_path = {
        let mut s = String::new();
        s.push_str(parsed.path());
        if let Some(q) = parsed.query() {
            s.push('?');
            s.push_str(q);
        }
        if let Some(f) = parsed.fragment() {
            s.push('#');
            s.push_str(f);
        }
        s
    };

    let line_end = buf
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| anyhow!("request line has no newline"))?;
    let old_line_len = line_end + 1;

    let first_line = std::str::from_utf8(&buf[..line_end])
        .map_err(|_| anyhow!("request line is not valid UTF-8"))?;
    let first_line_trimmed = first_line.trim_end_matches('\r');
    let version = first_line_trimmed
        .rsplit_once(' ')
        .map(|(_, v)| v)
        .ok_or_else(|| anyhow!("malformed request line: {first_line_trimmed}"))?;

    let new_first_line = format!("{method} {origin_path} {version}\r\n");
    let new_line_bytes = new_first_line.as_bytes();

    let rest = buf.split_off(old_line_len);
    buf.clear();
    buf.extend_from_slice(new_line_bytes);
    buf.unsplit(rest);

    Ok(())
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
}

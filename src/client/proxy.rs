use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use http::uri::Authority;
use tokio::io::AsyncReadExt;
use url::Url;

pub async fn parse_proxy_request(
    reader: &mut (impl AsyncReadExt + Unpin),
    buffer: &mut BytesMut,
) -> Result<(String, usize, String, Option<String>)> {
    const MAX_HEADER_LEN: usize = 16 * 1024;

    loop {
        if reader.read_buf(buffer).await? == 0 {
            return Err(anyhow!("connection closed during header parsing"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(amt) = req.parse(buffer)? {
            let proxy_auth = extract_header(req.headers, "proxy-authorization");
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
        return Ok(format!("{}:{port}", auth.host()));
    }

    let url = Url::parse(url_str).context("invalid proxy URL")?;
    let host = url.host_str().context("URL has no host")?;
    let port = url.port_or_known_default().context("port required")?;
    Ok(format!("{host}:{port}"))
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
}

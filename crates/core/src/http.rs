use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

static ROOT_CERT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub async fn request(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<Response> {
    let (host, path) = split_url(url)?;
    tokio::time::timeout(REQUEST_TIMEOUT, send(method, &host, &path, headers, body))
        .await
        .context("https request timed out")?
}

async fn send(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<Response> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, 443)))
        .await
        .with_context(|| format!("cannot reach {host}"))?
        .with_context(|| format!("cannot reach {host}"))?;
    stream.set_nodelay(true).ok();

    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow!("invalid server name: {host}"))?;
    let connector = TlsConnector::from(client_config());
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("tls handshake with {host} failed"))?;

    let mut head = String::with_capacity(256);
    let _ = write!(
        head,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .await
        .context("cannot write request head")?;
    stream
        .write_all(body)
        .await
        .context("cannot write request body")?;
    stream.flush().await.context("cannot flush request")?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .context("cannot read response")?;
    parse(&raw)
}

fn split_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https is supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let host = authority
        .split(':')
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow!("url holds no host: {url}"))?;
    Ok((host.to_owned(), path.to_owned()))
}

fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = ROOT_CERT_STORE.get_or_init(|| {
            Arc::new(RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        });
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(Arc::clone(roots))
                .with_no_client_auth(),
        )
    }))
}

fn parse(raw: &[u8]) -> Result<Response> {
    let split = memchr::memmem::find(raw, b"\r\n\r\n")
        .ok_or_else(|| anyhow!("response holds no header terminator"))?;
    let head = &raw[..split + 2];
    let body = &raw[split + 4..];

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(head).context("cannot parse response head")?;
    let status = response
        .code
        .ok_or_else(|| anyhow!("response holds no status"))?;

    let chunked = response.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && String::from_utf8_lossy(header.value)
                .to_ascii_lowercase()
                .contains("chunked")
    });
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };

    Ok(Response { status, body })
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    loop {
        let line_end =
            memchr::memmem::find(rest, b"\r\n").ok_or_else(|| anyhow!("truncated chunk size"))?;
        let line = std::str::from_utf8(&rest[..line_end]).context("invalid chunk size")?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .context("invalid chunk size")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            bail!("truncated chunk body");
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

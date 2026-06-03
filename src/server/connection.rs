use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use crate::dns::DnsClient;

pub async fn connect_upstream(
    dns_client: Option<&Arc<DnsClient>>,
    client_subnet: Option<IpAddr>,
    socks5_proxy: Option<&Arc<str>>,
    host: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    let upstream = if let Some(client) = dns_client {
        client
            .connect(
                host,
                port,
                client_subnet,
                socks5_proxy.map(|s| s.to_string()),
            )
            .await
            .map_err(|e| anyhow::anyhow!("dns error: {e}"))?
    } else {
        match socks5_proxy {
            Some(p) => Socks5Stream::connect(p.as_ref(), (host, port))
                .await
                .map(Socks5Stream::into_inner)
                .map_err(|e| anyhow::anyhow!("socks5 connect: {e}"))?,
            None => TcpStream::connect((host, port))
                .await
                .map_err(|e| anyhow::anyhow!("tcp connect: {e}"))?,
        }
    };
    upstream.set_nodelay(true)?;
    Ok(upstream)
}

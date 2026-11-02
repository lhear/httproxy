use std::net::IpAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use crate::dns::DnsClient;
use crate::server::upstream::Upstream;

/// 建立到 `host:port` 的上游连接。
///
/// 域名交给 DNS 模块解析，再由 Happy Eyeballs 逐个尝试；配置了 `[proxy] socks5`
/// 时经代理连。返回值统一成 [`Upstream`]，让隧道 actor 不必关心上游是 TCP 还是
/// 别的传输。
pub(crate) async fn connect_upstream(
    dns_client: Option<&Arc<DnsClient>>,
    client_subnet: Option<IpAddr>,
    socks5_proxy: Option<&Arc<str>>,
    host: &str,
    port: u16,
) -> anyhow::Result<Upstream> {
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
    Ok(Upstream::Direct(upstream))
}

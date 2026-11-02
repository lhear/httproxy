use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tracing::debug;

use crate::dns::DnsClient;
use crate::server::upstream::Upstream;
use crate::warp::WarpClient;

/// 一个域名最多尝试几个解析结果，避免在黑洞地址上耗掉整个连接超时。
const MAX_ADDRESS_ATTEMPTS: usize = 4;

/// 建立到 `host:port` 的上游连接。
///
/// 启用 WARP 后，域名**必须先由 DNS 模块解析成 IP 再交给 WARP**：CONNECT 的
/// `:authority` 始终是 IP 字面量，Cloudflare 侧不参与域名解析。解析结果里属于
/// 私网的地址（以及命中 `bypass_suffixes` 的域名）仍然直连。没开 WARP 时保持
/// 原有路径：DNS 模块解析 + Happy Eyeballs / SOCKS5 / 直连。
pub(crate) async fn connect_upstream(
    warp: Option<&Arc<WarpClient>>,
    dns_client: Option<&Arc<DnsClient>>,
    client_subnet: Option<IpAddr>,
    socks5_proxy: Option<&Arc<str>>,
    host: &str,
    port: u16,
) -> anyhow::Result<Upstream> {
    let Some(warp) = warp else {
        let upstream = connect_direct(dns_client, client_subnet, socks5_proxy, host, port).await?;
        return Ok(Upstream::Direct(upstream));
    };

    let addresses = resolve_target(dns_client, client_subnet, host).await?;
    let force_direct = warp.is_direct_name(host);

    let mut last_error = None;
    for ip in addresses.into_iter().take(MAX_ADDRESS_ATTEMPTS) {
        let attempt = if force_direct || warp.is_direct_ip(ip) {
            connect_ip(socks5_proxy, ip, port).await.map(Upstream::Direct)
        } else {
            warp.dial(ip, port).await.map(Upstream::Warp)
        };
        match attempt {
            Ok(upstream) => return Ok(upstream),
            Err(e) => {
                debug!(addr = %ip, port, error = %e, "upstream connect failed");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no address to connect for {host}")))
}

/// 把目标解析成 IP：IP 字面量直接用，域名交给 DNS 模块。
async fn resolve_target(
    dns_client: Option<&Arc<DnsClient>>,
    client_subnet: Option<IpAddr>,
    host: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    if let Ok(ip) = IpAddr::from_str(host) {
        return Ok(vec![ip]);
    }
    // localhost 不需要（也不该）去问上游
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(vec![
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]);
    }
    let Some(dns) = dns_client else {
        anyhow::bail!("warp: `{host}` needs a DNS resolver but none is configured");
    };
    dns.resolve(host, client_subnet).await
}

/// 直连一个已经解析好的地址（必要时经 SOCKS5）。
async fn connect_ip(
    socks5_proxy: Option<&Arc<str>>,
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    let stream = match socks5_proxy {
        Some(proxy) => Socks5Stream::connect(proxy.as_ref(), addr)
            .await
            .map(Socks5Stream::into_inner)
            .map_err(|e| anyhow::anyhow!("socks5 connect: {e}"))?,
        None => TcpStream::connect(addr)
            .await
            .map_err(|e| anyhow::anyhow!("tcp connect: {e}"))?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// 没有 WARP 时的老路径：DNS 模块解析 + Happy Eyeballs（或 SOCKS5 / 直连）。
async fn connect_direct(
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

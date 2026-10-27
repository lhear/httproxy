//! `[[redirect]]`：本地端口转发。
//!
//! 监听一个本地端口，把进来的原始 TCP 字节直接送进隧道，等价于 `ssh -L`。
//! 与 HTTP 代理入站的区别只有一点：这里不做任何协议解析，连上来就建隧道。

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{Instrument, debug, info, warn};

use crate::client::connection::open_tunnel;
use crate::client::state::SharedState;
use crate::config::RedirectSection;

/// accept 出现非瞬态错误（如 fd 耗尽）后的退避，避免 CPU 空转。
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// 校验通过的一条转发规则。
#[derive(Clone, Debug)]
pub struct RedirectRule {
    pub listen: SocketAddr,
    /// 上游 `host:port`，原样作为隧道的目标地址
    pub target: String,
}

impl RedirectRule {
    pub fn parse(section: &RedirectSection) -> Result<Self> {
        let listen: SocketAddr = section
            .listen
            .parse()
            .with_context(|| format!("invalid [[redirect]] listen address: {}", section.listen))?;
        let target = section.target.trim();
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("[[redirect]] target must be host:port, got: {target}"))?;
        if host.is_empty() {
            return Err(anyhow!("[[redirect]] target has an empty host: {target}"));
        }
        port.parse::<u16>()
            .with_context(|| format!("invalid [[redirect]] target port: {target}"))?;
        Ok(Self {
            listen,
            target: target.to_owned(),
        })
    }

    pub fn parse_all(sections: &[RedirectSection]) -> Result<Vec<Self>> {
        let mut rules = Vec::with_capacity(sections.len());
        for section in sections {
            let rule = Self::parse(section)?;
            if rules.iter().any(|r: &Self| r.listen == rule.listen) {
                return Err(anyhow!(
                    "duplicate [[redirect]] listen address: {}",
                    rule.listen
                ));
            }
            rules.push(rule);
        }
        Ok(rules)
    }
}

/// 绑定端口并开始接受连接，返回实际绑定的地址
/// （`listen` 写成 `127.0.0.1:0` 时方便拿到系统分配的端口）。
pub async fn spawn(
    rule: RedirectRule,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
    conn_sem: Arc<Semaphore>,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(rule.listen)
        .await
        .with_context(|| format!("[[redirect]] bind {} failed", rule.listen))?;
    let local = listener.local_addr()?;
    info!(listen = %local, target = %rule.target, "redirect listening");

    tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                    ) {
                        debug!(reason = %e, "redirect accept interrupted, retrying");
                    } else {
                        warn!(reason = %e, "redirect accept failed, backing off");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                    continue;
                }
            };

            // 与 HTTP 代理入站共享同一个连接数上限
            let permit = match Arc::clone(&conn_sem).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    debug!(
                        client = %peer,
                        target = %rule.target,
                        "redirect connection rejected: admission limit reached"
                    );
                    continue;
                }
            };

            let target = rule.target.clone();
            let http_client = Arc::clone(&http_client);
            let state = Arc::clone(&state);
            tokio::spawn(
                async move {
                    let _permit = permit;
                    if let Err(e) = serve(socket, &target, http_client, state).await
                        && !crate::client::utils::is_silent_error(e.root_cause())
                    {
                        warn!(reason = %e, "redirect connection aborted");
                    }
                }
                .instrument(tracing::info_span!(
                    "redirect",
                    client = %peer,
                    target = %rule.target
                )),
            );
        }
    });

    Ok(local)
}

async fn serve(
    socket: TcpStream,
    target: &str,
    http_client: Arc<wreq::Client>,
    state: Arc<SharedState>,
) -> Result<()> {
    socket.set_nodelay(true).ok();
    let (read_half, write_half) = socket.into_split();
    info!(target = %target, "redirect connection accepted");
    // 没有首包：连接建立后隧道两端各自等数据
    open_tunnel(
        read_half,
        write_half,
        http_client,
        state,
        Bytes::new(),
        target,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(listen: &str, target: &str) -> RedirectSection {
        RedirectSection {
            listen: listen.to_string(),
            target: target.to_string(),
        }
    }

    #[test]
    fn parse_accepts_valid_rule() {
        let rule = RedirectRule::parse(&section("127.0.0.1:2222", "172.16.0.207:22")).unwrap();
        assert_eq!(rule.listen, "127.0.0.1:2222".parse().unwrap());
        assert_eq!(rule.target, "172.16.0.207:22");
    }

    #[test]
    fn parse_accepts_hostname_target() {
        let rule = RedirectRule::parse(&section("127.0.0.1:0", " example.com:443 ")).unwrap();
        assert_eq!(rule.target, "example.com:443");
    }

    #[test]
    fn parse_rejects_bad_listen() {
        assert!(RedirectRule::parse(&section("127.0.0.1", "example.com:443")).is_err());
        assert!(RedirectRule::parse(&section("not-an-addr", "example.com:443")).is_err());
    }

    #[test]
    fn parse_rejects_bad_target() {
        assert!(RedirectRule::parse(&section("127.0.0.1:0", "example.com")).is_err());
        assert!(RedirectRule::parse(&section("127.0.0.1:0", ":443")).is_err());
        assert!(RedirectRule::parse(&section("127.0.0.1:0", "example.com:70000")).is_err());
    }

    #[test]
    fn parse_all_rejects_duplicate_listen() {
        let rules = vec![
            section("127.0.0.1:2222", "a:1"),
            section("127.0.0.1:2222", "b:2"),
        ];
        assert!(RedirectRule::parse_all(&rules).is_err());
    }
}

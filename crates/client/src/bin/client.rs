use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{Instrument, debug, error_span, info, warn};

static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,

    #[arg(
        long,
        value_name = "PATH",
        help = "Trust the given PEM certificate or CA bundle instead of the built-in Mozilla roots"
    )]
    trusted_cert: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_str = fs::read_to_string(&cli.config)?;
    let config: httproxy_core::config::ClientTopConfig = toml::from_str(&config_str)?;

    let _guard = httproxy_core::log::init_tracing(&config.log.clone().unwrap_or_default());

    let state = httproxy_client::build_state(&config)?;

    let addr: std::net::SocketAddr = config.client.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;

    let http_client = httproxy_client::build_http_client(&config, cli.trusted_cert.as_deref())?;

    info!(listen = %addr, "proxy listening");

    let conn_sem = Arc::new(Semaphore::new(state.max_connections));

    for rule in httproxy_client::redirect::RedirectRule::parse_all(&config.redirect)? {
        httproxy_client::redirect::spawn(
            rule,
            Arc::clone(&http_client),
            Arc::clone(&state),
            Arc::clone(&conn_sem),
        )
        .await?;
    }

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
                    debug!(reason = %e, "accept interrupted, retrying");
                } else {
                    warn!(reason = %e, "accept failed, backing off");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
                continue;
            }
        };

        let permit = match conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(
                    client = %peer,
                    max_connections = state.max_connections,
                    "connection rejected: admission limit reached"
                );
                continue;
            }
        };

        let http_client = Arc::clone(&http_client);
        let state = Arc::clone(&state);

        let span_id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(
            async move {
                let _permit = permit;
                if let Err(e) =
                    httproxy_client::connection::handle_connection_actor(socket, http_client, state)
                        .await
                    && !httproxy_client::utils::is_silent_error(e.root_cause())
                {
                    warn!(reason = %e, "connection aborted");
                }
            }
            .instrument(error_span!(
                "session",
                id = span_id,
                client = %peer,
                target = tracing::field::Empty,
            )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_cert_flag_is_parsed() {
        let cli = Cli::try_parse_from(["client", "--trusted-cert", "cert.pem"]).unwrap();
        assert_eq!(
            cli.trusted_cert.as_deref(),
            Some(std::path::Path::new("cert.pem"))
        );
    }

    #[test]
    fn trusted_cert_flag_is_optional() {
        let cli = Cli::try_parse_from(["client"]).unwrap();
        assert!(cli.trusted_cert.is_none());
    }
}

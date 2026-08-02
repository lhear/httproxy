use anyhow::Context;
use clap::Parser;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{Instrument, debug, error_span, info, warn};

static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_str = fs::read_to_string(&cli.config)?;
    let config: httproxy::config::ClientTopConfig = toml::from_str(&config_str)?;

    let _guard = httproxy::log::init_tracing(&config.log.clone().unwrap_or_default());

    let state = httproxy::client::build_state(&config)?;

    let addr: std::net::SocketAddr = config.client.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;

    let remote_url: url::Url = state.remote_str.parse()?;
    let domain = remote_url.host_str().context("No domain in remote URL")?;
    let final_addr = config
        .client
        .address
        .clone()
        .unwrap_or_else(|| domain.to_string());

    let http_client = Arc::new(
        wreq::Client::builder()
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(45))
            .tcp_keepalive_interval(Duration::from_secs(45))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(6)
            .emulation(wreq_util::Emulation::Chrome143)
            .no_proxy()
            .dns_resolver(Arc::new(httproxy::client::state::ManualResolver {
                target_addr: final_addr,
            }))
            .build()?,
    );

    info!(listen = %addr, "proxy listening");

    let conn_sem = Arc::new(Semaphore::new(state.max_connections));

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(reason = %e, "accept failed");
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
                if let Err(e) = httproxy::client::connection::handle_connection_actor(
                    socket,
                    http_client,
                    state,
                )
                .await
                    && !httproxy::client::utils::is_silent_error(e.root_cause())
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

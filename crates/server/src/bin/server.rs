use clap::Parser;
use std::fs;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    #[command(about = "Generate a tunnel token")]
    GenToken {
        #[arg(short, long, help = "Secret key for signing")]
        secret: String,
        #[arg(short, long, help = "Username or Subject")]
        user: String,
        #[arg(short, long, help = "Expiration timestamp (Unix)")]
        exp: u64,
    },
    #[command(about = "Generate an X25519 keypair")]
    GenKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::GenToken { secret, user, exp } => {
                let token = httproxy_server::token::issue(
                    &httproxy_server::token::key_from_secret(secret.as_bytes()),
                    &httproxy_server::Claims { sub: user, exp },
                );
                println!("{token}");
                return Ok(());
            }
            Commands::GenKey => {
                let (sk, pk) = httproxy_core::crypto::generate_keypair();
                println!(
                    "private_key = \"{}\"",
                    httproxy_core::crypto::private_key_to_b64(&sk)
                );
                println!(
                    "public_key = \"{}\"",
                    httproxy_core::crypto::public_key_to_b64(&pk)
                );
                return Ok(());
            }
        }
    }

    let mut config_str = fs::read_to_string(&cli.config)?;
    let mut config: httproxy_core::config::ServerTopConfig = toml::from_str(&config_str)?;
    config_str.zeroize();

    let _guard =
        httproxy_core::log::init_tracing(&config.log.as_ref().cloned().unwrap_or_default());

    let state = httproxy_server::build_state(&mut config).await?;

    let (_master_jh, _stream_jh) = httproxy_server::spawn_janitors(&state);

    let router = httproxy_server::build_router(state, &config.server.path);
    httproxy_server::run_server(router, &config.server.listen).await?;
    Ok(())
}

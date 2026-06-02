use clap::Parser;
use std::fs;

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
    #[command(about = "Generate a JWT token")]
    GenToken {
        #[arg(short, long, help = "Secret key for signing")]
        secret: String,
        #[arg(short, long, help = "Username or Subject")]
        user: String,
        #[arg(short, long, help = "Expiration timestamp (Unix)")]
        exp: u64,
    },
    #[command(about = "Generate an x25519 keypair")]
    GenKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::GenToken { secret, user, exp } => {
                let token = jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    &httproxy::server::Claims { sub: user, exp },
                    &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
                )?;
                println!("{token}");
                return Ok(());
            }
            Commands::GenKey => {
                let (sk, pk) = httproxy::crypto::generate_keypair();
                println!(
                    "private_key = \"{}\"",
                    httproxy::crypto::private_key_to_b64(&sk)
                );
                println!(
                    "public_key = \"{}\"",
                    httproxy::crypto::public_key_to_b64(&pk)
                );
                return Ok(());
            }
        }
    }

    let config_str = fs::read_to_string(&cli.config)?;
    let mut config: httproxy::config::ServerTopConfig = toml::from_str(&config_str)?;

    let _guard = httproxy::log::init_tracing(&config.log.as_ref().cloned().unwrap_or_default());

    let state = httproxy::server::build_state(&mut config).await?;

    let (_master_jh, _stream_jh) = httproxy::server::spawn_janitors(&state);

    let router = httproxy::server::build_router(state, &config.server.path);
    httproxy::server::run_server(router, &config.server.listen).await?;
    Ok(())
}

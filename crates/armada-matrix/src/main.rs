mod bridge;
mod config;
mod db;
mod keys;
mod matrix;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nostr::nips::nip19::ToBech32;
use tokio::sync::mpsc;

use config::{Config, Registration};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the bridge (the default).
    Run,
    /// Write the appservice registration for the homeserver.
    GenerateRegistration {
        /// Overwrite an existing registration (new tokens).
        #[arg(long)]
        force: bool,
    },
    /// Print the bridge's Armada identity.
    Whoami,
}

fn bot_keys(config: &Config, keys: &keys::KeyRing) -> Result<nostr::prelude::Keys> {
    match &config.bridge.nostr_key {
        Some(k) => keys::parse_secret(k),
        None => Ok(keys.default_bot()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| config.logging.filter.clone().into())).init();
    let keyring = keys::KeyRing::new(config.master_secret());

    match cli.command.unwrap_or(Cmd::Run) {
        Cmd::GenerateRegistration { force } => {
            let path = &config.appservice.registration;
            if path.exists() && !force {
                anyhow::bail!("{} exists; pass --force to replace it (the homeserver must then be given the new file)", path.display());
            }
            std::fs::write(path, Registration::generate(&config))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("Wrote {}. Add it to your homeserver's app_service_config_files and restart it.", path.display());
            Ok(())
        }
        Cmd::Whoami => {
            println!("{}", bot_keys(&config, &keyring)?.public_key().to_bech32()?);
            Ok(())
        }
        Cmd::Run => run(config, keyring).await,
    }
}

async fn run(config: Config, keyring: keys::KeyRing) -> Result<()> {
    let registration = Registration::load(&config.appservice.registration)?;
    let bot = bot_keys(&config, &keyring)?;
    let db = db::Db::connect(&config.database.url, config.database.max_connections, keyring.clone()).await.context("connecting to Postgres")?;
    let mx = matrix::Client::new(&config.homeserver.url, &registration.as_token);
    let (pool, pool_rx) = relay_pool::Pool::new(bot.clone());
    let bind = config.appservice.bind.clone();
    let b = bridge::Bridge::new(config, keyring, bot, db, mx, pool);
    tracing::info!(npub = %b.bot_npub(), mxid = %b.bot_mxid, "starting");

    let (txn_tx, txn_rx) = mpsc::channel(64);
    let ns = b.clone();
    let app = matrix::appservice::router(&registration.hs_token, txn_tx, move |mxid| ns.in_namespace(mxid));
    let listener = tokio::net::TcpListener::bind(&bind).await.with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "appservice listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "appservice server stopped");
        }
    });

    if let Err(e) = b.mx.ping(&registration.id).await {
        tracing::warn!(error = %e, "the homeserver couldn't reach the appservice (check `url` in the registration)");
    }
    b.start().await?;
    tokio::spawn(b.clone().run_nostr(pool_rx));
    tokio::spawn(b.clone().run_ticks());
    tokio::select! {
        _ = b.clone().run_matrix(txn_rx) => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}

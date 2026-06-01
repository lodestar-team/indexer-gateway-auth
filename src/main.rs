//! `indexer-gateway-auth` binary entrypoint.
//!
//! Loads configuration, assembles the authn → authz → audit → proxy pipeline,
//! and serves it. TLS, rate limiting, and the Prometheus metrics endpoint are
//! layered on in later slices.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use iga::audit::AuditSink;
use iga::auth::Authenticator;
use iga::config::Config;
use iga::proxy::Proxy;
use iga::server::{build_router, AppOptions, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = parse_config_path();
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    // Install the Prometheus recorder before any metric is recorded, then serve
    // it on the dedicated metrics address.
    let metrics_handle = iga::metrics::install_recorder()?;
    let metrics_addr = config.metrics;
    tokio::spawn(async move {
        if let Err(e) = iga::metrics::serve(metrics_addr, metrics_handle).await {
            tracing::error!(error = %e, "metrics server stopped");
        }
    });

    let authenticator = Authenticator::from_config(&config.auth)
        .map_err(|e| anyhow::anyhow!("authenticator: {e}"))?;

    let client = reqwest::Client::builder()
        .build()
        .context("building upstream HTTP client")?;
    let proxy = Proxy::new(client, &config.upstream);

    let audit = AuditSink::Stdout;
    let state = AppState::new(&config, authenticator, proxy, audit, AppOptions::default());
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding listener on {}", config.listen))?;
    tracing::info!(listen = %config.listen, "indexer-gateway-auth listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    Ok(())
}

/// Parse `--config <path>` (default `config.toml`).
fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("config.toml")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

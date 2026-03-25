//! veto-server: long-lived daemon listening on Unix domain socket.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tracing::info;
use veto::audit::AuditLog;
use veto::cedar_runtime::CedarRuntime;
use veto::config::Config;
use veto::server;
use veto::watcher;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env();

    // Validate policy directory
    if !config.policy_dir.is_dir() {
        anyhow::bail!(
            "Policy directory not found: {}\n\
             Set VETO_POLICY_DIR or run from the veto project root",
            config.policy_dir.display()
        );
    }

    // Ensure socket directory exists
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create socket dir {}", parent.display()))?;
    }

    // Remove stale socket
    let _ = std::fs::remove_file(&config.socket_path);

    let cedar = Arc::new(
        CedarRuntime::load(&config.policy_dir).context("load Cedar policies")?,
    );
    info!(
        policies = cedar.policy_count(),
        dir = %config.policy_dir.display(),
        "Cedar runtime loaded"
    );

    // Start file watcher for hot-reload
    let _watcher_handle = watcher::spawn_watcher(&config.policy_dir, Arc::clone(&cedar))
        .context("start policy watcher")?;

    let audit = AuditLog::open(&config.db_path).context("open audit log")?;
    info!(path = %config.db_path.display(), "Audit log opened");

    let listener = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("bind {}", config.socket_path.display()))?;
    info!(socket = %config.socket_path.display(), "Listening");

    // Shutdown via Ctrl+C
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let socket_path = config.socket_path.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("Received shutdown signal");
        let _ = shutdown_tx.send(());
    });

    server::run_accept_loop(listener, cedar, audit, shutdown_rx).await;

    let _ = std::fs::remove_file(&socket_path);
    info!("Cleaned up socket, exiting");

    Ok(())
}

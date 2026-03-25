//! veto-server: long-lived daemon listening on Unix domain socket.

use anyhow::{Context, Result};
use serde_json::json;
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{error, info};
use veto::adapters::claude::response as claude_response;
use veto::adjudicate;
use veto::audit::AuditLog;
use veto::cedar_runtime::CedarRuntime;
use veto::config::Config;
use veto::hook::HookKind;
use veto::ipc::{self, AdjudicateOk, AdjudicateRequest};
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

    loop {
        let (stream, _) = listener.accept().await?;
        let (mut reader, mut writer) = stream.into_split();

        // Read request frame
        let frame = match ipc::read_frame_async(&mut reader).await {
            Ok(f) => f,
            Err(e) => {
                error!(error = %e, "failed to read frame");
                continue;
            }
        };

        let request: AdjudicateRequest = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let resp = AdjudicateOk::failure(format!("invalid JSON: {e}"));
                let body = serde_json::to_vec(&resp).unwrap_or_default();
                let _ = ipc::write_frame_async(&mut writer, &body).await;
                continue;
            }
        };

        let response = match request.hook.as_str() {
            "ping" => AdjudicateOk::pong(),
            "reload" => match cedar.reload() {
                Ok(count) => {
                    info!(policies = count, "Policies reloaded");
                    AdjudicateOk::data(json!({"reloaded": true, "policy_count": count}))
                }
                Err(e) => AdjudicateOk::failure(format!("reload failed: {e}")),
            },
            "status" => AdjudicateOk::data(json!({
                "status": "ok",
                "policy_count": cedar.policy_count(),
                "event_count": audit.event_count().unwrap_or(-1),
            })),
            hook_type => {
                let kind = HookKind::from_hook_str(hook_type);
                let tool_name = request
                    .payload
                    .get("tool_name")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string());

                match adjudicate::adjudicate(&kind, &request.payload, &cedar) {
                    Ok((verdict, sig)) => {
                        let categories: Vec<&str> =
                            sig.categories.iter().map(|s| s.as_str()).collect();

                        // Log to audit
                        let cats_str = categories.join(",");
                        let sev_str = sig.severity.to_string();
                        let _ = audit.log_event(
                            hook_type,
                            tool_name.as_deref(),
                            verdict.reason(),
                            verdict.as_str(),
                            None,
                            if categories.is_empty() {
                                None
                            } else {
                                Some(&cats_str)
                            },
                            Some(&sev_str),
                        );

                        let hook_response = claude_response::encode(&verdict, hook_type);
                        AdjudicateOk::success(hook_response)
                    }
                    Err(e) => {
                        error!(error = %e, "adjudication failed");
                        AdjudicateOk::failure(format!("adjudication error: {e}"))
                    }
                }
            }
        };

        let body = serde_json::to_vec(&response).unwrap_or_default();
        if let Err(e) = ipc::write_frame_async(&mut writer, &body).await {
            error!(error = %e, "failed to write response");
        }
    }
}

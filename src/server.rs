//! Server request handling and socket accept loop.
//!
//! Extracted from bin/server.rs so integration/e2e tests can spin up
//! an in-process server with a real Unix socket.

use crate::adapters::claude::response as claude_response;
use crate::adjudicate;
use crate::audit::AuditLog;
use crate::cedar_runtime::CedarRuntime;
use crate::hook::HookKind;
use crate::ipc::{self, AdjudicateOk, AdjudicateRequest};
use serde_json::json;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tracing::{error, info};

/// Handle a single parsed request. Pure logic — no I/O.
pub fn handle_request(
    request: &AdjudicateRequest,
    cedar: &CedarRuntime,
    audit: &AuditLog,
) -> AdjudicateOk {
    match request.hook.as_str() {
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

            match adjudicate::adjudicate(&kind, &request.payload, cedar) {
                Ok((verdict, sig)) => {
                    let categories: Vec<&str> =
                        sig.categories.iter().map(|s| s.as_str()).collect();
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
    }
}

/// Run the server accept loop until the shutdown signal fires.
///
/// `shutdown_rx` — when a value is received (or the sender is dropped), the loop exits.
pub async fn run_accept_loop(
    listener: UnixListener,
    cedar: Arc<CedarRuntime>,
    audit: AuditLog,
    mut shutdown_rx: watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "accept failed");
                        continue;
                    }
                };
                let (mut reader, mut writer) = stream.into_split();

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

                let response = handle_request(&request, &cedar, &audit);
                let body = serde_json::to_vec(&response).unwrap_or_default();
                if let Err(e) = ipc::write_frame_async(&mut writer, &body).await {
                    error!(error = %e, "failed to write response");
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Server shutting down");
                break;
            }
        }
    }
}

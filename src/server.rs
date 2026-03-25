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
                Ok(result) => {
                    let categories: Vec<&str> =
                        result.sig.categories.iter().map(|s| s.as_str()).collect();
                    let cats_str = categories.join(",");
                    let sev_str = result.sig.severity.to_string();

                    // Build action summary: short description of what was evaluated.
                    // Truncate long scan text to keep audit readable.
                    let scan_trimmed = result.scan_text.trim().to_string();
                    let summary_text = if scan_trimmed.is_empty() {
                        None
                    } else if scan_trimmed.len() > 200 {
                        Some(format!("{}...", &scan_trimmed[..197]))
                    } else {
                        Some(scan_trimmed)
                    };
                    let summary = summary_text.as_deref();
                    let policy_id = match &result.verdict {
                        crate::hook::Verdict::Deny { reason } => Some(reason.as_str()),
                        _ => None,
                    };

                    let _ = audit.log_event(
                        hook_type,
                        tool_name.as_deref(),
                        summary,
                        result.verdict.as_str(),
                        policy_id,
                        if categories.is_empty() {
                            None
                        } else {
                            Some(&cats_str)
                        },
                        Some(&sev_str),
                    );

                    let hook_response = claude_response::encode(&result.verdict, hook_type);
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

/// Handle a single connection: read request, process, write response.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    cedar: Arc<CedarRuntime>,
    audit: Arc<AuditLog>,
) {
    let (mut reader, mut writer) = stream.into_split();

    let frame = match ipc::read_frame_async(&mut reader).await {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "failed to read frame");
            return;
        }
    };

    let request: AdjudicateRequest = match serde_json::from_slice(&frame) {
        Ok(r) => r,
        Err(e) => {
            let resp = AdjudicateOk::failure(format!("invalid JSON: {e}"));
            match serde_json::to_vec(&resp) {
                Ok(body) => {
                    let _ = ipc::write_frame_async(&mut writer, &body).await;
                }
                Err(ser_err) => {
                    error!(error = %ser_err, "failed to serialize error response");
                }
            }
            return;
        }
    };

    let response = handle_request(&request, &cedar, &audit);
    match serde_json::to_vec(&response) {
        Ok(body) => {
            if let Err(e) = ipc::write_frame_async(&mut writer, &body).await {
                error!(error = %e, "failed to write response");
            }
        }
        Err(e) => {
            error!(error = %e, "failed to serialize response");
        }
    }
}

/// Run the server accept loop until the shutdown signal fires.
///
/// Each connection is handled in its own spawned task for concurrency.
pub async fn run_accept_loop(
    listener: UnixListener,
    cedar: Arc<CedarRuntime>,
    audit: AuditLog,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let audit = Arc::new(audit);

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
                let cedar = Arc::clone(&cedar);
                let audit = Arc::clone(&audit);
                tokio::spawn(handle_connection(stream, cedar, audit));
            }
            _ = shutdown_rx.changed() => {
                info!("Server shutting down");
                break;
            }
        }
    }
}

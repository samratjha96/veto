//! Core adjudication pipeline: YARA scan → Cedar eval → Verdict.

use crate::adapters::claude::payload;
use crate::cedar_runtime::CedarRuntime;
use crate::hook::{HookKind, Verdict};
use crate::process_context;
use crate::signature::{self, Severity, SignatureContext};
use anyhow::Result;
use serde_json::Value;

/// Run the full adjudication pipeline for a hook event.
pub fn adjudicate(
    kind: &HookKind,
    hook_payload: &Value,
    cedar: &CedarRuntime,
) -> Result<(Verdict, SignatureContext)> {
    // 1. Extract scan text from the hook payload.
    let scan_text = payload::scan_target(kind, hook_payload);
    let tool_name = payload::tool_name(hook_payload);

    // 2. YARA scan.
    let sig = signature::scan(&scan_text);

    // 3. Process context enrichment for kill commands.
    let process_ctx = if is_kill_command(&scan_text) {
        Some(process_context::get_process_context())
    } else {
        None
    };

    // 4. Cedar evaluation.
    let cedar_decision = cedar.evaluate(
        kind,
        tool_name.as_deref(),
        hook_payload,
        &sig,
        process_ctx,
    )?;

    // 5. Build verdict.
    let verdict = if !cedar_decision.allowed {
        let reasons = if cedar_decision.deny_reasons.is_empty() {
            "Policy denied this action".to_string()
        } else {
            cedar_decision.deny_reasons.join(", ")
        };
        Verdict::Deny { reason: reasons }
    } else if sig.severity >= Severity::Medium {
        Verdict::Ask {
            reason: format_yara_warning(&sig),
        }
    } else {
        Verdict::Allow
    };

    Ok((verdict, sig))
}

fn is_kill_command(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("kill ") || lower.contains("pkill ") || lower.contains("killall ")
}

fn format_yara_warning(sig: &SignatureContext) -> String {
    let cats: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();
    format!(
        "YARA matched {} rule(s) [severity: {}, categories: {}]",
        sig.matches.len(),
        sig.severity,
        if cats.is_empty() {
            "none".to_string()
        } else {
            cats.join(", ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn test_cedar() -> CedarRuntime {
        let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        CedarRuntime::load(&policy_dir).expect("load policies")
    }

    #[test]
    fn safe_command_allowed() {
        let cedar = test_cedar();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"}
        });
        let (verdict, sig) = adjudicate(&HookKind::BeforeTool, &payload, &cedar).unwrap();
        assert_eq!(verdict, Verdict::Allow);
        assert!(sig.matches.is_empty());
    }

    #[test]
    fn rm_root_denied() {
        let cedar = test_cedar();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        });
        let (verdict, _) = adjudicate(&HookKind::BeforeTool, &payload, &cedar).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn git_force_push_denied() {
        let cedar = test_cedar();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"}
        });
        let (verdict, _) = adjudicate(&HookKind::BeforeTool, &payload, &cedar).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn destructive_rm_triggers_ask() {
        let cedar = test_cedar();
        // rm -rf node_modules/ triggers YARA (high severity) but not Cedar forbid
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf node_modules/"}
        });
        let (verdict, sig) = adjudicate(&HookKind::BeforeTool, &payload, &cedar).unwrap();
        // YARA detects destructive_recursive_rm (high severity), so at minimum Ask
        assert!(
            matches!(verdict, Verdict::Ask { .. } | Verdict::Deny { .. }),
            "destructive rm should trigger Ask or Deny, got {verdict:?}"
        );
        assert!(sig.severity >= Severity::High);
    }

    #[test]
    fn is_kill_command_detects_kill() {
        assert!(is_kill_command("kill 1234"));
        assert!(is_kill_command("pkill nginx"));
        assert!(is_kill_command("killall python"));
        assert!(!is_kill_command("echo killed it"));
    }
}

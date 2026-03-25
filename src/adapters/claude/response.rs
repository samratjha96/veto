//! Claude Code hook stdout JSON encoding.

use crate::hook::Verdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HookResponse {
    #[serde(rename = "continue")]
    pub continue_execution: bool,
    #[serde(rename = "stopReason", skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<serde_json::Value>,
}

impl HookResponse {
    pub fn allow() -> Self {
        Self {
            continue_execution: true,
            stop_reason: None,
            decision: None,
            reason: None,
            hook_specific_output: None,
        }
    }

    pub fn pre_tool_deny(reason: String) -> Self {
        Self {
            continue_execution: true,
            stop_reason: None,
            decision: None,
            reason: None,
            hook_specific_output: Some(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            })),
        }
    }

    pub fn pre_tool_ask(reason: String) -> Self {
        Self {
            continue_execution: true,
            stop_reason: None,
            decision: None,
            reason: None,
            hook_specific_output: Some(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
            })),
        }
    }
}

/// Encode a Verdict into a Claude hook response, given the hook type.
pub fn encode(verdict: &Verdict, hook_type: &str) -> HookResponse {
    match verdict {
        Verdict::Allow => HookResponse::allow(),
        Verdict::Deny { reason } => match hook_type {
            "pre-tool-use" | "PreToolUse" => HookResponse::pre_tool_deny(reason.clone()),
            _ => HookResponse::pre_tool_deny(reason.clone()),
        },
        Verdict::Ask { reason } => HookResponse::pre_tool_ask(reason.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_encodes_correctly() {
        let r = encode(&Verdict::Allow, "pre-tool-use");
        assert!(r.continue_execution);
        assert!(r.hook_specific_output.is_none());
    }

    #[test]
    fn deny_sets_permission_deny() {
        let r = encode(
            &Verdict::Deny {
                reason: "blocked".into(),
            },
            "pre-tool-use",
        );
        assert!(r.continue_execution);
        let out = r.hook_specific_output.unwrap();
        assert_eq!(out["permissionDecision"], "deny");
        assert_eq!(out["permissionDecisionReason"], "blocked");
    }

    #[test]
    fn ask_sets_permission_ask() {
        let r = encode(
            &Verdict::Ask {
                reason: "risky".into(),
            },
            "pre-tool-use",
        );
        let out = r.hook_specific_output.unwrap();
        assert_eq!(out["permissionDecision"], "ask");
    }
}

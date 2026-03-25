//! Map Claude Code hook JSON into scan text and metadata.

use crate::hook::HookKind;
use serde_json::Value;

use super::tool_json;

fn tool_scan_payload(tool_name: Option<&str>, tool_input: Option<&Value>) -> String {
    let Some(name) = tool_name else {
        return tool_input
            .map(|i| serde_json::to_string_pretty(i).unwrap_or_default())
            .unwrap_or_default();
    };

    let input = tool_input.cloned().unwrap_or(Value::Null);

    match name {
        "Bash" => tool_json::bash_command(&input).to_string(),
        "Read" | "Write" | "Edit" => {
            let path = tool_json::file_path(&input);
            let content = tool_json::file_text_for_scan(&input);
            format!("{path}\n{content}")
        }
        "WebFetch" => {
            format!(
                "{}\n{}",
                tool_json::webfetch_url(&input),
                tool_json::webfetch_prompt(&input)
            )
        }
        _ => serde_json::to_string_pretty(&input).unwrap_or_default(),
    }
}

/// Text fed to YARA for this hook payload.
pub fn scan_target(kind: &HookKind, v: &Value) -> String {
    match kind {
        HookKind::UserTurn => v
            .get("prompt")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),

        HookKind::BeforeTool | HookKind::PermissionPrompt => tool_scan_payload(
            v.get("tool_name").and_then(|x| x.as_str()),
            v.get("tool_input"),
        ),

        HookKind::AfterTool => {
            let tool = v.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
            let input = v.get("tool_input").cloned().unwrap_or(Value::Null);
            let resp = v.get("tool_response").cloned().unwrap_or(Value::Null);
            format!(
                "{}\n--- tool_input ---\n{}\n--- tool_response ---\n{}",
                tool,
                serde_json::to_string_pretty(&input).unwrap_or_default(),
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            )
        }

        HookKind::AfterToolError => {
            let tool = v.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
            let err = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
            let input = v.get("tool_input").cloned().unwrap_or(Value::Null);
            format!(
                "{}\nerror: {}\n{}",
                tool,
                err,
                serde_json::to_string_pretty(&input).unwrap_or_default()
            )
        }

        HookKind::Notify => v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),

        HookKind::SessionOpen | HookKind::SessionClose => {
            serde_json::to_string(v).unwrap_or_default()
        }

        HookKind::Other(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}

pub fn tool_name(v: &Value) -> Option<String> {
    v.get("tool_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scan_target_user_turn() {
        let v = json!({"prompt": "what files?"});
        assert_eq!(scan_target(&HookKind::UserTurn, &v), "what files?");
    }

    #[test]
    fn scan_target_bash_before_tool() {
        let v = json!({"tool_name": "Bash", "tool_input": {"command": "echo hello"}});
        assert_eq!(scan_target(&HookKind::BeforeTool, &v), "echo hello");
    }

    #[test]
    fn scan_target_webfetch() {
        let v = json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com", "prompt": "get"}});
        let target = scan_target(&HookKind::BeforeTool, &v);
        assert!(target.contains("https://example.com"));
        assert!(target.contains("get"));
    }

    #[test]
    fn scan_target_notify() {
        let v = json!({"message": "done"});
        assert_eq!(scan_target(&HookKind::Notify, &v), "done");
    }

    #[test]
    fn tool_name_extracted() {
        assert_eq!(
            tool_name(&json!({"tool_name": "Bash"})).as_deref(),
            Some("Bash")
        );
        assert_eq!(tool_name(&json!({})), None);
    }
}

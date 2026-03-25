//! Field extraction for Claude Code `tool_input` JSON.

use serde_json::Value;

pub fn clone_tool_input(v: &Value) -> Value {
    v.get("tool_input").cloned().unwrap_or(Value::Null)
}

pub fn bash_command(input: &Value) -> &str {
    input.get("command").and_then(|c| c.as_str()).unwrap_or("")
}

pub fn bash_working_dir(input: &Value) -> &str {
    input
        .get("working_directory")
        .or_else(|| input.get("cwd"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
}

pub fn webfetch_url(input: &Value) -> &str {
    input.get("url").and_then(|u| u.as_str()).unwrap_or("")
}

pub fn webfetch_prompt(input: &Value) -> &str {
    input.get("prompt").and_then(|p| p.as_str()).unwrap_or("")
}

pub fn file_path(input: &Value) -> &str {
    input
        .get("file_path")
        .and_then(|p| p.as_str())
        .unwrap_or("")
}

pub fn file_text_for_scan(input: &Value) -> &str {
    input
        .get("content")
        .or_else(|| input.get("new_string"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bash_command_extracted() {
        assert_eq!(bash_command(&json!({"command": "echo hello"})), "echo hello");
    }

    #[test]
    fn bash_command_missing_returns_empty() {
        assert_eq!(bash_command(&json!({})), "");
    }

    #[test]
    fn webfetch_url_extracted() {
        assert_eq!(
            webfetch_url(&json!({"url": "https://example.com"})),
            "https://example.com"
        );
    }

    #[test]
    fn file_path_extracted() {
        assert_eq!(
            file_path(&json!({"file_path": "/tmp/x.txt"})),
            "/tmp/x.txt"
        );
    }

    #[test]
    fn file_text_prefers_content() {
        assert_eq!(
            file_text_for_scan(&json!({"content": "hello", "new_string": "world"})),
            "hello"
        );
    }

    #[test]
    fn file_text_falls_back_to_new_string() {
        assert_eq!(
            file_text_for_scan(&json!({"new_string": "replacement"})),
            "replacement"
        );
    }

    #[test]
    fn clone_tool_input_returns_null_when_missing() {
        assert_eq!(clone_tool_input(&json!({})), Value::Null);
    }
}

//! OpenAI-compatible LLM client (chat completions).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub struct LlmClient {
    http: reqwest::Client,
    url: String,
    model: String,
    api_key: String,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

impl LlmClient {
    /// `gateway_base_url` is the OpenAI-compatible API root (e.g. `https://api.openai.com/v1`).
    pub fn new(gateway_base_url: &str, api_key: &str, model: &str) -> Self {
        let key = normalize_api_key(api_key);
        let base = gateway_base_url.trim().trim_end_matches('/');
        Self {
            http: reqwest::Client::new(),
            url: format!("{base}/chat/completions"),
            model: model.to_string(),
            api_key: key,
        }
    }

    /// Send a chat completion request and return the assistant's response text.
    pub async fn chat(&self, system: &str, user: &str) -> Result<String> {
        let req = ChatRequest {
            model: &self.model,
            messages: vec![
                Message {
                    role: "system",
                    content: system,
                },
                Message {
                    role: "user",
                    content: user,
                },
            ],
            temperature: 0.2,
            max_tokens: 2048,
        };

        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await
            .context("LLM HTTP request")?
            .error_for_status()
            .context("LLM API error")?
            .json::<ChatResponse>()
            .await
            .context("parse LLM response")?;

        resp.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .context("no choices in LLM response")
    }
}

fn normalize_api_key(raw: &str) -> String {
    let s = raw.trim();
    s.strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .unwrap_or(s)
        .trim()
        .to_string()
}

/// Extract the first balanced `{ ... }` or ```cedar ... ``` block from LLM output.
/// Models often wrap code in markdown fences.
pub fn extract_cedar_block(raw: &str) -> String {
    let s = raw.trim();

    // Try markdown cedar/text fence first
    if let Some(idx) = s.find("```") {
        let after = s[idx + 3..].trim_start();
        let after = after
            .strip_prefix("cedar")
            .or_else(|| after.strip_prefix("text"))
            .unwrap_or(after)
            .trim_start();
        if let Some(end) = after.find("```") {
            return after[..end].trim().to_string();
        }
    }

    // Fall back to returning everything that looks like Cedar policy
    // (lines starting with @, permit, forbid, or whitespace-indented continuations)
    let mut lines: Vec<&str> = Vec::new();
    let mut in_policy = false;
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("@id")
            || trimmed.starts_with("@description")
            || trimmed.starts_with("permit")
            || trimmed.starts_with("forbid")
        {
            in_policy = true;
        }
        if in_policy {
            lines.push(line);
        }
        if in_policy && trimmed.ends_with("};") {
            break;
        }
    }

    if !lines.is_empty() {
        lines.join("\n")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cedar_from_markdown_fence() {
        let raw = r#"Here's the policy:

```cedar
@id("test-policy")
forbid(
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm*"
};
```

This policy blocks rm commands."#;

        let result = extract_cedar_block(raw);
        assert!(result.starts_with("@id(\"test-policy\")"));
        assert!(result.contains("forbid("));
        assert!(result.ends_with("};"));
    }

    #[test]
    fn extract_cedar_without_fence() {
        let raw = r#"@id("test")
@description("block rm")
forbid(
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm*"
};"#;

        let result = extract_cedar_block(raw);
        assert!(result.contains("@id(\"test\")"));
        assert!(result.contains("forbid("));
    }

    #[test]
    fn normalize_key_strips_bearer() {
        assert_eq!(normalize_api_key("Bearer abc123"), "abc123");
        assert_eq!(normalize_api_key("  abc123  "), "abc123");
        assert_eq!(normalize_api_key("bearer xyz"), "xyz");
    }
}

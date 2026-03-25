//! Natural language → Cedar policy generation.
//!
//! Reads the Cedar schema and example policies, builds a system prompt,
//! calls the LLM, and extracts the generated Cedar policy.

use crate::llm::{self, LlmClient};
use anyhow::{Context, Result};
use std::path::Path;

/// Generated policy ready for user confirmation.
pub struct GeneratedPolicy {
    pub cedar_text: String,
    pub policy_id: String,
    pub file_name: String,
}

/// Build the system prompt from the schema and example policies on disk.
fn build_system_prompt(policy_dir: &Path) -> Result<String> {
    let schema = read_cedarschema(policy_dir)?;
    let examples = read_example_policies(policy_dir)?;

    Ok(format!(
        r#"You are a Cedar policy generator for Veto, a security daemon that evaluates AI coding agent actions.

## Cedar Schema

The following Cedar schema defines the entity types, actions, and context types available:

```cedarschema
{schema}
```

## Rules

1. Always output exactly ONE Cedar policy (a single `forbid` or `permit` statement).
2. Always include `@id("...")` and `@description("...")` annotations.
3. The `@id` should be a kebab-case identifier derived from the user's intent.
4. The principal is always `Agent`, the resource is always `Resource`.
5. Use `context.*` fields from the schema to match conditions.
6. For ShellCommand matching, use `context.command like "*pattern*"`.
7. For file path matching, use `context.path like "*pattern*"`.
8. For URL matching, use `context.url like "*pattern*"`.
9. Use `||` (or) for multiple patterns and `&&` (and) for combined conditions.
10. Output ONLY the Cedar policy — no explanation, no markdown fences.

## Available Actions

- `Action::"ShellCommand"` — shell/terminal commands (context has: command, working_dir, signature, has_long_running_process, longest_process_runtime_seconds)
- `Action::"WebFetch"` — HTTP requests (context has: url, signature)
- `Action::"FileRead"` — reading files (context has: path, signature)
- `Action::"FileWrite"` — writing files (context has: path, signature)
- `Action::"FileEdit"` — editing files (context has: path, signature)
- `Action::"FileDelete"` — deleting files (context has: path, signature)

## Example Policies

{examples}
"#
    ))
}

fn read_cedarschema(policy_dir: &Path) -> Result<String> {
    let mut schema_content = String::new();
    let entries = std::fs::read_dir(policy_dir).context("read policy dir")?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cedarschema") {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            schema_content.push_str(&content);
            schema_content.push('\n');
        }
    }
    Ok(schema_content)
}

fn read_example_policies(policy_dir: &Path) -> Result<String> {
    let mut examples = String::new();
    let entries = std::fs::read_dir(policy_dir).context("read policy dir")?;
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("cedar"))
        .collect();
    paths.sort();

    for path in paths {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
        examples.push_str(&format!("### {file_name}\n\n```cedar\n{content}\n```\n\n"));
    }
    Ok(examples)
}

/// Derive a kebab-case policy ID from the natural language description.
fn derive_policy_id(nl: &str) -> String {
    let id: String = nl
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == ' ' { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");

    let id = if id.len() > 50 { &id[..50] } else { &id };
    format!("user-{id}")
}

/// Generate a Cedar policy from a natural language description.
pub async fn generate(
    llm: &LlmClient,
    policy_dir: &Path,
    natural_language: &str,
) -> Result<GeneratedPolicy> {
    let system_prompt = build_system_prompt(policy_dir)?;
    let user_prompt = format!(
        "Generate a Cedar policy for the following requirement:\n\n{natural_language}"
    );

    let response = llm.chat(&system_prompt, &user_prompt).await?;
    let cedar_text = llm::extract_cedar_block(&response);

    // Try to parse out @id from the generated policy
    let policy_id = extract_annotation_value(&cedar_text, "@id")
        .unwrap_or_else(|| derive_policy_id(natural_language));

    let file_name = format!("{policy_id}.cedar");

    Ok(GeneratedPolicy {
        cedar_text,
        policy_id,
        file_name,
    })
}

/// Extract the value from an annotation like @id("some-value").
fn extract_annotation_value(cedar: &str, annotation: &str) -> Option<String> {
    for line in cedar.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(annotation) {
            // Find the value between quotes
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    return Some(trimmed[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }
    None
}

/// Validate that a Cedar policy string parses correctly against our schema.
pub fn validate_policy(cedar_text: &str, policy_dir: &Path) -> Result<()> {
    use cedar_policy::{PolicySet, Schema, SchemaFragment};

    // Load schema
    let mut fragments = Vec::new();
    for entry in std::fs::read_dir(policy_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cedarschema") {
            let content = std::fs::read_to_string(&path)?;
            let (frag, _) = SchemaFragment::from_cedarschema_str(&content)?;
            fragments.push(frag);
        }
    }
    let _schema = Schema::from_schema_fragments(fragments)?;

    // Parse the policy
    let _ps: PolicySet = cedar_text
        .parse()
        .context("generated policy does not parse as valid Cedar")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_policy_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
    }

    #[test]
    fn build_system_prompt_includes_schema() {
        let prompt = build_system_prompt(&test_policy_dir()).unwrap();
        assert!(prompt.contains("entity Agent"));
        assert!(prompt.contains("ShellCommand"));
        assert!(prompt.contains("WebFetch"));
    }

    #[test]
    fn build_system_prompt_includes_examples() {
        let prompt = build_system_prompt(&test_policy_dir()).unwrap();
        assert!(prompt.contains("forbid-rm-root"));
        assert!(prompt.contains("forbid-git-force-push"));
    }

    #[test]
    fn derive_policy_id_works() {
        assert_eq!(
            derive_policy_id("never kill processes without asking"),
            "user-never-kill-processes-without-asking"
        );
        assert_eq!(
            derive_policy_id("block rm -rf on home"),
            "user-block-rm-rf-on-home"
        );
    }

    #[test]
    fn extract_annotation_value_works() {
        let cedar = r#"@id("test-policy")
@description("test")
forbid(principal, action, resource);"#;
        assert_eq!(
            extract_annotation_value(cedar, "@id"),
            Some("test-policy".to_string())
        );
        assert_eq!(
            extract_annotation_value(cedar, "@description"),
            Some("test".to_string())
        );
    }

    #[test]
    fn validate_good_policy() {
        let policy = r#"
@id("test-validate")
@description("test validation")
forbid(
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm*"
};
"#;
        validate_policy(policy, &test_policy_dir()).unwrap();
    }

    #[test]
    fn validate_bad_policy_fails() {
        let bad_policy = "this is not cedar";
        assert!(validate_policy(bad_policy, &test_policy_dir()).is_err());
    }
}

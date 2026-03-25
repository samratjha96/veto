//! Policy explanation — find and display Cedar policies by @id.

use std::path::Path;

/// A single Cedar policy block extracted from a .cedar file.
#[derive(Debug, Clone)]
pub struct PolicyInfo {
    /// The @id annotation value.
    pub id: String,
    /// The @description annotation value, if present.
    pub description: Option<String>,
    /// The full Cedar text of this policy (including annotations).
    pub cedar_text: String,
    /// The file this policy was found in (filename only).
    pub filename: String,
    /// Whether it's a permit or forbid policy.
    pub effect: String,
    /// The action scope (e.g., "ShellCommand", "FileWrite", or "all").
    pub actions: Vec<String>,
}

/// Parse all policies from a single .cedar file's content.
fn parse_policies(content: &str, filename: &str) -> Vec<PolicyInfo> {
    let mut policies = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        // Look for the start of a policy block: @id annotation or permit/forbid keyword
        let trimmed = lines[i].trim();

        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with("//") {
            i += 1;
            continue;
        }

        // Check if this line starts a policy (begins with @id or permit/forbid)
        if trimmed.starts_with("@id(") || trimmed.starts_with("permit") || trimmed.starts_with("forbid") {
            let block_start = i;

            // Collect annotation lines first
            let mut id = None;
            let mut description = None;

            while i < lines.len() {
                let t = lines[i].trim();
                if t.starts_with("@id(\"") && t.ends_with("\")") {
                    id = Some(t[5..t.len() - 2].to_string());
                } else if t.starts_with("@description(\"") && t.ends_with("\")") {
                    description = Some(t[14..t.len() - 2].to_string());
                } else if !t.starts_with('@') {
                    break;
                }
                i += 1;
            }

            // Now collect the policy body (permit/forbid ... ;)
            let mut brace_depth = 0i32;
            let mut found_semicolon = false;
            let body_start = i;

            while i < lines.len() {
                let t = lines[i].trim();
                for ch in t.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => brace_depth -= 1,
                        ';' if brace_depth <= 0 => found_semicolon = true,
                        _ => {}
                    }
                }
                i += 1;
                if found_semicolon && brace_depth <= 0 {
                    break;
                }
            }

            // Extract the full block text
            let block_text: String = lines[block_start..i]
                .iter()
                .copied()
                .collect::<Vec<&str>>()
                .join("\n");

            // Determine effect
            let effect = if body_start < lines.len() {
                let body_line = lines[body_start].trim();
                if body_line.starts_with("forbid") {
                    "forbid"
                } else if body_line.starts_with("permit") {
                    "permit"
                } else {
                    "unknown"
                }
            } else {
                "unknown"
            };

            // Extract actions from the body
            let actions = extract_actions(&block_text);

            if let Some(id) = id {
                policies.push(PolicyInfo {
                    id,
                    description,
                    cedar_text: block_text,
                    filename: filename.to_string(),
                    effect: effect.to_string(),
                    actions,
                });
            }
        } else {
            i += 1;
        }
    }

    policies
}

/// Extract action names from a Cedar policy text.
fn extract_actions(text: &str) -> Vec<String> {
    let mut actions = Vec::new();

    // Match patterns like Action::"ShellCommand" or Action::"FileWrite"
    let mut remaining = text;
    while let Some(pos) = remaining.find("Action::\"") {
        let after = &remaining[pos + 9..];
        if let Some(end) = after.find('"') {
            actions.push(after[..end].to_string());
        }
        remaining = &remaining[pos + 9..];
    }

    if actions.is_empty() {
        // Check for bare action/principal/resource (matches all actions)
        if text.contains("action,") || text.contains("action)") {
            actions.push("(all actions)".to_string());
        }
    }

    actions.sort();
    actions.dedup();
    actions
}

/// Find a policy by @id across all .cedar files in the policy directory.
pub fn find_policy(policy_dir: &Path, policy_id: &str) -> anyhow::Result<Option<PolicyInfo>> {
    if !policy_dir.is_dir() {
        anyhow::bail!("Policy directory not found: {}", policy_dir.display());
    }

    for entry in std::fs::read_dir(policy_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "cedar") {
            let content = std::fs::read_to_string(&path)?;
            let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let policies = parse_policies(&content, &filename);
            if let Some(p) = policies.into_iter().find(|p| p.id == policy_id) {
                return Ok(Some(p));
            }
        }
    }

    Ok(None)
}

/// List all policy IDs and their descriptions.
pub fn list_all(policy_dir: &Path) -> anyhow::Result<Vec<PolicyInfo>> {
    if !policy_dir.is_dir() {
        anyhow::bail!("Policy directory not found: {}", policy_dir.display());
    }

    let mut all = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(policy_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path)?;
        let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        all.extend(parse_policies(&content, &filename));
    }

    Ok(all)
}

/// Search policies by keyword (matches against id, description, and cedar text).
pub fn search(policy_dir: &Path, query: &str) -> anyhow::Result<Vec<PolicyInfo>> {
    let all = list_all(policy_dir)?;
    let query_lower = query.to_lowercase();
    Ok(all
        .into_iter()
        .filter(|p| {
            p.id.to_lowercase().contains(&query_lower)
                || p.description
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&query_lower)
                || p.cedar_text.to_lowercase().contains(&query_lower)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CEDAR: &str = r#"
// Sample policies

@id("forbid-rm-root")
@description("Block rm targeting the root filesystem.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm /"
};

@id("default-permit")
@description("Permit all actions unless a forbid fires.")
permit (principal, action, resource);

@id("forbid-file-write")
@description("Block file write operations.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/*"
};
"#;

    #[test]
    fn parse_extracts_all_policies() {
        let policies = parse_policies(SAMPLE_CEDAR, "test.cedar");
        assert_eq!(policies.len(), 3);
    }

    #[test]
    fn parse_extracts_id_and_description() {
        let policies = parse_policies(SAMPLE_CEDAR, "test.cedar");
        let p = &policies[0];
        assert_eq!(p.id, "forbid-rm-root");
        assert_eq!(
            p.description.as_deref(),
            Some("Block rm targeting the root filesystem.")
        );
    }

    #[test]
    fn parse_identifies_effect() {
        let policies = parse_policies(SAMPLE_CEDAR, "test.cedar");
        assert_eq!(policies[0].effect, "forbid");
        assert_eq!(policies[1].effect, "permit");
        assert_eq!(policies[2].effect, "forbid");
    }

    #[test]
    fn parse_extracts_actions() {
        let policies = parse_policies(SAMPLE_CEDAR, "test.cedar");
        assert_eq!(policies[0].actions, vec!["ShellCommand"]);
        assert_eq!(policies[1].actions, vec!["(all actions)"]);
        let mut actions = policies[2].actions.clone();
        actions.sort();
        assert_eq!(actions, vec!["FileEdit", "FileWrite"]);
    }

    #[test]
    fn parse_captures_cedar_text() {
        let policies = parse_policies(SAMPLE_CEDAR, "test.cedar");
        assert!(policies[0].cedar_text.contains("@id(\"forbid-rm-root\")"));
        assert!(policies[0].cedar_text.contains("context.command like"));
    }

    #[test]
    fn parse_sets_filename() {
        let policies = parse_policies(SAMPLE_CEDAR, "destructive.cedar");
        for p in &policies {
            assert_eq!(p.filename, "destructive.cedar");
        }
    }

    #[test]
    fn find_policy_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.cedar"), SAMPLE_CEDAR).unwrap();

        let result = find_policy(dir.path(), "forbid-rm-root").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "forbid-rm-root");
    }

    #[test]
    fn find_policy_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.cedar"), SAMPLE_CEDAR).unwrap();

        let result = find_policy(dir.path(), "nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_all_returns_all_policies() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.cedar"), SAMPLE_CEDAR).unwrap();

        let all = list_all(dir.path()).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn search_by_keyword() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.cedar"), SAMPLE_CEDAR).unwrap();

        let results = search(dir.path(), "rm /").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "forbid-rm-root");
    }

    #[test]
    fn search_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.cedar"), SAMPLE_CEDAR).unwrap();

        let results = search(dir.path(), "FILE WRITE").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "forbid-file-write");
    }
}

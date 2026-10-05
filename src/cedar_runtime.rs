//! Load Cedar schema/policies and evaluate requests — stateless, no entity store.

use crate::hook::HookKind;
use crate::shell::Invocation;
use crate::signature::SignatureContext;
use anyhow::{Context, Result};
use cedar_policy::{
    Authorizer, Context as CedarContext, Entities, Entity, EntityTypeName, EntityUid, PolicyId,
    PolicySet, Request, Schema, SchemaFragment,
};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::warn;

/// Shared state that can be hot-reloaded.
struct Inner {
    schema: Schema,
    policy_set: PolicySet,
}

pub struct CedarRuntime {
    authorizer: Authorizer,
    inner: Arc<RwLock<Inner>>,
    policy_dir: std::path::PathBuf,
}

/// Result of a Cedar evaluation.
pub struct CedarDecision {
    pub allowed: bool,
    pub deny_reasons: Vec<String>,
    pub policy_id: Option<String>,
}

fn load_policies_and_schema(policy_dir: &Path) -> Result<(PolicySet, Schema)> {
    let mut schema_fragments: Vec<SchemaFragment> = Vec::new();
    let mut policy_set = PolicySet::new();

    let mut entries: Vec<_> = std::fs::read_dir(policy_dir)
        .with_context(|| format!("read policy dir {}", policy_dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let file_path = entry.path();
        match file_path.extension().and_then(|e| e.to_str()) {
            Some("cedarschema") => {
                let content = std::fs::read_to_string(&file_path)
                    .with_context(|| format!("read {}", file_path.display()))?;
                let (fragment, warnings) = SchemaFragment::from_cedarschema_str(&content)
                    .with_context(|| format!("parse schema {}", file_path.display()))?;
                for w in warnings {
                    warn!("{}: {}", file_path.display(), w);
                }
                schema_fragments.push(fragment);
            }
            Some("cedar") => {
                let content = std::fs::read_to_string(&file_path)
                    .with_context(|| format!("read {}", file_path.display()))?;
                let file_policies: PolicySet = content
                    .parse()
                    .with_context(|| format!("parse policies {}", file_path.display()))?;
                for policy in file_policies.policies() {
                    let id_str = policy
                        .annotation("id")
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| policy.id().as_ref());
                    let named = policy.new_id(PolicyId::new(id_str));
                    policy_set.add(named).with_context(|| {
                        format!("duplicate policy id {id_str} in {}", file_path.display())
                    })?;
                }
            }
            _ => {}
        }
    }

    anyhow::ensure!(
        !schema_fragments.is_empty(),
        "no .cedarschema files in {}",
        policy_dir.display()
    );

    let schema = Schema::from_schema_fragments(schema_fragments).context("merge schema")?;
    Ok((policy_set, schema))
}

fn euid(type_name: &str, id: &str) -> Result<EntityUid> {
    let tn: EntityTypeName = type_name.parse().context("parse entity type")?;
    Ok(EntityUid::from_type_name_and_id(tn, id.parse()?))
}

fn signature_json(ctx: &SignatureContext) -> Value {
    let cats: Vec<String> = ctx.categories.iter().cloned().collect();
    json!({
        "match_count": ctx.match_count(),
        "categories": cats,
        "severity": i64::from(ctx.severity),
    })
}

impl CedarRuntime {
    pub fn load(policy_dir: &Path) -> Result<Self> {
        let (policy_set, schema) = load_policies_and_schema(policy_dir)?;
        let inner = Inner {
            schema,
            policy_set,
        };
        Ok(Self {
            authorizer: Authorizer::new(),
            inner: Arc::new(RwLock::new(inner)),
            policy_dir: policy_dir.to_path_buf(),
        })
    }

    /// Reload policies from disk. Returns the new policy count.
    ///
    /// If reload fails, the previous policies remain active (fail-safe).
    pub fn reload(&self) -> Result<usize> {
        let (policy_set, schema) = load_policies_and_schema(&self.policy_dir)?;
        let count = policy_set.policies().count();
        let mut inner = self.inner.write().map_err(|e| anyhow::anyhow!("{e}"))?;
        inner.policy_set = policy_set;
        inner.schema = schema;
        Ok(count)
    }

    /// Path to the policy directory.
    pub fn policy_dir(&self) -> &std::path::Path {
        &self.policy_dir
    }

    /// Number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.inner
            .read()
            .map(|i| i.policy_set.policies().count())
            .unwrap_or(0)
    }

    /// Evaluate a hook event against Cedar policies.
    pub fn evaluate(
        &self,
        kind: &HookKind,
        tool_name: Option<&str>,
        payload: &Value,
        sig: &SignatureContext,
        process_ctx: Option<(bool, i64)>,
        invocation: Option<&Invocation>,
    ) -> Result<CedarDecision> {
        let inner = self.inner.read().map_err(|e| anyhow::anyhow!("{e}"))?;

        let action_str = kind.cedar_action(tool_name);
        let action_uid = euid("Action", action_str)?;
        let principal_uid = euid("Agent", "claude")?;
        let resource_uid = euid("Resource", "default")?;

        // Build context based on action type
        let context_json = match action_str {
            "ShellCommand" => {
                let command = invocation.map(|i| i.text.as_str()).unwrap_or_else(|| {
                    payload
                        .get("tool_input")
                        .and_then(|i| i.get("command"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                });
                let working_dir = payload
                    .get("tool_input")
                    .and_then(|i| {
                        i.get("working_directory")
                            .or_else(|| i.get("cwd"))
                    })
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                let (has_long, longest) = process_ctx.unwrap_or((false, 0));
                json!({
                    "command": command,
                    "program": invocation.map_or("", |i| i.program.as_str()),
                    "subcommand": invocation.map_or("", |i| i.subcommand.as_str()),
                    "flags": invocation.map_or(&[][..], |i| i.flags.as_slice()),
                    "working_dir": working_dir,
                    "signature": signature_json(sig),
                    "has_long_running_process": has_long,
                    "longest_process_runtime_seconds": longest,
                })
            }
            "WebFetch" => {
                let url = payload
                    .get("tool_input")
                    .and_then(|i| i.get("url"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");
                json!({
                    "url": url,
                    "signature": signature_json(sig),
                })
            }
            "FileRead" | "FileWrite" | "FileEdit" | "FileDelete" => {
                let path = payload
                    .get("tool_input")
                    .and_then(|i| i.get("file_path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                json!({
                    "path": path,
                    "signature": signature_json(sig),
                })
            }
            _ => {
                json!({
                    "command": "",
                    "working_dir": "",
                    "signature": signature_json(sig),
                    "has_long_running_process": false,
                    "longest_process_runtime_seconds": 0,
                })
            }
        };

        let context =
            CedarContext::from_json_value(context_json, Some((&inner.schema, &action_uid)))?;

        // Build inline entities (Agent + Resource)
        let mut agent_attrs = std::collections::HashMap::new();
        agent_attrs.insert(
            "provider_id".to_string(),
            cedar_policy::RestrictedExpression::new_string("claude".to_string()),
        );
        let agent_entity = Entity::new(
            principal_uid.clone(),
            agent_attrs,
            std::collections::HashSet::new(),
        )?;
        let resource_entity = Entity::new_no_attrs(resource_uid.clone(), std::collections::HashSet::new());
        let entities = Entities::from_entities(
            [agent_entity, resource_entity],
            Some(&inner.schema),
        )?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            Some(&inner.schema),
        )?;

        let response = self.authorizer.is_authorized(&request, &inner.policy_set, &entities);

        let allowed = matches!(response.decision(), cedar_policy::Decision::Allow);
        let deny_reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        let policy_id = deny_reasons.first().cloned();

        Ok(CedarDecision {
            allowed,
            deny_reasons,
            policy_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_runtime() -> CedarRuntime {
        let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        CedarRuntime::load(&policy_dir).expect("load policies")
    }

    #[test]
    fn loads_policies() {
        let rt = test_runtime();
        assert!(rt.policy_count() > 0);
    }

    #[test]
    fn allows_safe_command() {
        let rt = test_runtime();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"}
        });
        let sig = SignatureContext::default();
        let decision = rt
            .evaluate(&HookKind::BeforeTool, Some("Bash"), &payload, &sig, None, None)
            .unwrap();
        assert!(decision.allowed, "safe command should be allowed");
    }

    #[test]
    fn blocks_rm_root() {
        let rt = test_runtime();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        });
        let sig = SignatureContext::default();
        let decision = rt
            .evaluate(&HookKind::BeforeTool, Some("Bash"), &payload, &sig, None, None)
            .unwrap();
        assert!(!decision.allowed, "rm -rf / should be denied");
    }

    #[test]
    fn blocks_git_force_push() {
        let rt = test_runtime();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"}
        });
        let sig = SignatureContext::default();
        let analysis = crate::shell::analyze("git push --force origin main");
        let decision = rt
            .evaluate(
                &HookKind::BeforeTool,
                Some("Bash"),
                &payload,
                &sig,
                None,
                analysis.commands.first(),
            )
            .unwrap();
        assert!(!decision.allowed, "git push --force should be denied");
    }

    #[test]
    fn blocks_critical_yara_severity() {
        let rt = test_runtime();
        let payload = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"}
        });
        let mut sig = SignatureContext::default();
        sig.severity = crate::signature::Severity::Critical;
        let decision = rt
            .evaluate(&HookKind::BeforeTool, Some("Bash"), &payload, &sig, None, None)
            .unwrap();
        assert!(!decision.allowed, "critical YARA severity should deny");
    }

    #[test]
    fn reload_succeeds() {
        let rt = test_runtime();
        let count = rt.reload().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn load_missing_dir_fails() {
        let result = CedarRuntime::load(Path::new("/nonexistent/dir"));
        let msg = result.err().expect("should fail").to_string();
        assert!(
            msg.contains("nonexistent"),
            "error should mention the missing dir: {msg}"
        );
    }

    #[test]
    fn load_empty_dir_fails() {
        let dir = std::env::temp_dir().join(format!(
            "veto-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let result = CedarRuntime::load(&dir);
        let msg = result.err().expect("should fail").to_string();
        assert!(
            msg.contains("no .cedarschema"),
            "error should mention missing schema: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_preserves_policies_on_bad_file() {
        // Copy the policy dir to a temp location so we don't interfere with other tests
        let tmp_dir = std::env::temp_dir().join(format!(
            "veto-badpolicy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // Copy schema and policies
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        for entry in std::fs::read_dir(&src_dir).unwrap() {
            let entry = entry.unwrap();
            let dest = tmp_dir.join(entry.file_name());
            std::fs::copy(entry.path(), dest).unwrap();
        }

        let rt = CedarRuntime::load(&tmp_dir).expect("load copied policies");
        let original_count = rt.policy_count();
        assert!(original_count > 0);

        // Write a bad cedar file into the temp dir
        let bad_path = tmp_dir.join("bad_test.cedar");
        std::fs::write(&bad_path, "this is not valid cedar at all!!!").unwrap();

        // Reload should fail
        let result = rt.reload();
        assert!(result.is_err(), "reload with bad policy should fail");

        // Original policies should still be active (fail-safe)
        assert_eq!(
            rt.policy_count(),
            original_count,
            "original policies should be preserved after failed reload"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

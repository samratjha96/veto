//! YARA-X scanning (rules embedded from `rules/` at crate root).

use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;
use tracing::warn;
use yara_x::{Compiler, Rules, Scanner};

static YARA_RULES_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules");
static RULES: OnceLock<Rules> = OnceLock::new();

pub fn get_rules() -> &'static Rules {
    RULES.get_or_init(|| {
        let mut compiler = Compiler::new();
        for file in YARA_RULES_DIR.files() {
            if file.path().extension().is_some_and(|ext| ext == "yar") {
                compiler.add_source(file.contents()).unwrap_or_else(|e| {
                    panic!("Failed to compile {}: {}", file.path().display(), e)
                });
            }
        }
        compiler.build()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_metadata(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::None,
        }
    }
}

impl From<Severity> for i64 {
    fn from(s: Severity) -> Self {
        match s {
            Severity::None => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Match {
    pub identifier: String,
    pub namespace: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct SignatureContext {
    pub matches: Vec<Match>,
    pub categories: HashSet<String>,
    pub severity: Severity,
}

impl SignatureContext {
    pub fn match_count(&self) -> i64 {
        self.matches.len() as i64
    }
}

fn extract_metadata<'a>(
    entries: impl Iterator<Item = (&'a str, yara_x::MetaValue<'a>)>,
) -> HashMap<String, String> {
    entries
        .filter_map(|(key, value)| match value {
            yara_x::MetaValue::String(s) => Some((key.to_string(), s.to_string())),
            yara_x::MetaValue::Integer(i) => Some((key.to_string(), i.to_string())),
            yara_x::MetaValue::Float(fl) => Some((key.to_string(), fl.to_string())),
            yara_x::MetaValue::Bool(b) => Some((key.to_string(), b.to_string())),
            _ => None,
        })
        .collect()
}

pub fn scan(content: &str) -> SignatureContext {
    let rules = get_rules();
    let mut scanner = Scanner::new(rules);

    let matches = match scanner.scan(content.as_bytes()) {
        Ok(results) => results
            .matching_rules()
            .map(|rule| Match {
                identifier: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                metadata: extract_metadata(rule.metadata()),
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            warn!(error = %e, "YARA scanning error");
            Vec::new()
        }
    };

    let mut categories = HashSet::new();
    let mut max_severity = Severity::None;

    for m in &matches {
        if let Some(cat) = m.metadata.get("category") {
            categories.insert(cat.clone());
        }
        if let Some(sev) = m.metadata.get("severity") {
            max_severity = max_severity.max(Severity::from_metadata(sev));
        }
    }

    SignatureContext {
        matches,
        categories,
        severity: max_severity,
    }
}

/// Serializable summary for SQLite / JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSummary {
    pub identifier: String,
    pub category: Option<String>,
    pub severity: Option<String>,
}

impl From<&Match> for MatchSummary {
    fn from(m: &Match) -> Self {
        Self {
            identifier: m.identifier.clone(),
            category: m.metadata.get("category").cloned(),
            severity: m.metadata.get("severity").cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_recursive_rm() {
        for sample in [
            "cd blah && rm -rf",
            "rm -rf node_modules/",
            "sudo rm -fr /var/tmp/cache",
        ] {
            let ctx = scan(sample);
            assert!(
                ctx.matches
                    .iter()
                    .any(|m| m.identifier == "destructive_recursive_rm"),
                "expected destructive_recursive_rm for {sample:?}, got {:?}",
                ctx.matches
                    .iter()
                    .map(|m| &m.identifier)
                    .collect::<Vec<_>>()
            );
            assert!(ctx.categories.contains("destructive_ops"));
        }
    }

    #[test]
    fn detects_git_force_push() {
        let ctx = scan("git push --force origin main");
        assert!(ctx
            .matches
            .iter()
            .any(|m| m.identifier == "destructive_git_force"));
        assert!(ctx.severity >= Severity::High);
    }

    #[test]
    fn detects_private_key() {
        let ctx = scan("-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----");
        assert!(ctx.categories.contains("secrets_detection"));
        assert!(ctx.severity >= Severity::Critical);
    }

    #[test]
    fn clean_input_no_matches() {
        let ctx = scan("echo hello world");
        assert!(ctx.matches.is_empty());
        assert_eq!(ctx.severity, Severity::None);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
    }
}

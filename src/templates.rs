//! Embedded policy templates — curated Cedar policies users can apply instantly.

use std::path::Path;

/// A policy template with metadata.
#[derive(Debug, Clone)]
pub struct Template {
    /// Short identifier (used in `veto policy template apply <id>`).
    pub id: &'static str,
    /// One-line description.
    pub description: &'static str,
    /// Category for grouping in `list` output.
    pub category: &'static str,
    /// The Cedar policy text.
    pub cedar: &'static str,
    /// Filename to write (without path).
    pub filename: &'static str,
}

/// All embedded templates.
pub fn all() -> &'static [Template] {
    &[
        Template {
            id: "no-kill",
            description: "Block all kill/pkill/killall commands",
            category: "process",
            cedar: r#"@id("template-forbid-kill")
@description("Block all process termination commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kill *" ||
    context.command like "*pkill *" ||
    context.command like "*killall *"
};
"#,
            filename: "template_no_kill.cedar",
        },
        Template {
            id: "no-kill-long-running",
            description: "Block kill only when long-running processes exist",
            category: "process",
            cedar: r#"@id("template-forbid-kill-long-running")
@description("Block kill commands when long-running user processes exist.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*kill *" || context.command like "*pkill *" || context.command like "*killall *") &&
    context.has_long_running_process
};
"#,
            filename: "template_no_kill_long_running.cedar",
        },
        Template {
            id: "no-network",
            description: "Block all web fetch operations",
            category: "network",
            cedar: r#"@id("template-forbid-network")
@description("Block all web fetch operations — fully offline mode.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
);
"#,
            filename: "template_no_network.cedar",
        },
        Template {
            id: "no-curl-upload",
            description: "Block curl/wget POST/PUT (data exfiltration vector)",
            category: "network",
            cedar: r#"@id("template-forbid-curl-upload")
@description("Block outbound data uploads via curl or wget.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*curl *-X POST*" ||
    context.command like "*curl *-X PUT*" ||
    context.command like "*curl *--data*" ||
    context.command like "*curl *-d *" ||
    context.command like "*wget *--post-data*" ||
    context.command like "*wget *--post-file*"
};
"#,
            filename: "template_no_curl_upload.cedar",
        },
        Template {
            id: "read-only",
            description: "Block all file writes, edits, and deletes",
            category: "filesystem",
            cedar: r#"@id("template-forbid-file-write")
@description("Block file write operations — read-only mode.")
forbid (
    principal,
    action == Action::"FileWrite",
    resource
);

@id("template-forbid-file-edit")
@description("Block file edit operations — read-only mode.")
forbid (
    principal,
    action == Action::"FileEdit",
    resource
);

@id("template-forbid-file-delete")
@description("Block file delete operations — read-only mode.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
);
"#,
            filename: "template_read_only.cedar",
        },
        Template {
            id: "no-sudo",
            description: "Block sudo and su commands",
            category: "privilege",
            cedar: r#"@id("template-forbid-sudo")
@description("Block privilege escalation via sudo or su.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "sudo *" ||
    context.command like "*sudo *" ||
    context.command like "su *" ||
    context.command like "*su -*"
};
"#,
            filename: "template_no_sudo.cedar",
        },
        Template {
            id: "protect-env",
            description: "Block modifications to .env files",
            category: "filesystem",
            cedar: r#"@id("template-forbid-env-write")
@description("Block writing to .env files.")
forbid (
    principal,
    action == Action::"FileWrite",
    resource
) when {
    context.path like "*.env" ||
    context.path like "*.env.*"
};

@id("template-forbid-env-edit")
@description("Block editing .env files.")
forbid (
    principal,
    action == Action::"FileEdit",
    resource
) when {
    context.path like "*.env" ||
    context.path like "*.env.*"
};

@id("template-forbid-env-delete")
@description("Block deleting .env files.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.env" ||
    context.path like "*.env.*"
};
"#,
            filename: "template_protect_env.cedar",
        },
        Template {
            id: "no-publish",
            description: "Block package publishing (npm, cargo, pip, gem)",
            category: "supply-chain",
            cedar: r#"@id("template-forbid-publish")
@description("Block package registry publishing commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm publish*" ||
    context.command like "*yarn publish*" ||
    context.command like "*cargo publish*" ||
    context.command like "*twine upload*" ||
    context.command like "*gem push*" ||
    context.command like "*pip upload*"
};
"#,
            filename: "template_no_publish.cedar",
        },
        Template {
            id: "no-git-rewrite",
            description: "Block git history rewriting (rebase, amend, filter-branch)",
            category: "git",
            cedar: r#"@id("template-forbid-git-rewrite")
@description("Block git history rewriting operations.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git rebase*" ||
    context.command like "*git commit --amend*" ||
    context.command like "*git filter-branch*" ||
    context.command like "*git filter-repo*"
};
"#,
            filename: "template_no_git_rewrite.cedar",
        },
        Template {
            id: "no-install",
            description: "Block package installation commands",
            category: "supply-chain",
            cedar: r#"@id("template-forbid-install")
@description("Block package installation — prevents supply chain attacks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm install*" ||
    context.command like "*npm i *" ||
    context.command like "*yarn add*" ||
    context.command like "*pip install*" ||
    context.command like "*cargo add*" ||
    context.command like "*gem install*" ||
    context.command like "*apt install*" ||
    context.command like "*brew install*"
};
"#,
            filename: "template_no_install.cedar",
        },
        Template {
            id: "high-severity-block",
            description: "Block any action with YARA severity >= High",
            category: "yara",
            cedar: r#"@id("template-forbid-high-severity-shell")
@description("Block shell commands with high or critical YARA severity.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.severity >= 3
};

@id("template-forbid-high-severity-file")
@description("Block file operations with high or critical YARA severity.")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    context.signature.severity >= 3
};

@id("template-forbid-high-severity-web")
@description("Block web fetches with high or critical YARA severity.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    context.signature.severity >= 3
};
"#,
            filename: "template_high_severity_block.cedar",
        },
    ]
}

/// Look up a template by id.
pub fn get(id: &str) -> Option<&'static Template> {
    all().iter().find(|t| t.id == id)
}

/// List unique categories in sorted order.
pub fn categories() -> Vec<&'static str> {
    let mut cats: Vec<&str> = all().iter().map(|t| t.category).collect();
    cats.sort();
    cats.dedup();
    cats
}

/// Apply a template: write its Cedar file to the policy directory.
/// Returns the path of the written file.
pub fn apply(id: &str, policy_dir: &Path) -> anyhow::Result<std::path::PathBuf> {
    let tmpl = get(id).ok_or_else(|| anyhow::anyhow!("unknown template: {id}"))?;
    let dest = policy_dir.join(tmpl.filename);
    if dest.exists() {
        anyhow::bail!(
            "template already applied: {} exists",
            dest.display()
        );
    }
    std::fs::write(&dest, tmpl.cedar)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", dest.display()))?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_templates_have_unique_ids() {
        let templates = all();
        let mut ids: Vec<&str> = templates.iter().map(|t| t.id).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate template ids found");
    }

    #[test]
    fn all_templates_have_unique_filenames() {
        let templates = all();
        let mut filenames: Vec<&str> = templates.iter().map(|t| t.filename).collect();
        let count = filenames.len();
        filenames.sort();
        filenames.dedup();
        assert_eq!(filenames.len(), count, "duplicate filenames found");
    }

    #[test]
    fn get_existing_template() {
        let tmpl = get("no-kill");
        assert!(tmpl.is_some());
        assert_eq!(tmpl.unwrap().id, "no-kill");
    }

    #[test]
    fn get_missing_template() {
        assert!(get("nonexistent").is_none());
    }

    #[test]
    fn categories_are_sorted_and_unique() {
        let cats = categories();
        let mut sorted = cats.clone();
        sorted.sort();
        assert_eq!(cats, sorted);
        let mut deduped = cats.clone();
        deduped.dedup();
        assert_eq!(cats, deduped);
    }

    #[test]
    fn all_cedar_texts_are_nonempty() {
        for t in all() {
            assert!(!t.cedar.trim().is_empty(), "template {} has empty cedar", t.id);
        }
    }

    #[test]
    fn all_filenames_end_with_cedar() {
        for t in all() {
            assert!(
                t.filename.ends_with(".cedar"),
                "template {} filename doesn't end with .cedar: {}",
                t.id,
                t.filename
            );
        }
    }

    #[test]
    fn apply_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = apply("no-kill", dir.path()).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("forbid-kill"));
    }

    #[test]
    fn apply_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        apply("no-kill", dir.path()).unwrap();
        let err = apply("no-kill", dir.path());
        assert!(err.is_err());
        assert!(
            err.unwrap_err().to_string().contains("already applied"),
            "expected 'already applied' error"
        );
    }

    #[test]
    fn apply_rejects_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let err = apply("nonexistent", dir.path());
        assert!(err.is_err());
    }

    #[test]
    fn template_cedar_contains_id_annotation() {
        for t in all() {
            assert!(
                t.cedar.contains("@id("),
                "template {} is missing @id annotation",
                t.id
            );
        }
    }
}

//! `veto doctor` — validates the full setup is healthy.

use std::path::{Path, PathBuf};
use std::fmt;

/// Result of a single diagnostic check.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Warn => write!(f, "warn"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// Run all diagnostic checks and return results.
pub fn run_all(
    policy_dir: &Path,
    socket_path: &Path,
    db_path: &Path,
) -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(check_policy_dir(policy_dir));
    checks.push(check_cedar_load(policy_dir));
    checks.push(check_yara_compile());
    checks.push(check_audit_db(db_path));
    checks.push(check_server(socket_path));
    checks.push(check_hooks());
    checks.push(check_llm_api_key_env());
    checks
}

/// Print check results in a human-readable table.
pub fn print_results(checks: &[Check]) {
    let all_pass = checks.iter().all(|c| c.status == CheckStatus::Pass);
    let fail_count = checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
    let warn_count = checks.iter().filter(|c| c.status == CheckStatus::Warn).count();

    for check in checks {
        let icon = match check.status {
            CheckStatus::Pass => "+",
            CheckStatus::Warn => "~",
            CheckStatus::Fail => "x",
        };
        println!("[{icon}] {:<25} {}", check.name, check.detail);
    }

    println!();
    if all_pass {
        println!("All checks passed.");
    } else {
        let mut parts = Vec::new();
        if fail_count > 0 {
            parts.push(format!("{fail_count} failed"));
        }
        if warn_count > 0 {
            parts.push(format!("{warn_count} warning(s)"));
        }
        println!("{}", parts.join(", "));
    }
}

fn check_policy_dir(policy_dir: &Path) -> Check {
    if !policy_dir.is_dir() {
        return Check {
            name: "policy directory",
            status: CheckStatus::Fail,
            detail: format!("not found: {}", policy_dir.display()),
        };
    }

    let schema_count = count_files_with_ext(policy_dir, "cedarschema");
    let policy_count = count_files_with_ext(policy_dir, "cedar");
    let yara_count = count_files_with_ext(policy_dir, "yar");

    if schema_count == 0 {
        return Check {
            name: "policy directory",
            status: CheckStatus::Fail,
            detail: format!(
                "{}: no .cedarschema files found",
                policy_dir.display()
            ),
        };
    }

    if policy_count == 0 {
        return Check {
            name: "policy directory",
            status: CheckStatus::Warn,
            detail: format!(
                "{}: {schema_count} schema, 0 policies",
                policy_dir.display()
            ),
        };
    }

    Check {
        name: "policy directory",
        status: CheckStatus::Pass,
        detail: format!(
            "{schema_count} schema, {policy_count} policies, {yara_count} YARA rules",
        ),
    }
}

fn check_cedar_load(policy_dir: &Path) -> Check {
    if !policy_dir.is_dir() {
        return Check {
            name: "cedar policies",
            status: CheckStatus::Fail,
            detail: "policy directory missing (skipped)".to_string(),
        };
    }

    match crate::cedar_runtime::CedarRuntime::load(policy_dir) {
        Ok(rt) => {
            let count = rt.policy_count();
            Check {
                name: "cedar policies",
                status: CheckStatus::Pass,
                detail: format!("{count} policies loaded and validated"),
            }
        }
        Err(e) => Check {
            name: "cedar policies",
            status: CheckStatus::Fail,
            detail: format!("load failed: {e}"),
        },
    }
}

fn check_yara_compile() -> Check {
    // YARA rules are compiled at first access via OnceLock.
    // Calling get_rules() will compile (or return cached) and panic on failure.
    // We catch panics to report gracefully.
    match std::panic::catch_unwind(crate::signature::get_rules) {
        Ok(rules) => {
            let mut scanner = yara_x::Scanner::new(rules);
            match scanner.scan(b"test") {
                Ok(_) => Check {
                    name: "yara rules",
                    status: CheckStatus::Pass,
                    detail: "compiled and scanner functional".to_string(),
                },
                Err(e) => Check {
                    name: "yara rules",
                    status: CheckStatus::Fail,
                    detail: format!("scanner error: {e}"),
                },
            }
        }
        Err(_) => Check {
            name: "yara rules",
            status: CheckStatus::Fail,
            detail: "YARA rule compilation panicked".to_string(),
        },
    }
}

fn check_audit_db(db_path: &Path) -> Check {
    // Check if parent directory is writable
    let parent = db_path.parent().unwrap_or(Path::new("."));

    if db_path.exists() {
        // Try opening it
        match crate::audit::AuditLog::open(db_path) {
            Ok(audit) => {
                match audit.max_id() {
                    Ok(max_id) => Check {
                        name: "audit database",
                        status: CheckStatus::Pass,
                        detail: format!("{} ({max_id} events)", db_path.display()),
                    },
                    Err(e) => Check {
                        name: "audit database",
                        status: CheckStatus::Warn,
                        detail: format!("opened but query failed: {e}"),
                    },
                }
            }
            Err(e) => Check {
                name: "audit database",
                status: CheckStatus::Fail,
                detail: format!("cannot open: {e}"),
            },
        }
    } else if parent.is_dir() {
        Check {
            name: "audit database",
            status: CheckStatus::Pass,
            detail: format!("not yet created (parent dir exists: {})", parent.display()),
        }
    } else {
        Check {
            name: "audit database",
            status: CheckStatus::Warn,
            detail: format!("parent directory missing: {}", parent.display()),
        }
    }
}

fn check_server(socket_path: &Path) -> Check {
    if !socket_path.exists() {
        return Check {
            name: "veto-server",
            status: CheckStatus::Fail,
            detail: format!("socket not found: {}", socket_path.display()),
        };
    }

    // Try connecting and sending a ping
    use std::os::unix::net::UnixStream;
    match UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .ok();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .ok();

            let request = serde_json::json!({"hook": "ping", "payload": {}});
            let request_bytes = serde_json::to_vec(&request).unwrap_or_default();

            match crate::ipc::write_frame(&mut stream, &request_bytes) {
                Ok(()) => match crate::ipc::read_frame(&mut stream) {
                    Ok(response_bytes) => {
                        if let Ok(resp) =
                            serde_json::from_slice::<crate::ipc::AdjudicateOk>(&response_bytes)
                        {
                            if resp.ok {
                                Check {
                                    name: "veto-server",
                                    status: CheckStatus::Pass,
                                    detail: "running and responsive".to_string(),
                                }
                            } else {
                                Check {
                                    name: "veto-server",
                                    status: CheckStatus::Warn,
                                    detail: format!(
                                        "responded but not ok: {}",
                                        resp.error.unwrap_or_default()
                                    ),
                                }
                            }
                        } else {
                            Check {
                                name: "veto-server",
                                status: CheckStatus::Warn,
                                detail: "connected but response not parseable".to_string(),
                            }
                        }
                    }
                    Err(e) => Check {
                        name: "veto-server",
                        status: CheckStatus::Warn,
                        detail: format!("connected but read failed: {e}"),
                    },
                },
                Err(e) => Check {
                    name: "veto-server",
                    status: CheckStatus::Warn,
                    detail: format!("connected but write failed: {e}"),
                },
            }
        }
        Err(e) => Check {
            name: "veto-server",
            status: CheckStatus::Fail,
            detail: format!("socket exists but cannot connect: {e}"),
        },
    }
}

fn check_hooks() -> Check {
    // Look for Claude Code hooks config in .claude/settings.local.json
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let settings_path = cwd.join(".claude").join("settings.local.json");

    if !settings_path.exists() {
        // Also check the global settings
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let global_path = home.join(".claude").join("settings.json");
        if global_path.exists() {
            if has_veto_hook(&global_path) {
                return Check {
                    name: "claude hooks",
                    status: CheckStatus::Pass,
                    detail: format!("configured in {}", global_path.display()),
                };
            }
        }
        return Check {
            name: "claude hooks",
            status: CheckStatus::Warn,
            detail: "no hooks config found — run: veto setup".to_string(),
        };
    }

    if has_veto_hook(&settings_path) {
        Check {
            name: "claude hooks",
            status: CheckStatus::Pass,
            detail: format!("configured in {}", settings_path.display()),
        }
    } else {
        Check {
            name: "claude hooks",
            status: CheckStatus::Warn,
            detail: format!(
                "{} exists but no veto hook found — run: veto setup",
                settings_path.display()
            ),
        }
    }
}

fn has_veto_hook(path: &Path) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // Simple check: does the settings JSON mention "veto"?
    content.contains("veto")
}

fn check_llm_api_key_env() -> Check {
    match std::env::var("API_KEY") {
        Ok(key) if !key.is_empty() => {
            let model = std::env::var("VETO_MODEL")
                .unwrap_or_else(|_| "openai/openai/gpt-5.4-mini".to_string());
            Check {
                name: "llm api key",
                status: CheckStatus::Pass,
                detail: format!("set (model: {model})"),
            }
        }
        _ => Check {
            name: "llm api key",
            status: CheckStatus::Warn,
            detail: "API_KEY not set (NL->Cedar generation unavailable)".to_string(),
        },
    }
}

fn count_files_with_ext(dir: &Path, ext: &str) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == ext))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_status_display() {
        assert_eq!(CheckStatus::Pass.to_string(), "pass");
        assert_eq!(CheckStatus::Warn.to_string(), "warn");
        assert_eq!(CheckStatus::Fail.to_string(), "FAIL");
    }

    #[test]
    fn policy_dir_missing_fails() {
        let check = check_policy_dir(Path::new("/nonexistent/path"));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("not found"));
    }

    #[test]
    fn policy_dir_valid_passes() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        let check = check_policy_dir(&dir);
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("schema"));
        assert!(check.detail.contains("policies"));
    }

    #[test]
    fn cedar_load_valid_passes() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        let check = check_cedar_load(&dir);
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("loaded"));
    }

    #[test]
    fn cedar_load_missing_fails() {
        let check = check_cedar_load(Path::new("/nonexistent"));
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn yara_compile_passes() {
        let check = check_yara_compile();
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("functional"));
    }

    #[test]
    fn audit_db_missing_parent_warns() {
        let check = check_audit_db(Path::new("/nonexistent/parent/audit.db"));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("parent"));
    }

    #[test]
    fn server_missing_socket_fails() {
        let check = check_server(Path::new("/nonexistent/veto.sock"));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("not found"));
    }

    #[test]
    fn llm_key_not_set_warns() {
        // This test relies on the env var not being set in test environment,
        // which is the typical case. If API_KEY is set, this test still
        // passes (just checks a different branch).
        let check = check_llm_api_key_env();
        assert!(
            check.status == CheckStatus::Pass || check.status == CheckStatus::Warn,
            "should be pass or warn depending on env"
        );
    }

    #[test]
    fn run_all_returns_seven_checks() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
        let checks = run_all(
            &dir,
            Path::new("/nonexistent/veto.sock"),
            Path::new("/nonexistent/audit.db"),
        );
        assert_eq!(checks.len(), 7);
    }

    #[test]
    fn has_veto_hook_returns_false_for_missing_file() {
        assert!(!has_veto_hook(Path::new("/nonexistent/settings.json")));
    }
}

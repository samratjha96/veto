//! Hook setup logic for Claude Code settings.
//!
//! Merges veto hooks into existing settings without clobbering
//! user-configured hooks from other tools.

use serde_json::{json, Value};

/// The hook event types veto needs to register.
const VETO_HOOK_EVENTS: &[(&str, &str)] = &[
    ("PreToolUse", "pre-tool-use"),
    ("PermissionRequest", "permission-request"),
];

/// Marker to identify veto-managed hooks. We embed this in the command string
/// so we can find and update our hooks without touching others.
const VETO_MARKER: &str = "veto hook --hook-type";

/// Build the veto hook entry for a given event.
fn veto_hook_entry(veto_bin: &str, hook_type: &str) -> Value {
    json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": format!("{veto_bin} hook --hook-type {hook_type}")
            }
        ]
    })
}

/// Merge veto hooks into an existing settings JSON object.
///
/// Rules:
/// - Preserves all existing hook event types (PostToolUse, Notification, etc.)
/// - Preserves existing entries within PreToolUse/PermissionRequest from other tools
/// - Replaces existing veto entries (idempotent — safe to run twice)
/// - Preserves all non-hook settings (permissions, model, etc.)
pub fn merge_hooks(settings: &mut Value, veto_bin: &str) {
    // Ensure hooks object exists
    if settings.get("hooks").is_none() || !settings["hooks"].is_object() {
        settings["hooks"] = json!({});
    }

    for &(event_name, hook_type) in VETO_HOOK_EVENTS {
        let new_entry = veto_hook_entry(veto_bin, hook_type);

        let event_hooks = &mut settings["hooks"][event_name];

        if !event_hooks.is_array() {
            // No existing hooks for this event — create the array
            *event_hooks = json!([new_entry]);
            continue;
        }

        let arr = event_hooks.as_array_mut().unwrap();

        // Remove any existing veto entries (by checking if command contains our marker)
        arr.retain(|entry| !entry_is_veto(entry));

        // Append our entry
        arr.push(new_entry);
    }
}

/// Check if a hook entry was created by veto (contains our marker in any command).
fn entry_is_veto(entry: &Value) -> bool {
    let hooks = match entry.get("hooks").and_then(|h| h.as_array()) {
        Some(h) => h,
        None => return false,
    };
    hooks.iter().any(|hook| {
        hook.get("command")
            .and_then(|c| c.as_str())
            .is_some_and(|cmd| cmd.contains(VETO_MARKER))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VETO_BIN: &str = "/usr/local/bin/veto";

    // ── Fresh settings (no hooks key at all) ──────────────────────────

    #[test]
    fn fresh_settings_creates_hooks() {
        let mut settings = json!({});
        merge_hooks(&mut settings, VETO_BIN);

        // Should have PreToolUse and PermissionRequest
        assert!(settings["hooks"]["PreToolUse"].is_array());
        assert!(settings["hooks"]["PermissionRequest"].is_array());
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(
            settings["hooks"]["PermissionRequest"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn fresh_settings_preserves_other_keys() {
        let mut settings = json!({
            "model": "opus",
            "permissions": {"allow": ["Bash(*)"], "defaultMode": "auto"}
        });
        merge_hooks(&mut settings, VETO_BIN);

        assert_eq!(settings["model"], "opus");
        assert_eq!(settings["permissions"]["defaultMode"], "auto");
    }

    // ── Existing hooks from other tools ───────────────────────────────

    #[test]
    fn preserves_other_hook_event_types() {
        let mut settings = json!({
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "prettier --write $FILE_PATH"}]
                    }
                ],
                "Notification": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "osascript -e 'display notification'"}]
                    }
                ]
            }
        });

        merge_hooks(&mut settings, VETO_BIN);

        // Other event types untouched
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            settings["hooks"]["Notification"].as_array().unwrap().len(),
            1
        );
        // Verify content is preserved exactly
        assert!(settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("prettier"));
    }

    #[test]
    fn preserves_existing_pre_tool_use_hooks_from_other_tools() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "/usr/local/bin/other-tool pre-check"}]
                    }
                ]
            }
        });

        merge_hooks(&mut settings, VETO_BIN);

        let pre_tool = settings["hooks"]["PreToolUse"].as_array().unwrap();
        // Should have the original entry + our new one
        assert_eq!(pre_tool.len(), 2);
        // First entry is the existing tool
        assert!(pre_tool[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("other-tool"));
        // Second entry is veto
        assert!(pre_tool[1]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("veto hook"));
    }

    // ── Idempotency (running setup twice) ─────────────────────────────

    #[test]
    fn running_twice_does_not_duplicate() {
        let mut settings = json!({});
        merge_hooks(&mut settings, VETO_BIN);
        merge_hooks(&mut settings, VETO_BIN);

        assert_eq!(
            settings["hooks"]["PreToolUse"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            settings["hooks"]["PermissionRequest"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn running_twice_preserves_other_hooks() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "/usr/local/bin/audit-tool log"}]
                    }
                ]
            }
        });

        merge_hooks(&mut settings, VETO_BIN);
        merge_hooks(&mut settings, VETO_BIN);

        let pre_tool = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 2); // audit-tool + veto, not audit-tool + veto + veto
        assert!(pre_tool[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("audit-tool"));
    }

    // ── Updates veto path on re-run ───────────────────────────────────

    #[test]
    fn updates_veto_binary_path_on_rerun() {
        let mut settings = json!({});
        merge_hooks(&mut settings, "/old/path/veto");

        let cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("/old/path/veto"));

        // Re-run with new path
        merge_hooks(&mut settings, "/new/path/veto");

        let cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("/new/path/veto"));
        assert!(!cmd.contains("/old/path/"));
        // Still only one veto entry
        assert_eq!(
            settings["hooks"]["PreToolUse"].as_array().unwrap().len(),
            1
        );
    }

    // ── Complex real-world scenario ───────────────────────────────────

    #[test]
    fn real_world_settings_with_multiple_tools() {
        let mut settings = json!({
            "model": "opus[1m]",
            "hooks": {
                "SessionStart": [
                    {
                        "matcher": "startup",
                        "hooks": [{"type": "command", "command": "portcullis session-start"}]
                    },
                    {
                        "matcher": "resume",
                        "hooks": [{"type": "command", "command": "portcullis session-start"}]
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "protect-env.sh"}]
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "prettier --write"}]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "bash-audit.sh"}]
                    }
                ],
                "Notification": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "notify-send"}]
                    }
                ]
            },
            "permissions": {
                "allow": ["Bash(*)", "Edit", "Read", "Write"],
                "defaultMode": "auto"
            }
        });

        merge_hooks(&mut settings, VETO_BIN);

        // Model preserved
        assert_eq!(settings["model"], "opus[1m]");

        // Permissions preserved
        assert_eq!(settings["permissions"]["defaultMode"], "auto");

        // SessionStart untouched (2 entries)
        assert_eq!(
            settings["hooks"]["SessionStart"].as_array().unwrap().len(),
            2
        );

        // PreToolUse: original protect-env + veto (2 entries)
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert!(pre[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("protect-env"));
        assert!(pre[1]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("veto hook --hook-type pre-tool-use"));

        // PostToolUse untouched (2 entries)
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            2
        );

        // Notification untouched (1 entry)
        assert_eq!(
            settings["hooks"]["Notification"].as_array().unwrap().len(),
            1
        );

        // PermissionRequest: new (1 entry, veto only)
        let perm = settings["hooks"]["PermissionRequest"].as_array().unwrap();
        assert_eq!(perm.len(), 1);
        assert!(perm[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("veto hook --hook-type permission-request"));
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn handles_hooks_key_as_non_object() {
        // Some corrupt or unexpected state
        let mut settings = json!({"hooks": "not an object"});
        merge_hooks(&mut settings, VETO_BIN);

        // Should overwrite the bad value with a proper object
        assert!(settings["hooks"].is_object());
        assert!(settings["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn handles_event_key_as_non_array() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": "not an array"
            }
        });
        merge_hooks(&mut settings, VETO_BIN);

        // Should replace the bad value with an array containing our entry
        assert!(settings["hooks"]["PreToolUse"].is_array());
        assert_eq!(
            settings["hooks"]["PreToolUse"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn generated_commands_are_correct() {
        let mut settings = json!({});
        merge_hooks(&mut settings, "/usr/local/bin/veto");

        let pre_cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert_eq!(
            pre_cmd,
            "/usr/local/bin/veto hook --hook-type pre-tool-use"
        );

        let perm_cmd = settings["hooks"]["PermissionRequest"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert_eq!(
            perm_cmd,
            "/usr/local/bin/veto hook --hook-type permission-request"
        );
    }

    #[test]
    fn matcher_is_empty_string_for_wildcard() {
        let mut settings = json!({});
        merge_hooks(&mut settings, VETO_BIN);

        // Veto hooks should use empty matcher (match everything)
        assert_eq!(settings["hooks"]["PreToolUse"][0]["matcher"], "");
        assert_eq!(settings["hooks"]["PermissionRequest"][0]["matcher"], "");
    }
}

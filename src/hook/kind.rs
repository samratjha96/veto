//! Hook event types from Claude Code.

use std::fmt;

/// The type of hook event being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookKind {
    /// User prompt submission.
    UserTurn,
    /// Before a tool executes (pre-tool-use).
    BeforeTool,
    /// After a tool executes successfully (post-tool-use).
    AfterTool,
    /// After a tool errors.
    AfterToolError,
    /// Permission prompt for a tool.
    PermissionPrompt,
    /// Notification event.
    Notify,
    /// Session opened.
    SessionOpen,
    /// Session closed.
    SessionClose,
    /// Unknown hook type.
    Other(String),
}

impl HookKind {
    pub fn from_hook_str(s: &str) -> Self {
        match s {
            "UserPromptSubmit" | "user-prompt-submit" => Self::UserTurn,
            "PreToolUse" | "pre-tool-use" => Self::BeforeTool,
            "PostToolUse" | "post-tool-use" => Self::AfterTool,
            "PostToolUseError" | "post-tool-use-error" => Self::AfterToolError,
            "PermissionRequest" | "permission-request" => Self::PermissionPrompt,
            "Notification" | "notification" | "notify" => Self::Notify,
            "SessionStart" | "session-start" => Self::SessionOpen,
            "SessionEnd" | "session-end" => Self::SessionClose,
            other => Self::Other(other.to_string()),
        }
    }

    /// Map hook kind to a Cedar action name.
    pub fn cedar_action(&self, tool_name: Option<&str>) -> &'static str {
        match self {
            Self::BeforeTool | Self::PermissionPrompt => match tool_name {
                Some("Bash") => "ShellCommand",
                Some("WebFetch") => "WebFetch",
                Some("Read") => "FileRead",
                Some("Write") => "FileWrite",
                Some("Edit") => "FileEdit",
                Some("Delete") | Some("FileDelete") => "FileDelete",
                _ => "ShellCommand", // default for unknown tools
            },
            Self::AfterTool | Self::AfterToolError => "ShellCommand",
            Self::UserTurn => "ShellCommand",
            Self::Notify | Self::SessionOpen | Self::SessionClose | Self::Other(_) => {
                "ShellCommand"
            }
        }
    }
}

impl fmt::Display for HookKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserTurn => write!(f, "UserTurn"),
            Self::BeforeTool => write!(f, "BeforeTool"),
            Self::AfterTool => write!(f, "AfterTool"),
            Self::AfterToolError => write!(f, "AfterToolError"),
            Self::PermissionPrompt => write!(f, "PermissionPrompt"),
            Self::Notify => write!(f, "Notify"),
            Self::SessionOpen => write!(f, "SessionOpen"),
            Self::SessionClose => write!(f, "SessionClose"),
            Self::Other(s) => write!(f, "Other({s})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hook_strings() {
        assert_eq!(
            HookKind::from_hook_str("pre-tool-use"),
            HookKind::BeforeTool
        );
        assert_eq!(
            HookKind::from_hook_str("PreToolUse"),
            HookKind::BeforeTool
        );
        assert_eq!(
            HookKind::from_hook_str("post-tool-use"),
            HookKind::AfterTool
        );
        assert_eq!(
            HookKind::from_hook_str("user-prompt-submit"),
            HookKind::UserTurn
        );
    }

    #[test]
    fn cedar_action_for_bash() {
        assert_eq!(
            HookKind::BeforeTool.cedar_action(Some("Bash")),
            "ShellCommand"
        );
    }

    #[test]
    fn cedar_action_for_file_ops() {
        assert_eq!(HookKind::BeforeTool.cedar_action(Some("Read")), "FileRead");
        assert_eq!(
            HookKind::BeforeTool.cedar_action(Some("Write")),
            "FileWrite"
        );
        assert_eq!(HookKind::BeforeTool.cedar_action(Some("Edit")), "FileEdit");
    }

    #[test]
    fn unknown_hook_becomes_other() {
        assert!(matches!(
            HookKind::from_hook_str("something-new"),
            HookKind::Other(_)
        ));
    }
}

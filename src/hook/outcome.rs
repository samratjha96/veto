//! Verdict types returned by the adjudication pipeline.

use std::fmt;

/// Final verdict for a hook event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Action is allowed to proceed.
    Allow,
    /// Action is denied with a reason.
    Deny { reason: String },
    /// Action requires human confirmation.
    Ask { reason: String },
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny { .. } => "deny",
            Self::Ask { .. } => "ask",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } | Self::Ask { reason } => Some(reason),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny { reason } => write!(f, "deny: {reason}"),
            Self::Ask { reason } => write!(f, "ask: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_as_str() {
        assert_eq!(Verdict::Allow.as_str(), "allow");
        assert_eq!(
            Verdict::Deny {
                reason: "bad".into()
            }
            .as_str(),
            "deny"
        );
        assert_eq!(
            Verdict::Ask {
                reason: "risky".into()
            }
            .as_str(),
            "ask"
        );
    }

    #[test]
    fn verdict_reason() {
        assert_eq!(Verdict::Allow.reason(), None);
        assert_eq!(
            Verdict::Deny {
                reason: "nope".into()
            }
            .reason(),
            Some("nope")
        );
    }
}

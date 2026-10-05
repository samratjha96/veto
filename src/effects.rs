//! What a command does to files, in terms policies already guard.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectKind {
    Write,
    Delete,
}

impl EffectKind {
    /// The tool name whose Cedar action carries the same file policies.
    pub fn tool_name(self) -> &'static str {
        match self {
            Self::Write => "Write",
            Self::Delete => "FileDelete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub kind: EffectKind,
    pub path: String,
}

/// Resolves `.`, `..` and repeated slashes without touching the filesystem, so
/// `/etc/./passwd` and `/tmp/../etc/passwd` reach the policy as `/etc/passwd`.
/// A relative path is joined to `cwd`, or gets a `./` prefix when `cwd` is unknown
/// so directory-based policies like `*/.git/hooks/*` still match.
pub fn normalize_path(path: &str, cwd: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let rooted = path.starts_with('/') || path.starts_with('~');
    let joined;
    let path = if rooted || cwd.is_empty() {
        path
    } else {
        joined = format!("{cwd}/{path}");
        &joined
    };
    let absolute = path.starts_with('/');

    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                // The home directory's parent is unknown, so keep the `..`.
                Some(&last) if last != ".." && last != "~" => {
                    parts.pop();
                }
                _ if absolute => {}
                _ => parts.push(".."),
            },
            part => parts.push(part),
        }
    }

    let body = parts.join("/");
    if absolute {
        format!("/{body}")
    } else if rooted || parts.first() == Some(&"..") {
        body
    } else {
        format!("./{body}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_dotdot_and_slashes_collapse() {
        for path in [
            "/etc/./passwd",
            "//etc/passwd",
            "/tmp/../etc/passwd",
            "/etc/passwd/",
        ] {
            assert_eq!(normalize_path(path, ""), "/etc/passwd", "{path}");
        }
        assert_eq!(
            normalize_path("/home/u/.ssh/../.ssh/id_rsa", ""),
            "/home/u/.ssh/id_rsa"
        );
        assert_eq!(normalize_path("/../etc", ""), "/etc");
    }

    #[test]
    fn home_prefix_is_kept() {
        assert_eq!(normalize_path("~/./.bashrc", ""), "~/.bashrc");
        assert_eq!(normalize_path("~/x/../.zshrc", ""), "~/.zshrc");
        assert_eq!(normalize_path("~/../x", ""), "~/../x");
    }

    #[test]
    fn relative_paths_join_the_working_directory() {
        assert_eq!(
            normalize_path(".git/hooks/pre-commit", "/repo"),
            "/repo/.git/hooks/pre-commit"
        );
        assert_eq!(normalize_path("../x", "/repo/sub"), "/repo/x");
    }

    #[test]
    fn relative_paths_without_a_working_directory_keep_a_slash() {
        assert_eq!(
            normalize_path(".git/hooks/pre-commit", ""),
            "./.git/hooks/pre-commit"
        );
        assert_eq!(normalize_path("../x", ""), "../x");
    }
}

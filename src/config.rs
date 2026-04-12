//! Environment-based configuration.

use std::path::PathBuf;

pub struct Config {
    pub policy_dir: PathBuf,
    pub socket_path: PathBuf,
    pub db_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let veto_dir = home.join(".veto");

        Self {
            policy_dir: std::env::var("VETO_POLICY_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./policies")),
            socket_path: std::env::var("VETO_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|_| veto_dir.join("veto.sock")),
            db_path: std::env::var("VETO_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| veto_dir.join("audit.db")),
        }
    }
}

/// Base URL for OpenAI-compatible chat completions (`.../v1` — no trailing slash).
///
/// Used by `veto policy add`. Defaults to `https://api.openai.com/v1` when unset.
pub fn llm_gateway_base_url() -> String {
    let raw = std::env::var("LLM_GATEWAY_BASE_URL").unwrap_or_else(|_| {
        "https://api.openai.com/v1".to_string()
    });
    normalize_llm_base_url(&raw)
}

fn normalize_llm_base_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_llm_base_url_trims() {
        assert_eq!(
            normalize_llm_base_url(" https://example.com/v1/  "),
            "https://example.com/v1"
        );
    }
}

//! Environment-based configuration.

use std::path::PathBuf;

pub struct Config {
    pub policy_dir: PathBuf,
    pub socket_path: PathBuf,
    pub db_path: PathBuf,
    pub llm_api_key_env: Option<String>,
    pub model: String,
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
            llm_api_key_env: std::env::var("API_KEY").ok(),
            model: std::env::var("VETO_MODEL")
                .unwrap_or_else(|_| "openai/openai/gpt-5.4-mini".to_string()),
        }
    }
}

//! veto CLI: thin client for the veto-server daemon.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use veto::ipc::{self, AdjudicateOk};

#[derive(Parser)]
#[command(name = "veto", about = "Policy daemon client for AI coding agents")]
struct Cli {
    /// Path to Unix socket
    #[arg(long, env = "VETO_SOCKET")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Forward a Claude hook event from stdin to the server
    Hook {
        /// Hook type (e.g., pre-tool-use)
        #[arg(long)]
        hook_type: String,
    },
    /// Reload policies on the server
    Reload,
    /// Check server status
    Status,
    /// Ping server
    Ping,
    /// Manage policies
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Generate a Cedar policy from natural language
    Add {
        /// Natural language description of the policy
        description: String,
    },
}

fn socket_path(cli_socket: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = cli_socket {
        return p.clone();
    }
    if let Ok(p) = std::env::var("VETO_SOCKET") {
        return PathBuf::from(p);
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".veto/veto.sock")
}

fn policy_dir() -> PathBuf {
    std::env::var("VETO_POLICY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./policies"))
}

fn send_request(socket: &std::path::Path, request_json: &[u8]) -> Result<AdjudicateOk> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to {}", socket.display()))?;

    ipc::write_frame(&mut stream, request_json).context("write request")?;
    let response_bytes = ipc::read_frame(&mut stream).context("read response")?;
    let response: AdjudicateOk =
        serde_json::from_slice(&response_bytes).context("parse response")?;
    Ok(response)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket = socket_path(cli.socket.as_ref());

    match cli.command {
        Commands::Hook { hook_type } => {
            let mut stdin_buf = String::new();
            std::io::stdin()
                .read_to_string(&mut stdin_buf)
                .context("read stdin")?;

            let payload: serde_json::Value =
                serde_json::from_str(&stdin_buf).context("parse stdin JSON")?;

            let request = json!({
                "hook": hook_type,
                "payload": payload,
            });
            let request_bytes = serde_json::to_vec(&request)?;
            let response = send_request(&socket, &request_bytes)?;

            // Output the hook response (what Claude Code expects)
            if let Some(hook_resp) = &response.response {
                let output = serde_json::to_string(hook_resp)?;
                println!("{output}");
            } else if let Some(err) = &response.error {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        Commands::Reload => {
            let request = json!({"hook": "reload", "payload": {}});
            let request_bytes = serde_json::to_vec(&request)?;
            let response = send_request(&socket, &request_bytes)?;
            if response.ok {
                if let Some(data) = response.data {
                    println!("Reloaded: {}", serde_json::to_string_pretty(&data)?);
                } else {
                    println!("Reloaded successfully");
                }
            } else {
                eprintln!("Error: {}", response.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Commands::Status => {
            let request = json!({"hook": "status", "payload": {}});
            let request_bytes = serde_json::to_vec(&request)?;
            let response = send_request(&socket, &request_bytes)?;
            if let Some(data) = response.data {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else if let Some(err) = response.error {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        Commands::Ping => {
            let request = json!({"hook": "ping", "payload": {}});
            let request_bytes = serde_json::to_vec(&request)?;
            let response = send_request(&socket, &request_bytes)?;
            if response.ok {
                println!("pong");
            } else {
                eprintln!("Error: {}", response.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Commands::Policy { command } => match command {
            PolicyCommands::Add { description } => {
                // Build an async runtime for this one-shot operation
                let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
                rt.block_on(handle_policy_add(&description, &socket))?;
            }
        },
    }

    Ok(())
}

async fn handle_policy_add(description: &str, socket: &std::path::Path) -> Result<()> {
    let api_key = std::env::var("API_KEY")
        .context("API_KEY env var required for policy generation")?;
    let model = std::env::var("VETO_MODEL")
        .unwrap_or_else(|_| "openai/openai/gpt-5.4-mini".to_string());

    let llm = veto::llm::LlmClient::new(&api_key, &model);
    let dir = policy_dir();

    eprintln!("Generating Cedar policy from: \"{description}\"");
    eprintln!("Using model: {model}");

    let generated = veto::policy_gen::generate(&llm, &dir, description).await?;

    // Validate the generated policy
    match veto::policy_gen::validate_policy(&generated.cedar_text, &dir) {
        Ok(()) => {
            eprintln!("Policy validates against schema.");
        }
        Err(e) => {
            eprintln!("WARNING: Generated policy may have validation issues: {e}");
            eprintln!("Proceeding anyway — you can edit the file after saving.");
        }
    }

    // Display the policy
    println!("\n--- Generated Policy: {} ---\n", generated.policy_id);
    println!("{}", generated.cedar_text);
    println!("\n--- End Policy ---\n");

    // Ask for confirmation
    eprint!("Save to {}/{}? [Enter to confirm, Ctrl+C to cancel] ", dir.display(), generated.file_name);

    let mut confirm = String::new();
    std::io::stdin()
        .read_line(&mut confirm)
        .context("read confirmation")?;

    // Write the policy file
    let policy_path = dir.join(&generated.file_name);
    std::fs::write(&policy_path, &generated.cedar_text)
        .with_context(|| format!("write {}", policy_path.display()))?;
    eprintln!("Saved: {}", policy_path.display());

    // Try to notify the server to reload
    let request = serde_json::json!({"hook": "reload", "payload": {}});
    let request_bytes = serde_json::to_vec(&request)?;
    match send_request(socket, &request_bytes) {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                let count = data["policy_count"].as_i64().unwrap_or(0);
                eprintln!("Server reloaded: {count} policies active");
            }
        }
        Ok(resp) => {
            eprintln!(
                "Server reload failed: {}",
                resp.error.unwrap_or_default()
            );
        }
        Err(_) => {
            eprintln!("Note: could not reach veto-server for reload (file watcher will pick up the change)");
        }
    }

    Ok(())
}

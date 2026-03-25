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
    }

    Ok(())
}

//! veto CLI: thin client for the veto-server daemon.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use veto::audit::AuditLog;
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
    /// Generate Claude Code hooks configuration
    Setup {
        /// Print config to stdout instead of writing to settings file
        #[arg(long)]
        print: bool,
    },
    /// Query the audit log
    Audit {
        /// Max events to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Filter by decision (allow, deny, ask)
        #[arg(long)]
        decision: Option<String>,
        /// Filter by hook type (e.g. pre-tool-use)
        #[arg(long, name = "hook-type")]
        hook_type: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Stream new events as they arrive (like tail -f)
        #[arg(long)]
        tail: bool,
        /// Poll interval in seconds for --tail mode
        #[arg(long, default_value = "1")]
        interval: u64,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Generate a Cedar policy from natural language
    Add {
        /// Natural language description of the policy
        description: String,
        /// Print generated policy without saving
        #[arg(long)]
        dry_run: bool,
    },
    /// List loaded Cedar policies
    List,
    /// Remove a Cedar policy file
    Remove {
        /// Policy filename (with or without .cedar extension)
        name: String,
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

fn db_path() -> PathBuf {
    std::env::var("VETO_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home.join(".veto/audit.db")
        })
}

fn send_request(socket: &std::path::Path, request_json: &[u8]) -> Result<AdjudicateOk> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow::anyhow!(
                    "veto-server is not running (socket not found: {})\n\
                     Start it with: veto-server",
                    socket.display()
                )
            }
            std::io::ErrorKind::ConnectionRefused => {
                anyhow::anyhow!(
                    "veto-server socket exists but connection refused ({})\n\
                     The server may have crashed. Try restarting: veto-server",
                    socket.display()
                )
            }
            _ => {
                anyhow::anyhow!("connect to {}: {e}", socket.display())
            }
        }
    })?;

    // Set timeouts to avoid hanging indefinitely
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

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
            PolicyCommands::Add { description, dry_run } => {
                let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
                rt.block_on(handle_policy_add(&description, &socket, dry_run))?;
            }
            PolicyCommands::List => {
                handle_policy_list()?;
            }
            PolicyCommands::Remove { name } => {
                handle_policy_remove(&name, &socket)?;
            }
        },
        Commands::Setup { print } => {
            handle_setup(print)?;
        }
        Commands::Audit {
            limit,
            decision,
            hook_type,
            json,
            tail,
            interval,
        } => {
            if tail {
                handle_audit_tail(
                    limit,
                    decision.as_deref(),
                    hook_type.as_deref(),
                    json,
                    interval,
                )?;
            } else {
                handle_audit(limit, decision.as_deref(), hook_type.as_deref(), json)?;
            }
        }
    }

    Ok(())
}

async fn handle_policy_add(description: &str, socket: &std::path::Path, dry_run: bool) -> Result<()> {
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

    if dry_run {
        eprintln!("(dry-run: not saving)");
        return Ok(());
    }

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

fn handle_policy_list() -> Result<()> {
    let dir = policy_dir();
    if !dir.is_dir() {
        bail!("Policy directory not found: {}", dir.display());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "cedar")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        println!("No .cedar policy files in {}", dir.display());
        return Ok(());
    }

    for entry in &entries {
        let path = entry.path();
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let content = std::fs::read_to_string(&path).unwrap_or_default();

        // Extract @id annotations
        let ids: Vec<&str> = content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("@id(\"") && trimmed.ends_with("\")") {
                    Some(&trimmed[5..trimmed.len() - 2])
                } else {
                    None
                }
            })
            .collect();

        if ids.is_empty() {
            println!("  {filename}  (no @id annotations)");
        } else {
            println!("  {filename}");
            for id in ids {
                println!("    - {id}");
            }
        }
    }

    Ok(())
}

fn handle_policy_remove(name: &str, socket: &std::path::Path) -> Result<()> {
    let dir = policy_dir();
    let filename = if name.ends_with(".cedar") {
        name.to_string()
    } else {
        format!("{name}.cedar")
    };
    let path = dir.join(&filename);

    if !path.exists() {
        bail!("Policy file not found: {}", path.display());
    }

    // Show what we're about to delete
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    eprintln!("--- {} ---", filename);
    eprintln!("{content}");
    eprintln!("--- end ---\n");

    eprint!("Delete {}? [Enter to confirm, Ctrl+C to cancel] ", path.display());
    let mut confirm = String::new();
    std::io::stdin()
        .read_line(&mut confirm)
        .context("read confirmation")?;

    std::fs::remove_file(&path)
        .with_context(|| format!("delete {}", path.display()))?;
    eprintln!("Deleted: {}", path.display());

    // Try to reload server
    let request = json!({"hook": "reload", "payload": {}});
    let request_bytes = serde_json::to_vec(&request)?;
    match send_request(socket, &request_bytes) {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                let count = data["policy_count"].as_i64().unwrap_or(0);
                eprintln!("Server reloaded: {count} policies active");
            }
        }
        Ok(_) | Err(_) => {
            eprintln!("Note: could not reload server (file watcher will pick up the change)");
        }
    }

    Ok(())
}

fn handle_setup(print_only: bool) -> Result<()> {
    // Find the veto binary path
    let veto_bin = std::env::current_exe().context("determine veto binary path")?;
    let veto_bin_str = veto_bin.display().to_string();

    let hooks_config = serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": format!("{veto_bin_str} hook --hook-type pre-tool-use")
                        }
                    ]
                }
            ]
        }
    });

    if print_only {
        println!("{}", serde_json::to_string_pretty(&hooks_config)?);
        return Ok(());
    }

    // Determine target settings file
    let settings_path = std::env::current_dir()
        .context("get current directory")?
        .join(".claude")
        .join("settings.local.json");

    // Read existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("read {}", settings_path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("parse {}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    // Merge hooks into settings
    settings["hooks"] = hooks_config["hooks"].clone();

    // Write settings
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let pretty = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, format!("{pretty}\n"))
        .with_context(|| format!("write {}", settings_path.display()))?;

    eprintln!("Wrote hooks to: {}", settings_path.display());
    eprintln!();
    eprintln!("Hook command: {veto_bin_str} hook --hook-type pre-tool-use");
    eprintln!();
    eprintln!("Make sure veto-server is running before starting Claude Code.");

    Ok(())
}

fn handle_audit_tail(
    initial_limit: usize,
    decision: Option<&str>,
    hook_type: Option<&str>,
    as_json: bool,
    interval_secs: u64,
) -> Result<()> {
    let db_path = db_path();
    if !db_path.exists() {
        bail!("Audit database not found: {}", db_path.display());
    }

    let audit = AuditLog::open(&db_path)
        .with_context(|| format!("open {}", db_path.display()))?;

    // Print header unless JSON mode
    if !as_json {
        println!(
            "{:<5} {:<20} {:<15} {:<10} {:<8} {}",
            "ID", "TIMESTAMP", "HOOK", "TOOL", "DECISION", "SUMMARY"
        );
        println!("{}", "-".repeat(80));
    }

    // Show recent events first
    let initial = audit.query_events(initial_limit, decision, hook_type)?;
    let mut last_id = 0i64;
    // Print in chronological order (query returns newest-first)
    for e in initial.iter().rev() {
        print_event(e, as_json)?;
        if e.id > last_id {
            last_id = e.id;
        }
    }
    // If no initial events, start from current max
    if last_id == 0 {
        last_id = audit.max_id()?;
    }

    let interval = std::time::Duration::from_secs(interval_secs);
    loop {
        std::thread::sleep(interval);
        let new_events = audit.query_events_since(100, decision, hook_type, Some(last_id))?;
        // Print in chronological order
        for e in new_events.iter().rev() {
            print_event(e, as_json)?;
            if e.id > last_id {
                last_id = e.id;
            }
        }
    }
}

fn print_event(e: &veto::audit::AuditEvent, as_json: bool) -> Result<()> {
    if as_json {
        println!("{}", serde_json::to_string(e)?);
    } else {
        let tool = e.tool_name.as_deref().unwrap_or("-");
        let summary = e.action_summary.as_deref().unwrap_or("-");
        let summary_short = if summary.len() > 40 {
            format!("{}...", &summary[..37])
        } else {
            summary.to_string()
        };
        println!(
            "{:<5} {:<20} {:<15} {:<10} {:<8} {}",
            e.id, e.timestamp, e.hook_type, tool, e.decision, summary_short
        );
    }
    Ok(())
}

fn handle_audit(
    limit: usize,
    decision: Option<&str>,
    hook_type: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let db_path = db_path();
    if !db_path.exists() {
        bail!("Audit database not found: {}", db_path.display());
    }

    let audit = AuditLog::open(&db_path)
        .with_context(|| format!("open {}", db_path.display()))?;
    let events = audit.query_events(limit, decision, hook_type)?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }

    if events.is_empty() {
        println!("No audit events found.");
        return Ok(());
    }

    // Table header
    println!(
        "{:<5} {:<20} {:<15} {:<10} {:<8} {}",
        "ID", "TIMESTAMP", "HOOK", "TOOL", "DECISION", "SUMMARY"
    );
    println!("{}", "-".repeat(80));

    for e in &events {
        let tool = e.tool_name.as_deref().unwrap_or("-");
        let summary = e.action_summary.as_deref().unwrap_or("-");
        // Truncate summary for table display
        let summary_short = if summary.len() > 40 {
            format!("{}...", &summary[..37])
        } else {
            summary.to_string()
        };
        println!(
            "{:<5} {:<20} {:<15} {:<10} {:<8} {}",
            e.id, e.timestamp, e.hook_type, tool, e.decision, summary_short
        );
    }

    Ok(())
}

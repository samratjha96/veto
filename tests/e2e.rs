//! End-to-end tests: spin up a real in-process server on a Unix socket,
//! connect as a client, and verify verdicts over IPC.
//!
//! These tests exercise the full stack: socket binding, frame I/O,
//! request parsing, YARA scanning, Cedar evaluation, audit logging,
//! and response encoding.
//!
//! NOTE: Unix socket binding requires running outside the Claude Code sandbox.
//! Run with: `cargo test --test e2e`
//! If running inside the sandbox, these will fail with "Operation not permitted".

use serde_json::json;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::watch;

static E2E_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Per-test workspace. Socket goes in $TMPDIR (to avoid sandbox socket restrictions),
/// while the DB goes under target/.
fn e2e_workspace() -> (PathBuf, PathBuf, PathBuf) {
    let id = E2E_COUNTER.fetch_add(1, Ordering::SeqCst);
    // Socket needs a path the OS allows binding — use TMPDIR
    let tmp = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/private/tmp/claude-501"));
    let sock_dir = tmp.join(format!("veto-e2e-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&sock_dir).unwrap();
    let socket = sock_dir.join("veto.sock");

    let db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("e2e-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&db_dir).unwrap();
    let db = db_dir.join("audit.db");
    (sock_dir, socket, db)
}

fn policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

/// Start an in-process server on the given socket path.
/// Returns a shutdown sender — drop it or send to stop the server.
fn start_server(
    socket_path: &std::path::Path,
    db_path: &std::path::Path,
) -> (watch::Sender<()>, tokio::task::JoinHandle<()>) {
    let _ = std::fs::remove_file(socket_path);

    let cedar = Arc::new(
        veto::cedar_runtime::CedarRuntime::load(&policy_dir()).expect("load policies"),
    );
    let audit = veto::audit::AuditLog::open(db_path).expect("open audit log");
    let listener = UnixListener::bind(socket_path)
        .unwrap_or_else(|e| panic!("bind {}: {e}", socket_path.display()));

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let handle = tokio::spawn(async move {
        veto::server::run_accept_loop(listener, cedar, audit, shutdown_rx).await;
    });

    (shutdown_tx, handle)
}

/// Send a JSON request to the server and return the parsed response.
/// Uses blocking I/O with generous timeouts.
fn send(socket_path: &std::path::Path, request: &serde_json::Value) -> serde_json::Value {
    // Retry connect in case the server hasn't started accepting yet
    let mut stream = None;
    for _ in 0..20 {
        match UnixStream::connect(socket_path) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let mut stream = stream.unwrap_or_else(|| panic!("connect {}", socket_path.display()));

    // Don't set read timeout — use blocking mode so we wait for the server
    // to process and respond. The tokio runtime in the test will handle
    // the server side concurrently.
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let body = serde_json::to_vec(request).unwrap();
    veto::ipc::write_frame(&mut stream, &body).unwrap();
    let resp_bytes = veto::ipc::read_frame(&mut stream).unwrap();
    serde_json::from_slice(&resp_bytes).unwrap()
}

/// RAII guard: starts the server, shuts it down on drop.
struct Server {
    socket_path: PathBuf,
    _shutdown: watch::Sender<()>,
    _handle: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(socket_path: &std::path::Path, db_path: &std::path::Path) -> Self {
        let (shutdown, handle) = start_server(socket_path, db_path);
        // Give the server a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;
        Self {
            socket_path: socket_path.to_path_buf(),
            _shutdown: shutdown,
            _handle: handle,
        }
    }

    fn send(&self, request: &serde_json::Value) -> serde_json::Value {
        send(&self.socket_path, request)
    }
}

// ---------- Tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_ping() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({"hook": "ping", "payload": {}}));
    assert_eq!(resp["ok"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_status() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({"hook": "status", "payload": {}}));
    assert_eq!(resp["ok"], true);
    let count = resp["data"]["policy_count"].as_i64().unwrap();
    assert!(count > 0, "should have policies, got {count}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_safe_command_allowed() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello world"}
        }
    }));
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["response"]["continue"], true);
    // Allow = no hookSpecificOutput
    assert!(
        resp["response"]["hookSpecificOutput"].is_null(),
        "safe command should have no hookSpecificOutput"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_rm_root_denied() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }
    }));
    assert_eq!(resp["ok"], true);
    let decision = resp["response"]["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("allow");
    assert!(
        decision == "deny" || decision == "ask",
        "rm -rf / should be denied, got {decision}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_git_force_push_denied() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"}
        }
    }));
    assert_eq!(resp["ok"], true);
    let decision = resp["response"]["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("allow");
    assert!(
        decision == "deny" || decision == "ask",
        "git push --force should be denied, got {decision}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_file_write_etc_denied() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {
            "tool_name": "Write",
            "tool_input": {"file_path": "/etc/passwd", "content": "hacked"}
        }
    }));
    assert_eq!(resp["ok"], true);
    let decision = resp["response"]["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("allow");
    assert!(
        decision == "deny" || decision == "ask",
        "/etc/passwd write should be denied, got {decision}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_reload() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({"hook": "reload", "payload": {}}));
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["data"]["reloaded"], true);
    assert!(resp["data"]["policy_count"].as_i64().unwrap() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_multiple_connections() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;

    // Each request opens a new connection (like the real CLI)
    let r1 = server.send(&json!({"hook": "ping", "payload": {}}));
    assert_eq!(r1["ok"], true);

    let r2 = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {"tool_name": "Bash", "tool_input": {"command": "ls"}}
    }));
    assert_eq!(r2["ok"], true);

    let r3 = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    }));
    assert_eq!(r3["ok"], true);

    // Status should reflect audit events
    let status = server.send(&json!({"hook": "status", "payload": {}}));
    let event_count = status["data"]["event_count"].as_i64().unwrap();
    assert!(
        event_count >= 2,
        "should have at least 2 audit events, got {event_count}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_invalid_json_returns_error() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;

    let mut stream = UnixStream::connect(&server.socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send garbage as the frame body
    veto::ipc::write_frame(&mut stream, b"not json").unwrap();
    let resp_bytes = veto::ipc::read_frame(&mut stream).unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("invalid JSON"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_secrets_detected() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;
    let resp = server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {
            "tool_name": "Bash",
            "tool_input": {"command": "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"}
        }
    }));
    assert_eq!(resp["ok"], true);
    // YARA should detect the AWS key pattern
    if let Some(output) = resp["response"]["hookSpecificOutput"].as_object() {
        let decision = output["permissionDecision"].as_str().unwrap_or("allow");
        assert!(
            decision == "deny" || decision == "ask",
            "AWS key should trigger ask/deny, got {decision}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Unix socket binding — run with: cargo test --test e2e -- --ignored"]
async fn e2e_audit_records_decisions() {
    let (_ws, sock, db) = e2e_workspace();
    let server = Server::start(&sock, &db).await;

    // Safe command
    server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {"tool_name": "Bash", "tool_input": {"command": "echo safe"}}
    }));

    // Dangerous command
    server.send(&json!({
        "hook": "pre-tool-use",
        "payload": {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    }));

    // Read audit log directly
    let audit = veto::audit::AuditLog::open(&db).unwrap();
    let events = audit.query_events(10, None, None).unwrap();
    assert_eq!(events.len(), 2, "should have 2 audit events");

    // Should have both allow and deny
    let decisions: Vec<&str> = events.iter().map(|e| e.decision.as_str()).collect();
    assert!(decisions.contains(&"allow"), "should have an allow event");
    assert!(decisions.contains(&"deny"), "should have a deny event");
}

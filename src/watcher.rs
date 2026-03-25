//! File watcher for hot-reloading Cedar policies.
//!
//! Watches the policy directory for `.cedar` and `.cedarschema` file changes
//! and triggers a CedarRuntime reload.

use crate::cedar_runtime::CedarRuntime;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Start watching a policy directory for changes.
/// Returns a handle that keeps the watcher alive — drop it to stop watching.
pub fn spawn_watcher(
    policy_dir: &Path,
    cedar: Arc<CedarRuntime>,
) -> anyhow::Result<WatcherHandle> {
    let (tx, rx) = mpsc::unbounded_channel();
    let policy_dir_owned = policy_dir.to_path_buf();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                if is_policy_event(&event) {
                    let _ = tx.send(event);
                }
            }
            Err(e) => warn!(error = %e, "file watcher error"),
        }
    })?;

    watcher.watch(&policy_dir_owned, RecursiveMode::NonRecursive)?;
    info!(dir = %policy_dir_owned.display(), "Policy watcher started");

    // Spawn the reload task
    let dir_display = policy_dir_owned.display().to_string();
    tokio::spawn(reload_loop(rx, cedar, dir_display));

    Ok(WatcherHandle {
        _watcher: watcher,
    })
}

/// Handle that keeps the file watcher alive. Drop to stop watching.
pub struct WatcherHandle {
    _watcher: RecommendedWatcher,
}

fn is_policy_event(event: &Event) -> bool {
    // Only care about create/modify/remove events on .cedar or .cedarschema files
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {}
        _ => return false,
    }
    event.paths.iter().any(|p| {
        p.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext == "cedar" || ext == "cedarschema")
    })
}

async fn reload_loop(
    mut rx: mpsc::UnboundedReceiver<Event>,
    cedar: Arc<CedarRuntime>,
    dir_display: String,
) {
    // Debounce: wait a short period after the first event before reloading,
    // in case multiple files change at once (e.g. editor save + backup).
    loop {
        // Wait for the first event
        if rx.recv().await.is_none() {
            break; // channel closed
        }

        // Debounce: drain any events that arrive within 200ms
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        while rx.try_recv().is_ok() {}

        // Reload
        match cedar.reload() {
            Ok(count) => {
                info!(
                    policies = count,
                    dir = %dir_display,
                    "Hot-reloaded Cedar policies"
                );
            }
            Err(e) => {
                error!(error = %e, "Hot-reload failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_policy_event_filters_correctly() {
        use notify::event::{CreateKind, ModifyKind, RemoveKind};
        use std::path::PathBuf;

        let cedar_event = Event {
            kind: EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/policies/test.cedar")],
            attrs: Default::default(),
        };
        assert!(is_policy_event(&cedar_event));

        let schema_event = Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![PathBuf::from("/tmp/policies/base.cedarschema")],
            attrs: Default::default(),
        };
        assert!(is_policy_event(&schema_event));

        let remove_event = Event {
            kind: EventKind::Remove(RemoveKind::File),
            paths: vec![PathBuf::from("/tmp/policies/old.cedar")],
            attrs: Default::default(),
        };
        assert!(is_policy_event(&remove_event));

        // Non-policy files should be ignored
        let json_event = Event {
            kind: EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/policies/config.json")],
            attrs: Default::default(),
        };
        assert!(!is_policy_event(&json_event));

        // Access events should be ignored
        let access_event = Event {
            kind: EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![PathBuf::from("/tmp/policies/test.cedar")],
            attrs: Default::default(),
        };
        assert!(!is_policy_event(&access_event));
    }
}

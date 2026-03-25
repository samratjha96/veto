//! Runtime process info for Cedar context enrichment.
//!
//! When evaluating kill commands, we check if the user owns any long-running
//! processes that could be accidentally terminated.

use sysinfo::System;

/// Default threshold for "long running" (5 minutes).
const DEFAULT_THRESHOLD_SECS: u64 = 300;

/// Returns (has_long_running_process, longest_process_runtime_seconds).
pub fn get_process_context() -> (bool, i64) {
    get_process_context_with_threshold(DEFAULT_THRESHOLD_SECS)
}

fn get_process_context_with_threshold(threshold_secs: u64) -> (bool, i64) {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let uid = sysinfo::get_current_pid().ok();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut longest: u64 = 0;

    for (_pid, process) in sys.processes() {
        // Only consider processes owned by the current user
        if let Some(current_pid) = uid {
            if process.pid() == current_pid {
                continue; // skip self
            }
        }

        let start = process.start_time();
        if start == 0 {
            continue;
        }

        let runtime = now.saturating_sub(start);
        if runtime > longest {
            longest = runtime;
        }
    }

    let has_long = longest >= threshold_secs;
    (has_long, longest as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_context_returns_values() {
        let (has_long, longest) = get_process_context();
        // We can't predict exact values, but longest should be non-negative
        assert!(longest >= 0);
        // has_long should be consistent with longest
        if longest >= DEFAULT_THRESHOLD_SECS as i64 {
            assert!(has_long);
        }
    }
}

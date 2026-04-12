<div align="center">

# Veto

**Policy enforcement, audit, and governance for powerful coding agents.** Draft rules in **natural language**, publish them from a **central policy store**, and have the **same guardrails enforced on every developer machine**—with a full audit trail, on infrastructure you control.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Edition](https://img.shields.io/badge/edition-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

</div>

### Quick install

```bash
cargo install --git https://github.com/samratjha96/veto.git
```

**Or** clone and install from the repo root:

```bash
git clone https://github.com/samratjha96/veto.git
cd veto
cargo install --path .
```

---

## TL;DR

**The problem:** Powerful coding agents can run shell, rewrite files, and fetch URLs with little friction. Without shared governance, every machine is a snowflake—and one bad tool call can become an incident.

**The solution:** Veto gives you **one policy regime for your whole org**: maintain Cedar policies in a **single source of truth** (for example a Git repo or package your platform team owns), **optionally draft new rules from natural language** (`veto policy add`), distribute that tree to each workstation, and run a **small local daemon** that enforces the same decisions everywhere. Every verdict is auditable. Typical adjudication stays **sub-millisecond** on commodity laptops (see [Performance](#performance)).

### Central governance, local enforcement

| What you centralize | What runs on each dev machine |
|---------------------|-------------------------------|
| The `policies/` tree (and who may change it) | `veto-server` reading `VETO_POLICY_DIR`, hot-reloading on updates |
| How new rules are proposed (NL draft → review → merge) | Hooks so the agent cannot bypass the daemon |

Veto does not replace your delivery mechanism: use **Git**, configuration management, or internal packages to sync the policy directory to developers. The daemon only cares that the directory is present and up to date.

### Why Veto?

| Capability | What you get |
|------------|----------------|
| **Default guardrails** | **44** Cedar policies (destructive shell, file guards, severity gates) plus **72** YARA rules across 7 categories |
| **Speed** | YARA + Cedar + verdict in **~0.3–0.4 ms** median; **&lt; ~0.5 ms** p99 (release build; see [Performance](#performance)) |
| **Hot reload** | Edit `policies/*.cedar`; the daemon reloads without restart (file watcher + manual `veto reload`) |
| **User prompts** | Cedar forbid policies whose `@id` contains `ask` become **Ask** (confirm) instead of silent **Deny**; medium+ YARA hits can **Ask** even when Cedar permits |
| **Process context** | Optional enrichment for `kill`/`pkill`/`killall` (long-running processes) for tighter policies |
| **Audit** | `veto audit` / `--tail` over `~/.veto/audit.db` |
| **Natural language policies** | `veto policy add "..."` drafts Cedar for review; commit the result to your **central** policy repo so every machine inherits it after sync |

---

## Quick example

```bash
# Terminal 1: daemon (set policy dir if not running from repo root)
export VETO_POLICY_DIR=/path/to/veto/policies
veto-server

# Terminal 2: health check
veto ping && veto status

# Dry-run without the server (same pipeline)
veto test "rm -rf /"                    # exit 2 = deny
veto test "echo hello"                  # exit 0 = allow
veto test --tool WebFetch --url 'https://pastebin.com/upload'   # often exit 3 = ask (YARA)

# Hook-shaped JSON (what Claude Code sends)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | veto hook --hook-type pre-tool-use

# Audit trail
veto audit --limit 10
veto audit --decision deny --json
```

---

## Design philosophy

1. **Stateless per action** — No session store: each hook builds fresh Cedar entities from the payload, YARA signature, and optional process snapshot. Easier to reason about than multi-turn taint tracking.
2. **Defense in depth** — YARA catches broad classes of misuse; Cedar encodes *your* org rules. Medium-or-higher YARA severity escalates to **Ask** even when no Cedar rule fires.
3. **Local first** — Unix domain socket, SQLite audit log, policies on disk. No cloud dependency for adjudication (LLM is optional and only for `veto policy add`).
4. **Agent-native I/O** — Responses match Claude Code hook JSON (`permissionDecision`, reasons) so the agent stops or prompts without custom clients.
5. **Explicit policy IDs** — Cedar `@id` values surface as deny/ask reasons and in the audit log—no opaque scores.

---

## How Veto compares

| | Veto | Shell aliases / one-off wrappers | Enterprise DLP only | “Trust the model” |
|--|------|-----------------------------------|---------------------|-------------------|
| Declarative policies (Cedar) | Yes | Rarely | Sometimes | No |
| Fast pre-scan (YARA) | Yes | Ad hoc | Varies | No |
| Sub-ms local decision | Yes | Varies | Often network-bound | N/A |
| First-class Claude Code hooks | Yes | DIY | DIY | N/A |
| Open source, self-hosted | Yes | N/A | Often proprietary | N/A |

**Good fit:** you use Claude Code (or can emit the same hook JSON), you want **allow/deny/ask** with **auditability**, and you’re OK running a small local daemon.

**Poor fit:** you need Windows-native support today (Unix socket + Claude hooks are the happy path), or you want a hosted SaaS with zero local processes.

---

## Installation

### From GitHub (recommended)

```bash
cargo install --git https://github.com/samratjha96/veto.git
```

Installs two binaries: `veto` (CLI) and `veto-server` (daemon).

### From a local clone

```bash
git clone https://github.com/samratjha96/veto.git
cd veto
cargo build --release
# Binaries: target/release/veto, target/release/veto-server
cargo install --path .   # copies into ~/.cargo/bin
```

### Requirements

- **Rust** toolchain (2024 edition)
- **macOS or Linux** for the Unix socket workflow (primary target)
- **Claude Code** (or compatible hook JSON) if you use `veto setup` / `veto hook`

---

## Quick start

1. **Install** (see above).

2. **Policies:** point `VETO_POLICY_DIR` at a directory containing `*.cedarschema` and `*.cedar` (the repo’s `policies/` tree is the reference).

3. **Start the daemon**

   ```bash
   export VETO_POLICY_DIR=/path/to/veto/policies
   veto-server
   ```

4. **Verify**

   ```bash
   veto ping    # pong
   veto status  # JSON with policy_count, event_count
   ```

5. **Wire Claude Code** (from the project where you want hooks)

   ```bash
   cd /path/to/your/project
   veto setup # merges into .claude/settings.local.json
   ```

6. **Sanity check**

   ```bash
   veto doctor
   ```

---

## Architecture

```
+------------------------------------------------------------------+
|  Claude Code (PreToolUse / PermissionRequest)                    |
|  JSON on stdin -> veto hook --hook-type pre-tool-use             |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  veto-server (Unix socket ~/.veto/veto.sock by default)          |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  1. Adapter: hook JSON -> scan text (command, path, URL, ...)    |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  2. YARA-X: embedded rules -> SignatureContext                   |
|     (severity, categories, matches)                              |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  3. Optional: process context for kill-like commands             |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  4. Cedar: PolicySet + schema -> Allow / Forbid (+ policy @id)   |
+------------------------------------------------------------------+
                               |
           +-------------------+-------------------+
           |                   |                   |
           v                   v                   v
    +-------------+     +-------------+     +-------------+
    | Allow       |     | Deny        |     | Ask         |
    | (continue)  |     | + reasons   |     | (prompt)    |
    +-------------+     +-------------+     +-------------+
           |                   |                   |
           +-------------------+-------------------+
                               |
                               v
+------------------------------------------------------------------+
|  SQLite audit log (VETO_DB, default ~/.veto/audit.db)            |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|  Hook JSON response (permissionDecision allow/deny/ask + reason) |
+------------------------------------------------------------------+
```

Framing: length-prefixed JSON over the socket; no HTTP server in the default path.

---

## Command reference

Global socket override:

```bash
veto --socket /path/to/veto.sock ping
# or VETO_SOCKET=/path/to/veto.sock
```

### `veto-server`

```bash
veto-server
VETO_POLICY_DIR=./policies veto-server
RUST_LOG=debug veto-server
```

### `veto hook`

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | veto hook --hook-type pre-tool-use
```

### `veto test` (no server)

Dry-run the pipeline; exit codes: **0** allow, **2** deny, **3** ask.

```bash
veto test "rm -rf /"
veto test --tool Write --path /etc/passwd
veto test --tool WebFetch --url https://example.com
veto test "git push --force" --verbose
veto test "echo ok" --json
```

### `veto policy`

```bash
veto policy list
veto policy explain forbid-rm-root
veto policy search kill
veto policy add "block curl to non-HTTPS URLs" --dry-run
veto policy add "describe your rule"
veto policy remove my_policy
veto policy template list
veto policy template show no-kill
veto policy template apply no-kill
```

### `veto audit`

```bash
veto audit
veto audit --limit 50 --decision deny
veto audit --hook-type pre-tool-use --json
veto audit --tail --interval 2
```

### Other

```bash
veto ping
veto status
veto reload
veto doctor
veto setup # write Claude hooks; use --print to stdout only
veto bench --iterations 1000
```

---

## Configuration

Veto is configured with **environment variables**. Example shell profile snippet:

```bash
# --- Veto ---
# Directory containing base.cedarschema, *.cedar
export VETO_POLICY_DIR="$HOME/src/veto/policies"

# Unix socket for veto-server (default: ~/.veto/veto.sock)
# export VETO_SOCKET="$HOME/.veto/veto.sock"

# SQLite audit database (default: ~/.veto/audit.db)
# export VETO_DB="$HOME/.veto/audit.db"

# Optional: natural-language policy generation (veto policy add)
export API_KEY="sk-..."   # bearer token for your LLM vendor
export LLM_GATEWAY_BASE_URL="https://api.openai.com/v1"
export VETO_MODEL="gpt-4o-mini"

# Logging: error, warn, info, debug, trace
export RUST_LOG="info"
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `VETO_POLICY_DIR` | `./policies` (relative to **server** cwd if unset) | Cedar policies + schema |
| `VETO_SOCKET` | `~/.veto/veto.sock` | Daemon socket |
| `VETO_DB` | `~/.veto/audit.db` | Audit SQLite |
| `API_KEY` | (unset) | Required for `veto policy add` |
| `LLM_GATEWAY_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible `/v1` root |
| `VETO_MODEL` | `gpt-4o-mini` | Chat model id |
| `RUST_LOG` | `info` | `tracing` filter |

---

## Policies and YARA (summary)

- **Cedar:** `policies/*.cedar` with `@id("...")` annotations; actions include `ShellCommand`, `WebFetch`, `FileRead` / `FileWrite` / `FileEdit` / `FileDelete`. Context includes YARA `signature.*` and optional process fields for kill-like commands.
- **“Ask” policies:** if every firing forbid policy’s `@id` contains the substring `ask`, the verdict is **Ask** instead of **Deny** (Cedar has no built-in third effect).
- **YARA:** rules under `rules/*.yar` are **compiled into the binary**; changing rules requires a **rebuild**. Policies can still be edited live on disk.

Included policy files (representative): `base.cedar`, `destructive.cedar`, `file_guards.cedar`, `ask_before_kill.cedar`.

---

## Performance

Release-oriented microbenchmarks (see `veto bench`; hardware-dependent):

| Stage | Median (approx.) | p99 (approx.) |
|-------|------------------|---------------|
| YARA scan | ~220 µs | ~300 µs |
| Cedar eval | ~60 µs | ~100 µs |
| Full pipeline | ~340 µs | ~400 µs |

---

## Troubleshooting

### `veto-server is not running (socket not found)`

```bash
veto-server
VETO_SOCKET=/path/to/sock veto ping
```

### Policy directory missing

```bash
VETO_POLICY_DIR=/absolute/path/to/policies veto-server
```

### `API_KEY env var required`

Only affects `veto policy add`. Set `API_KEY`, and if needed `LLM_GATEWAY_BASE_URL` / `VETO_MODEL`, then retry.

### Full diagnostics

```bash
veto doctor
```

---

## Limitations

- **Platform:** Unix socket workflow is aimed at **macOS/Linux**. Windows is not a first-class target.
- **Agent integration:** Hook JSON and `veto setup` target **Claude Code** conventions; other agents need their own adapter or manual hook wiring.
- **YARA updates:** rule changes require **recompiling** the crate (rules are `include_dir!` embedded).
- **Threat model:** Veto guards the **agent’s tool path**, not a compromised host kernel, malicious binaries already on disk, or users who bypass hooks.
- **NL policies:** `veto policy add` quality depends on the LLM and your prompts; always review generated Cedar before trusting it in production.
- **Fleet rollout:** there is no hosted multi-tenant control plane—you distribute the policy directory with the same Git / MDM / packaging tools you already use.

---

## FAQ

### How do the same policies end up on every developer machine?

You keep **one canonical `policies/` tree** (typically in Git or an internal artifact). Sync it to each workstation—`git pull`, configuration management, MDM, or a package your platform team publishes—then point `VETO_POLICY_DIR` at that path and run `veto-server`. Updates **hot-reload** when files change. Use **`veto policy add`** on a maintainer machine to draft text; **merge reviewed Cedar** into the central tree so the next sync rolls the rule out everywhere.

### Why Cedar and YARA together?

YARA is a fast, pattern-first signal (secrets, exfil patterns, destructive idioms). Cedar is a small, analyzable policy language for explicit permits and forbids with structured context—including YARA severity and categories.

### Does Veto replace secrets scanners or EDR?

No. It’s a **focused control** for **agent-issued** commands and tool I/O, with auditing.

### Can I use a different LLM vendor?

Yes. Any **OpenAI-compatible** chat completions server works: set `LLM_GATEWAY_BASE_URL` to its `/v1` base and pick a matching `VETO_MODEL`.

### What if multiple Cedar policies forbid an action?

Diagnostics aggregate policy ids; **Ask** only applies when **every** matched id contains `ask`—otherwise you get **Deny**.

### How do I test policies in CI?

Use `veto test` with explicit `VETO_POLICY_DIR` and assert exit codes (`0` / `2` / `3`) or `--json` output.

---

## Developing

```bash
cargo test   # unit + integration tests (~160+ in the main crate; plus integration harness)
cargo build --release
```

---

## Contributing

Issues and PRs welcome. Please run `cargo test` before submitting changes.

---

## License

MIT

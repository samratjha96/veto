<div align="center">

# Veto

**One shared policy layer for coding agents** — **Claude Code**, **Codex**, **OpenCode**, **Pi**, and anything else that can call **`veto hook`**. Rules live in one place; every machine enforces them locally and logs what happened.

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

Agents need real access to shell, files, and URLs; asking everyone to curate their own “don’t do this” lists doesn’t scale. Veto keeps **one shared `policies/` tree** (often a Git repo), runs **`veto-server`** on each machine, and wires **hooks** so **Claude Code**, **Codex**, **OpenCode**, **Pi**, or any tool that can hit **`veto hook`** with the same pre-tool JSON gets the same checks before a run. **`veto setup`** is the turnkey path for Claude Code; others follow their product docs. Ship policy updates once, sync the folder however you already do (`git pull`, MDM, packages)—**`*.cedar` reloads live** without restarting the daemon. Typical adjudication is **sub-millisecond** (see [Performance](#performance)); outcomes are **audited** (`veto audit`).

### Who maintains what

| One place (you choose how to host it) | On each developer laptop |
|---------------------------------------|----------------------------|
| The shared **`policies/`** folder (who may edit it is up to you) | **`veto-server`** watches that folder and reloads when files change |
| Optional: draft new rules in chat (`veto policy add`), then merge reviewed text into the shared folder | **Hooks** so the agent talks to Veto instead of skipping checks |

Veto does not replace how you ship files: use **Git**, MDM, or internal packages so the policy directory stays current. The daemon only needs the folder on disk and read access.

### What you get

| Topic | What it means |
|-------|----------------|
| **Batteries included** | **44** Cedar policies and **72** YARA rules (destructive commands, sensitive paths, risky URLs, secrets-shaped strings, and more) |
| **Fast** | Full check in about **~0.3–0.4 ms** median on a typical laptop (see [Performance](#performance)) |
| **Live policy updates** | Change `*.cedar` on disk; the server reloads (**no restart**). You can also run `veto reload`. |
| **Block vs “are you sure?”** | Rules can **deny** outright or **ask** for confirmation. Some risky patterns trigger **ask** even when your Cedar rules would allow the action—so you get a second look when it matters. |
| **Kill commands** | Optional extra context for `kill` / `pkill` / `killall` so policies can reason about targets. |
| **Audit trail** | `veto audit` over `~/.veto/audit.db` |
| **Draft from English** | `veto policy add "…"` proposes Cedar for humans to review; ship the result in the shared policy repo |

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
veto test --tool WebFetch --url 'https://pastebin.com/upload'   # often exit 3 = ask (built-in patterns)

# Hook-shaped JSON (what Claude Code and compatible agents send)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | veto hook --hook-type pre-tool-use

# Audit trail
veto audit --limit 10
veto audit --decision deny --json
```

---

## Design philosophy

1. **One decision at a time** — Each tool call is judged from the request, a quick pattern scan, optional process info, and your policies—no hidden session state to debug.
2. **Two layers** — Broad pattern checks catch a wide range of bad ideas; your Cedar policies say what *your* org allows or forbids. Serious pattern hits can still surface a **confirm** prompt even when Cedar would allow the action.
3. **Local by default** — Socket to a small daemon, SQLite audit log, policies as files. No vendor cloud required to allow or deny a run (an LLM is only used if you use `veto policy add`).
4. **Works with common coding agents** — Replies use the hook JSON those tools expect (`allow` / `deny` / `ask` plus reasons). **Claude Code**, **Codex**, **OpenCode**, **Pi**, and others can integrate as long as they can invoke **`veto hook`** with the same payload shape.
5. **Named rules** — When something is blocked or questioned, you see **which policy** fired—not a mystery score.

---

## How Veto compares

| | Veto | Shell aliases / one-off wrappers | Enterprise DLP only | “Trust the model” |
|--|------|-----------------------------------|---------------------|-------------------|
| Versioned org rules (Cedar files) | Yes | Rarely | Sometimes | No |
| Fast built-in pattern pack | Yes | Ad hoc | Varies | No |
| Sub-ms local decision | Yes | Varies | Often network-bound | N/A |
| Hooks for Claude Code, Codex, OpenCode, Pi, … (same JSON) | Yes | DIY | DIY | N/A |
| Open source, self-hosted | Yes | N/A | Often proprietary | N/A |

**Good fit:** you use **Claude Code**, **Codex**, **OpenCode**, **Pi**, or another agent that can call **`veto hook`** with the same JSON; you want **allow/deny/ask** with **auditability**; and you’re OK running a small local daemon.

**Poor fit:** you need Windows-native support today (Unix socket + hook wiring are the happy path), or you want a hosted SaaS with zero local processes.

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
- A **coding agent** that can run **`veto hook`** (**Claude Code**, **Codex**, **OpenCode**, **Pi**, …). Use **`veto setup`** for Claude Code; other products need hook config per their documentation.

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

5. **Wire your agent** (from the project where you want hooks)—for **Claude Code**, use **`veto setup`**; for **Codex**, **OpenCode**, **Pi**, or others, configure the equivalent pre-tool hook to call **`veto hook`**

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
|  Coding agent (e.g. Claude Code, Codex, OpenCode, Pi)            |
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
|  2. Pattern scan (YARA) -> summary for policies                  |
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
|  4. Cedar policies -> allow / forbid / confirm (+ rule names)    |
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

## How rules work

**Team policies (Cedar)** live as `*.cedar` files under your shared `policies/` folder. They describe what is allowed or not for shell commands, file access, fetches, and similar actions. You can reference the built-in pattern scan (severity and categories) inside those rules, and optionally use extra process details when the command looks like `kill` / `pkill` / `killall`.

**Built-in pattern pack (YARA)** ships inside the `veto` binary. It catches many “obviously risky” shapes (secrets-looking strings, exfil idioms, destructive commands, and more). Updating those patterns means **rebuilding or upgrading the binary**; updating Cedar files on disk does **not** require that.

**Confirm vs deny:** Your Cedar rules can end in a hard **deny** or in a **confirm** (ask the user) depending on how the rule is written. If several deny-style rules fire at once, they only become a single **confirm** when *all* of them are the “ask first” kind—otherwise the outcome is **deny**. (This avoids half your rules saying “stop” and one rule quietly turning it into a prompt.)

Shipped examples you can start from: `base.cedar`, `destructive.cedar`, `file_guards.cedar`, `ask_before_kill.cedar`.

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
- **Agent integration:** **`veto setup`** targets **Claude Code**. **Codex**, **OpenCode**, **Pi**, and other agents need hook configuration that forwards the same JSON to **`veto hook`** (per product docs).
- **YARA updates:** rule changes require **recompiling** the crate (rules are `include_dir!` embedded).
- **Threat model:** Veto guards the **agent’s tool path**, not a compromised host kernel, malicious binaries already on disk, or users who bypass hooks.
- **NL policies:** `veto policy add` quality depends on the LLM and your prompts; always review generated Cedar before trusting it in production.
- **Fleet rollout:** there is no hosted multi-tenant control plane—you distribute the policy directory with the same Git / MDM / packaging tools you already use.

---

## FAQ

### How do the same policies end up on every developer machine?

Put the **`policies/`** folder in **one shared place**—usually a Git repo or an internal package your team already distributes. Each laptop points `VETO_POLICY_DIR` at that folder and runs **`veto-server`**. When the files change on disk (after `git pull`, a package update, or sync from IT), the server **reloads automatically**; people do not restart the daemon for routine Cedar edits.

To propose new rules in plain language, use **`veto policy add`** on a maintainer machine, **review** the generated Cedar, then **merge** into the shared folder so the next update reaches everyone.

### Why two kinds of rules (patterns + policies)?

The **pattern pack** is a fast, wide net for common bad ideas (secrets-shaped text, risky URLs, destructive shell, and similar). **Cedar** is where you write **your** org’s allow/deny/confirm logic, and you can use the pattern results inside those policies. Together you get broad coverage plus rules you can read and version like normal code.

### Does Veto replace secrets scanners or EDR?

No. It’s a **focused control** for **agent-issued** commands and tool I/O, with auditing.

### Can I use a different LLM vendor?

Yes. Any **OpenAI-compatible** chat completions server works: set `LLM_GATEWAY_BASE_URL` to its `/v1` base and pick a matching `VETO_MODEL`.

### What if several policies disagree?

You always see **which rules** fired. **Confirm** only wins when **every** firing “stop” rule is the kind meant to **ask first**; if any rule is a plain **deny**, the result is **deny**.

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

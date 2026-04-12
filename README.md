# Veto

**Stateless policy daemon that intercepts AI coding agent actions and enforces Cedar policies with YARA-X pre-scanning.**

Your AI agent just ran `rm -rf /`. Or `git push --force`. Or exfiltrated your `.env` to pastebin. Veto sits between the agent and the shell, evaluating every action against declarative policies before it executes.

```
cargo install --path .
```

## TL;DR

**The problem:** AI coding agents execute shell commands, write files, and fetch URLs with broad permissions. One hallucination or prompt injection away from `terraform destroy` on your production infra.

**The solution:** Veto intercepts every action through Claude Code hooks, runs it through YARA pattern matching and Cedar policy evaluation, and returns allow/deny/ask -- all in under 0.5ms.

| Feature                       | What it does                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| **43 default policies**       | Blocks `rm -rf`, `git push --force`, `chmod 777`, `terraform destroy`, and 39 more out of the box |
| **70+ YARA rules**            | Detects command injection, secrets exposure, exfiltration, prompt injection, supply chain attacks |
| **Hot-reload**                | Add or edit `.cedar` files -- policies take effect in seconds, no restart                        |
| **Natural language policies** | `veto policy add "block curl to non-HTTPS URLs"` generates Cedar via LLM                        |
| **Process-aware**             | Knows when long-running processes exist before allowing `kill`                                   |
| **Audit log**                 | Every decision logged to SQLite with timestamp, policy, and verdict                              |
| **< 0.5ms p99**              | YARA + Cedar + verdict in under half a millisecond                                               |

## See It Work

```bash
# Start the daemon
veto-server &

# Safe command -- allowed
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | veto hook --hook-type pre-tool-use
# {"continue":true}

# Destructive command -- blocked
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | veto hook --hook-type pre-tool-use
# {"continue":true,"hookSpecificOutput":{"hookEventName":"PreToolUse",
#   "permissionDecision":"deny","permissionDecisionReason":"forbid-rm-root"}}

# Suspicious URL -- asks the user
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://pastebin.com/upload"}}' \
  | veto hook --hook-type pre-tool-use
# {"continue":true,"hookSpecificOutput":{"hookEventName":"PreToolUse",
#   "permissionDecision":"ask","permissionDecisionReason":"YARA matched 1 rule(s)..."}}

# Check the audit trail
veto audit
# ID  | TIMESTAMP            | HOOK           | TOOL     | DECISION | SUMMARY
# --- | -------------------- | -------------- | -------- | -------- | ---------------------------
# 3   | 2026-03-29 18:11:20  | pre-tool-use   | WebFetch | ask      | https://pastebin.com/upload
# 2   | 2026-03-29 18:11:12  | pre-tool-use   | Bash     | deny     | rm -rf /
# 1   | 2026-03-29 18:11:03  | pre-tool-use   | Bash     | allow    | ls -la
```

## The Demo Scenario

This is the workflow Veto is built for:

```bash
# 1. Agent runs kill on a long-running process -- no kill policy yet, so it's allowed
echo '{"tool_name":"Bash","tool_input":{"command":"kill 99999"}}' \
  | veto hook --hook-type pre-tool-use
# {"continue":true}

# 2. You decide that's not okay. Add a policy in plain English:
veto policy add "never kill running processes without asking me first"
# Generating Cedar policy from: "never kill running processes without asking me first"
# --- Generated Policy: forbid-kill-without-confirm ---
# forbid(principal, action == Action::"ShellCommand", resource)
# when { context.command like "*kill *" || ... };
# Save to ./policies/forbid_kill_without_confirm.cedar? [Enter to confirm]

# 3. Policy is live immediately (hot-reloaded). Agent tries kill again:
echo '{"tool_name":"Bash","tool_input":{"command":"kill 99999"}}' \
  | veto hook --hook-type pre-tool-use
# {"continue":true,"hookSpecificOutput":{"hookEventName":"PreToolUse",
#   "permissionDecision":"deny","permissionDecisionReason":"forbid-kill-without-confirm"}}

# 4. Audit log shows both the allow and the deny:
veto audit --limit 2
# ID  | TIMESTAMP            | HOOK           | TOOL | DECISION | SUMMARY
# --- | -------------------- | -------------- | ---- | -------- | ----------
# 5   | 2026-03-29 18:12:22  | pre-tool-use   | Bash | deny     | kill 99999
# 4   | 2026-03-29 18:11:37  | pre-tool-use   | Bash | allow    | kill 99999
```

## Quick Start

```bash
# 1. Build and install
cargo install --path .

# 2. Start the server (from the repo root, or set VETO_POLICY_DIR)
veto-server

# 3. In another terminal, verify it's running
veto ping    # pong
veto status  # {"status":"ok","policy_count":43,"event_count":0}

# 4. Wire up Claude Code hooks
veto setup   # writes to .claude/settings.local.json

# 5. Start Claude Code -- Veto is now intercepting every action
```

## How It Works

Every action goes through a three-stage pipeline:

```
              +--------------------------------+
              |  Claude Code Hook JSON         |
              |  (shell cmd, file op, URL)     |
              +---------------+----------------+
                              |
              +---------------v----------------+
              |  1. YARA-X Scan                |
              |  70+ rules, 7 categories       |
              |  -> severity + categories      |
              +---------------+----------------+
                              |
              +---------------v----------------+
              |  2. Cedar Policy Evaluation    |
              |  43 policies, 6 action types   |
              |  YARA results as context       |
              +---+----------+----------+------+
                  |          |          |
         +--------v---+  +--v-------+  +--v--------+
         | ALLOW      |  | DENY     |  | ASK       |
         | continue   |  | + reason |  | prompt    |
         +--------+---+  +--+-------+  +--+--------+
                  |          |             |
                  +----------+-------------+
                             |
              +--------------v-----------------+
              |  3. SQLite Audit Log           |
              |  Every decision recorded       |
              +--------------------------------+
```

Entities are built fresh per request. No session state, no multi-turn tracking, no persistent entity store.

## CLI Reference

### `veto-server`

Long-lived daemon. Listens on `~/.veto/veto.sock`.

```bash
veto-server                              # default config
VETO_POLICY_DIR=./policies veto-server   # explicit policy dir
RUST_LOG=debug veto-server               # verbose logging
```

### `veto test`

Dry-run a command through the pipeline without the server running.

```bash
veto test "rm -rf /"                         # shell command → DENY
veto test "echo hello"                       # safe command → ALLOW
veto test --tool Write --path /etc/passwd    # file write → DENY
veto test --tool WebFetch --url https://evil.com  # web fetch
veto test "git push --force" --verbose       # show YARA match details
veto test "rm -rf /" --json                  # machine-readable output
```

Exit codes: `0` = allow, `2` = deny, `3` = ask.

### `veto hook`

Forwards Claude Code hook events to the server. This is what the hooks configuration calls.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | veto hook --hook-type pre-tool-use
```

### `veto policy`

```bash
veto policy list                                    # show all loaded policies
veto policy explain forbid-rm-root                  # show a policy's Cedar, description, and file
veto policy search kill                             # find policies matching a keyword
veto policy add "block all sudo commands"           # generate from natural language
veto policy add "..." --dry-run                     # preview without saving
veto policy remove my_policy                        # delete a policy file (with confirmation)
veto policy template list                           # browse 11 curated templates
veto policy template show no-kill                   # preview a template
veto policy template apply no-kill                  # apply a template to the policy dir
```

### `veto audit`

```bash
veto audit                          # last 20 events
veto audit --limit 50               # more events
veto audit --decision deny          # only denials
veto audit --hook-type pre-tool-use # filter by hook type
veto audit --json                   # JSON output
veto audit --tail                   # stream new events (like tail -f)
```

### Other Commands

```bash
veto ping                           # health check
veto status                         # policy count, event count
veto reload                         # force policy reload
veto doctor                         # diagnose setup issues
veto setup                          # write Claude Code hooks config
veto bench                          # run pipeline microbenchmarks
```

## Writing Policies

Cedar policies live in `policies/`. The schema defines six actions:

| Action         | Context Fields                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------------- |
| `ShellCommand` | `command`, `working_dir`, `signature.*`, `has_long_running_process`, `longest_process_runtime_seconds` |
| `WebFetch`     | `url`, `signature.*`                                                                               |
| `FileRead`     | `path`, `signature.*`                                                                              |
| `FileWrite`    | `path`, `signature.*`                                                                              |
| `FileEdit`     | `path`, `signature.*`                                                                              |
| `FileDelete`   | `path`, `signature.*`                                                                              |

The `signature` context (from YARA) provides: `severity` (0-4), `categories` (set of strings), `match_count`.

### Example: Block Force Pushes

```cedar
@id("forbid-git-force-push")
@description("Block git push --force to prevent history rewriting.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git push*--force*" ||
    context.command like "*git push*-f *"
};
```

### Example: Block Kill When Long-Running Processes Exist

```cedar
@id("forbid-kill-long-running")
@description("Block kill commands when long-running user processes exist.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*kill *" || context.command like "*pkill *") &&
    context.has_long_running_process
};
```

### Example: Block High-Severity Actions

```cedar
@id("block-high-severity")
@description("Block any shell command with YARA severity >= High.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.severity >= 3
};
```

### Included Policies

| File | Rules | Coverage |
|------|-------|----------|
| `base.cedar` | 4 | Default-permit baseline, severity gates for shell/web/file |
| `destructive.cedar` | 29 | `rm -rf`, `git push --force`, `chmod 777`, `mkfs`, `terraform destroy`, `docker rm -f`, `DROP TABLE`, lockfile deletion, and more |
| `file_guards.cedar` | 10 | Protects `/etc/passwd`, SSH keys, cloud credentials, `.env` files, shell profiles, git hooks |

## YARA Rules

Embedded at compile time from `rules/`. Seven categories:

| File | Detects |
|------|---------|
| `destructive_ops.yar` | `rm -rf`, force push, disk format, partition delete, Docker/K8s teardown |
| `injection.yar` | Command injection (`$()`, backticks, pipes to `sh`), SQL injection, reverse shells |
| `secrets.yar` | AWS/GCP/Azure keys, JWTs, PGP keys, GitHub tokens, Slack webhooks, DB connection strings |
| `exfil.yar` | DNS tunneling, curl/wget to external hosts, `.ssh` key access, steganography, paste sites |
| `obfuscation.yar` | Base64/hex encoding, ROT13, decode+execute, polyglots |
| `pi.yar` | Prompt injection (ignore instructions, role manipulation, credential extraction) |
| `supply_chain.yar` | Package installs from URLs, `npm publish`, global installs, registry overrides |

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `VETO_POLICY_DIR` | `./policies` | Cedar policies and schema directory |
| `VETO_SOCKET` | `~/.veto/veto.sock` | Unix socket path |
| `VETO_DB` | `~/.veto/audit.db` | SQLite audit log path |
| `API_KEY` | -- | Required for `veto policy add` (NL → Cedar); bearer token for the LLM gateway |
| `LLM_GATEWAY_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible API root (chat completions) |
| `VETO_MODEL` | `gpt-4o-mini` | Model id for policy generation (must match your gateway) |
| `RUST_LOG` | `info` | Tracing filter |

## Performance

Release build benchmarks on Apple Silicon:

| Stage | Median | p99 |
|-------|--------|-----|
| YARA scan | ~220 us | ~300 us |
| Cedar eval | ~60 us | ~100 us |
| Full pipeline | ~340 us | ~400 us |

All p99 latencies under 0.5ms. Your agent won't notice.

## Troubleshooting

### "veto-server is not running (socket not found)"

The server isn't running or the socket path doesn't match.

```bash
veto-server                    # start it
VETO_SOCKET=/path/to/sock veto ping  # check with explicit path
```

### "Policy directory not found"

Run `veto-server` from the repo root, or set `VETO_POLICY_DIR`:

```bash
VETO_POLICY_DIR=/path/to/policies veto-server
```

### "API_KEY env var required"

Only needed for `veto policy add`. Set your provider key and, if needed, the gateway URL:

```bash
export API_KEY=sk-...
export LLM_GATEWAY_BASE_URL=https://api.openai.com/v1
export VETO_MODEL=gpt-4o-mini
```

### Diagnose Everything at Once

```bash
veto doctor
# [+] policy directory          1 schema, 3 policies
# [+] cedar policies            43 policies loaded and validated
# [+] yara rules                compiled and scanner functional
# [+] audit database            /Users/you/.veto/audit.db (42 events)
# [+] veto-server               running (43 policies)
# [+] claude hooks              configured in .claude/settings.local.json
# [~] llm (policy add)         API_KEY not set (policy add unavailable)
```

## Testing

```bash
cargo test            # 27 unit + integration tests
```

## License

MIT

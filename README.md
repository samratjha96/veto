# Veto

Stateless per-action policy daemon for AI coding agents. Intercepts shell commands, file operations, and web fetches, evaluates each against Cedar policies with YARA-X pre-scanning, and returns allow/deny/ask.

```
hook JSON in -> YARA scan -> Cedar eval -> verdict -> SQLite audit log -> response out
```

## Install

```bash
cargo install --path .
```

This installs two binaries: `veto-server` (daemon) and `veto` (CLI).

## Quick Start

```bash
# 1. Start the server (from the repo root, or set VETO_POLICY_DIR)
veto-server

# 2. In another terminal, verify it's running
veto ping

# 3. Wire up Claude Code hooks
veto setup              # writes to .claude/settings.local.json
veto setup --print      # preview the config without writing

# 4. Start Claude Code -- veto is now intercepting actions
```

## How It Works

Every action Claude Code takes (shell command, file write, web fetch) goes through a three-stage pipeline:

1. **YARA-X scan** -- pattern-matches the action content against ~70 embedded rules across 7 categories (destructive ops, injection, secrets, exfiltration, obfuscation, prompt injection, supply chain)
2. **Cedar evaluation** -- evaluates the action against Cedar policies with the YARA results as context. Policies can reference command text, file paths, URLs, YARA severity/categories, and process context.
3. **Verdict** -- `allow`, `deny` (with reason), or `ask` (prompt user). Every decision is logged to SQLite.

Entities are built fresh per request. No session state, no multi-turn tracking.

## CLI Reference

### `veto-server`

Long-lived daemon. Listens on `~/.veto/veto.sock`.

```bash
veto-server                          # default config
VETO_POLICY_DIR=./policies veto-server   # explicit policy dir
RUST_LOG=debug veto-server           # verbose logging
```

### `veto hook`

Forwards Claude Code hook events to the server. This is what the hooks configuration calls.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | veto hook --hook-type pre-tool-use
```

### `veto status`

Shows server status: policy count, uptime, last reload.

### `veto reload`

Forces an immediate policy reload. Also happens automatically when `.cedar` files change on disk.

### `veto policy list`

Lists loaded Cedar policies with their `@id` annotations.

```
  base.cedar
    - default-permit
    - block-high-severity-shell-commands
    - block-critical-severity-file-writes
  destructive.cedar
    - forbid-rm-rf
    - forbid-git-force-push
    ...
  file_guards.cedar
    - forbid-write-etc-passwd
    - forbid-delete-env-files
    ...
```

### `veto policy add "<description>"`

Generates a Cedar policy from natural language using an LLM, validates it against the schema, and saves it to the policy directory.

```bash
export API_KEY=...
veto policy add "never kill running processes without asking me first"
veto policy add "block all curl commands to non-HTTPS URLs" --dry-run
```

### `veto policy remove <name>`

Deletes a policy file (with confirmation). Triggers server reload.

### `veto audit`

Query the audit log.

```bash
veto audit                          # last 20 events
veto audit --limit 50               # more events
veto audit --decision deny          # only denials
veto audit --hook-type pre-tool-use # filter by hook type
veto audit --json                   # JSON output
veto audit --tail                   # stream new events (like tail -f)
veto audit --tail --decision deny   # stream only denials
```

### `veto bench`

Run adjudication pipeline microbenchmarks.

```bash
veto bench                          # 1000 iterations
veto bench --iterations 5000        # more iterations
veto bench --json                   # machine-readable output
```

## Policies

Cedar policies live in the `policies/` directory. The schema (`base.cedarschema`) defines six actions:

| Action | Context fields |
|--------|---------------|
| `ShellCommand` | `command`, `working_dir`, `signature.*`, `has_long_running_process`, `longest_process_runtime_seconds` |
| `WebFetch` | `url`, `signature.*` |
| `FileRead` | `path`, `signature.*` |
| `FileWrite` | `path`, `signature.*` |
| `FileEdit` | `path`, `signature.*` |
| `FileDelete` | `path`, `signature.*` |

The `signature` context (from YARA) has: `severity` (0-4), `categories` (set of strings), `match_count`.

### Example policy

```cedar
@id("forbid-rm-rf")
forbid(
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -rf *" || context.command like "*rm -r /*"
};
```

### Included policies

- **base.cedar** -- default-permit baseline with severity gates (blocks high-severity shell commands and critical-severity file writes)
- **destructive.cedar** -- 40+ forbid rules for `rm -rf`, `git push --force`, `chmod 777`, `mkfs`, `dd if=`, `iptables -F`, `docker rm -f`, etc.
- **file_guards.cedar** -- protects system files (`/etc/passwd`, SSH keys, cloud credentials, shell profiles, `.env` files, git hooks)

## YARA Rules

Embedded at compile time from `rules/`. Seven categories:

| File | Rules | Detects |
|------|-------|---------|
| `destructive_ops.yar` | ~15 | rm -rf, force push, disk format, partition delete, etc. |
| `injection.yar` | ~8 | Command injection ($(), backticks, pipes to sh, eval) |
| `secrets.yar` | ~15 | AWS/GCP/Azure keys, JWTs, PGP keys, Slack webhooks, etc. |
| `exfil.yar` | ~10 | DNS tunneling, curl/wget to external, .ssh key access, steganography |
| `obfuscation.yar` | 8 | Base64/hex encoding, ROT13, decode+execute, polyglots |
| `pi.yar` | 7 | Prompt injection (ignore instructions, role manipulation, credential extraction) |
| `supply_chain.yar` | 9 | Package install from URLs, npm/pip publish, global installs, registry overrides |

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VETO_POLICY_DIR` | `./policies` | Cedar + YARA directory |
| `VETO_SOCKET` | `~/.veto/veto.sock` | Unix socket path |
| `VETO_DB` | `~/.veto/audit.db` | SQLite audit log |
| `API_KEY` | -- | Required for `veto policy add` |
| `VETO_MODEL` | `openai/openai/gpt-5.4-mini` | LLM for policy generation |
| `RUST_LOG` | `info` | Tracing filter |

## Architecture

```
veto/
├── src/
│   ├── lib.rs
│   ├── adjudicate.rs         # YARA -> Cedar -> Verdict pipeline
│   ├── audit.rs              # SQLite append-only event log
│   ├── bench.rs              # In-process microbenchmarks
│   ├── cedar_runtime.rs      # Cedar policy loading + evaluation
│   ├── config.rs             # Env var config
│   ├── ipc.rs                # Length-prefixed JSON framing
│   ├── llm.rs                # LLM API client
│   ├── policy_gen.rs         # NL -> Cedar generation
│   ├── process_context.rs    # sysinfo-based process detection
│   ├── server.rs             # Request handler (shared by daemon + tests)
│   ├── signature.rs          # YARA-X rule compilation + scanning
│   ├── watcher.rs            # notify-based hot-reload
│   ├── hook/
│   │   ├── kind.rs           # HookKind enum
│   │   └── outcome.rs        # Verdict: Allow / Deny / Ask
│   ├── adapters/claude/
│   │   ├── payload.rs        # Extract scan text from Claude hook JSON
│   │   ├── response.rs       # Build Claude hook response JSON
│   │   └── tool_json.rs      # Tool input field extraction
│   └── bin/
│       ├── server.rs          # veto-server entry point
│       └── cli.rs             # veto CLI entry point
├── policies/
│   ├── base.cedarschema       # Entity + action schema
│   ├── base.cedar             # Default-permit + severity gates
│   ├── destructive.cedar      # 40+ destructive operation rules
│   └── file_guards.cedar      # System file protection
└── rules/
    ├── destructive_ops.yar
    ├── injection.yar
    ├── secrets.yar
    ├── exfil.yar
    ├── obfuscation.yar
    ├── pi.yar
    └── supply_chain.yar
```

## Performance

Release build benchmarks (2000 iterations on Apple Silicon):

| Stage | Median | p99 |
|-------|--------|-----|
| YARA scan | ~220 us | ~300 us |
| Cedar eval | ~60 us | ~100 us |
| Full pipeline | ~340 us | ~400 us |
| Policy load | ~1.8 ms | -- |

All p99 latencies under 0.5ms.

## Testing

```bash
cargo test                               # unit + integration (134 tests)
cargo test --test e2e -- --ignored       # e2e tests (require real Unix socket)
```

## License

MIT

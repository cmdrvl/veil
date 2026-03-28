# veil — Implementation Plan

## Overview

veil is a data exfiltration guard for AI coding agents. It prevents agents from
reading sensitive file contents into their context window while allowing
orchestration of spine tools that process those files as authorized
subprocesses.

Architecturally modeled after [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) (Destructive Command Guard), which intercepts destructive commands. veil intercepts data access.

`veil` is not boundary attestation. `airlock` owns proof of what crossed the
model boundary. `veil` owns prevention of raw sensitive reads before any model
boundary exists.

---

## Architecture

### Position in the stack

`veil` sits upstream of `airlock`:

```text
dcg / veil
  -> local tool execution
  -> authorized spine subprocesses
  -> derived telemetry artifacts
  -> airlock assemble / verify
  -> model request
```

- `dcg` blocks destructive commands
- `veil` blocks raw sensitive reads
- `airlock` proves what derived artifacts crossed into the model request

### Hook Integration

veil registers as a Claude Code `PreToolUse` hook with multiple matchers:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }]
      },
      {
        "matcher": "Grep",
        "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }]
      },
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }]
      }
    ]
  }
}
```

#### Hook ordering with dcg

Both veil and dcg register PreToolUse hooks on `Bash`. Claude Code runs all matching hooks — if any returns deny, the tool call is blocked. This means:

- **No conflict:** Both hooks fire independently. dcg checks for destructive commands, veil checks for data exfiltration. A command can be blocked by either or both.
- **No ordering dependency:** Each hook makes its own allow/deny decision. They do not need to coordinate.
- **Spine tool pass-through:** dcg has no reason to block spine tool invocations (they are not destructive). veil explicitly allows them. Both will return allow for `shape data.csv`.

### Decision Pipeline

```
Hook Input (JSON on stdin)
    │
    ▼
┌─────────────────────────────────────┐
│  1. Parse hook input                │
│     - Detect protocol (Claude/      │
│       Gemini/Copilot)               │
│     - Extract tool type + args      │
│     - Extract file path(s)          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  2. Path extraction                 │
│     - Read tool: file_path field    │
│     - Grep tool: path field +        │
│       check output_mode (only       │
│       "content" leaks data;         │
│       "files_with_matches" is safe) │
│     - Bash: parse cat/head/tail/    │
│       less/python -c/node -e args   │
│     - Normalize relative → absolute │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  3. Allowlist check (fast path)     │
│     - Exact match on safe files     │
│     - Glob match on safe patterns   │
│     - If safe → ALLOW (silent)      │
└──────────────┬──────────────────────┘
               │ not allowlisted
               ▼
┌─────────────────────────────────────┐
│  4. Sensitivity classification      │
│     - Match against protected       │
│       path patterns                 │
│     - Check sensitivity packs       │
│       (secrets, PII, compliance)    │
│     - Score confidence              │
│     - If NOT sensitive → ALLOW      │
│       (audit log only)              │
└──────────────┬──────────────────────┘
               │ sensitive
               ▼
┌─────────────────────────────────────┐
│  5. Spine tool check (Bash only)    │
│     - Is this a spine tool          │
│       subprocess invocation?        │
│     - e.g., "shape data.csv"        │
│     - If spine tool → ALLOW (audit) │
│     - N/A for Read/Grep (those      │
│       always read into context)     │
└──────────────┬──────────────────────┘
               │ not spine tool
               ▼
┌─────────────────────────────────────┐
│  6. Policy resolution               │
│     - Apply per-sensitivity policy  │
│     - Deny / Warn / Log            │
│     - Generate explanation          │
│     - Suggest spine tool alternative│
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  7. Output                          │
│     - JSON to stdout (hook proto)   │
│     - Colorful warning to stderr    │
│     - Append to audit log           │
└─────────────────────────────────────┘
```

### Configuration Layers

Precedence (highest to lowest):

1. **Environment variables** — `VEIL_PROTECTED`, `VEIL_POLICY`, etc.
2. **Project config** — `.veil.toml` at repo root
3. **User config** — `~/.config/veil/config.toml`
4. **System config** — `/etc/veil/config.toml`
5. **Compiled defaults** — built-in safe patterns

### Sensitivity Packs (Modular)

Following dcg's pack architecture:

| Pack | What It Protects |
|------|-----------------|
| `core.filesystem` | Common sensitive paths (`.env`, `.ssh/`, `*.pem`, `*.key`) |
| `core.credentials` | API keys, tokens, database URLs in config files |
| `data.tabular` | CSV/TSV/parquet files — only triggers inside `[sensitivity] protected` directories, not globally on extension |
| `data.xml` | XML filings (NPORT, EDGAR, etc.) — only triggers inside protected directories |
| `data.database` | SQLite, DuckDB, dump files — triggers globally (databases are always sensitive) |
| `compliance.financial` | Financial data, fund holdings, trading records |
| `compliance.pii` | Personally identifiable information |
| `compliance.hipaa` | Health records |

### Spine Tool Authorization

veil maintains a registry of authorized spine tools. When a Bash command matches the pattern `<spine-tool> [flags] <file>`, it's treated as an authorized subprocess invocation — the spine tool processes the file, not the agent.

```toml
[spine]
authorized_tools = [
    "shape", "rvl", "vacuum", "hash",
    "fingerprint", "profile", "canon", "lock", "pack",
]
# Custom tools can be added per-project
```

This list should stay limited to tools that operate on protected files without
exposing raw contents to the agent. `airlock` does not belong in this list
because it operates downstream on derived telemetry and prompt artifacts, not
on raw sensitive files.

### Audit Trail

Every access attempt is logged. Default location is `~/.local/state/veil/audit.jsonl` (user-level, outside repo — avoids committing sensitive file paths to git). Overridable via `[policy] audit_path`:

```json
{
  "ts": "2026-03-01T16:00:00Z",
  "tool": "Read",
  "path": "data/clients/holdings.csv",
  "decision": "deny",
  "reason": "Protected by data.csv pack",
  "sensitivity": "compliance.financial",
  "confidence": 0.95,
  "session_id": "abc-123"
}
```

---

## Relationship to dcg and airlock

veil borrows heavily from dcg's architecture:

| Component | dcg | veil |
|-----------|-----|------|
| Hook type | PreToolUse (Bash) | PreToolUse (Read, Grep, Bash) |
| Input | Shell commands | File paths + shell commands |
| Patterns | Destructive command regexes | Sensitive path globs |
| Packs | Security packs (git, k8s, etc.) | Sensitivity packs (secrets, PII, etc.) |
| Allowlist | Command allowlists | File allowlists |
| Fast path | Keyword quick-reject | Safe pattern quick-allow |
| Policy | Deny/Warn/Log per pack | Deny/Warn/Log per sensitivity |
| Output | Block explanation + safe alternative | Block explanation + spine tool suggestion |
| Audit | SQLite history | JSONL audit log |

### Key Difference: Default Stance

- **dcg is fail-open:** Unknown commands are allowed (most commands are safe)
- **veil is fail-open by default** but supports **fail-closed per directory:** The global default must be fail-open (an agent that can't read any files is useless). But for explicitly protected directories, the stance inverts — unknown files inside a protected directory are blocked. This is configured via `[sensitivity] protected` patterns, not a global toggle.
- **On timeout/error:** Always fail-open. A guard that blocks the agent due to its own bugs is worse than no guard. Audit-log the timeout so operators can investigate.

### Different problem than airlock

`airlock` solves a different problem:

| Tool | Primary question |
|------|------------------|
| `dcg` | Is this command destructive? |
| `veil` | Would this tool call expose raw sensitive file contents to the agent? |
| `airlock` | What exact prompt/request bytes crossed into the model, and what claim level was earned? |

So:

- `veil` is a preventive local guard
- `airlock` is a deterministic boundary attestor
- neither replaces the other

---

## Build & Distribution

### Binary

Single Rust binary, same release profile as spine tools:

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### Installation

```bash
# Homebrew
brew tap cmdrvl/tap
brew install veil

# Cargo
cargo install --path .

# Installer script (curl | bash)
curl -fsSL https://raw.githubusercontent.com/cmdrvl/veil/main/install.sh | bash
```

### Installer

Following dcg's installer pattern:
- Auto-detects platform (macOS arm/intel, Linux arm/intel)
- Downloads pre-built binary from GitHub Releases
- Configures `~/.claude/settings.json` hook entries
- Idempotent (safe to re-run)
- Supports `--uninstall`, `--status`, `--dry-run`

---

## CLI Subcommands

```bash
veil                    # Hook mode (reads stdin, called by Claude Code)
veil test <path>        # Test if a file would be blocked
veil explain <path>     # Show why a file is sensitive
veil scan <dir>         # Scan directory for sensitivity classification
veil packs              # List available sensitivity packs
veil config             # Show resolved configuration
veil audit              # Show recent audit log entries
veil doctor             # Self-test installation health
veil install            # Configure hooks in settings.json
veil uninstall          # Remove hooks from settings.json
```

---

## Out of Scope (v0)

**Write/Edit tools are not guarded.** veil prevents data from entering the agent's context. It does not prevent the agent from writing data that's already in context to files. An agent could theoretically capture spine tool output to a file, commit it, and push — but this is a different threat (exfiltration via output) than the one veil addresses (exfiltration via input). Guarding writes is a future consideration, not a v0 requirement.

**PostToolUse output filtering is not guarded.** When spine tools run as subprocesses, their stdout is captured back into the agent's context. veil trusts spine tool output by design (redacted by default). Filtering subprocess output would require a PostToolUse hook, which is architecturally different from PreToolUse interception.

**Model-boundary proof is not guarded.** If a workflow later sends derived
telemetry or summaries to a model, `veil` does not prove that boundary.
`airlock` is the companion tool for that job.

---

## Interaction with Spine Tool Redaction

veil and spine tool `--explicit` flags are complementary:

| Layer | What It Does |
|-------|-------------|
| **veil** | Prevents agent from reading raw files into context |
| **spine --redacted (default)** | Spine tool output shows structure, not values |
| **spine --explicit** | Opt-in to full values in spine output |

In zero-retention environments:
- veil blocks all direct file access
- Spine tools run with redacted output (default)
- Agent sees only structural metadata
- For debugging, operator can run spine tools with `--explicit` outside the agent

---

## Performance Budget

Following dcg's performance model:

| Phase | Budget |
|-------|--------|
| Parse hook input | < 100µs |
| Path extraction | < 100µs |
| Allowlist check | < 200µs |
| Sensitivity classification | < 500µs |
| Policy resolution | < 100µs |
| **Total** | **< 1ms** |

If budget exceeded → allow with audit log (fail-open).

---

## Testing Strategy

### Unit Tests
- Path extraction from each tool type (Read, Grep, Bash)
- Allowlist matching (exact, glob, directory)
- Sensitivity pack matching
- Spine tool detection
- Configuration loading and merging

### Integration Tests
- End-to-end hook invocation with JSON stdin
- Multi-protocol support (Claude, Gemini, Copilot)
- Audit log writing
- Installer script

### Golden File Tests
- Known-sensitive paths → expected decisions
- Known-safe paths → expected allows
- Edge cases (symlinks, relative paths, `..` traversal)

### Property Tests
- Any path matching an allowlist pattern should never be denied
- Spine tool invocations on protected paths should be allowed (that's the authorized processing path)
- Sensitivity + no allowlist + no spine tool → always denied

---

## Build Order

1. **Scaffold** — Cargo project, CI, release profile, installer
2. **Hook protocol** — Parse stdin JSON, detect protocol, extract tool type + path
3. **Path extraction** — Read, Grep, Bash path parsing
4. **Configuration** — Layered TOML config, sensitivity patterns
5. **Allowlist** — Safe pattern matching (fast path)
6. **Sensitivity packs** — Modular pack registry
7. **Spine tool detection** — Authorized subprocess check
8. **Policy engine** — Deny/Warn/Log resolution
9. **Output** — Hook response + stderr warning + audit log
10. **CLI subcommands** — test, explain, scan, packs, doctor
11. **Installer** — curl | bash, homebrew formula
12. **Hardening** — Symlink resolution, path traversal, edge cases

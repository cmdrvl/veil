# veil

**Data exfiltration guard for AI coding agents.**

A high-performance Claude Code hook that prevents agents from reading sensitive file contents into their context window, enforcing a clean boundary between orchestration and data access.

---

## The Problem

AI coding agents can read any file on your machine. When orchestrating data pipelines on sensitive documents, the agent might `cat` a file, use the Read tool, or grep through contents — pulling private data into the prompt, which gets sent to the inference API. This violates zero-retention policies and exposes confidential information.

## The Solution

veil intercepts file access attempts before they execute, blocking reads of sensitive files while allowing authorized processing through spine tools (shape, rvl, profile, canon, etc.) that run as subprocesses and produce structured metadata — never raw data.

```
ALLOW:  shape client_data.csv        → subprocess, output is schema report
BLOCK:  cat client_data.csv          → raw data would enter prompt
BLOCK:  Read tool on client_data.csv → raw data would enter prompt
ALLOW:  Read tool on shape-report.json → derived artifact, safe
```

---

## Quick Install

```bash
brew tap cmdrvl/tap
brew install veil
```

Or build from source:

```bash
cargo install --path .
```

---

## How It Works

veil hooks into Claude Code's `PreToolUse` event for multiple tool types:

| Hook Matcher | What It Guards |
|-------------|----------------|
| `Read` | Direct file reads into context |
| `Grep` | Content-mode grep exposing file contents |
| `Bash` | Shell commands that read files (`cat`, `head`, `python -c "open(...)"`) |

### Configuration

```toml
# .veil.toml (project root) or ~/.config/veil/config.toml

[sensitivity]
# Paths that are sensitive (glob patterns)
protected = [
    "data/clients/**",
    "filings/**/*.xml",
    "*.nport.xml",
    "exports/*.csv",
]

[spine]
# Spine tools allowed to process sensitive files as subprocesses
authorized_tools = [
    "shape", "rvl", "vacuum", "hash",
    "fingerprint", "profile", "canon", "lock", "pack",
]

[allowlist]
# Files always safe to read
safe_patterns = [
    "*.md", "*.toml", "*.lock",
    "docs/**", "tests/**", ".github/**",
    "*-report.json", "*-report.yaml",
    "package.json", "tsconfig.json",
    "Cargo.toml", "Cargo.lock",
]
# NOTE: *.json and *.yaml are NOT safe by default.
# Files like credentials.json, secrets.yaml, service-account.json
# are common sensitive targets. Allowlist specific filenames instead.

[policy]
# What to do when a sensitive file is accessed
default = "deny"           # deny | warn | log
audit_log = true           # Log all access attempts
audit_path = "~/.local/state/veil/audit.jsonl"  # default; outside repo
```

### Decision Pipeline

```
File access attempt (Read/Grep/Bash)
    │
    ├── Allowlist check → safe pattern? → ALLOW (silent)
    │
    ├── Sensitivity check → protected path?
    │       │
    │       ├── Is this a spine tool subprocess? → ALLOW (audit log)
    │       │
    │       └── Direct read into context? → DENY (explain why)
    │
    └── Unknown file → policy default (deny|warn|log)
```

---

## Pairs With

| Tool | Role |
|------|------|
| **dcg** | Blocks destructive commands (git reset, rm -rf) |
| **veil** | Blocks data exfiltration (reading sensitive files) |
| **post-compact-reminder** | Re-reads AGENTS.md after context compaction |
| **spine tools** | Authorized processing path for sensitive data |

---

## Architecture

veil is modeled after [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) and shares key architectural patterns:

- **Layered configuration:** project > user > system > defaults
- **Fail-safe design:** budget exceeded → allow with audit log
- **Sub-millisecond latency:** fast-path glob matching with early exit
- **Multi-protocol support:** Claude Code, Gemini CLI, Copilot
- **Rich denial output:** explains why, suggests alternatives
- **Audit trail:** every access attempt logged with timestamps

---

## Two Operating Modes

### Normal Mode (95% case)
Agent orchestrates spine tools directly. veil blocks direct file reads. Spine tool output is redacted by default (`--explicit` to show raw values). Good for most sensitivity levels.

### Zero-Retention Mode (100% case)
Agent never touches documents. It writes a deterministic pipeline script that the client deploys on their own machine. Claude's job ends at code generation. No veil needed — the agent never runs on the same machine as the data.

---

## License

MIT

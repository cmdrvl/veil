# veil

**Data exfiltration guard for AI coding agents.**

A high-performance Claude Code hook that prevents agents from reading sensitive
file contents into their context window, enforcing a clean boundary between
orchestration and data access.

`veil` is the preventive companion to `airlock`:

- `veil` blocks raw sensitive data from entering the agent context in the first
  place
- `airlock` proves what derived artifacts later crossed the model boundary

---

## The Problem

AI coding agents can read any file on your machine. When orchestrating data pipelines on sensitive documents, the agent might `cat` a file, use the Read tool, or grep through contents — pulling private data into the prompt, which gets sent to the inference API. This violates zero-retention policies and exposes confidential information.

## The Solution

veil intercepts file access attempts before they execute, blocking reads of
sensitive files while allowing authorized processing through spine tools
(`shape`, `rvl`, `profile`, `canon`, etc.) that run as subprocesses and
produce structured metadata — never raw data.

If a downstream workflow later sends derived telemetry to a model, `veil` is
not the proof layer for that step. `airlock` owns that boundary attestation.

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
# What to do when veil detects a sensitive access
# (either a classified-sensitive file anywhere, or any unknown file inside an
# explicitly protected directory)
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
    ├── Protected-dir / sensitivity check
    │       │
    │       ├── Is this a spine tool subprocess? → ALLOW (audit log)
    │       │
    │       └── Direct read into context? → policy default (deny|warn|log)
    │
    └── Unknown file outside protected dirs → ALLOW
```

### Default Stance

- Unknown file outside `[sensitivity] protected` directories is allowed.
- Unknown file inside a protected directory is treated as sensitive and resolved through `[policy] default`.
- Classified-sensitive file anywhere is resolved through pack-specific rules or `[policy] default`, with direct reads denied by default.

---

## Pairs With

| Tool | Role |
|------|------|
| **dcg** | Blocks destructive commands (git reset, rm -rf) |
| **veil** | Blocks data exfiltration (reading sensitive files) |
| **airlock** | Proves what derived artifacts crossed the model boundary |
| **post-compact-reminder** | Re-reads AGENTS.md after context compaction |
| **spine tools** | Authorized processing path for sensitive data |

---

## Architecture

veil is modeled after
[dcg](https://github.com/Dicklesworthstone/destructive_command_guard) and
shares key architectural patterns:

- **Layered configuration:** project > user > system > defaults
- **Fail-safe design:** budget exceeded → allow with audit log
- **Sub-millisecond latency:** fast-path glob matching with early exit
- **Multi-protocol support:** Claude Code, Gemini CLI, Copilot
- **Rich denial output:** explains why, suggests alternatives
- **Audit trail:** every access attempt logged with timestamps

## Relationship to Airlock

`veil` and `airlock` are complementary, not competitive.

```text
raw sensitive files
  -> veil / local read guard
  -> authorized spine subprocesses
  -> derived telemetry artifacts
  -> airlock assemble / verify
  -> model request
```

- `veil` is a host-side prevention tool. It decides whether the agent may read
  a file or invoke a shell command that would expose raw contents.
- `airlock` is a model-boundary proof tool. It decides what claim can be made
  about the exact prompt and request bytes that crossed to a model.
- `veil` does not emit boundary manifests or prove model cleanliness.
- `airlock` does not stop a local agent from `cat`-ing a file before prompt
  assembly.

That split matters. `veil` protects the local working environment. `airlock`
attests the model boundary.

---

## Two Operating Modes

### Normal Mode (95% case)
Agent orchestrates spine tools directly. `veil` blocks direct file reads. Spine
tool output is redacted by default (`--explicit` to show raw values). If any
derived telemetry later goes to a model, pair this with `airlock` for boundary
proof. Good for most sensitivity levels.

### Zero-Retention Mode (100% case)
Agent never touches documents. It writes a deterministic pipeline script that the client deploys on their own machine. Claude's job ends at code generation. No veil needed — the agent never runs on the same machine as the data.

---

## License

MIT

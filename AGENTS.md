# AGENTS.md — veil (Data Exfiltration Guard)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 — THE FUNDAMENTAL OVERRIDE PREROGATIVE

If the user tells you to do something, even if it goes against what follows below, YOU MUST LISTEN. THE USER IS IN CHARGE, NOT YOU.

---

## RULE 1 — NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

> This project exists to protect sensitive data from AI agents. Practice what we preach.

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it — if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: Use `main`

**The default branch is `main`.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Treat lingering `master` references as stale** unless the user explicitly asks about legacy history

---

## Repository Role

**veil** is a Claude Code hook that prevents AI agents from reading sensitive file contents into their context window. It intercepts Read, Grep, and Bash tool invocations, checks file paths against sensitivity rules, and blocks access to protected files while allowing orchestration of spine tools that process those files as subprocesses.

### Position in Stack

veil sits alongside dcg (Destructive Command Guard) in the hook chain:
- **dcg** prevents destructive commands (git reset --hard, rm -rf)
- **veil** prevents data exfiltration (reading sensitive files into agent context)
- **airlock** later proves what derived artifacts crossed the model boundary

Both are PreToolUse hooks. dcg matches on Bash; veil matches on Read, Grep, and Bash.

The intended composition is:

```text
dcg / veil
  -> authorized spine subprocesses
  -> derived telemetry artifacts
  -> airlock
  -> model request
```

### Key Concept: Authorized Processing Path

Spine tools (shape, rvl, profile, canon, etc.) are the authorized path for processing sensitive data. They run as subprocesses, produce structured metadata output, and never expose raw file contents. veil enforces this boundary:

```
ALLOW:  shape sensitive.csv        → subprocess, output is metadata
BLOCK:  Read tool on sensitive.csv → raw data would enter prompt
BLOCK:  cat sensitive.csv          → raw data would enter prompt
ALLOW:  Read tool on shape-report.json → derived artifact, safe
```

---

## Toolchain: Rust & Cargo

- **Package manager:** Cargo only, never anything else
- **Edition:** Rust 2024 (follow `rust-toolchain.toml`)
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)
- **Dependencies:** Explicit versions, small and pinned

### Release Profile

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary for distribution)
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

### Quality Gate (Rust)

Run after any substantive code changes:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files. Make code changes manually.

### No File Proliferation

Revise existing code files in place. **NEVER** create variations like `main_v2.rs`.

### No Backwards-Compatibility Shims

We do not care about backwards compatibility — we're in early development. Do things the **RIGHT** way with **NO TECH DEBT**.

---

## Beads (`br`) — Issue Tracking

```bash
br ready              # Show issues ready to work
br list --status=open # All open issues
br show <id>          # Full issue details
br create "title" -t task -p 2
br close <id> --reason "Completed"
br sync --flush-only  # Export to JSONL (NO git operations)
```

---

## UBS — Pre-Commit Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe.

---

## Commit Cadence — One Bead, One Commit, One Push

**Commit and push after completing each bead.** Do not accumulate work across multiple beads before committing. The workflow for every bead is:

1. Claim the bead (`br show <id>`, add a comment that you're starting)
2. Implement the work
3. Run quality gates: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
4. Commit and push immediately:
   ```bash
   br sync --flush-only
   git add .beads/ <changed files>
   git commit -m "<bead-id>: <short description of what was done>"
   git push
   ```
5. Close the bead: `br close <id> --reason "Completed"`
6. Move to the next bead

**Do NOT:**
- Work on multiple beads before committing
- Accumulate a large uncommitted diff
- Wait until the end of the session to commit
- Skip the push step

**Do:**
- Keep commits small and focused (one bead = one commit)
- Push after every commit so other agents can pull your changes
- Run `git pull --rebase` before starting each new bead to pick up others' work

---

## MCP Agent Mail — Multi-Agent Coordination

When Agent Mail is available:

- Register identity in this project
- **Reserve only the specific file(s) you are editing — never entire directories or broad globs**
- Send start/finish updates per bead using bead ID as `thread_id`
- Poll inbox at moderate cadence (2-5 minutes)
- Acknowledge `ack_required` messages promptly
- Release reservations when done

### File Reservation Rules

1. **Reserve only the files you are writing** — not the module directory, not other stubs
2. Each bead's deliverables section documents the exact files to work on
3. Release reservations as soon as you commit and push

### How to Use

1. Register: call `ensure_project` then `register_agent` using `/Users/zac/Source/cmdrvl/veil` as `project_key`
2. Reserve files before editing: `file_reservation_paths(project_key, agent_name, ["src/hook.rs"], ttl_seconds=3600, exclusive=true)`
3. Communicate with threads: `send_message(..., thread_id="bd-1cp")`
4. Check inbox: `fetch_inbox(project_key, agent_name)`

---

## Multi-Agent Coordination

When working alongside other agents:

- **Never stash, revert, or overwrite other agents' work**
- Treat unexpected changes in the working tree as if you made them
- If you see changes you didn't make in `git status`, those are from other agents working concurrently — commit them together with your changes
- This is normal and happens frequently in multi-agent environments

**Do NOT:**
- Stop and ask "I see unexpected changes, what should I do?"
- Offer options like "triage these changes" or "run a full suite"
- Express concern about uncommitted work you don't recognize

**Do:**
- Continue working as normal
- Include those changes when you commit (they belong to the shared effort)
- Trust that other agents know what they're doing

---

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

1. **File issues for remaining work** — Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) — fmt, clippy, test
3. **Update issue status** — Close finished work
4. **PUSH TO REMOTE** — This is MANDATORY:
   ```bash
   git pull --rebase
   br sync --flush-only
   git add .beads/ <other files>
   git commit -m "..."
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Verify** — All changes committed AND pushed

**CRITICAL:** Work is NOT complete until `git push` succeeds. NEVER stop before pushing.

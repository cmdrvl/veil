#!/usr/bin/env bash
# bd-sel: run the INSTALLED veil hook through real PreToolUse JSON for every row
# of the bypass matrix, and say what it did, row by row.
#
#   tests/e2e_hook_matrix.sh [--veil PATH] [--run-dir DIR] [--matrix FILE]
#
# What it does, in order:
#   1. builds the fixture repo that docs/bypass-matrix.json describes (the same
#      files, links and .veil.toml that tests/bypass_matrix.rs builds);
#   2. runs `veil install` against a throwaway Claude settings file and takes the
#      hook command and matchers from what it WROTE, not from a guess: the
#      command Claude Code would run is the command this runs;
#   3. for every row, sends the row's tool call to that command as a PreToolUse
#      payload on stdin and records the exit code, the decision, the reason, the
#      audit record veil wrote for it and the wall time (process start included);
#   4. compares each with the matrix's hook-only expectation, prints a per-row
#      line and a summary, and exits 1 if any row differs.
#
# It never runs a vector. A row is a command the hook is ASKED about; nothing it
# names is executed, so a "cat data/..." row reads nothing and an "rm" row would
# delete nothing. The hook decides; this script only reads the decision.
#
# Output goes to a run directory (printed first): rows.jsonl, summary.json,
# summary.txt, and per row a payload, the hook's stdout and its stderr. The run
# directory is never deleted by this script; pass a directory that does not
# exist yet or is empty.
#
# What it does not check: that Claude Code matches a plain matcher such as `Read`
# exactly and not as a substring of another tool name (that is Claude Code's
# behaviour; the rows that say "not routed" depend on it), and the sandbox
# column of the matrix (nothing runs a sandbox). Latency is reported, not
# asserted: a threshold here would be a flaky test.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
veil_bin=""
run_dir=""
matrix="$script_dir/../docs/bypass-matrix.json"

usage() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --veil) veil_bin="${2:?--veil needs a path}"; shift 2 ;;
    --run-dir) run_dir="${2:?--run-dir needs a path}"; shift 2 ;;
    --matrix) matrix="${2:?--matrix needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "e2e_hook_matrix: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$veil_bin" ]; then
  veil_bin="$(command -v veil || true)"
fi
if [ -z "$veil_bin" ] || [ ! -x "$veil_bin" ]; then
  echo "e2e_hook_matrix: no installed veil found; pass --veil PATH (cargo install --path . --locked --root DIR, then DIR/bin/veil)" >&2
  exit 2
fi
if [ ! -f "$matrix" ]; then
  echo "e2e_hook_matrix: matrix not found: $matrix" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "e2e_hook_matrix: python3 is needed to read the matrix JSON" >&2
  exit 2
fi

if [ -z "$run_dir" ]; then
  run_dir="$(mktemp -d "${TMPDIR:-/tmp}/veil-e2e-hook-matrix.XXXXXX")"
else
  if [ -e "$run_dir" ] && [ -n "$(ls -A "$run_dir" 2>/dev/null)" ]; then
    echo "e2e_hook_matrix: run directory is not empty and this script does not delete anything: $run_dir" >&2
    exit 2
  fi
  mkdir -p "$run_dir"
fi
# the fixture root is resolved (/var is /private/var on macOS): a path in a row
# and the path veil sees for the same file must be the same text
run_dir="$(cd "$run_dir" && pwd -P)"

veil_bin="$(cd "$(dirname "$veil_bin")" && pwd -P)/$(basename "$veil_bin")"

python3 -I - "$veil_bin" "$matrix" "$run_dir" <<'PY'
import json
import os
import pathlib
import shlex
import statistics
import subprocess
import sys
import time

veil_bin, matrix_path, run_dir = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])

matrix = json.load(open(matrix_path))
if matrix.get("schema_version") != "veil.bypass-matrix.v1":
    sys.exit(f"e2e_hook_matrix: unexpected matrix schema {matrix.get('schema_version')!r}")

repo = run_dir / "repo"
audit_path = repo / "state" / "audit.jsonl"
payload_dir = run_dir / "payloads"
out_dir = run_dir / "out"
for directory in (repo / "state", payload_dir, out_dir):
    directory.mkdir(parents=True, exist_ok=True)
repo = repo.resolve()
audit_path = repo / "state" / "audit.jsonl"

# ---- 1. the fixture
fixture = matrix["fixture"]
for entry in fixture["files"]:
    target = repo / entry["path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if "text" in entry:
        target.write_text(entry["text"])
    else:
        target.write_text(entry["head"] + entry["fill"] * entry["count"] + entry["tail"])
for link in fixture["symlinks"]:
    os.symlink(link["target"], repo / link["path"])
for link in fixture["hardlinks"]:
    os.link(repo / link["target"], repo / link["path"])
(repo / ".veil.toml").write_text(fixture["config"].replace("@AUDIT@", str(audit_path)))


def hook_env(extra=None):
    # the same environment tests/bypass_matrix.rs gives the hook: nothing of the
    # caller's veil configuration leaks in
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("VEIL_") and key not in ("XDG_CONFIG_HOME", "XDG_STATE_HOME")
    }
    env["HOME"] = str(repo)
    env["VEIL_HARNESS"] = "plain"
    env.update(extra or {})
    return env


# ---- 2. what `veil install` writes
settings = run_dir / "claude-settings.json"
installed = subprocess.run(
    [veil_bin, "install"],
    cwd=repo,
    env=hook_env({"VEIL_CLAUDE_SETTINGS_PATH": str(settings)}),
    capture_output=True,
    text=True,
)
if installed.returncode != 0:
    sys.exit(f"e2e_hook_matrix: veil install failed ({installed.returncode}): {installed.stderr}")
entries = json.load(open(settings))["hooks"]["PreToolUse"]
routes = []  # (matcher, command)
for entry in entries:
    for hook in entry.get("hooks", []):
        if hook.get("type") == "command":
            routes.append((entry["matcher"], hook["command"]))
if not routes:
    sys.exit("e2e_hook_matrix: veil install wrote no PreToolUse command hooks")


def route_for(tool_name):
    """The installed command Claude Code would run for this tool, or None. A
    plain matcher matches a tool name exactly, and `mcp__.*` every MCP tool."""
    for matcher, command in routes:
        if matcher == tool_name or (matcher == "mcp__.*" and tool_name.startswith("mcp__")):
            return command
    return None


print(f"run directory: {run_dir}")
print(f"veil: {veil_bin}")
print(f"matchers installed by `veil install`: {', '.join(m for m, _ in routes)}")
print(f"fixture repo: {repo}")
print(f"vectors: {len(matrix['vectors'])}")
print("latency is wall time per hook process, start-up included; it is reported, not asserted")
print()

# ---- 3. every row
root_text = str(repo)


def substitute(value):
    if isinstance(value, str):
        return value.replace("@ROOT@", root_text)
    if isinstance(value, list):
        return [substitute(item) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item) for key, item in value.items()}
    return value


def read_new_records(offset):
    if not audit_path.exists():
        return [], offset
    with open(audit_path, "rb") as handle:
        handle.seek(offset)
        data = handle.read()
    records = []
    for line in data.decode("utf-8", "replace").splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records, offset + len(data)


rows = []
mismatches = []
offset = 0
total = len(matrix["vectors"])
for index, vector in enumerate(matrix["vectors"], start=1):
    row_id = vector["id"]
    tool_name = vector["tool_name"]
    tool_input = substitute(vector["tool_input"])
    expected = vector["hook_only"]
    payload = {
        "session_id": row_id,
        "cwd": str(repo),
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    stem = f"{index:03d}-{row_id}"
    (payload_dir / f"{stem}.json").write_text(json.dumps(payload, indent=2) + "\n")

    command = route_for(tool_name)
    routed = command is not None
    run_command = command if routed else routes[0][1]
    started = time.perf_counter()
    result = subprocess.run(
        shlex.split(run_command),
        input=json.dumps(payload),
        cwd=repo,
        env=hook_env(),
        capture_output=True,
        text=True,
    )
    latency_ms = (time.perf_counter() - started) * 1000
    (out_dir / f"{stem}.stdout").write_text(result.stdout)
    (out_dir / f"{stem}.stderr").write_text(result.stderr)
    records, offset = read_new_records(offset)
    mine = [r for r in records if r.get("session_id") == row_id]

    problems = []
    got = "?"
    reason = ""
    got_reason_class = ""
    got_class = ""
    if expected["decision"] == "not_routed":
        if routed:
            problems.append(f"`veil install` routes {tool_name} to veil, the matrix says it does not")
        if result.returncode == 2 and "unsupported Claude Code tool" in result.stderr:
            got = "not_routed"
            reason = result.stderr.strip()
        else:
            got = f"exit {result.returncode}"
            problems.append(
                f"expected veil to refuse an unsupported tool (exit 2), got exit {result.returncode}: {result.stderr.strip()[:160]}"
            )
    else:
        if not routed:
            problems.append(f"`veil install` does not route {tool_name} to veil, the matrix says it does")
        if result.returncode != 0:
            got = f"exit {result.returncode}"
            problems.append(f"hook exited {result.returncode}: {result.stderr.strip()[:160]}")
        elif result.stdout == "":
            # exit 0 and not one byte: no decision, which is how veil allows
            got = "allow"
        else:
            # anything veil prints has to be exactly one deny
            try:
                reply = json.loads(result.stdout)
                reason = reply["hookSpecificOutput"]["permissionDecisionReason"]
                deny = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
                if reply == deny and isinstance(reason, str) and reason:
                    got = "deny"
                else:
                    problems.append(f"hook output is not exactly one deny: {result.stdout[:160]}")
            except (ValueError, KeyError, TypeError) as error:
                problems.append(f"hook output is not a decision ({error}): {result.stdout[:160]}")
        if got != expected["decision"] and not problems:
            problems.append(f"expected {expected['decision']}, got {got}")
        if expected["decision"] == "deny" and got == "deny":
            deny = [r for r in mine if r.get("decision") == "deny"]
            if not deny:
                problems.append("denied, but no deny record in the audit log")
            else:
                got_reason_class = deny[0].get("reason_class") or ""
                got_class = deny[0].get("class") or ""
                if got_reason_class != expected["reason_class"] or got_class != expected["class"]:
                    problems.append(
                        f"expected {expected['reason_class']}/{expected['class']!r}, the audit record says {got_reason_class}/{got_class!r}"
                    )
                if deny[0].get("enforcement") != "hook":
                    problems.append(f"audit record enforcement is {deny[0].get('enforcement')!r}, not 'hook'")

    ok = not problems
    label = got if not got_reason_class else f"{got}/{got_reason_class}" + (f"/{got_class}" if got_class else "")
    want = expected["decision"] if expected["decision"] != "deny" else (
        f"deny/{expected['reason_class']}" + (f"/{expected['class']}" if expected["class"] else "")
    )
    first_line = f"[{index:03d}/{total}] {'ok  ' if ok else 'FAIL'} {row_id:<34} {tool_name:<17} got {label:<34} want {want:<34} {latency_ms:7.1f} ms"
    print(first_line)
    shown_input = tool_input.get("command") if tool_name == "Bash" else json.dumps(tool_input)
    print(f"        input:  {shown_input[:200]}")
    if reason:
        print(f"        reason: {reason.splitlines()[0][:200]}")
    for problem in problems:
        print(f"        PROBLEM: {problem}")
    row = {
        "index": index,
        "id": row_id,
        "class": vector["class"],
        "tool_name": tool_name,
        "tool_input": tool_input,
        "expected": expected,
        "got": got,
        "reason": reason,
        "audit_reason_class": got_reason_class,
        "audit_class": got_class,
        "exit_code": result.returncode,
        "latency_ms": round(latency_ms, 2),
        "ok": ok,
        "problems": problems,
    }
    rows.append(row)
    if not ok:
        mismatches.append(row)

# ---- 4. the summary
with open(run_dir / "rows.jsonl", "w") as handle:
    for row in rows:
        handle.write(json.dumps(row) + "\n")


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


lines = []
lines.append(f"{'class':<42} {'rows':>5} {'ok':>5} {'FAIL':>5} {'p50 ms':>8} {'max ms':>8}")
for cls in dict.fromkeys(row["class"] for row in rows):
    group = [row for row in rows if row["class"] == cls]
    times = [row["latency_ms"] for row in group]
    lines.append(
        f"{cls:<42} {len(group):>5} {sum(r['ok'] for r in group):>5} {sum(not r['ok'] for r in group):>5} "
        f"{statistics.median(times):>8.1f} {max(times):>8.1f}"
    )
times = [row["latency_ms"] for row in rows]
lines.append(
    f"{'ALL':<42} {len(rows):>5} {sum(r['ok'] for r in rows):>5} {len(mismatches):>5} "
    f"{statistics.median(times):>8.1f} {max(times):>8.1f}"
)
lines.append(
    f"latency over all rows: p50 {percentile(times, 0.5):.1f} ms, p95 {percentile(times, 0.95):.1f} ms, max {max(times):.1f} ms"
)
summary_text = "\n".join(lines)
(run_dir / "summary.txt").write_text(summary_text + "\n")
(run_dir / "summary.json").write_text(
    json.dumps(
        {
            "veil": veil_bin,
            "rows": len(rows),
            "ok": len(rows) - len(mismatches),
            "mismatches": [row["id"] for row in mismatches],
            "latency_ms": {
                "p50": percentile(times, 0.5),
                "p95": percentile(times, 0.95),
                "max": max(times),
            },
        },
        indent=2,
    )
    + "\n"
)
print()
print(summary_text)
print()
if mismatches:
    print(f"{len(mismatches)} of {len(rows)} rows differ from the matrix:")
    for row in mismatches:
        print(f"  {row['id']}: {'; '.join(row['problems'])}")
    print(f"details: {run_dir}/rows.jsonl")
    sys.exit(1)
print(f"all {len(rows)} rows are decided as the matrix says (details: {run_dir}/rows.jsonl)")
PY

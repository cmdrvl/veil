#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../../.."

VEIL_BIN="${VEIL_BIN:-target/debug/veil}"
if [ ! -x "$VEIL_BIN" ]; then
  cargo build >/dev/null
fi

help="$("$VEIL_BIN" --help)"
printf '%s\n' "$help" | grep -F -- '--robot-triage' >/dev/null
printf '%s\n' "$help" | grep -F 'capabilities' >/dev/null
printf '%s\n' "$help" | grep -F 'robot-docs' >/dev/null
printf '%s\n' "$help" | grep -F 'Emit the machine-readable CLI capabilities contract' >/dev/null
printf '%s\n' "$help" | grep -F 'Print agent-facing operational guidance' >/dev/null

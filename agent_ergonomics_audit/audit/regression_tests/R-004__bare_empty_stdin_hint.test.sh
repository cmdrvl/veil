#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../../.."

VEIL_BIN="${VEIL_BIN:-target/debug/veil}"
if [ ! -x "$VEIL_BIN" ]; then
  cargo build >/dev/null
fi

set +e
stderr="$(printf '' | "$VEIL_BIN" 2>&1 >/dev/null)"
status="$?"
set -e

[ "$status" -eq 2 ]
printf '%s\n' "$stderr" | grep -F 'bare `veil` is hook mode' >/dev/null
printf '%s\n' "$stderr" | grep -F 'veil --robot-triage' >/dev/null
printf '%s\n' "$stderr" | grep -F 'veil capabilities --json' >/dev/null
printf '%s\n' "$stderr" | grep -F 'veil robot-docs guide' >/dev/null

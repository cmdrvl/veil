#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../../.."

VEIL_BIN="${VEIL_BIN:-target/debug/veil}"
if [ ! -x "$VEIL_BIN" ]; then
  cargo build >/dev/null
fi

output="$("$VEIL_BIN" robot-docs guide)"
printf '%s\n' "$output" | grep -F 'veil --robot-triage' >/dev/null
printf '%s\n' "$output" | grep -F 'Bare `veil` expects a Claude/Gemini/Copilot hook payload on stdin.' >/dev/null
printf '%s\n' "$output" | grep -F 'Use `airlock` to attest derived artifacts' >/dev/null

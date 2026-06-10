#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../../.."

VEIL_BIN="${VEIL_BIN:-target/debug/veil}"
if [ ! -x "$VEIL_BIN" ]; then
  cargo build >/dev/null
fi

"$VEIL_BIN" capabilities --json | jq -e '
  .schema_version == "veil.capabilities.v1"
  and .discovery.triage == "veil --robot-triage"
  and .discovery.capabilities == "veil capabilities --json"
  and .discovery.robot_docs == "veil robot-docs guide"
  and ([.commands[] | select(.command == "veil < hook-payload.json" and .read_only == false)] | length) == 1
  and ([.commands[] | select(.command == "veil operator --json" and .guard_preflight_required == true)] | length) == 1
' >/dev/null

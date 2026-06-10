#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../../.."

VEIL_BIN="${VEIL_BIN:-target/debug/veil}"
if [ ! -x "$VEIL_BIN" ]; then
  cargo build >/dev/null
fi

"$VEIL_BIN" --robot-triage | jq -e '
  .schema_version == "veil.doctor.triage.v1"
  and .tool == "veil"
  and .capabilities.read_only == true
  and .capabilities.fix_mode == "not_available"
' >/dev/null

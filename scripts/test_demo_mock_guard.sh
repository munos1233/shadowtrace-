#!/usr/bin/env bash
# Unit-style checks for demo_mock_guard fail-closed paths (ISSUE-141 / #647).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="${ROOT}/scripts/demo_mock_guard.sh"

run_guard() {
  env -i PATH="${PATH:-/usr/bin:/bin}" HOME="${HOME:-/tmp}" "$@" bash "${GUARD}"
}

assert_fails() {
  local label="$1"
  shift
  if run_guard "$@" >/dev/null 2>&1; then
    echo "FAIL: expected guard to reject ${label}" >&2
    exit 1
  fi
  echo "ok: rejects ${label}"
}

assert_passes() {
  if ! run_guard >/dev/null 2>&1; then
    echo "FAIL: expected default guard to pass" >&2
    exit 1
  fi
  echo "ok: default guard passes"
}

assert_passes
assert_fails "ALLOW_LIVE_SIDE_EFFECTS" ALLOW_LIVE_SIDE_EFFECTS=true
assert_fails "BLOCK_LIVE_ACTION_EXECUTION" BLOCK_LIVE_ACTION_EXECUTION=true
assert_fails "ALLOW_XDR_WRITEBACK" ALLOW_XDR_WRITEBACK=true
assert_fails "AUTO_INVESTIGATE_ENABLED" AUTO_INVESTIGATE_ENABLED=true
assert_fails "AUTO_RESPONSE_ENABLED" AUTO_RESPONSE_ENABLED=true
assert_fails "SIMULATION_ENABLED=false" SIMULATION_ENABLED=false
assert_fails "SOURCE_MODE live" SOURCE_MODE=live_crowdstrike
assert_fails "DISPOSITION_MODE live" DISPOSITION_MODE=live
assert_fails "TOOL_MODE live" TOOL_MODE=live

echo "demo_mock_guard tests passed"

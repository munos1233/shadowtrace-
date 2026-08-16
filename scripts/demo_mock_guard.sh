#!/usr/bin/env bash
# Fail closed when mock-only demo profile conflicts with live overrides (ISSUE-141 / #647).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT}/.env.live" ]]; then
  echo "[demo-guard] ERROR: .env.live is present; demo profile is mock-only." >&2
  echo "  Remove or rename .env.live before make up-demo / make smoke-demo." >&2
  exit 1
fi

_live_conflict() {
  local name="$1"
  local value="${2:-}"
  if [[ "${value}" == "true" ]]; then
    echo "[demo-guard] ERROR: ${name}=true conflicts with mock-only demo profile." >&2
    exit 1
  fi
}

_live_conflict "ALLOW_LIVE_SIDE_EFFECTS" "${ALLOW_LIVE_SIDE_EFFECTS:-false}"
_live_conflict "BLOCK_LIVE_ACTION_EXECUTION" "${BLOCK_LIVE_ACTION_EXECUTION:-false}"
_live_conflict "ALLOW_XDR_WRITEBACK" "${ALLOW_XDR_WRITEBACK:-false}"
_live_conflict "AUTO_INVESTIGATE_ENABLED" "${AUTO_INVESTIGATE_ENABLED:-false}"
_live_conflict "AUTO_RESPONSE_ENABLED" "${AUTO_RESPONSE_ENABLED:-false}"

if [[ -n "${SIMULATION_ENABLED:-}" && "${SIMULATION_ENABLED}" != "true" ]]; then
  echo "[demo-guard] ERROR: SIMULATION_ENABLED=${SIMULATION_ENABLED}; demo requires true." >&2
  exit 1
fi

if [[ -n "${SOURCE_MODE:-}" && "${SOURCE_MODE}" != "mock_xdr" ]]; then
  echo "[demo-guard] ERROR: SOURCE_MODE=${SOURCE_MODE}; demo requires mock_xdr." >&2
  exit 1
fi

if [[ -n "${DISPOSITION_MODE:-}" && "${DISPOSITION_MODE}" != "mock_xdr" ]]; then
  echo "[demo-guard] ERROR: DISPOSITION_MODE=${DISPOSITION_MODE}; demo requires mock_xdr." >&2
  exit 1
fi

if [[ -n "${TOOL_MODE:-}" && "${TOOL_MODE}" != "mock" ]]; then
  echo "[demo-guard] ERROR: TOOL_MODE=${TOOL_MODE}; demo requires mock." >&2
  exit 1
fi

echo "[demo-guard] mock-only checks passed"

#!/usr/bin/env bash
# ============================================================================
# ShadowTrace bootstrap — one-command demo setup (ISSUE-088)
#
# Usage:
#   make bootstrap          # migrate + seed 3 demo scenarios
#   LOAD_KB=true make bootstrap  # also load knowledge bases (P1, slower)
#
# Prerequisites:
#   - Docker Compose core services must be healthy (make up).
#   - ``python3`` available on host for the inline API trigger script.
#
# What this does:
#   1. Wait for backend health endpoint to respond 200.
#   2. Run alembic upgrade head inside the backend container (idempotent).
#   3. Generate & ingest 3 demo scenarios (insider_data_exfiltration,
#      account_anomaly_fp, suspicious_domain_access).
#   4. Trigger investigation on ingested events via API (with retry).
#   5. Optionally load attack/case/playbook knowledge bases.
#   6. Print access URLs.
# ============================================================================

set -euo pipefail

# --------------------------------------------------------------------------
# 0. Prerequisite checks
# --------------------------------------------------------------------------
if ! command -v docker &> /dev/null; then
  echo -e "\033[0;31m[bootstrap] ERROR: 'docker' not found in PATH — please install Docker 24+\033[0m" >&2
  exit 1
fi
if ! docker info > /dev/null 2>&1; then
  echo -e "\033[0;31m[bootstrap] ERROR: Docker daemon is not running or not accessible\033[0m" >&2
  exit 1
fi
if ! command -v python3 &> /dev/null; then
  echo -e "\033[0;31m[bootstrap] ERROR: 'python3' not found in PATH — Python 3.11+ is required on the host\033[0m" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose.yml"

# Resolve the compose project name the same way the Makefile does.
WORKTREE_ID="$(printf '%s' "$ROOT_DIR" | cksum | cut -d ' ' -f 1)"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shadowtrace-${WORKTREE_ID}}"

COMPOSE_CMD="docker compose --project-name ${COMPOSE_PROJECT_NAME} -f ${COMPOSE_FILE}"

# Ports — match infra/.env.example defaults.
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
BACKEND_HEALTH="http://127.0.0.1:${BACKEND_PORT}/api/v1/health"
FRONTEND_URL="http://127.0.0.1:${FRONTEND_PORT}"

# Auth token — must match DEV_AUTH_TOKENS in docker-compose.yml.
AUTH_TOKEN="${BOOTSTRAP_AUTH_TOKEN:-bootstrap-token}"

# Demo scenario IDs (ISSUE-088 — 3 demo scenarios).
DEMO_SCENARIOS=(
  "insider_data_exfiltration"
  "account_anomaly_fp"
  "suspicious_domain_access"
)

# Color helpers for terminal output.
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --------------------------------------------------------------------------
# 1. Wait for backend health
# --------------------------------------------------------------------------
echo "[bootstrap] waiting for backend health at ${BACKEND_HEALTH} ..."
for i in $(seq 1 90); do
  if curl -sf "${BACKEND_HEALTH}" > /dev/null 2>&1; then
    echo "[bootstrap] backend healthy (attempt ${i})"
    break
  fi
  if [ "$i" -eq 90 ]; then
    echo -e "${RED}[bootstrap] ERROR: backend did not become healthy within 180 s${NC}" >&2
    exit 1
  fi
  sleep 2
done

# --------------------------------------------------------------------------
# 2. Run database migrations (inside backend container)
# --------------------------------------------------------------------------
echo "[bootstrap] running alembic upgrade head ..."
${COMPOSE_CMD} exec -T backend python3 -m alembic upgrade head
echo "[bootstrap] migrations complete"

# --------------------------------------------------------------------------
# 3. Generate & ingest 3 demo scenarios (ISSUE-088 §验收标准 #1)
#
#    Each scenario writes telemetry to a separate subdirectory so that
#    per-scenario filenames (which are identical across scenarios) do not
#    overwrite each other.  The FileIngester is then called once per
#    scenario directory.
# --------------------------------------------------------------------------
DEMO_BASE="/tmp/shadowtrace-demo-scenarios"
${COMPOSE_CMD} exec -T backend rm -rf "${DEMO_BASE}"

for scenario_id in "${DEMO_SCENARIOS[@]}"; do
  echo "[bootstrap] generating demo scenario: ${scenario_id} ..."
  ${COMPOSE_CMD} exec -T backend python3 scripts/generate_mock_data.py \
    --scenario "${scenario_id}" \
    --out "${DEMO_BASE}/${scenario_id}" \
    --seed 42

  echo "[bootstrap] ingesting demo scenario: ${scenario_id} ..."
  ${COMPOSE_CMD} exec -T backend python3 scripts/ingest_mock_data.py \
    --path "${DEMO_BASE}/${scenario_id}"
done

${COMPOSE_CMD} exec -T backend rm -rf "${DEMO_BASE}"
echo "[bootstrap] 3 demo scenarios generated and ingested"

# --------------------------------------------------------------------------
# 4. Trigger investigation on all "new" events via the backend API
#    Includes retry logic for transient API failures.
# --------------------------------------------------------------------------
echo "[bootstrap] triggering investigation on demo events ..."
python3 - "${BACKEND_PORT}" "${AUTH_TOKEN}" << 'PYTHON_SCRIPT'
import http.client
import json
import sys
import time

backend_port = sys.argv[1]
auth_token = sys.argv[2]

def api_call(method: str, path: str, body: dict | None = None, max_retries: int = 3):
    """Make an HTTP API call with retry on transient errors.

    Retries on: connection failures, HTTP 5xx, and malformed (non-JSON)
    responses.  HTTP 4xx is NOT retried — it indicates a client error
    that won't be fixed by waiting.
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", int(backend_port), timeout=30)
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth_token}",
            }
            body_bytes = json.dumps(body).encode() if body else None
            conn.request(method, path, body_bytes, headers)
            resp = conn.getresponse()
            raw = resp.read()
            conn.close()

            # Server errors and gateway timeouts are transient — retry.
            if resp.status >= 500:
                raise OSError(f"HTTP {resp.status}")

            # Parse JSON; malformed payloads (e.g. proxy HTML error pages)
            # are also transient and worth retrying.
            try:
                data = json.loads(raw.decode()) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise OSError(f"invalid JSON: {exc}") from exc

            return resp, data
        except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            last_exc = exc
            if attempt < max_retries:
                wait = 2 ** attempt
                print(f"  [retry] attempt {attempt} failed ({exc}), waiting {wait}s ...")
                time.sleep(wait)
            else:
                raise
    raise last_exc  # type: ignore[misc]


# List events
resp, events_data = api_call("GET", "/api/v1/events?page_size=50")
items = events_data.get("items", [])
print(f"Found {len(items)} event(s)")

triggered = 0
for item in items:
    event_id = item["event_id"]
    status = item.get("status", "")
    if status != "new":
        print(f"  [skip] {event_id}: status={status}")
        continue
    resp, inv_data = api_call(
        "POST",
        f"/api/v1/events/{event_id}/investigate",
        {},
    )
    if resp.status in (200, 202):
        print(f"  triggered investigation for {event_id} (type={item.get('event_type')})")
        triggered += 1
    else:
        print(f"  [skip] {event_id}: HTTP {resp.status}")

print(f"Investigation triggered on {triggered} event(s)")
PYTHON_SCRIPT

# --------------------------------------------------------------------------
# 5. Optional: load knowledge bases (P1 — slower, ~30–60 s extra)
# --------------------------------------------------------------------------
if [ "${LOAD_KB:-false}" = "true" ]; then
  echo "[bootstrap] LOAD_KB=true — loading knowledge bases ..."
  # KB loading is P1 optional; failure must NOT crash the bootstrap.
  ${COMPOSE_CMD} exec -T backend python3 -m scripts.load_attack_kb || \
    echo "[bootstrap] WARNING: load_attack_kb failed — continuing"
  ${COMPOSE_CMD} exec -T backend python3 -m scripts.load_case_kb || \
    echo "[bootstrap] WARNING: load_case_kb failed — continuing"
  ${COMPOSE_CMD} exec -T backend python3 -m scripts.load_playbook_kb || \
    echo "[bootstrap] WARNING: load_playbook_kb failed — continuing"
  echo "[bootstrap] knowledge bases loading complete (errors above are non-fatal)"
else
  echo "[bootstrap] knowledge bases skipped (set LOAD_KB=true to load)"
fi

# --------------------------------------------------------------------------
# 6. Print access URLs
# --------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  ShadowTrace 演示环境已就绪${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  前端看板:  ${YELLOW}${FRONTEND_URL}${NC}"
echo -e "  API 文档:  ${YELLOW}http://127.0.0.1:${BACKEND_PORT}/docs${NC}"
echo -e "  健康检查:  ${YELLOW}${BACKEND_HEALTH}${NC}"
echo ""
echo -e "  查看日志:  ${COMPOSE_CMD} logs -f backend"
echo -e "  make down  停止并移除容器（数据卷保留）"
echo ""

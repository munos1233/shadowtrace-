#!/usr/bin/env bash
# ============================================================================
# ShadowTrace bootstrap — one-command demo setup (ISSUE-088)
#
# Usage:
#   make bootstrap               # migrate + seed 3 demo scenarios + playbook release
#   LOAD_KB=true make bootstrap  # also load attack/case knowledge bases (P1, slower)
#   BOOTSTRAP_GENERATE_REPORT=true make bootstrap          # ISSUE-256 demo report profile
#   BOOTSTRAP_INCLUDE_RESPONSE=true make bootstrap         # full_loop (needs scripted approve)
#
# Prerequisites:
#   - Docker Compose core services must be healthy (make up).
#   - ``python3`` available on host for the inline API trigger script.
#
# What this does:
#   1. Wait for backend + mock-xdr health endpoints.
#   2. Run alembic upgrade head inside the backend container (idempotent).
#   3. Ensure playbook release is staged+activated (ISSUE-245; idempotent).
#   4. For each demo scenario: seed standalone mock-xdr, then poll-ingest via
#      SourceAdapter (keeps PostgreSQL + mock-xdr writeback objects aligned).
#   5. Trigger investigation on ingested events via API (with retry).
#   6. Optionally load attack/case knowledge bases.
#   7. Verify health.playbook_resources.status=ready (demo gate).
#   8. Print access URLs.
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
MOCK_XDR_PORT="${MOCK_XDR_PORT:-8100}"
MOCK_XDR_URL="${MOCK_XDR_URL:-http://mock-xdr:8100}"
BACKEND_HEALTH="http://127.0.0.1:${BACKEND_PORT}/api/v1/health"
MOCK_XDR_HEALTH="http://127.0.0.1:${MOCK_XDR_PORT}/mock-xdr/v1/health"
FRONTEND_URL="http://127.0.0.1:${FRONTEND_PORT}"

# Auth token — must match DEV_AUTH_TOKENS in docker-compose.yml.
AUTH_TOKEN="${BOOTSTRAP_AUTH_TOKEN:-bootstrap-token}"

# ISSUE-256 demo/eval profile knobs (defaults preserve ISSUE-088 behaviour).
# - BOOTSTRAP_GENERATE_REPORT=true  → investigate with generate_report=true
# - BOOTSTRAP_INCLUDE_RESPONSE=true → include_response_execution=true (needs
#   scripted approve via scripts/dynamic_eval_approve.py — do NOT wait for
#   production APPROVAL_TIMEOUT_MINUTES=30).
BOOTSTRAP_GENERATE_REPORT="${BOOTSTRAP_GENERATE_REPORT:-false}"
BOOTSTRAP_INCLUDE_RESPONSE="${BOOTSTRAP_INCLUDE_RESPONSE:-false}"

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
# 1. Wait for backend + mock-xdr health
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

echo "[bootstrap] waiting for mock-xdr health at ${MOCK_XDR_HEALTH} ..."
for i in $(seq 1 60); do
  if curl -sf "${MOCK_XDR_HEALTH}" > /dev/null 2>&1; then
    echo "[bootstrap] mock-xdr healthy (attempt ${i})"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo -e "${RED}[bootstrap] ERROR: mock-xdr did not become healthy within 120 s${NC}" >&2
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
# 2a. Ensure playbook release is active (ISSUE-245 / #820)
#     Compose backend entrypoint also seeds when SEED_PLAYBOOK_RELEASE=true;
#     bootstrap re-runs for older images / FORCE paths (idempotent).
# --------------------------------------------------------------------------
echo "[bootstrap] ensuring playbook release is active ..."
if ! ${COMPOSE_CMD} exec -T backend bash -c "cd /app/backend && python3 -m scripts.load_playbook_release"; then
  echo -e "${RED}[bootstrap] ERROR: playbook release seed failed${NC}" >&2
  echo -e "${RED}[bootstrap] Response/Playbook binding will silently degrade without an active release${NC}" >&2
  exit 1
fi
echo "[bootstrap] playbook release ready"

# --------------------------------------------------------------------------
# 2b. Skip re-seed when demo events already exist (idempotent bootstrap)
#     Set FORCE_BOOTSTRAP=true to re-seed on a non-empty volume.
# --------------------------------------------------------------------------
existing_count="$(
  curl -sf -H "Authorization: Bearer ${AUTH_TOKEN}" \
    "http://127.0.0.1:${BACKEND_PORT}/api/v1/events?page_size=50" \
    | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('items', [])))" \
    2>/dev/null || echo 0
)"
if [ "${FORCE_BOOTSTRAP:-false}" != "true" ] && [ "${existing_count}" -ge 3 ]; then
  echo "[bootstrap] found ${existing_count} existing event(s); skipping seed/ingest"
  echo "[bootstrap] (set FORCE_BOOTSTRAP=true to re-seed on this volume)"
  skip_seed=1
else
  skip_seed=0
fi

# --------------------------------------------------------------------------
# 3. Seed mock-xdr + poll-ingest demo scenarios (ISSUE-088 §验收标准 #1)
# --------------------------------------------------------------------------
if [ "${skip_seed}" -eq 0 ]; then
  for scenario_id in "${DEMO_SCENARIOS[@]}"; do
    echo "[bootstrap] seeding mock-xdr + ingesting scenario: ${scenario_id} ..."
    ${COMPOSE_CMD} exec -T backend python3 scripts/seed_mock_xdr_and_ingest.py \
      --scenario "${scenario_id}" \
      --mock-xdr-url "${MOCK_XDR_URL}" \
      --seed 42
  done
  echo "[bootstrap] 3 demo scenarios seeded in mock-xdr and ingested"
fi

# --------------------------------------------------------------------------
# 4. Trigger investigation on all "new" events via the backend API
# --------------------------------------------------------------------------
echo "[bootstrap] triggering investigation on demo events ..."
echo "[bootstrap] profile: generate_report=${BOOTSTRAP_GENERATE_REPORT} include_response_execution=${BOOTSTRAP_INCLUDE_RESPONSE}"
if [ "${BOOTSTRAP_INCLUDE_RESPONSE}" = "true" ]; then
  echo "[bootstrap] NOTE: full_loop will pause on waiting_approval — use"
  echo "[bootstrap]   python3 scripts/dynamic_eval_approve.py --event-id <id>"
  echo "[bootstrap]   or: make eval-full-loop"
  echo "[bootstrap] Do NOT wait for APPROVAL_TIMEOUT_MINUTES (prod default 30)."
fi
# Worker concurrency honesty (R2-017): compose worker uses celery -c 2.
echo "[bootstrap] NOTE: with worker -c 2, triggering 3 investigations queues (~minutes)."
python3 - "${BACKEND_PORT}" "${AUTH_TOKEN}" "${BOOTSTRAP_GENERATE_REPORT}" "${BOOTSTRAP_INCLUDE_RESPONSE}" << 'PYTHON_SCRIPT'
import http.client
import json
import sys
import time

backend_port = sys.argv[1]
auth_token = sys.argv[2]
generate_report = sys.argv[3].strip().lower() in {"1", "true", "yes", "on"}
include_response = sys.argv[4].strip().lower() in {"1", "true", "yes", "on"}

def api_call(method: str, path: str, body: dict | None = None, max_retries: int = 3):
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

            if resp.status >= 500:
                raise OSError(f"HTTP {resp.status}")

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


resp, events_data = api_call("GET", "/api/v1/events?page_size=50")
items = events_data.get("items", [])
print(f"Found {len(items)} event(s)")
if len(items) < 3:
    raise SystemExit(f"expected at least 3 demo events, found {len(items)}")

triggered = 0
for item in items:
    event_id = item["event_id"]
    status = item.get("status", "")
    if status != "new":
        print(f"  [skip] {event_id}: status={status}")
        continue
    resp, _inv_data = api_call(
        "POST",
        f"/api/v1/events/{event_id}/investigate",
        {
            "generate_report": generate_report,
            "include_response_execution": include_response,
        },
    )
    if resp.status in (200, 202):
        print(
            f"  triggered investigation for {event_id} "
            f"(type={item.get('event_type')} generate_report={generate_report} "
            f"include_response_execution={include_response})"
        )
        triggered += 1
    else:
        print(f"  [skip] {event_id}: HTTP {resp.status}")

print(f"Investigation triggered on {triggered} event(s)")
PYTHON_SCRIPT

# --------------------------------------------------------------------------
# 5. Optional: load attack/case knowledge bases (P1 — slower, ~30–60 s extra)
#     Playbook release is always loaded in step 2a (not optional).
# --------------------------------------------------------------------------
if [ "${LOAD_KB:-false}" = "true" ]; then
  echo "[bootstrap] LOAD_KB=true — loading attack/case knowledge bases ..."
  kb_failed=0
  for loader in load_attack_kb load_case_kb; do
    if ! ${COMPOSE_CMD} exec -T backend bash -c "cd /app/backend && python3 -m scripts.${loader}"; then
      echo -e "${RED}[bootstrap] ERROR: ${loader} failed${NC}" >&2
      kb_failed=1
    fi
  done
  if [ "${kb_failed}" -ne 0 ]; then
    exit 1
  fi
  echo "[bootstrap] knowledge bases loaded"
else
  echo "[bootstrap] attack/case knowledge bases skipped (set LOAD_KB=true to load)"
fi

# --------------------------------------------------------------------------
# 6. Demo gate: playbook_resources must be ready (ISSUE-245)
# --------------------------------------------------------------------------
echo "[bootstrap] verifying health.playbook_resources.status=ready ..."
# Use curl without -f so PLAYBOOK_REQUIRED=503 still yields a JSON body for diagnostics.
if ! curl -s "${BACKEND_HEALTH}" | python3 -c "
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    raise SystemExit(f'health endpoint returned non-JSON: {exc}: {raw[:200]!r}') from exc
pb = data.get('playbook_resources') or {}
status = pb.get('status')
release_id = pb.get('active_release_id') or ''
print(f\"  playbook_resources.status={status} active_release_id={release_id or '(none)'}\")
if status != 'ready':
    raise SystemExit(
        'playbook_resources not ready — demo Response/Playbook binding is degraded. '
        'Re-run bootstrap or check SEED_PLAYBOOK_RELEASE on backend.'
    )
if not release_id:
    raise SystemExit('playbook_resources ready but active_release_id is empty')
"; then
  echo -e "${RED}[bootstrap] ERROR: playbook readiness gate failed${NC}" >&2
  exit 1
fi

# --------------------------------------------------------------------------
# 7. Print access URLs
# --------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  ShadowTrace 演示环境已就绪${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  前端看板:  ${YELLOW}${FRONTEND_URL}${NC}"
echo -e "  API 文档:  ${YELLOW}http://127.0.0.1:${BACKEND_PORT}/docs${NC}"
echo -e "  健康检查:  ${YELLOW}${BACKEND_HEALTH}${NC}"
echo -e "  Mock XDR:  ${YELLOW}${MOCK_XDR_HEALTH}${NC}"
echo ""
echo -e "  演示门禁:  curl -s ${BACKEND_HEALTH} | jq .playbook_resources"
echo -e "  冒烟验证:  make smoke-demo          # 官方 demo（compat 终态门禁）"
echo -e "  短路径冒烟: bash scripts/smoke_bootstrap.sh   # 默认不含终态门禁"
echo -e "  金标全闭环: make demo-full-loop     # ISSUE-256/304（seed + 脚本审批 → CLOSED）"
echo -e "  Matrix:     EVAL_MATRIX_REQUIRE_CLOSED=1 make eval-full-loop-matrix"
echo -e "  查看日志:  ${COMPOSE_CMD} logs -f backend"
echo -e "  make down  停止并移除容器（数据卷保留）"
echo ""
echo -e "  剖面开关: BOOTSTRAP_GENERATE_REPORT=true make bootstrap"
echo -e "           BOOTSTRAP_INCLUDE_RESPONSE=true make bootstrap  # 需脚本审批，勿空等 30min"
echo ""

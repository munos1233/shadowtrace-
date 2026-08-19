#!/usr/bin/env bash
# Full mock demo stack smoke (ISSUE-141 / #647).
#
# Prerequisites: make up-demo && make bootstrap-demo (analysis seed; NOT CLOSED)
# Checks: core health/events, Celery worker, ingestion scheduler, observability URLs + OTEL path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Match Makefile/bootstrap project naming when not exported by the caller.
WORKTREE_ID="$(printf '%s' "$ROOT" | cksum | cut -d ' ' -f 1)"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shadowtrace-${WORKTREE_ID}}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
MOCK_XDR_PORT="${MOCK_XDR_PORT:-8100}"
GRAFANA_PORT="${GRAFANA_PORT:-3001}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
OTEL_HTTP_PORT="${OTEL_HTTP_PORT:-4318}"
COMPOSE_FILE="${ROOT}/infra/docker-compose.yml"
OBS_COMPOSE_FILE="${ROOT}/infra/observability/docker-compose.observability.yml"

compose_cmd() {
  local args=(compose)
  if [[ -n "${COMPOSE_PROJECT_NAME}" ]]; then
    args+=(--project-name "${COMPOSE_PROJECT_NAME}")
  fi
  args+=(-f "${COMPOSE_FILE}" -f "${OBS_COMPOSE_FILE}" --profile demo "$@")
  docker "${args[@]}"
}

print_demo_urls() {
  cat <<EOF

[demo] Service URLs (host ports):
  Frontend:       http://127.0.0.1:${FRONTEND_PORT}/
  Backend API:    http://127.0.0.1:${BACKEND_PORT}/api/v1/health
  Backend docs:   http://127.0.0.1:${BACKEND_PORT}/docs
  Mock XDR:       http://127.0.0.1:${MOCK_XDR_PORT}/mock-xdr/v1/health
  Grafana:        http://127.0.0.1:${GRAFANA_PORT}/  (admin / shadowtrace)
  Prometheus:     http://127.0.0.1:${PROMETHEUS_PORT}/
  OTLP HTTP:      http://127.0.0.1:${OTEL_HTTP_PORT}/

EOF
}

echo "[smoke-demo] celery investigation worker (before terminal poll) ..."
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME}" \
  COMPOSE_PROFILE="demo" \
  OBS_COMPOSE_FILE="${OBS_COMPOSE_FILE}" \
  BACKEND_PORT="${BACKEND_PORT}" \
  PYTHON="${PYTHON:-}" \
  bash "${ROOT}/scripts/celery_worker_smoke.sh"

echo "[smoke-demo] ingestion scheduler worker ..."
scheduler_id="$(compose_cmd ps -q scheduler-worker 2>/dev/null | head -1 || true)"
if [[ -z "${scheduler_id}" ]]; then
  echo "[smoke-demo] ERROR: scheduler-worker container not found (run make up-demo)" >&2
  exit 1
fi
scheduler_host="$(docker exec "${scheduler_id}" hostname)"
if ! docker exec "${scheduler_id}" python -m celery -A app.core.celery_app inspect ping \
  -d "ingestion-scheduler@${scheduler_host}" -t 10; then
  echo "[smoke-demo] ERROR: scheduler-worker celery ping failed" >&2
  exit 1
fi
beat_id="$(compose_cmd ps -q scheduler-beat 2>/dev/null | head -1 || true)"
if [[ -z "${beat_id}" ]]; then
  echo "[smoke-demo] ERROR: scheduler-beat container not found" >&2
  exit 1
fi
if ! docker exec "${beat_id}" sh -c 'test -f /tmp/celerybeat.pid && kill -0 "$(cat /tmp/celerybeat.pid)"'; then
  echo "[smoke-demo] ERROR: scheduler-beat process not running" >&2
  exit 1
fi
echo "  ok: scheduler beat + ingestion worker healthy"

echo "[smoke-demo] core bootstrap smoke (requires make bootstrap-demo / bootstrap-demo-analysis) ..."
if ! BACKEND_PORT="${BACKEND_PORT}" FRONTEND_PORT="${FRONTEND_PORT}" MOCK_XDR_PORT="${MOCK_XDR_PORT}" \
  BOOTSTRAP_AUTH_TOKEN="${BOOTSTRAP_AUTH_TOKEN:-bootstrap-token}" \
  SMOKE_TERMINAL_MODE="${SMOKE_TERMINAL_MODE:-compat}" \
  SMOKE_TERMINAL_TIMEOUT_S="${SMOKE_TERMINAL_TIMEOUT_S:-600}" \
  SMOKE_TERMINAL_MIN_EVENTS="${SMOKE_TERMINAL_MIN_EVENTS:-3}" \
  SMOKE_TERMINAL_POLL_S="${SMOKE_TERMINAL_POLL_S:-5}" \
  bash "${ROOT}/scripts/smoke_bootstrap.sh"; then
  echo "[smoke-demo] ERROR: bootstrap smoke failed — analysis seed: make bootstrap-demo-analysis (NOT CLOSED); CLOSED gold path: make demo-full-loop" >&2
  exit 1
fi

echo "[smoke-demo] observability stack ..."
curl -sf "http://127.0.0.1:${PROMETHEUS_PORT}/-/ready" >/dev/null
curl -sf "http://127.0.0.1:${GRAFANA_PORT}/api/health" >/dev/null
curl -sf "http://127.0.0.1:${PROMETHEUS_PORT}/api/v1/query?query=up%7Bjob%3D%22otel-collector%22%7D" \
  | python3 -c "
import json, sys
payload = json.load(sys.stdin)
results = payload.get('data', {}).get('result', [])
assert results, payload
value = results[0].get('value', [None, None])[1]
assert value == '1', payload
print('  ok: prometheus scrapes otel-collector')
"

backend_id="$(compose_cmd ps -q backend 2>/dev/null | head -1 || true)"
if [[ -z "${backend_id}" ]]; then
  echo "[smoke-demo] ERROR: backend container not found" >&2
  exit 1
fi
docker exec "${backend_id}" sh -c \
  'test "${OTEL_ENABLED}" = "true" && test "${OTEL_EXPORTER_OTLP_ENDPOINT}" = "http://otel-collector:4318"'
http_code="$(docker exec "${backend_id}" curl -sS --connect-timeout 5 -o /dev/null -w "%{http_code}" \
  "http://otel-collector:4318/v1/traces" || true)"
if [[ "${http_code}" != "405" && "${http_code}" != "404" && "${http_code}" != "200" ]]; then
  echo "[smoke-demo] ERROR: backend cannot reach otel-collector in-network (HTTP ${http_code})" >&2
  exit 1
fi
echo "  ok: backend OTEL in-network (${http_code} from collector)"

echo "[smoke-demo] bootstrap telemetry in Prometheus (OTLP → collector → Prometheus) ..."
telemetry_ok=false
for attempt in 1 2 3 4; do
  if curl -sf "http://127.0.0.1:${PROMETHEUS_PORT}/api/v1/label/__name__/values" \
    | python3 -c "
import json, sys
names = json.load(sys.stdin).get('data', [])
# FastAPI auto-instrumentation exports http_* metrics after bootstrap health hits.
http_metrics = [n for n in names if n.startswith('http_') or n.startswith('http.')]
if not http_metrics:
    raise SystemExit(1)
print(f'  ok: bootstrap telemetry metrics present ({len(http_metrics)} http_* series names)')
"; then
    telemetry_ok=true
    break
  fi
  if [[ "${attempt}" -lt 4 ]]; then
    echo "  waiting for OTLP metric export (attempt ${attempt}/4) ..."
    sleep 5
  fi
done
if [[ "${telemetry_ok}" != "true" ]]; then
  echo "[smoke-demo] ERROR: no HTTP telemetry metrics in Prometheus after bootstrap" >&2
  exit 1
fi

print_demo_urls
echo "[smoke-demo] full demo smoke passed"

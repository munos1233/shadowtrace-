#!/usr/bin/env bash
# Lightweight post-bootstrap smoke check (ISSUE-088).
#
# Usage (host, after ``make bootstrap``):
#   bash scripts/smoke_bootstrap.sh
#
# Exits 0 when health is OK and at least three demo events are visible.

set -euo pipefail

BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
MOCK_XDR_PORT="${MOCK_XDR_PORT:-8100}"
AUTH_TOKEN="${BOOTSTRAP_AUTH_TOKEN:-bootstrap-token}"

BACKEND_HEALTH="http://127.0.0.1:${BACKEND_PORT}/api/v1/health"
EVENTS_URL="http://127.0.0.1:${BACKEND_PORT}/api/v1/events?page_size=50"
FRONTEND_HEALTH="http://127.0.0.1:${FRONTEND_PORT}/health"
PROXY_HEALTH="http://127.0.0.1:${FRONTEND_PORT}/api/v1/health"
MOCK_XDR_HEALTH="http://127.0.0.1:${MOCK_XDR_PORT}/mock-xdr/v1/health"

echo "[smoke] backend health ..."
curl -sf "${BACKEND_HEALTH}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert data.get('status') == 'ok', data
assert data.get('simulation_enabled') is True, data
assert data.get('source_adapter', {}).get('mode') == 'mock_xdr', data
print('  ok: simulation_enabled=true source_mode=mock_xdr')
"

# ISSUE-245 / #820 — demo gate: playbook release must be active (not silent degrade).
echo "[smoke] playbook_resources ready ..."
curl -s "${BACKEND_HEALTH}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
pb = data.get('playbook_resources') or {}
status = pb.get('status')
release_id = pb.get('active_release_id') or ''
print(f'  playbook_resources={json.dumps(pb, ensure_ascii=False)}')
if status != 'ready':
    raise SystemExit(
        f'playbook_resources.status={status!r} (expected ready). '
        'Run make bootstrap / ensure SEED_PLAYBOOK_RELEASE=true on backend.'
    )
if not release_id:
    raise SystemExit('playbook_resources.active_release_id is empty')
print(f'  ok: status=ready active_release_id={release_id}')
"

echo "[smoke] mock-xdr health ..."
curl -sf "${MOCK_XDR_HEALTH}" >/dev/null
echo "  ok"

echo "[smoke] frontend nginx health + API proxy ..."
curl -sf "${FRONTEND_HEALTH}" >/dev/null
curl -sf "${PROXY_HEALTH}" >/dev/null
echo "  ok"

echo "[smoke] demo events count ..."
event_count="$(
  curl -sf -H "Authorization: Bearer ${AUTH_TOKEN}" "${EVENTS_URL}" \
    | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('items', [])))"
)"
if [ "${event_count}" -lt 3 ]; then
  echo "[smoke] ERROR: expected >=3 events, got ${event_count}" >&2
  exit 1
fi
echo "  ok: ${event_count} event(s)"
echo "[smoke] bootstrap smoke passed"

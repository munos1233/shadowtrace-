#!/bin/sh
# Apply schema before serving traffic so Compose/e2e never hit an empty DB.
#
# Migration ownership (ISSUE-238):
#   Compose: only the `backend` service should run alembic. Sidecars that share
#   this image/ENTRYPOINT (mock-xdr, worker, scheduler-*) MUST set
#   SKIP_DB_MIGRATE=true so parallel `up` cannot race-create alembic_version.
#   Do not "ignore migrate failures and continue" — fail closed, or skip entirely.
set -eu
if [ "${SKIP_DB_MIGRATE:-}" = "true" ]; then
  echo "SKIP_DB_MIGRATE=true; skipping alembic (not the Compose migration owner)."
else
  echo "Running alembic upgrade head ..."
  python -m alembic upgrade head
  echo "Migrations applied."
fi
exec "$@"

#!/bin/sh
# Apply schema before serving traffic so Compose/e2e never hit an empty DB.
# Set SKIP_DB_MIGRATE=true for stateless sidecars (e.g. mock-xdr) that do not need Postgres.
# Set SEED_PLAYBOOK_RELEASE=true on the backend (demo/dev Compose) so
# /health.playbook_resources is ready before the process accepts traffic (ISSUE-245).
# Workers/schedulers must leave SEED_PLAYBOOK_RELEASE unset/false (backend owns seed).
set -eu
if [ "${SKIP_DB_MIGRATE:-}" != "true" ]; then
  echo "Running alembic upgrade head ..."
  python -m alembic upgrade head
  echo "Migrations applied."
fi
if [ "${SEED_PLAYBOOK_RELEASE:-}" = "true" ]; then
  echo "Seeding playbook release (SEED_PLAYBOOK_RELEASE=true) ..."
  # Nested tree matches Dockerfile layout; module path is backend.scripts.*
  (cd /app/backend && python -m scripts.load_playbook_release)
  echo "Playbook release seed complete."
fi
exec "$@"

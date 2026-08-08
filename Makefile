# Prefer uv when lockfile is present; fall back to project venv / system python.
UV ?= uv
PYTHON ?= $(shell if [ -f "$(CURDIR)/backend/uv.lock" ]; then echo "$(UV) run --frozen python"; elif [ -x "$(CURDIR)/backend/.venv/bin/python" ]; then echo "$(CURDIR)/backend/.venv/bin/python"; else echo python3; fi)

WORKTREE_ID ?= $(shell printf '%s' "$(CURDIR)" | cksum | cut -d ' ' -f 1)
COMPOSE_PROJECT_NAME ?= shadowtrace-$(WORKTREE_ID)
POSTGRES_PORT ?= 5432
REDIS_PORT ?= 6379
BACKEND_PORT ?= 8000
FRONTEND_PORT ?= 3000
MOCK_XDR_PORT ?= 8100
OTEL_HTTP_PORT ?= 4318
OTEL_GRPC_PORT ?= 4317
OTEL_PROMETHEUS_PORT ?= 8889
PROMETHEUS_PORT ?= 9090
GRAFANA_PORT ?= 3001

COMPOSE_FILE := $(CURDIR)/infra/docker-compose.yml
OBS_COMPOSE_FILE := $(CURDIR)/infra/observability/docker-compose.observability.yml
COMPOSE := COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
	BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
	MOCK_XDR_PORT="$(MOCK_XDR_PORT)" \
	docker compose --project-name "$(COMPOSE_PROJECT_NAME)" \
	-f "$(COMPOSE_FILE)"

# Demo profile (ISSUE-141): core + worker + scheduler + observability; in-network OTEL.
# ISSUE-245: demo gate PLAYBOOK_REQUIRED=true → health 503 unless playbook release ready.
DEMO_OTEL_ENABLED ?= true
DEMO_OTEL_ENDPOINT ?= http://otel-collector:4318
DEMO_PLAYBOOK_REQUIRED ?= true
COMPOSE_DEMO := COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
	BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
	MOCK_XDR_PORT="$(MOCK_XDR_PORT)" \
	OTEL_HTTP_PORT="$(OTEL_HTTP_PORT)" OTEL_GRPC_PORT="$(OTEL_GRPC_PORT)" \
	OTEL_PROMETHEUS_PORT="$(OTEL_PROMETHEUS_PORT)" PROMETHEUS_PORT="$(PROMETHEUS_PORT)" \
	GRAFANA_PORT="$(GRAFANA_PORT)" \
	OTEL_ENABLED="$(DEMO_OTEL_ENABLED)" \
	OTEL_EXPORTER_OTLP_ENDPOINT="$(DEMO_OTEL_ENDPOINT)" \
	PLAYBOOK_REQUIRED="$(DEMO_PLAYBOOK_REQUIRED)" \
	SEED_PLAYBOOK_RELEASE=true \
	TASK_MODE=celery \
	docker compose --project-name "$(COMPOSE_PROJECT_NAME)" \
	-f "$(COMPOSE_FILE)" -f "$(OBS_COMPOSE_FILE)" \
	--profile demo

# Optional: set WORKER=1 to include the Celery investigation worker (sets TASK_MODE=celery).
# DB migrations: only the backend container runs alembic; workers use SKIP_DB_MIGRATE (ISSUE-238).
WORKER ?=
WORKER_PROFILE = $(if $(WORKER),--profile worker,)
# Optional: set SCHEDULER=1 to include Celery Beat + ingestion worker (ISSUE-107).
SCHEDULER ?=
SCHEDULER_PROFILE = $(if $(SCHEDULER),--profile scheduler,)
export TASK_MODE := $(if $(WORKER),celery,$(if $(TASK_MODE),$(TASK_MODE),background))

INTEGRATION_PROJECT_NAME ?= $(COMPOSE_PROJECT_NAME)-integration
CI_TEST_PROJECT_NAME ?= $(COMPOSE_PROJECT_NAME)-ci-test
CI_BUILD_PROJECT_PREFIX ?= $(COMPOSE_PROJECT_NAME)-ci-build

# Host-side URLs for tests that talk to Compose postgres/redis from the workstation / CI runner.
CI_DATABASE_URL ?= postgresql+asyncpg://shadowtrace:shadowtrace@localhost:$(POSTGRES_PORT)/shadowtrace
CI_REDIS_URL ?= redis://localhost:$(REDIS_PORT)/0

.PHONY: up down down-v bootstrap smoke-bootstrap up-demo down-demo bootstrap-demo smoke-demo demo-guard-test up-observability down-observability llm-smoke test lint fmt migrate migrate-down load-kb integration-test orchestration-test worker-smoke-test worker-nightly-pytest worker-nightly-smoke worker-nightly-matrix ingestion-scheduler-test auto-investigate-test autonomous-mock-e2e autonomous-mock-e2e-pytest autonomous-mock-e2e-worker-pytest eval-full-loop test-tools test-system test-regression update-baseline test-e2e-frontend frontend-test ci-lint ci-test ci-build update-contracts check-contract-drift check-migration-revisions evaluation-run evaluation-test detection-evaluation-run detection-production-comparison-run

up:
	$(COMPOSE) $(WORKER_PROFILE) $(SCHEDULER_PROFILE) up -d --build

down:
	@demo_running=$$($(COMPOSE_DEMO) ps -q 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$demo_running" != "0" ]; then \
	  echo "NOTE: demo/observability containers still running — use 'make down-demo' after 'make up-demo'." >&2; \
	fi
	$(COMPOSE) down

# Remove containers AND volumes (ISSUE-088 — full reset).
down-v:
	@demo_running=$$($(COMPOSE_DEMO) ps -q 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$demo_running" != "0" ]; then \
	  echo "NOTE: demo/observability containers still running — use 'make down-demo' after 'make up-demo'." >&2; \
	fi
	$(COMPOSE) down -v

# ---------------------------------------------------------------------------
# One-command bootstrap: migrate + seed demo scenarios (ISSUE-088)
#
# Requires core services already healthy (make up first).
# Always ensures playbook release is active (ISSUE-245).
# Set LOAD_KB=true to also load attack/case knowledge bases (~30-60 s extra).
# ---------------------------------------------------------------------------
bootstrap:
	@LOAD_KB="$(LOAD_KB)" \
	BOOTSTRAP_GENERATE_REPORT="$(BOOTSTRAP_GENERATE_REPORT)" \
	BOOTSTRAP_INCLUDE_RESPONSE="$(BOOTSTRAP_INCLUDE_RESPONSE)" \
	bash "$(CURDIR)/scripts/bootstrap.sh"

smoke-bootstrap:
	@bash "$(CURDIR)/scripts/smoke_bootstrap.sh"

# ---------------------------------------------------------------------------
# ISSUE-256 gold-path dynamic eval (mock-xdr seed → full_loop → scripted approve)
#
# Prerequisites: healthy stack with investigation execution
#   (make up-demo, or make up WORKER=1). Prefer one scenario for predictable
#   timing — worker celery -c 2 queues when 3 investigations run in parallel.
# Does NOT change production APPROVAL_TIMEOUT_MINUTES (default 30).
# ---------------------------------------------------------------------------
EVAL_SCENARIO ?= insider_data_exfiltration
EVAL_MAX_EVENTS ?= 1
EVAL_DECISION ?= approve
BOOTSTRAP_AUTH_TOKEN ?= bootstrap-token
BOOTSTRAP_GENERATE_REPORT ?= false
BOOTSTRAP_INCLUDE_RESPONSE ?= false
eval-full-loop:
	@echo "[eval-full-loop] gold fixture=seed_mock_xdr_and_ingest scenario=$(EVAL_SCENARIO)"
	@echo "[eval-full-loop] scripted $(EVAL_DECISION) — never finish via APPROVAL_TIMEOUT"
	COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	BACKEND_PORT="$(BACKEND_PORT)" \
	python3 "$(CURDIR)/scripts/dynamic_eval_full_loop.py" \
		--seed-via-compose \
		--scenario "$(EVAL_SCENARIO)" \
		--base-url "http://127.0.0.1:$(BACKEND_PORT)" \
		--token "$(BOOTSTRAP_AUTH_TOKEN)" \
		--max-events "$(EVAL_MAX_EVENTS)" \
		--decision "$(EVAL_DECISION)"

# ---------------------------------------------------------------------------
# Mock demo full stack (ISSUE-141 / #647): core + worker + scheduler + OTEL
# Default ``make up`` / ``make bootstrap`` unchanged.
# ---------------------------------------------------------------------------
up-demo:
	@bash "$(CURDIR)/scripts/demo_mock_guard.sh"
	$(COMPOSE_DEMO) up -d --build

down-demo:
	$(COMPOSE_DEMO) down

bootstrap-demo:
	@bash "$(CURDIR)/scripts/demo_mock_guard.sh"
	@$(MAKE) bootstrap

smoke-demo:
	@bash "$(CURDIR)/scripts/demo_mock_guard.sh"
	COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
	MOCK_XDR_PORT="$(MOCK_XDR_PORT)" \
	GRAFANA_PORT="$(GRAFANA_PORT)" PROMETHEUS_PORT="$(PROMETHEUS_PORT)" \
	OTEL_HTTP_PORT="$(OTEL_HTTP_PORT)" \
	PYTHON="$(PYTHON)" \
	bash "$(CURDIR)/scripts/smoke_demo.sh"

demo-guard-test:
	@bash "$(CURDIR)/scripts/test_demo_mock_guard.sh"

up-observability:
	COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	OTEL_HTTP_PORT="$(OTEL_HTTP_PORT)" OTEL_GRPC_PORT="$(OTEL_GRPC_PORT)" \
	OTEL_PROMETHEUS_PORT="$(OTEL_PROMETHEUS_PORT)" PROMETHEUS_PORT="$(PROMETHEUS_PORT)" \
	GRAFANA_PORT="$(GRAFANA_PORT)" \
	docker compose --project-name "$(COMPOSE_PROJECT_NAME)" \
	-f "$(OBS_COMPOSE_FILE)" up -d

down-observability:
	COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	docker compose --project-name "$(COMPOSE_PROJECT_NAME)" \
	-f "$(OBS_COMPOSE_FILE)" down

# LLM provider smoke (ISSUE-106): optional outbound when LLM_MODE=openai_compatible.
llm-smoke:
	cd backend && $(PYTHON) ../scripts/llm_smoke_test.py

# Apply / roll back the database schema. Override DATABASE_URL to target a host
# (e.g. DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace).
migrate:
	cd backend && $(PYTHON) -m alembic upgrade head

migrate-down:
	cd backend && $(PYTHON) -m alembic downgrade base

# --- ISSUE-042 / ISSUE-043 / ISSUE-044 / ISSUE-245 knowledge base loaders --- #
load-kb:
	cd backend && $(PYTHON) -m scripts.load_attack_kb
	cd backend && $(PYTHON) -m scripts.load_case_kb
	cd backend && $(PYTHON) -m scripts.load_playbook_release

test:
	cd backend && $(PYTHON) -m pytest tests/test_infra/test_health.py -v

lint:
	cd backend && $(PYTHON) -m ruff check app tests && $(PYTHON) -m mypy app

fmt:
	cd backend && $(PYTHON) -m ruff check --fix app tests && $(PYTHON) -m ruff format app tests

# --- ISSUE-025 tool-system integration quality gate ---------------------- #
# In-memory Registry/Executor/Mock chains + unit tool tests.
# - Excludes `@pytest.mark.integration` (needs Dockerized Postgres/Redis).
# - Enforces statement coverage >= 80% on app.tools + app.providers.tools.
# - Expected runtime: well under 3 minutes (typically ~30s locally).
# Equivalent:
#   cd backend && pytest tests/test_tools/ tests/integration/test_tool_system.py \
#     -v -m "not integration" --cov=app.tools --cov=app.providers.tools \
#     --cov-fail-under=80
test-tools:
	cd backend && $(PYTHON) -m pytest tests/test_tools/ \
		tests/integration/test_tool_system.py -v -m "not integration" \
		--cov=app.tools --cov=app.providers.tools \
		--cov-report=term-missing --cov-fail-under=80

# --- ISSUE-017 data-foundation integration quality gate ------------------ #
integration-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/integration -m integration -v

# --- ISSUE-055 orchestration integration quality gate -------------------- #
orchestration-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
		DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/integration/test_orchestration.py -m orchestration -v \
		--cov=app.orchestration --cov=app.agents.super_agent \
		--cov-report=term-missing --cov-fail-under=75

# --- ISSUE-117 Celery worker / broker semantics quality gate ---------------- #
worker-smoke-test:
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest \
		tests/test_core/test_celery_health.py \
		tests/test_core/test_celery_delivery.py \
		tests/test_api/test_celery_worker_health.py \
		tests/test_tasks/test_worker_tasks.py \
		tests/test_tasks/test_celery_redelivery_matrix.py \
		tests/test_api/test_celery_investigation.py \
		tests/test_tasks/test_investigation_tasks.py -q

# --- ISSUE-117 Phase B nightly matrix (pytest; Docker smoke optional) ----------- #
worker-nightly-pytest:
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest \
		tests/test_core/test_celery_health.py \
		tests/test_core/test_celery_delivery.py \
		tests/test_tasks/test_celery_redelivery_matrix.py \
		tests/test_tasks/test_investigation_task_contract.py \
		tests/test_tasks/test_fake_redis_contract.py \
		tests/test_api/test_celery_investigation.py \
		tests/test_tasks/test_investigation_tasks.py -q

worker-nightly-smoke:
	bash "$(CURDIR)/scripts/celery_worker_smoke.sh"

worker-nightly-matrix: worker-nightly-pytest autonomous-mock-e2e-worker-pytest
	@echo "Phase B pytest matrix + ISSUE-110/283 worker-gated E2E (incl. SIGKILL fault injection) passed."
	@echo "Prerequisite: Docker with worker profile (see autonomous-mock-e2e-worker-pytest)."

# --- ISSUE-108 auto-investigate intent quality gate ------------------------- #
auto-investigate-test:
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/test_services/test_auto_investigate_policy.py \
		tests/test_services/test_investigation_intent_service.py \
		tests/test_services/test_investigation_intent_crash_windows.py \
		tests/integration/test_auto_investigate_mock.py \
		tests/test_api/test_investigation_intents_api.py \
		tests/test_tasks/test_investigation_tasks.py -q

# --- ISSUE-110 autonomous mock full-loop E2E (requires postgres+redis; worker for full gate) --- #
autonomous-mock-e2e-pytest:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		TASK_MODE=celery \
		CELERY_BROKER_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/integration/autonomous_e2e/ \
		-m "integration and not autonomous_mock_e2e" -v --tb=short

autonomous-mock-e2e: autonomous-mock-e2e-pytest
	@echo "Integration scenarios A–E (no worker) passed."
	@echo "Full ISSUE-110 gate: make autonomous-mock-e2e-worker-pytest"

autonomous-mock-e2e-worker-pytest:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	export COMPOSE_PROJECT_NAME="$$project"; \
	export INTEGRATION_PROJECT_NAME="$$project"; \
	export CELERY_CRASH_ARTIFACT_DIR="$(CURDIR)/backend/artifacts/celery-crash"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" --profile worker "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis worker || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 180 postgres redis worker; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		TASK_MODE=celery \
		CELERY_BROKER_URL="$(CI_REDIS_URL)" \
		COMPOSE_PROJECT_NAME="$$project" \
		INTEGRATION_PROJECT_NAME="$$project" \
		CELERY_CRASH_ARTIFACT_DIR="$(CURDIR)/backend/artifacts/celery-crash" \
		$(PYTHON) -m pytest tests/integration/autonomous_e2e/ \
		-m "autonomous_mock_e2e" -v --tb=short

# --- ISSUE-107 Mock XDR ingestion scheduler quality gate -------------------- #
ingestion-scheduler-test:
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/test_ingestion/test_ingestion_scheduler.py -q

# --- ISSUE-086 full-system quality gate ----------------------------------- #
test-system:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/system/ -m system -v --tb=short

# --- ISSUE-087 regression golden-path snapshot gate ----------------------- #
test-regression:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/regression/ -m regression -v --tb=short

update-baseline:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	printf 'This will overwrite all regression baselines under backend/tests/regression/baseline/.\n'; \
	printf 'Type ISSUE-087 to confirm: '; \
	read confirm; \
	if [ "$$confirm" != "ISSUE-087" ]; then \
		echo "Aborted baseline refresh (confirmation mismatch)." >&2; \
		exit 1; \
	fi; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		UPDATE_BASELINE=1 UPDATE_BASELINE_CONFIRM=ISSUE-087 $(PYTHON) -m scripts.update_regression_baseline

# --- ISSUE-111 frontend Vitest unit tests (Playwright e2e stays separate) --- #
frontend-test:
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm test

# --- ISSUE-077 frontend Playwright e2e (optional; does not block P0 CI) --- #
# Requires a healthy Compose stack (postgres/redis/backend/frontend).
# Usage: docker compose up -d && make test-e2e-frontend
# Backend container entrypoint applies alembic on boot.
E2E_FRONTEND_URL ?= http://127.0.0.1:$(FRONTEND_PORT)
E2E_BACKEND_URL ?= http://127.0.0.1:$(BACKEND_PORT)/api/v1
E2E_AUTH_TOKEN ?= e2e-token

test-e2e-frontend:
	@set -eu; \
	echo "Checking frontend health at $(E2E_FRONTEND_URL)/health …"; \
	curl --fail --show-error --silent "$(E2E_FRONTEND_URL)/health" >/dev/null; \
	echo "Checking backend health at $(E2E_BACKEND_URL)/health …"; \
	curl --fail --show-error --silent "$(E2E_BACKEND_URL)/health" >/dev/null; \
	cd "$(CURDIR)/frontend"; \
	(corepack enable && corepack prepare pnpm@9.15.9 --activate || true); \
	pnpm install --frozen-lockfile; \
	pnpm exec playwright install chromium; \
	E2E_FRONTEND_URL="$(E2E_FRONTEND_URL)" \
	E2E_BACKEND_URL="$(E2E_BACKEND_URL)" \
	E2E_AUTH_TOKEN="$(E2E_AUTH_TOKEN)" \
		pnpm test:e2e

# --- ISSUE-112 contract drift / frozen export -------------------------------- #
update-contracts:
	cd backend && $(UV) run --frozen python ../scripts/export_contracts.py

check-contract-drift:
	cd backend && $(UV) run --frozen python ../scripts/check_contract_drift.py

check-migration-revisions:
	cd backend && $(UV) run --frozen python ../scripts/check_migration_revisions.py

# --- ISSUE-105 evaluation pipeline (artifact-only; mock-only replay) ---------- #
evaluation-run:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m alembic upgrade head; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m scripts.run_evaluation \
		--output "$(CURDIR)/artifacts/evaluation/latest_run.json" \
		--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)" \
		--seed 42 \
		--threshold-manifest "$(CURDIR)/data/evaluation/shadowtrace_demo_v1/threshold_manifest.json" \
		--compare-baseline "$(CURDIR)/data/evaluation/shadowtrace_demo_v1/baseline_artifact.json"

evaluation-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m alembic upgrade head; \
	DATABASE_URL="$(CI_DATABASE_URL)" \
		$(PYTHON) -m pytest tests/evaluation/ -m evaluation -v --tb=short

# --- ISSUE-126 detection shadow evaluation (report-only baseline; mock-only replay) --- #
# Drop --allow-gate-fail once detection_shadow_v1 gate is deterministically green (#642/#686).
detection-evaluation-run:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m alembic upgrade head; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m scripts.run_detection_evaluation \
		--output "$(CURDIR)/artifacts/evaluation/detection_latest_run.json" \
		--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)" \
		--seed 42 \
		--threshold-manifest "$(CURDIR)/data/evaluation/detection_shadow_v1/threshold_manifest.json" \
		--compare-baseline "$(CURDIR)/data/evaluation/detection_shadow_v1/baseline_artifact.json" \
		--allow-gate-fail

# --- ISSUE-126 detection production comparison (Phase B; requires promoted candidates) --- #
detection-production-comparison-run:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" $(PYTHON) -m alembic upgrade head; \
	DETECTION_PHASE_A="$(CURDIR)/artifacts/evaluation/detection_latest_run.json"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m scripts.run_detection_evaluation \
		--output "$$DETECTION_PHASE_A" \
		--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)" \
		--seed 42 \
		--threshold-manifest "$(CURDIR)/data/evaluation/detection_shadow_v1/threshold_manifest.json"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m scripts.bootstrap_detection_production_promotions \
		--phase-a-artifact "$$DETECTION_PHASE_A" \
		--dataset-dir "$(CURDIR)/data/evaluation/detection_production_v1" \
		--threshold-manifest "$(CURDIR)/data/evaluation/detection_shadow_v1/threshold_manifest.json"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m scripts.run_detection_production_comparison \
		--phase-a-artifact "$$DETECTION_PHASE_A" \
		--dataset-dir "$(CURDIR)/data/evaluation/detection_production_v1" \
		--output "$(CURDIR)/artifacts/evaluation/detection_production_latest.json" \
		--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)" \
		--seed 42 \
		--compare-baseline "$(CURDIR)/data/evaluation/detection_production_v1/baseline_comparison_artifact.json"

# --- ISSUE-009 local / CI parity gates ------------------------------------ #
ci-lint:
	cd backend && $(UV) sync --frozen --extra dev
	$(MAKE) check-migration-revisions
	cd backend && $(UV) run --frozen ruff check app tests
	cd backend && $(UV) run --frozen ruff format --check app tests
	cd backend && $(UV) run --frozen mypy app
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm lint
	cd frontend && pnpm typecheck
	# ISSUE-111: same Vitest step as CI frontend-build; use `make frontend-test` for frontend-only.
	cd frontend && pnpm test

ci-test:
	cd backend && $(UV) sync --frozen --extra dev
	@set -eu; \
	project="$(CI_TEST_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(UV) run --frozen pytest --cov=app --cov-report=term --cov-report=xml:coverage.xml

ci-build:
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm build
	@set -e; \
	project="$(CI_BUILD_PROJECT_PREFIX)-$$(date +%s)-$$$$"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis backend frontend || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose build; \
	compose up -d --wait --wait-timeout 180; \
	for service in postgres redis mock-xdr backend frontend; do \
		container_id=$$(compose ps -q "$$service"); \
		if [ -z "$$container_id" ]; then \
			echo "$$service container is missing"; \
			exit 1; \
		fi; \
		health=$$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$$container_id"); \
		if [ "$$health" != "healthy" ]; then \
			echo "$$service is not healthy: $$health"; \
			exit 1; \
		fi; \
	done; \
	compose ps; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(BACKEND_PORT)/api/v1/health" >/dev/null; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(FRONTEND_PORT)/health" >/dev/null; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(MOCK_XDR_PORT)/mock-xdr/v1/health" >/dev/null

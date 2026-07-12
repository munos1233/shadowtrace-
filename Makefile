.PHONY: up down test lint fmt migrate migrate-down ci-lint ci-test ci-build

COMPOSE := docker compose -f infra/docker-compose.yml
# Host-side URLs for tests that talk to Compose postgres/redis from the workstation / CI runner.
CI_DATABASE_URL ?= postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace
CI_REDIS_URL ?= redis://localhost:6379/0

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

# Apply / roll back the database schema. Override DATABASE_URL to target a host
# (e.g. DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace).
migrate:
	cd backend && alembic upgrade head

migrate-down:
	cd backend && alembic downgrade base

test:
	cd backend && python -m pytest tests/test_infra/test_health.py -v

lint:
	cd backend && ruff check app tests && mypy app

fmt:
	cd backend && ruff check --fix app tests && ruff format app tests

# --- ISSUE-009 local / CI parity gates ------------------------------------ #
# Prefer the project venv when present so bare `make ci-*` matches CI's
# freshly installed ``.[dev]`` extras (incl. pytest-cov) without relying on PATH.
PYTHON ?= $(shell if [ -x "$(CURDIR)/backend/.venv/bin/python" ]; then echo "$(CURDIR)/backend/.venv/bin/python"; else echo python3; fi)

ci-lint:
	cd backend && $(PYTHON) -m pip install -e ".[dev]" -q
	cd backend && ruff check app tests
	cd backend && ruff format --check app tests
	cd backend && mypy app
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm lint
	cd frontend && pnpm typecheck

ci-test:
	cd backend && $(PYTHON) -m pip install -e ".[dev]" -q
	$(COMPOSE) up -d postgres redis
	@echo "Waiting for postgres + redis to become healthy..."
	@ok=0; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do \
		if $(COMPOSE) exec -T postgres pg_isready -U shadowtrace -d shadowtrace >/dev/null 2>&1 \
			&& $(COMPOSE) exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then \
			ok=1; break; \
		fi; \
		sleep 2; \
	done; \
	if [ "$$ok" != "1" ]; then \
		echo "postgres/redis health check timed out"; \
		$(COMPOSE) ps; \
		$(COMPOSE) logs postgres redis || true; \
		exit 1; \
	fi
	cd backend && DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest --cov=app --cov-report=term --cov-report=xml:coverage.xml

ci-build:
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm build
	$(COMPOSE) build
	@set -e; \
	cleanup() { $(COMPOSE) down || true; }; \
	trap cleanup EXIT; \
	$(COMPOSE) up -d; \
	echo "Waiting for backend health..."; \
	ok=0; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do \
		if curl -sf http://localhost:8000/api/v1/health >/dev/null; then ok=1; break; fi; \
		sleep 2; \
	done; \
	if [ "$$ok" != "1" ]; then echo "backend health check timed out"; $(COMPOSE) logs; exit 1; fi; \
	curl -sf http://localhost:8000/api/v1/health

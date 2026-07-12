.PHONY: up down test lint fmt migrate migrate-down

COMPOSE := docker compose -f infra/docker-compose.yml

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

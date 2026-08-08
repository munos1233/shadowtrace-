# ---------------------------------------------------------------------------
# ShadowTrace backend — multi-stage production image (ISSUE-088, ISSUE-112)
#
# Build context: project root (scripts/, data/, contracts/ accessible).
#   docker build -f backend/Dockerfile .
#
# Runtime layout matches main (/app flat app tree + /contracts) so Socket.IO
# schema resolution and alembic entrypoint stay compatible with ISSUE-077.
# Nested /app/backend/ is also present for bootstrap CLI scripts.
# Dependencies are installed from the committed uv.lock (frozen sync).
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/app/.venv/bin:$PATH"

COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./alembic.ini
COPY backend/docker-entrypoint.sh /docker-entrypoint.sh
COPY contracts /contracts
# Nested tree for entrypoint `python -m scripts.load_playbook_release` (ISSUE-245).
# Do not COPY backend/tests or host .venv — .dockerignore + selective COPY (ISSUE-278).
COPY backend/scripts ./backend/scripts
COPY backend/.python-version ./backend/.python-version
COPY scripts/ ./scripts/
COPY data/ ./data/

RUN uv sync --frozen --no-dev \
    && chmod +x /docker-entrypoint.sh

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim

ARG PYTHON_VERSION

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app
# Entrypoint lives at the image root (ISSUE-088/ISSUE-077 contract). The builder
# stage chmod +x it; COPY --from preserves the executable bit. Without this the
# runtime stage only copies /app and `ENTRYPOINT ["/docker-entrypoint.sh"]`
# fails with "no such file or directory" (ISSUE-142 regression from ISSUE-112).
COPY --from=builder /docker-entrypoint.sh /docker-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"

RUN groupadd -r shadowtrace && useradd -r -g shadowtrace shadowtrace \
    && chown -R shadowtrace:shadowtrace /app
USER shadowtrace

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "app.main:socket_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info"]

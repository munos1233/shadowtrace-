# ---------------------------------------------------------------------------
# ShadowTrace backend — multi-stage production image (ISSUE-088)
#
# Build context: project root (so scripts/ and data/ are accessible).
#   docker build -f backend/Dockerfile .
#
# Stage 1: install dependencies from pyproject.toml (no dev extras).
# Stage 2: slim runtime with uvicorn multi-worker.
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /app

# Install curl for healthcheck; keep layer lean.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Preserve the backend/ directory layout so scripts that compute
# ``Path(__file__).parents[1] / "backend"`` resolve correctly.
COPY backend/ ./backend/
# Bootstrap & demo-data scripts (ISSUE-088).
COPY scripts/ ./scripts/
COPY data/ ./data/

# Install *core* dependencies only (no dev extras).
RUN pip install --no-cache-dir -e "./backend"

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim

# Re-declare ARG so it is available for COPY instructions below.
# (ARGs declared before the first FROM only apply to FROM instructions.)
ARG PYTHON_VERSION

WORKDIR /app

# Curl for healthcheck (already in builder; re-add in slim runtime).
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed site-packages + app code + scripts + data from builder.
COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /app /app

# Pre-create a non-root user.
RUN groupadd -r shadowtrace && useradd -r -g shadowtrace shadowtrace \
    && chown -R shadowtrace:shadowtrace /app
USER shadowtrace

EXPOSE 8000

# Multi-worker uvicorn (ISSUE-088 §实现步骤 point 1).
# ``socket_app`` wraps the FastAPI app with the Socket.IO ASGI handler.
# Uses ``python -m uvicorn`` rather than the bare ``uvicorn`` console script
# because the multi-stage build only copies site-packages, not /usr/local/bin.
CMD ["python", "-m", "uvicorn", "app.main:socket_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--log-level", "info"]

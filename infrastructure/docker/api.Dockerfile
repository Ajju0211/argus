# ARGUS API image: FastAPI + LangGraph orchestrator + tool adapters.
# Supports multi-stage builds:
#   - dev:  installs dev dependencies in editable mode, runs uvicorn with --reload
#   - prod: installs optimized production dependencies, non-root user, no reload

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# curl is used by container healthchecks and HTTP adapters.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 argus \
    && mkdir -p /app/artifacts /app/data \
    && chown -R argus:argus /app

COPY pyproject.toml README.md ./

# ==============================================================================
# Development stage: runs uvicorn with --reload for auto-reloading on code changes
# ==============================================================================
FROM base AS dev

COPY core ./core
COPY engine ./engine
COPY integrations ./integrations
COPY packages ./packages
COPY apps ./apps
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]" \
    && chown -R argus:argus /app

USER argus
EXPOSE 8000

ENV ARGUS_ARTIFACTS_DIR=/app/artifacts \
    ARGUS_DB_PATH=/app/data/argus.db \
    ARGUS_SIMULATION_MODE=true \
    PYTHONPATH=/app

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app"]

# ==============================================================================
# Production stage: clean production installation without reload or dev tooling
# ==============================================================================
FROM base AS prod

COPY core ./core
COPY engine ./engine
COPY integrations ./integrations
COPY packages ./packages
COPY apps ./apps

RUN pip install --no-cache-dir . \
    && chown -R argus:argus /app

USER argus
EXPOSE 8000

ENV ARGUS_ARTIFACTS_DIR=/app/artifacts \
    ARGUS_DB_PATH=/app/data/argus.db \
    ARGUS_SIMULATION_MODE=true

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

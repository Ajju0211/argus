# ARGUS API image: FastAPI + LangGraph orchestrator + tool adapters.
# The demo stack runs in explicit SIMULATION_MODE; live mode still fails closed
# unless ARGUS_BIFROST_API_KEY is supplied and simulation is disabled.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# curl is used by the container healthcheck and by the HTTP adapters.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY core ./core
COPY engine ./engine
COPY integrations ./integrations
COPY packages ./packages
COPY apps ./apps

RUN pip install --no-cache-dir .

RUN useradd -m -u 1000 argus \
    && mkdir -p /app/artifacts /app/data \
    && chown -R argus:argus /app

USER argus

EXPOSE 8000

ENV ARGUS_ARTIFACTS_DIR=/app/artifacts \
    ARGUS_DB_PATH=/app/data/argus.db \
    ARGUS_SIMULATION_MODE=true

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

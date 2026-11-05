# Track 06 — API & Dashboard Deliverables

**Priority:** P1 (Core user and judge interface)  
**Status:** Complete (verified 2026-11-05)

---

## Subtask A-01: FastAPI Backend with SQLite WAL Persistence & SSE Telemetry
- **Files:** `apps/api/main.py`, `apps/api/routers/assessments.py`,
  `apps/api/database.py`, `apps/api/models.py`, `apps/api/runner.py`
- **Implemented:**
  1. FastAPI application factory with CORS allow-list and security headers
     (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
     `Permissions-Policy`, CSP).
  2. SQLite store in WAL mode (`PRAGMA journal_mode=WAL`, `synchronous=NORMAL`,
     `busy_timeout`) with `assessments` and `events` tables.
  3. Endpoints:
     - `POST /api/v1/assessments` — validate scope, persist, return `202`.
     - `GET /api/v1/assessments` / `GET /api/v1/assessments/{id}`.
     - `GET /api/v1/assessments/{id}/events` — replayable SSE stream
       (`Last-Event-ID` support) for node transitions and lifecycle events.
     - `POST /api/v1/assessments/{id}/cancel` — idempotent cooperative
       cancellation at the next safe graph boundary.
     - `GET /api/v1/assessments/{id}/report?format=md|html|pdf`.
  4. Background worker (`AssessmentRunner`) consumes `graph.stream(...)`,
     persists every update, and publishes SSE events.
  5. Live mode fails closed with `503` when Bifrost is not configured; scope
     parsing/expiry failures return `400`.
- **Acceptance evidence:** `tests/integration/test_api.py` — 9 tests covering
  create/execute/fetch, all report formats, SSE replay, cancellation,
  fail-closed live mode, invalid/expired scope, 404s, dashboard and headers.
- **Verification:** `.venv/bin/pytest -q tests/integration/test_api.py` → **9 passed**.

---

## Subtask A-02: Judge Dashboard
- **Files:** `apps/api/static/index.html`, `apps/api/main.py`
- **Implemented:**
  1. Dependency-free HTML/JS dashboard served by the API at `/` (and proxied by
     nginx in the compose stack). No Node build step, so the demo cannot fail on
     a missing frontend build.
  2. Live LangGraph node visualization via SSE: graph transition log, status /
     outcome pills, iteration and budget metrics.
  3. Verified-findings panel with severity, confidence, affected asset, and
     evidence IDs; blocked-action panel for the scope firewall.
  4. One-click launch of an authorized assessment, cancellation control, and
     Markdown / HTML / PDF report links.
  5. Scope YAML editor and explicit simulation-mode toggle; the simulation label
     is always visible and results are never presented as live.
- **Next.js Upgrade Target:** The static dashboard provides the zero-dependency fallback. The flagship Next.js 15+ "wow factor" dashboard is defined in `specs/07-frontend-and-judge-dashboard.md` and broken down into 8 parallel subagent tasks in `tasks/07-frontend-nextjs-dashboard.md`.
- **Acceptance evidence:** `TestDashboardAndHeaders` in
  `tests/integration/test_api.py`.

---

## Subtask A-03: Reproducible `docker compose up` Stack
- **Files:** `docker-compose.yml`, `infrastructure/docker/api.Dockerfile`,
  `infrastructure/docker/dashboard.Dockerfile`,
  `infrastructure/docker/nginx.conf`, `infrastructure/docker/lab/Dockerfile`,
  `infrastructure/docker/lab/lab.py`, `.dockerignore`
- **Implemented:**
  1. `argus-api` — FastAPI + LangGraph orchestrator, non-root user, persisted
     SQLite database and artifacts volumes, healthcheck.
  2. `argus-dashboard` — nginx serving the static judge UI on port 3000, with a
     same-origin `/api` and `/healthz` reverse proxy and unbuffered SSE.
  3. `mock-target-lab` — authorized Apache 2.4.49-shaped lab fixture on port
     8080 with a deterministic traversal proof and healthcheck.
  4. Compose health-gated startup order (`mock-target-lab` → `argus-api` →
     `argus-dashboard`), `no-new-privileges`, dedicated bridge network.
  5. Explicit `ARGUS_SIMULATION_MODE=true` default; live keys are opt-in.
- **Verification:** `docker compose config` validates cleanly. Full image build
  and `docker compose up` require a running Docker daemon (the daemon was not
  available in this environment); the lab server itself was exercised locally
  (`/healthz` and traversal path return the expected banner/proof).
- **Usage:** `docker compose up --build`, then open <http://localhost:3000>.

---

## Track Verification Snapshot

| Check | Command | Result |
|---|---|---|
| Full test suite | `.venv/bin/pytest -q` | **215 passed** |
| Lint | `.venv/bin/ruff check .` | clean |
| Types | `.venv/bin/mypy core engine integrations packages apps` | clean (49 files) |
| Compose schema | `docker compose config` | valid |
| API tests | `.venv/bin/pytest -q tests/integration/test_api.py` | **9 passed** |

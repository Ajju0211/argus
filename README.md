# ARGUS — Autonomous Penetration Testing Platform

> **"Autonomous Security Testing. Verified by Evidence."**

ARGUS is an autonomous security-testing platform for authorized, isolated penetration-testing labs. Developed for Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03).

---

## Documentation & Architecture

- **Master Documentation:** [`docs/`](docs/README.md)
  - [`ARGUS_Requirements_and_Build_Specification.md`](docs/ARGUS_Requirements_and_Build_Specification.md) — Master hackathon specification
  - [`ARGUS_MVP_ARCHITECTURE_SPEC.md`](docs/ARGUS_MVP_ARCHITECTURE_SPEC.md) — Master MVP architecture blueprint
- **Modular Specifications (10 Modules):** [`specs/`](specs/README.md)
- **Implementation Plan & Todo List:**
  - Roadmap: [`tasks/plan.md`](tasks/plan.md)
  - Checkable Task List: [`tasks/todo.md`](tasks/todo.md)

---

## Quick Start

### One-command judge demo (Docker Compose)

```bash
docker compose up --build
# Dashboard:  http://localhost:3000
# API docs:   http://localhost:8000/docs
# Mock lab:   http://localhost:8080
```

The stack ships an authorized mock target lab, the FastAPI assessment API, and
the dependency-free judge dashboard (nginx, same-origin API proxy). It starts in
explicit **simulation mode**; results are always labelled `SIMULATION`. Live
mode fails closed unless `ARGUS_BIFROST_API_KEY` is set and
`ARGUS_SIMULATION_MODE=false`.

> **Safety:** `mock-target-lab` is an intentionally vulnerable fixture. It is
> bound to a dedicated Compose network, must only be run on an isolated demo
> host, and must never be exposed to the public internet.

### Local development

```bash
# Setup Python 3.12 virtual environment with uv
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Full verification
pytest -q
ruff check .
mypy core engine integrations packages apps

# Run the API + dashboard locally
uvicorn apps.api.main:app --reload --port 8000
# open http://localhost:8000
```

### Evidence-backed offline demo

```bash
python scripts/demo_run.py --output /tmp/argus-demo
```

This runs a lab-agnostic simulated assessment and writes Markdown/HTML/PDF
reports with cryptographic evidence references.


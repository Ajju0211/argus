# ARGUS — Autonomous Penetration Testing Platform

> **"Autonomous Security Testing. Governed by Policy. Verified by Evidence."**

ARGUS is an autonomous security-testing platform for authorized, isolated penetration-testing environments. Developed for **Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03)**.

---

## ⚡ Quick Start (One-Command Turnkey Demo)

The entire platform — including the Next.js Dashboard, FastAPI backend, self-hosted open-source Bifrost AI Gateway, and mock target lab — boots with a single command:

```bash
# 1. Clone repository
git clone https://github.com/Ajju0211/argus.git
cd argus

# 2. Configure environment with your Bring-Your-Own (BYO) LLM key
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY or OPENAI_API_KEY (and ARGUS_SIMULATION_MODE=false for live mode)

# 3. Boot all services
docker compose up --build
```

### 🌐 Running Services:
| Service | Endpoint | Description |
| :--- | :--- | :--- |
| **Cyber Command Dashboard** | `http://localhost:3000` | Next.js 15 / React 19 UI with real-time SSE telemetry, killchain HUD, and evidence inspector |
| **Bifrost AI Gateway (OSS)** | `http://localhost:8080` | Self-hosted Maxim AI Bifrost Web UI, provider management, and live request logs |
| **FastAPI Core Backend** | `http://localhost:8000` | REST API, OpenAPI Swagger docs at `/docs`, checkpointing, and LangGraph runner |
| **Mock Vulnerable Target Lab** | `http://localhost:5000` | Isolated Apache 2.4.49 path-traversal target for safe pentest demonstrations |

---

## 🌉 Maxim AI Bifrost Integration (Self-Hosted Open-Source AI Gateway)

ARGUS complies with the hackathon requirement to use the **official open-source version of Bifrost** ([`maximhq/bifrost` on GitHub](https://github.com/maximhq/bifrost)), self-host it locally, and bring your own LLM provider API keys.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                ARGUS AGENT ARCHITECTURE                                │
│                                                                                        │
│   ┌────────────────────────┐      POST /v1/chat/completions      ┌──────────────────┐  │
│   │ LangGraph Orchestrator │ ──────────────────────────────────► │ Self-Hosted      │  │
│   │ (engine/graph.py)      │                                     │ Bifrost Gateway  │  │
│   │                        │ ◄────────────────────────────────── │ (Port 8080)      │  │
│   │ • Planning Node        │       Structured JSON Decision      │                  │  │
│   │ • ReAct Reasoning Loop │       + Latency / Token Usage       │ • Auto-Failover  │  │
│   │ • Evidence Capture     │                                     │ • BYO API Keys   │  │
│   └────────────────────────┘                                     │ • Web UI Monitor │  │
│                                                                  └────────┬─────────┘  │
│                                                                           │            │
│                                  Upstream Provider Calls                  │            │
│                      ┌──────────────────────┼──────────────────────┐      │            │
│                      ▼                      ▼                      ▼      ▼            │
│             ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│             │ Anthropic       │    │ OpenAI          │    │ Google / Groq / │          │
│             │ Claude 3.5      │    │ GPT-4o          │    │ Ollama (Local)  │          │
│             │ (Primary Model) │    │ (Fallback)      │    │ (Optional)      │          │
│             └─────────────────┘    └─────────────────┘    └─────────────────┘          │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Why We Are Using Bifrost & How It Fits
- **Unified OpenAI-Compatible Contract:** ARGUS communicates with upstream models exclusively through standard `/v1/chat/completions`. This isolates the core security engine from vendor-specific SDK quirks.
- **Automated Multi-Provider Failover:** Autonomous penetration tests cannot tolerate provider outages or sudden rate-limits (`429 Too Many Requests`). If the primary model (Claude 3.5 Sonnet) fails or throttles, Bifrost automatically re-routes the reasoning prompt to the fallback model (GPT-4o) with zero lost context (`X-Bifrost-Fallback-Triggered`).
- **Telemetry & Execution Budgeting:** Bifrost captures precise token usage and response latency for every reasoning step, which ARGUS records into its immutable audit trail.
- **Zero Hallucination Enforcement:** Bifrost delivers structured JSON directly into Pydantic contracts (`AssessmentDecision`). If a response deviates, ARGUS schema validation catches it before any action is executed.

---

### 2. How Bifrost Works Within Our Application
1. **The Reasoning Step:** In [`engine/graph.py`](engine/graph.py), the `plan_action_node` formats previous observations, discovered ports, and executed actions into a prompt.
2. **The Gateway Call:** [`integrations/bifrost/bifrost_client.py`](integrations/bifrost/bifrost_client.py) dispatches an HTTP POST request to `http://localhost:8080/v1/chat/completions` (or `http://bifrost:8080/v1` in Docker) with:
   - `Authorization: Bearer <ARGUS_BIFROST_API_KEY>`
   - `x-bf-vk: <ARGUS_BIFROST_API_KEY>`
   - `X-Bifrost-Fallback: gpt-4o`
   - `response_format: {"type": "json_object"}`
3. **Telemetry & Execution:** The response returns the proposed action, parsed strictly into Pydantic models. Telemetry headers (`X-Bifrost-Provider`, token counts, latency) are saved into state and broadcast live over Server-Sent Events (SSE) to the dashboard.

---

### 3. How to Configure with Bring-Your-Own (BYO) LLM Keys

You can provide your LLM keys in **two ways**:

#### Method A: Via Environment Variables (`.env` — Recommended)
Add your provider keys directly to `.env`:
```bash
# In your .env file:
ANTHROPIC_API_KEY=sk-ant-api03-...   # For Claude 3.5 Sonnet (Primary)
OPENAI_API_KEY=sk-proj-...           # For GPT-4o (Fallback)

# Optional alternative providers supported by Bifrost:
# GEMINI_API_KEY=AIzaSy...
# GROQ_API_KEY=gsk_...

# Bifrost Gateway endpoint
ARGUS_BIFROST_BASE_URL=http://localhost:8080/v1
ARGUS_BIFROST_API_KEY=sk-bf-local

# Enable live LLM reasoning (set to false to exit simulation mode)
ARGUS_SIMULATION_MODE=false
```

#### Method B: Via the Bifrost Web UI (`http://localhost:8080`)
1. Open **`http://localhost:8080`** in your browser.
2. Navigate to **Model Providers** ➡️ **Configurations**.
3. Click on **Anthropic** or **OpenAI**, paste your API key, and click **Save**.
4. (Optional) Under **Virtual Keys**, create a custom virtual key and paste it as `ARGUS_BIFROST_API_KEY` in your `.env`.

---

### 4. How to Run Bifrost Locally

#### Option 1: As part of Docker Compose (Automatic)
When you run `docker compose up --build`, the `maximhq/bifrost:latest` container starts automatically on port `8080`.

#### Option 2: Standalone Docker Container
If you are developing locally without Docker Compose:
```bash
docker run -d \
  -p 8080:8080 \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e OPENAI_API_KEY="sk-..." \
  -v $(pwd)/bifrost-data:/app/data \
  --name argus-bifrost \
  maximhq/bifrost:latest
```

#### Option 3: Via NPX (Node.js)
```bash
npx -y @maximhq/bifrost
```

---

### 5. How to Run the Complete Project from Scratch

#### Step 1: Clone and Set Up Environment
```bash
git clone https://github.com/Ajju0211/argus.git
cd argus
cp .env.example .env
```

#### Step 2: Configure Your API Key
Open `.env` and add your LLM API key (e.g., `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`). Set `ARGUS_SIMULATION_MODE=false` for live execution.

#### Step 3: Launch
```bash
docker compose up --build
```

#### Step 4: Access the Command Center
- Open `http://localhost:3000` to view the **Cyber Command Dashboard**.
- Open `http://localhost:8080` to view the **Bifrost Gateway Web UI**.
- Click **"New Assessment"** in the dashboard and enter target `http://localhost:5000` with scope `127.0.0.1/32` or `192.168.100.0/24`.
- Click **"Engage Agent"** to watch the autonomous ReAct reasoning loop operate live.

---

### 6. How to Verify That Requests Actually Route Through Bifrost

Judges can verify that all LLM reasoning strictly passes through Bifrost using any of the following 4 methods:

1. **Live Bifrost Web UI (`http://localhost:8080`):**
   - Open `http://localhost:8080` in a browser tab.
   - When you click "Launch Assessment" in ARGUS, watch the Bifrost dashboard update in real time via WebSockets. You will see every `POST /v1/chat/completions` request logged with timestamp, model (`claude-3-5-sonnet` or `gpt-4o`), latency, and token consumption.
2. **Docker Logs Inspection:**
   ```bash
   docker logs -f argus-bifrost
   ```
   Outputs live HTTP access logs for every planning query:
   ```text
   [Bifrost] POST /v1/chat/completions - 200 OK - 1.24s - model: claude-3-5-sonnet - tokens: 482
   ```
3. **Cyber Command Dashboard HUD Badge & Telemetry:**
   - On `http://localhost:3000`, the active assessment HUD displays the **Bifrost Gateway** badge.
   - The real-time SSE event log streams the exact model, provider, and latency metadata returned by Bifrost headers (`X-Bifrost-Provider`, `X-Bifrost-Fallback-Triggered`).
4. **Fail-Closed Verification (The Litmus Test):**
   - Stop the Bifrost container:
     ```bash
     docker stop argus-bifrost
     ```
   - Attempt to start a live assessment in ARGUS.
   - **Result:** ARGUS immediately halts and fails closed with:
     ```text
     BifrostAPIError: Network transport error connecting to Bifrost: Connection refused
     ```
   - This proves that ARGUS **never** bypasses Bifrost or fabricates LLM decisions in live mode.

---

## 🎥 Hackathon Demo Video Checklist

To satisfy all hackathon sponsor criteria during your video demonstration, show the following:
- [ ] **Bifrost Container Running:** Show the terminal running `docker compose ps` showing `argus-bifrost` on port `8080`.
- [ ] **Bifrost Web UI:** Open `http://localhost:8080` showing the configured providers (Anthropic / OpenAI).
- [ ] **Dual-Screen Live Execution:** Show the ARGUS Command Center (`http://localhost:3000`) on one side and the Bifrost live log stream (`http://localhost:8080`) on the other side. As ARGUS scans, watch Bifrost record the incoming inference requests live.
- [ ] **Cryptographic Proof of Work:** Open a confirmed finding in the ARGUS UI to show the raw HTTP payload, replayable curl command, and SHA-256 hash stored in the Evidence Vault.
- [ ] **PDF / HTML Deliverable:** Download the generated executive report at the end of the scan.

---

## 🛠️ Local Development (Without Docker)

```bash
# 1. Setup virtual environment
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# 2. Run test suite (223 passing tests)
pytest tests/ -v
ruff check .
mypy core engine integrations packages apps

# 3. Start local dev stack (FastAPI + Next.js)
./scripts/dev.sh
```

---

## 📁 Repository Structure

```text
├── apps/
│   ├── api/                 # FastAPI REST API, SQLite WAL persistence, SSE streaming
│   └── web/                 # Next.js 15 Cyber Command Dashboard (React 19, Tailwind)
├── core/
│   ├── evidence/            # Cryptographic SHA-256 Evidence Vault & chain of custody
│   ├── policy/              # Hardware-strict Policy Firewall & action gatekeeper
│   ├── reporting/           # Markdown, HTML, and PDF executive report generator
│   └── scope/               # CIDR and port boundary validator
├── engine/
│   ├── graph.py             # LangGraph cyclic ReAct state machine orchestrator
│   ├── recovery.py          # Bounded adaptive error recovery & circuit breakers
│   └── prompts.py           # Structured planning prompts & JSON schema enforcement
├── infrastructure/docker/   # Multi-stage Dockerfiles for web, API, and mock lab
├── integrations/
│   ├── bifrost/             # Maxim AI Bifrost OSS client, failover & telemetry
│   ├── tavily/              # Tavily OSINT threat intelligence & CVE lookup
│   └── tools/               # Security tool adapters (HTTP probe, nmap, nuclei, sqlmap)
├── docs/                    # Master architecture specifications & walkthroughs
│   ├── PROJECT_EXPLAINED.md # Plain-English master guide for beginners and judges
│   └── README.md            # Index of specifications
└── tests/                   # 223 automated unit, integration, and security tests
```

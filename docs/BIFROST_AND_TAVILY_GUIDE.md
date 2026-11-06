# Maxim AI Bifrost & Tavily Intelligence Architecture Guide

This guide provides a comprehensive technical walkthrough of how **Maxim AI Bifrost** (LLM routing & failover gateway) and **Tavily Security Intelligence** (OSINT & CVE research) are integrated into **ARGUS**, how they interact with the LangGraph orchestrator, where to configure credentials, and how to operate them across development and production environments.

---

## Table of Contents
1. [High-Level Architecture](#1-high-level-architecture)
2. [Maxim AI Bifrost Implementation](#2-maxim-ai-bifrost-implementation)
   - [Gateway Container & Networking](#gateway-container--networking)
   - [Python Client & Structured Outputs](#python-client--structured-outputs)
   - [Model Routing & Failover Mechanism](#model-routing--failover-mechanism)
   - [Telemetry & Audit Logging](#telemetry--audit-logging)
   - [Administrative Web UI](#administrative-web-ui)
3. [Tavily Intelligence Implementation](#3-tavily-intelligence-implementation)
   - [Role in Autonomous Penetration Testing](#role-in-autonomous-penetration-testing)
   - [Authoritative Domain Restriction](#authoritative-domain-restriction)
   - [LangGraph State Machine Ingestion](#langgraph-state-machine-ingestion)
4. [Credentials & Configuration Management](#4-credentials--configuration-management)
   - [Environment Variables (.env)](#environment-variables-env)
   - [Docker Compose Forwarding](#docker-compose-forwarding)
5. [Running the Stack](#5-running-the-stack)
   - [Development Mode (HMR & Auto-Reload)](#development-mode-hmr--auto-reload)
   - [Production Mode (Optimized Standalone)](#production-mode-optimized-standalone)
   - [Local Hybrid Execution (Without Docker Compose)](#local-hybrid-execution-without-docker-compose)
6. [Verification & Health Checks](#6-verification--health-checks)
   - [Testing Bifrost Gateway](#testing-bifrost-gateway)
   - [Testing Tavily Reconnaissance](#testing-tavily-reconnaissance)
   - [Running Automated Integration Tests](#running-automated-integration-tests)

---

## 1. High-Level Architecture

ARGUS couples autonomous penetration testing with strict cryptographic verification and deterministic scope enforcement. The AI planning loop depends on two external sponsor technologies:

```mermaid
flowchart TD
    subgraph ClientLayer ["1. Presentation Layer"]
        Dashboard["Next.js Cyber Command Dashboard<br/>(Port 3000)"]
        BifrostAdmin["Bifrost Gateway Web UI<br/>(Port 8080)"]
    end

    subgraph OrchestratorLayer ["2. Orchestration Layer (FastAPI & LangGraph)"]
        Graph["LangGraph State Engine<br/>(engine/graph.py)"]
        ScopeFirewall["Scope Firewall<br/>(core/scope/firewall.py)"]
        EvidenceVault["Evidence Vault & Merkle Log<br/>(core/evidence/)"]
    end

    subgraph IntegrationLayer ["3. Sponsor Integration Adapters"]
        TavilyAdapter["TavilyIntelService<br/>(integrations/tavily/)"]
        BifrostAdapter["BifrostClient<br/>(integrations/bifrost/)"]
        BifrostGateway["Self-Hosted Bifrost AI Gateway<br/>(maximhq/bifrost:latest :8080)"]
    end

    subgraph UpstreamLayer ["4. External Cloud Services"]
        TavilyCloud["Tavily Search API<br/>(api.tavily.com)"]
        AnthropicCloud["Anthropic API<br/>(Claude 3.5 Sonnet)"]
        OpenAICloud["OpenAI API<br/>(GPT-4o Failover)"]
    end

    subgraph TargetLayer ["5. Target Infrastructure"]
        TargetLabs["Authorized Test Labs<br/>(Mock Lab, Lab A, Lab B)"]
    end

    Dashboard -->|REST & SSE Events| Graph
    
    %% Reconnaissance flow
    Graph -->|Discovered Service Banner| TavilyAdapter
    TavilyAdapter -->|Domain-restricted search| TavilyCloud
    TavilyCloud -->|Authoritative CVEs & advisories| TavilyAdapter
    TavilyAdapter -->|Enrich state.research_refs| Graph

    %% Planning flow
    Graph -->|Audit Context + Tavily Intel| BifrostAdapter
    BifrostAdapter -->|Structured completion| BifrostGateway
    BifrostGateway -->|Primary: Claude 3.5 Sonnet| AnthropicCloud
    BifrostGateway -.->|Auto-failover on outage| OpenAICloud
    BifrostGateway -->|Telemetry + Typed JSON| BifrostAdapter
    BifrostAdapter -->|Pydantic AssessmentDecision| Graph

    %% Execution flow
    Graph -->|Proposed Action| ScopeFirewall
    ScopeFirewall -->|Deterministic validation| TargetLabs
    TargetLabs -->|Raw Tool Proofs & Logs| EvidenceVault
```

---

## 2. Maxim AI Bifrost Implementation

### Gateway Container & Networking
* **Docker Image**: `maximhq/bifrost:latest`
* **Container Name**: `argus-bifrost`
* **Port**: `8080`
* **Endpoints**:
  * Gateway API: `http://localhost:8080/v1` (host) or `http://bifrost:8080/v1` (inside Docker network `argus-lab`)
  * Administrative Web UI: `http://localhost:8080`
* **Data Volume**: `bifrost-data:/app/data` (persists routing configs, provider settings, and metrics across container rebuilds).

### Python Client & Structured Outputs
Located in [`integrations/bifrost/bifrost_client.py`](file:///Users/ajaysingh/Documents/Open-source/argus/integrations/bifrost/bifrost_client.py):
* **`BifrostClient`**: An asynchronous HTTP client communicating with the Bifrost gateway using standard OpenAI-compatible `/chat/completions` payloads.
* **Authentication Options**:
  1. *Virtual Key*: Bearer token `sk-bf-local` (or custom virtual keys configured in the Bifrost dashboard).
  2. *HTTP Basic Auth*: Automatically base64-encodes `admin_username:admin_password` when configured.
* **Structured Output Guarantee**:
  ```python
  decision, telemetry = await bifrost_client.complete_structured(
      prompt=planning_prompt,
      schema=AssessmentDecision,
      system_prompt=SYSTEM_PROMPT,
  )
  ```
  The client strips markdown code fences (` ```json `), parses the raw response, and validates it against the `AssessmentDecision` Pydantic model (`packages/contracts/actions.py`). If the LLM generates invalid JSON, it raises a typed `BifrostValidationError` rather than allowing unverified actions into the executor.

### Model Routing & Failover Mechanism
Bifrost handles enterprise LLM resilience:
* **Primary Model**: `claude-3-5-sonnet-20241022` (Anthropic). Handles deep reasoning, complex network topology planning, and precision vulnerability chaining.
* **Fallback Model**: `gpt-4o` (OpenAI).
* **Automatic Failover Behavior**: If the Anthropic API triggers a 429 rate limit, 500/503 server error, or connection timeout, Bifrost transparently re-routes the prompt to OpenAI GPT-4o without terminating the live assessment.

### Telemetry & Audit Logging
Located in [`integrations/bifrost/telemetry.py`](file:///Users/ajaysingh/Documents/Open-source/argus/integrations/bifrost/telemetry.py):
Every LLM call captures:
* `prompt_tokens` & `completion_tokens`
* `total_tokens`
* `latency_ms`
* `model_used` & `provider`
* `fallback_triggered` (boolean flag)

These metrics are logged in the assessment state and written to the executive reports (`core/reporting/report_generator.py`).

### Administrative Web UI
Navigating to **http://localhost:8080** displays:
* Real-time throughput and request rate charts.
* Token usage metrics by provider and virtual key.
* Upstream provider health and failover events.
* Interactive playground for testing routing rules.

---

## 3. Tavily Intelligence Implementation

### Role in Autonomous Penetration Testing
During automated reconnaissance (e.g., Nmap service discovery), ARGUS detects exposed application banners such as `Apache/2.4.49` or `vsftpd 2.3.4`. 

Rather than relying purely on LLM memory (which can hallucinate exploits or CVE numbers), ARGUS queries the **Tavily Search API** in real time for authoritative vulnerability advisories and proof-of-concept indicators.

### Authoritative Domain Restriction
Located in [`integrations/tavily/tavily_client.py`](file:///Users/ajaysingh/Documents/Open-source/argus/integrations/tavily/tavily_client.py):
To eliminate web noise, blog spam, and unverified content, all Tavily queries enforce strict domain filtering:
```python
AUTHORITATIVE_DOMAINS = [
    "nvd.nist.gov",
    "cve.mitre.org",
    "exploit-db.com",
    "github.com",
    "apache.org",
]
```

### LangGraph State Machine Ingestion
Located in [`engine/graph.py`](file:///Users/ajaysingh/Documents/Open-source/argus/engine/graph.py#L259-L265):
1. **Query Construction**: When services are discovered in `RECONNAISSANCE`, ARGUS queries:
   `"<service_name> <version> vulnerability advisory CVE exploit"`
2. **State Enrichment**: Retained search hits are transformed into immutable `ResearchSource` objects and appended to `state["research_refs"]`.
3. **Planner Prompt Injection**: During the `PLAN` node, the planning prompt injects:
   ```text
   ### THREAT INTELLIGENCE (Tavily Advisories)
   - CVE-2021-41773: Apache 2.4.49 Path Traversal and Remote Code Execution
     URL: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
     Snippet: A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49...
   ```
4. **Report Citations**: Confirmed findings cite the exact advisory URLs retrieved by Tavily.

---

## 4. Credentials & Configuration Management

### Environment Variables (.env)
All secrets and URLs are centralized in the root `.env` file (`argus/.env`). Copy from `.env.example`:

```bash
# ==============================================================================
# 1. BIFROST AI GATEWAY (Self-Hosted)
# ==============================================================================
# Token to access Bifrost Web UI for the first time at http://localhost:8080
BIFROST_SETUP_TOKEN=argus-admin-token-2026

# Virtual key used by ARGUS to authenticate with Bifrost
ARGUS_BIFROST_API_KEY=sk-bf-local

# Upstream LLM provider keys forwarded into self-hosted Bifrost container:
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxx
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx

# Base URL:
# - Inside Docker: http://bifrost:8080/v1
# - Local process: http://localhost:8080/v1
ARGUS_BIFROST_BASE_URL=http://localhost:8080/v1
ARGUS_BIFROST_PRIMARY_MODEL=claude-3-5-sonnet-20241022
ARGUS_BIFROST_FALLBACK_MODEL=gpt-4o

# ==============================================================================
# 2. TAVILY SECURITY INTELLIGENCE
# ==============================================================================
# Get your key at https://app.tavily.com
ARGUS_TAVILY_API_KEY=tvly-xxxxxxxxxxxxxxxxxxxx

# ==============================================================================
# 3. EXECUTION MODE & FEATURE FLAGS
# ==============================================================================
# Set false for real LLM planning and live Tavily lookups
ARGUS_SIMULATION_MODE=false
ARGUS_ENABLE_TAVILY_RESEARCH=true
ARGUS_ENABLE_PROVIDER_FALLBACK=true
ARGUS_STRICT_SCOPE_ENFORCEMENT=true
```

### Docker Compose Forwarding
In [`compose.base.yaml`](file:///Users/ajaysingh/Documents/Open-source/argus/compose.base.yaml):
* Upstream keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) and `BIFROST_SETUP_TOKEN` are forwarded into the `bifrost` service.
* `ARGUS_TAVILY_API_KEY` and `ARGUS_BIFROST_API_KEY` are forwarded into `argus-api`.
* Both services run on the internal bridge network `argus-lab`.

---

## 5. Running the Stack

Ensure you are in the root directory:
```bash
cd /Users/ajaysingh/Documents/Open-source/argus
```

### Development Mode (HMR & Auto-Reload)
Runs with live bind-mounts, FastAPI Uvicorn `--reload`, and Next.js Fast Refresh:
```bash
docker compose -f compose.dev.yaml up --build
```
* **Dashboard**: [http://localhost:3000](http://localhost:3000)
* **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **Bifrost Web UI**: [http://localhost:8080](http://localhost:8080)
* **Mock Target Lab**: [http://localhost:8888](http://localhost:8888)

### Production Mode (Optimized Standalone)
Runs with standalone production images, non-root execution, `restart: always`, and no bind-mounts:
```bash
docker compose -f compose.prod.yaml up -d --build
```

To stop containers:
```bash
docker compose -f compose.prod.yaml down
# or
docker compose -f compose.dev.yaml down
```

### Local Hybrid Execution (Without Docker Compose)
If developing outside Docker:
1. **Start Bifrost Gateway**:
   ```bash
   docker run -d --name argus-bifrost -p 8080:8080 \
     -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
     -e OPENAI_API_KEY=$OPENAI_API_KEY \
     -e BIFROST_SETUP_TOKEN=argus-admin-token-2026 \
     maximhq/bifrost:latest
   ```
2. **Start ARGUS API**:
   ```bash
   source .venv/bin/activate
   export ARGUS_BIFROST_BASE_URL="http://localhost:8080/v1"
   export ARGUS_BIFROST_API_KEY="sk-bf-local"
   export ARGUS_TAVILY_API_KEY="your_tavily_key"
   export ARGUS_SIMULATION_MODE="false"
   uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
   ```
3. **Start Dashboard**:
   ```bash
   cd apps/web
   npm run dev
   ```

---

## 6. Verification & Health Checks

### Testing Bifrost Gateway
1. **Web UI Check**:
   Open [http://localhost:8080](http://localhost:8080). If prompted for a setup token, enter `argus-admin-token-2026`.
2. **Models Endpoint Check**:
   ```bash
   curl -i http://localhost:8080/v1/models \
     -H "Authorization: Bearer sk-bf-local"
   ```
   *Expected Response*: HTTP 200 with JSON listing `claude-3-5-sonnet-20241022` and `gpt-4o`.
3. **Direct Chat Completion Test**:
   ```bash
   curl -X POST http://localhost:8080/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer sk-bf-local" \
     -d '{
       "model": "claude-3-5-sonnet-20241022",
       "messages": [{"role": "user", "content": "ping"}]
     }'
   ```

### Testing Tavily Reconnaissance
To test Tavily query resolution directly from python:
```bash
python -c '
import asyncio, os
from integrations.tavily import TavilyIntelService

async def test():
    key = os.getenv("ARGUS_TAVILY_API_KEY", "")
    service = TavilyIntelService(api_key=key)
    results = await service.search("Apache 2.4.49 path traversal")
    print(f"Retrieved {len(results)} authoritative sources:")
    for r in results:
        print(f" - [{r.score:.2f}] {r.title} -> {r.url}")

asyncio.run(test())
'
```

### Running Automated Integration Tests
The test suite includes dedicated wire-mock and live-fallback tests for both integrations:
```bash
# Run all Bifrost and Tavily wiring tests
pytest tests/security/test_integrity_wiring.py -v
```

---

*Document maintained by ARGUS Autonomous Security Platform.*


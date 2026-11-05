# Module 05 — Sponsor Integrations (Bifrost & Tavily)

**Module ID:** `bifrost-gateway` / `tavily-intel`  
**Status:** Approved Specification  
**Primary Owner:** Dev 1  
**Dependencies:** None  
**Downstream Consumers:** `agent-orchestrator`, `finding-verifier`, `report-engine`, `dashboard-ui`  

---

## 1. Overview & Architectural Role

The hackathon brief mandates meaningful, production-grade integration of **both Bifrost (by Maxim AI) and Tavily**.

ARGUS integrates both services directly into the core assessment loop:
- **Bifrost:** Serves as the single model gateway for all LLM calls, providing automatic multi-provider fallback, latency instrumentation, and real-time cost/token telemetry.
- **Tavily:** Conducts targeted vulnerability and remediation research on observed software versions, populating the final report with authoritative vendor advisories.

---

## 2. Bifrost Gateway Integration (`integrations/bifrost/bifrost_client.py`)

### 2.1 Multi-Provider Routing & Failover Architecture

```mermaid
flowchart LR
    AGENT[LangGraph Agent] --> CLIENT[Bifrost Client]
    CLIENT --> GATEWAY[Bifrost Model Gateway (Maxim AI)]
    
    GATEWAY -->|Primary Route| CLAUDE[Anthropic Claude 3.5 Sonnet]
    GATEWAY -.->|Automated Failover on 5xx / Rate Limit| GPT4O[OpenAI GPT-4o]
    
    GATEWAY --> TELEMETRY[Telemetry Logger: Latency, Tokens, Cost]
    TELEMETRY --> SQL[(SQLite & Dashboard SSE)]
```

### 2.2 Client Implementation
```python
import httpx
import time
from typing import Type, TypeVar
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class BifrostClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://bifrost.maxim.ai/v1",
        primary_model: str = "claude-3-5-sonnet-20241022",
        fallback_model: str = "gpt-4o",
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.primary_model = primary_model
        self.fallback_model = fallback_model

    async def complete_structured(self, prompt: str, schema: Type[T]) -> tuple[T, dict]:
        """Routes prompt through Bifrost with fallback header and structured JSON parsing."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-Bifrost-Fallback": self.fallback_model,
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.primary_model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        start_time = time.perf_counter()
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions", headers=headers, json=payload
            )
            resp.raise_for_status()

        latency_ms = int((time.perf_counter() - start_time) * 1000)
        data = resp.json()
        raw_content = data["choices"][0]["message"]["content"]

        # Parse into typed Pydantic contract
        structured_obj = schema.model_validate_json(raw_content)

        # Extract telemetry
        telemetry = {
            "provider_used": resp.headers.get("X-Bifrost-Provider", "anthropic"),
            "model_used": data.get("model", self.primary_model),
            "prompt_tokens": data["usage"]["prompt_tokens"],
            "completion_tokens": data["usage"]["completion_tokens"],
            "latency_ms": latency_ms,
            "fallback_triggered": resp.headers.get("X-Bifrost-Fallback-Triggered", "false")
            == "true",
        }

        return structured_obj, telemetry
```

---

## 3. Tavily Security Intelligence Integration (`integrations/tavily/tavily_client.py`)

### 3.1 Targeted Vulnerability & Remediation Research
When Nmap or HTTP recon discovers a software banner (e.g. `Apache 2.4.49`), Tavily is invoked with a scoped security search:

```python
from tavily import AsyncTavilyClient
from pydantic import BaseModel
from typing import List
from datetime import datetime


class ResearchSource(BaseModel):
    source_id: str
    query: str
    url: str
    title: str
    snippet: str
    score: float
    retrieved_at: datetime


class TavilyIntelService:
    def __init__(self, api_key: str):
        self.client = AsyncTavilyClient(api_key=api_key)

    async def research_technology(self, product: str, version: str) -> List[ResearchSource]:
        query = f'"{product} {version}" vulnerability CVE NVD advisory'
        response = await self.client.search(
            query=query,
            search_depth="advanced",
            include_domains=[
                "nvd.nist.gov",
                "cve.mitre.org",
                "exploit-db.com",
                "github.com",
                "apache.org",
            ],
            max_results=5,
        )

        sources = []
        for idx, result in enumerate(response.get("results", [])):
            sources.append(
                ResearchSource(
                    source_id=f"tavily-{product}-{version}-{idx}",
                    query=query,
                    url=result["url"],
                    title=result["title"],
                    snippet=result["content"][:400],
                    score=result.get("score", 0.0),
                    retrieved_at=datetime.utcnow(),
                )
            )
        return sources
```

### 3.2 Labeling & Guardrails
- **External Intel vs Local Evidence:** Tavily search results are explicitly labeled as `EXTERNAL_INTEL`.
- **False Positive Prevention:** A Tavily finding *never* marks a vulnerability as `CONFIRMED` on its own. It only acts as an informational lead that guides the agent to plan an active verification check.

---

## 4. Dashboard Telemetry & Sponsor Showcase

In the Next.js frontend, a persistent top bar showcases both integrations live:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ BIFROST GATEWAY: Claude 3.5 Sonnet (Primary) │ 2,410 Tokens │ 412ms Latency │ $0.04 │
│ 🔍 TAVILY INTEL: 4 Authoritative CVE Advisories Indexed (NVD, Apache.org)              │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Acceptance Criteria & Test Scenarios

1. `test_bifrost_structured_completion`: Sends a test prompt and verifies received object validates against `ActionProposal`.
2. `test_bifrost_fallback_resilience`: Injects a simulated primary provider 500 error; verifies fallback model completes request.
3. `test_tavily_security_search`: Queries `Apache 2.4.49` and verifies returned sources contain official CVE advisory URLs.
4. `test_tavily_citations_in_report`: Generates report and verifies Tavily URLs are rendered under Remediation Guidance.


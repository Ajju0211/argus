# Module 06 — API Contracts & Persistence Layer

**Module ID:** `api-lifecycle`  
**Status:** Approved Specification  
**Primary Owner:** Dev 2  
**Dependencies:** `agent-orchestrator`, `core-scope`, `evidence-vault`  
**Downstream Consumers:** `dashboard-ui`, `report-engine`  

---

## 1. Overview & Architectural Role

The **API Lifecycle & Persistence** module powers the ARGUS platform backend using **FastAPI** and **SQLite**.

Core responsibilities:
1. **Assessment State Management:** Creating, listing, starting, pausing, and cancelling security assessments.
2. **Real-time Event Streaming:** Broadcasting agent decisions, tool execution updates, and findings via **Server-Sent Events (SSE)**.
3. **Durable Persistence:** Storing execution events, graph checkpoints, and findings in SQLite using Write-Ahead Logging (WAL) mode.

---

## 2. Complete REST API Surface

### 2.1 Endpoints Specification

| Method | Endpoint | Description | Request Body | Response |
|---|---|---|---|---|
| `POST` | `/api/v1/assessments` | Create assessment & validate scope | `AssessmentCreate` | `AssessmentDetail` (HTTP 201) |
| `GET` | `/api/v1/assessments` | List historical assessments | *None* | `List[AssessmentSummary]` |
| `GET` | `/api/v1/assessments/{id}` | Get full assessment state | *None* | `AssessmentDetail` |
| `POST` | `/api/v1/assessments/{id}/start` | Launch LangGraph agent runner | *None* | `{"status": "RUNNING"}` |
| `POST` | `/api/v1/assessments/{id}/pause` | Pause active execution cleanly | *None* | `{"status": "PAUSED"}` |
| `POST` | `/api/v1/assessments/{id}/resume`| Resume from checkpoint | *None* | `{"status": "RUNNING"}` |
| `POST` | `/api/v1/assessments/{id}/cancel`| Cancel run & kill child processes | *None* | `{"status": "CANCELLED"}` |
| `GET` | `/api/v1/assessments/{id}/events`| **Live SSE stream of audit events**| *None* | `text/event-stream` |
| `GET` | `/api/v1/assessments/{id}/findings`| List findings & evidence links | *None* | `List[Finding]` |
| `GET` | `/api/v1/assessments/{id}/evidence/{ev_id}` | Download raw artifact file | *None* | `text/plain` |
| `GET` | `/api/v1/assessments/{id}/report`| Retrieve Markdown report | *None* | `{"markdown": "..."}` |
| `GET` | `/api/v1/assessments/{id}/report/pdf` | Download client-ready PDF | *None* | `application/pdf` |

---

## 3. Pydantic Request & Response Contracts

```python
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

class AssessmentTarget(BaseModel):
    type: str = Field(description="Target type: 'web' or 'network'")
    value: str = Field(description="URL or IP, e.g. 'http://192.168.100.5:8080'")

class AssessmentLimits(BaseModel):
    max_duration_seconds: int = Field(default=1800)
    max_iterations: int = Field(default=15)
    max_concurrency: int = Field(default=2)

class AssessmentCreate(BaseModel):
    name: str
    target: AssessmentTarget
    scope_yaml: str
    objective: str
    limits: Optional[AssessmentLimits] = None

class AssessmentDetail(BaseModel):
    id: str
    name: str
    status: str
    target: AssessmentTarget
    objective: str
    discovered_assets: List[str]
    discovered_services: List[Dict[str, Any]]
    total_findings: int
    created_at: datetime
    completed_at: Optional[datetime]
```

---

## 4. Server-Sent Events (SSE) Protocol

Clients connect to `/api/v1/assessments/{id}/events` to stream real-time events formatted as:

```
event: message
data: {"event_id":"evt-101","type":"action_approved","timestamp":"2026-11-04T12:05:00Z","data":{"tool":"nmap","target":"192.168.100.5"}}

```

### Complete Event Types
- `assessment_created`
- `scope_validated`
- `assessment_started`
- `recon_completed`
- `action_proposed`
- `action_approved`
- `action_blocked`
- `tool_started`
- `tool_completed`
- `tool_failed`
- `finding_detected`
- `finding_verified`
- `assessment_paused`
- `assessment_completed`
- `report_generated`

---

## 5. SQLite Persistence Schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    scope_yaml TEXT NOT NULL,
    objective TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessment_events (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    verification_method TEXT,
    affected_asset TEXT NOT NULL,
    impact TEXT,
    remediation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_path TEXT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS graph_checkpoints (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    thread_id TEXT NOT NULL,
    checkpoint_blob BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 6. Acceptance Criteria & Test Scenarios

1. `test_create_assessment_valid_scope`: Valid YAML returns HTTP 201 with status `READY`.
2. `test_create_assessment_invalid_scope`: Malformed scope returns HTTP 422 with validation errors.
3. `test_sse_event_streaming`: Subscribing to `/events` receives real-time JSON events in sequential order.
4. `test_pause_and_resume`: Pausing assessment cleanly saves checkpoint; resuming resumes from exact state.


# Module 07 — Frontend & Judge Dashboard

**Module ID:** `dashboard-ui`  
**Status:** Approved Specification  
**Primary Owner:** Dev 2  
**Dependencies:** `api-lifecycle`  
**Downstream Consumers:** Hackathon Judges & End Users  

---

## 1. Overview & Architectural Role

The **Frontend & Judge Dashboard** provides a responsive, dark-mode-first user interface built with **Next.js 15 (App Router)**.

Core objectives:
1. **Explainable Autonomy:** Surface the agent's thought process, approved vs blocked decisions, and tool status without exposing unformatted LLM token dumps.
2. **Real-time Live Room:** Connect via Server-Sent Events (SSE) to display live tool activity, discovered ports, and verified findings.
3. **Turnkey Judge Experience:** Deliver a polished, intuitive interface that allows a hackathon judge to configure a lab, run the assessment, and download a client-ready PDF report within 3 minutes.

---

## 2. Tech Stack & Project Organization

- **Framework:** Next.js 15.1+ (React 19, App Router)
- **Styling:** Tailwind CSS v3.4 + Radix UI Primitives / Lucide Icons
- **State Management:** Custom React hooks (`useAssessmentStream`) with zero heavy state library overhead
- **Directory Tree:**
  ```
  apps/web/
  ├── src/
  │   ├── app/
  │   │   ├── page.tsx                    <- Screen 1: Dashboard & History
  │   │   ├── new/page.tsx                <- Screen 2: Assessment Launcher
  │   │   ├── assessments/[id]/page.tsx   <- Screen 3: Live Assessment Room
  │   │   ├── assessments/[id]/evidence/  <- Screen 4: Evidence Vault Inspector
  │   │   └── assessments/[id]/report/    <- Screen 5: Client Report & PDF View
  │   ├── components/
  │   │   ├── AuditTimeline.tsx           <- Live streaming audit log
  │   │   ├── BifrostTelemetryBar.tsx     <- Model, tokens, latency, cost
  │   │   ├── TopologyCard.tsx            <- Discovered ports and services
  │   │   ├── FindingsBoard.tsx           <- Severity-coded finding cards
  │   │   └── ScopePreview.tsx            <- Real-time scope validator
  │   └── lib/
  │       ├── api.ts                      <- Fetch wrapper for FastAPI
  │       └── useAssessmentStream.ts      <- SSE stream hook
  ```

---

## 3. Five Essential Screen Layouts

### 3.1 Screen 1: Dashboard (`/`)
- Table of historical assessments with status chips (`READY`, `RUNNING`, `COMPLETED`, `FAILED`).
- Metric cards: Total Assessments, Discovered Assets, Confirmed Vulnerabilities, Total Tokens Consumed via Bifrost.
- Prominent **"+ New Assessment"** action button.

### 3.2 Screen 2: Assessment Launcher (`/new`)
```
┌────────────────────────────────────────────────────────────────────────┐
│  Create Security Assessment                                            │
├────────────────────────────────────────────────────────────────────────┤
│  Target Type: [ Web URL ▼ ]    Target Value: [ http://192.168.100.5:8080 ]
│                                                                        │
│  Scope YAML: [ Upload file / Paste ]                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ targets:                                                         │  │
│  │   allowed_hosts: ["192.168.100.5"]                               │  │
│  │ ports: [8080, 8443]                                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ✓ Scope Validated: 1 host, 2 ports, 0 conflicts detected             │
│                                                                        │
│  Objective: [ Discover services and identify potential CVEs          ] │
│                                                                        │
│  [ Cancel ]                                       [ Launch Assessment ]│
└────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Screen 3: Live Assessment Room (`/assessments/[id]`)
```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│  Target: http://192.168.100.5:8080 │ Status: RUNNING │ Elapsed: 01:42 │ [ Pause ] [ Cancel ]   │
│  Bifrost: Claude 3.5 Sonnet (Primary) │ 2,840 Tokens │ 380ms Latency │ Cost: $0.05             │
├────────────────────────────────────────┬───────────────────────────────────────────────────────┤
│  AUDIT TIMELINE (LIVE SSE STREAM)      │  TOPOLOGY & FINDINGS                                  │
│  ────────────────────────────────      │  ──────────────────                                   │
│  [12:05:01] Scope validated (Pass)     │  Discovered Services:                                 │
│  [12:05:05] Tool Started: nmap         │  • Port 8080/tcp (http: Apache 2.4.49)                │
│  [12:05:18] Recon complete: 1 port open│                                                       │
│  [12:05:22] Tavily Query: Apache 2.4.49│  Active Findings:                                     │
│  [12:05:30] Action Approved: nuclei    │  🔴 CRITICAL: Path Traversal (CVE-2021-41773)         │
│  [12:05:42] Finding CONFIRMED (ev-003) │     Status: CONFIRMED                                 │
│  [12:05:45] Assessment Complete        │     Evidence: ev-20261104-003 (sha256:7f8a...)        │
│                                        │     [ View Raw Evidence ]                             │
└────────────────────────────────────────┴───────────────────────────────────────────────────────┘
```

### 3.4 Screen 4: Evidence Vault Inspector (`/assessments/[id]/evidence`)
- Split-screen layout.
- Left column: List of immutable artifacts, captured timestamps, and SHA-256 prefixes.
- Right pane: Syntax-highlighted raw HTTP request/response payloads with sensitive headers automatically redacted (`[REDACTED_BY_ARGUS]`).

### 3.5 Screen 5: Client Report & PDF View (`/assessments/[id]/report`)
- Executive Summary of the target posture.
- Discovered attack surface and asset inventory.
- Finding details with severity badges, CVSS scores, reproduction `curl` commands, and SHA-256 evidence digests.
- Tavily-sourced remediation advisories with authoritative references.
- One-click **"Download PDF"** button.

---

## 4. SSE Stream Hook (`apps/web/src/lib/useAssessmentStream.ts`)

```typescript
import { useState, useEffect } from 'react';

export interface AssessmentEvent {
  event_id: string;
  type: string;
  timestamp: string;
  data: Record<string, any>;
}

export function useAssessmentStream(assessmentId: string) {
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [status, setStatus] = useState<string>('CONNECTING');

  useEffect(() => {
    if (!assessmentId) return;
    const es = new EventSource(`/api/v1/assessments/${assessmentId}/events`);

    es.onopen = () => setStatus('CONNECTED');
    es.onmessage = (e) => {
      try {
        const parsed: AssessmentEvent = JSON.parse(e.data);
        setEvents((prev) => [...prev, parsed]);
      } catch (err) {
        console.error('SSE parse error', err);
      }
    };
    es.onerror = () => {
      setStatus('DISCONNECTED');
      es.close();
    };

    return () => es.close();
  }, [assessmentId]);

  return { events, status };
}
```

---

## 5. Acceptance Criteria & Test Scenarios

1. `test_launcher_validation_preview`: Invalid YAML scope immediately shows red validation alert in launcher.
2. `test_live_sse_updates`: Emitting `action_approved` event from backend renders new item in `AuditTimeline` without full page refresh.
3. `test_pdf_download_button`: Clicking "Download PDF" retrieves valid `application/pdf` binary stream.


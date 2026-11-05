# Module 07 — Next.js Cyber Defense & Judge Dashboard

**Module ID:** `dashboard-ui`  
**Status:** Approved Architecture & Implementation Specification  
**Primary Framework:** Next.js 15.1+ (React 19, App Router, TypeScript, Tailwind CSS v4, Lucide Icons, Radix UI Primitives, Framer Motion)  
**Dependencies:** `api-lifecycle` (FastAPI backend at `/api/v1`)  
**Target Audience:** Hackathon Judges, Security Analysts, and Red Team Operators  

---

## 1. Executive Summary & Design Vision

The **ARGUS Next.js Cyber Command Dashboard** is an enterprise-grade, high-velocity Security Operations Center (SOC) interface designed to deliver an unforgettable "wow factor" for hackathon judges and security teams.

### Core Objectives
1. **Explainable Agentic Autonomy:** Visually articulate every LangGraph node transition, LLM reasoning step, and policy firewall decision in real-time without dumping unformatted raw tokens.
2. **Real-Time Bifrost Telemetry HUD:** Display live metrics for AI execution: active model (Claude 3.5 Sonnet), token consumption, request latency, and real-time assessment cost tickers.
3. **Proof-Carrying Findings & Zero Hallucination:** Every security finding is linked to an immutable cryptographic SHA-256 artifact in the Evidence Vault. Judges can inspect raw tool outputs, reproduction curl commands, and sanitized logs with one click.
4. **Interactive Lifecycle Controls:** Full control over agent execution with one-click **Start**, **Pause**, **Resume**, **Cancel**, and instant **PDF Report Export**.
5. **Instant Turnkey Judge Experience:** A hackathon judge can open the dashboard, select a pre-configured target preset, observe real-time tool execution via streaming SSE, and download a client-ready executive PDF report in under 2 minutes.

---

## 2. Design System: Cyber Defense Command Center Aesthetic

The visual language is inspired by high-end red-team command consoles (such as CrowdStrike Falcon, Linear, and Vercel dark mode), avoiding generic AI-generated templates.

### Color Palette
- **Canvas & Backgrounds:**
  - Base: `#050811` (Deep Space Navy)
  - Surface Panel: `#0b1220` with `backdrop-blur-md` and `rgba(18, 28, 51, 0.65)`
  - Card Elevated: `#101a2e` with subtle 1px border `rgba(56, 85, 148, 0.25)`
- **Accent & Status Glows:**
  - **Verified / Safe:** `#10b981` (Emerald Glow `rgba(16, 185, 129, 0.4)`)
  - **Critical Exploit / Breach:** `#f43f5e` (Rose Pulse `rgba(244, 63, 94, 0.45)`)
  - **High Severity:** `#fb923c` (Tangerine)
  - **Policy Blocked / Firewall:** `#f59e0b` (Amber Alert `rgba(245, 158, 11, 0.35)`)
  - **Live Tool Probe / Active Scan:** `#06b6d4` (Cyan Laser)
  - **Bifrost AI Intelligence:** `#8b5cf6` (Electric Violet Glow)
- **Typography:**
  - Display / Headings: `Geist Sans` or `Inter Display` (tight letter spacing `-0.02em`)
  - Data / Metrics / Logs / Code: `Geist Mono` or `JetBrains Mono`

---

## 3. Architecture & Project Layout

The frontend resides in `apps/web/` as a standalone Next.js 15 application connecting to the FastAPI backend at `http://localhost:8000` (or `/api` via reverse proxy):

```
apps/web/
├── package.json                        <- Next.js 15, React 19, Tailwind, Lucide, Framer Motion
├── tsconfig.json                       <- Strict TypeScript configuration
├── next.config.ts                      <- Fast API rewrites and unbuffered SSE proxy
├── tailwind.config.ts                  <- Custom cyber color scheme and keyframe animations
├── src/
│   ├── app/
│   │   ├── layout.tsx                  <- Root layout with Cyber Nav & Status Bar
│   │   ├── page.tsx                    <- Screen 1: Executive Dashboard & Threat Surface Map
│   │   ├── new/
│   │   │   └── page.tsx                <- Screen 2: High-Octane Assessment Launcher
│   │   ├── assessments/
│   │   │   └── [id]/
│   │   │       ├── page.tsx            <- Screen 3: Live Assessment Room
│   │   │       ├── evidence/
│   │   │       │   └── page.tsx        <- Screen 4: Evidence Vault & Cryptographic Inspector
│   │   │       └── report/
│   │   │           └── page.tsx        <- Screen 5: Client Report & Deliverable Suite
│   ├── components/
│   │   ├── navigation/
│   │   │   ├── TopNav.tsx              <- Branding, connection indicator, judge demo presets
│   │   │   └── BifrostHUD.tsx          <- Live telemetry HUD (model, tokens, latency, cost)
│   │   ├── dashboard/
│   │   │   ├── KpiCardGrid.tsx         <- Metrics cards with sparkline trends
│   │   │   ├── AssessmentsTable.tsx    <- Historical runs with status chips and search
│   │   │   └── AttackSurfaceMap.tsx    <- Discovered asset and port visualizer
│   │   ├── live/
│   │   │   ├── AuditTimeline.tsx       <- Live animated SSE event feed with node cards
│   │   │   ├── TopologyGrid.tsx        <- Interactive open ports & services badges
│   │   │   ├── FindingsBoard.tsx       <- Proof-carrying vulnerability cards
│   │   │   ├── ScopeFirewallCard.tsx   <- Real-time policy blocked actions
│   │   │   └── ExecutionControls.tsx   <- Pause, Resume, Cancel, PDF Download buttons
│   │   ├── launcher/
│   │   │   ├── ScopeYamlEditor.tsx     <- Code editor with line numbers and syntax styling
│   │   │   └── ScopeValidatorBadge.tsx <- Real-time client validation (hosts, ports, subnets)
│   │   ├── evidence/
│   │   │   ├── ArtifactExplorer.tsx    <- Artifact tree with tool tags and timestamps
│   │   │   └── HexEvidenceViewer.tsx   <- Raw viewer with secret redaction markers & SHA verify
│   │   └── ui/                         <- Base primitives (Button, Badge, Card, Dialog, Tabs)
│   ├── lib/
│   │   ├── api.ts                      <- Type-safe HTTP client for FastAPI backend
│   │   ├── useAssessmentStream.ts      <- Auto-reconnecting SSE hook with Last-Event-ID
│   │   ├── types.ts                    <- TypeScript models matching backend Pydantic schemas
│   │   └── utils.ts                    <- Formatters (currency, bytes, time, hashes)
```

---

## 4. Five "Wow-Factor" Screen Specifications

### 4.1 Screen 1: Executive Dashboard & Threat Surface Map (`/`)
**Target Impression:** *"This looks like an elite cyber operations center."*

- **Hero Telemetry Banner:**
  - Status indicator: `ARGUS Engine ONLINE` (Pulsing green dot).
  - Mode: `Simulation Sandbox` or `Live Bifrost Gateway`.
  - Quick action: `[+ Launch Assessment]` button with keyboard shortcut (`⌘N`).
- **Four High-Impact KPI Micro-Cards:**
  1. **Total Assessments Conducted:** Cumulative counter with success rate pill (`98.4% success`).
  2. **Discovered Attack Surface:** Count of unique IPs, subnets, and active ports.
  3. **Verified Vulnerabilities:** Zero-hallucination finding count broken down by severity badges: `🔴 3 Crit` `🟠 8 High` `🟡 14 Med`.
  4. **AI Gateway Efficiency:** Total tokens consumed via Bifrost, average latency (`340ms`), and cumulative LLM cost ticker (`$0.14`).
- **Historical Assessments Table:**
  - Real-time status chips: `READY`, `RUNNING` (pulsing blue), `PAUSED` (amber), `COMPLETED` (emerald), `CANCELLED` (rose).
  - Columns: ID, Assessment Name, Target (IP/URL), Scope ID, Objective, Findings Found, Created At, Quick Actions (`View Live`, `Download PDF`).
  - Search input with instant client filtering and status filters (`All`, `Active`, `Terminal`).

---

### 4.2 Screen 2: High-Octane Assessment Launcher (`/new`)
**Target Impression:** *"The policy engine guards everything before a single packet is sent."*

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  🛡️  LAUNCH AUTHORIZED SECURITY ASSESSMENT                                ⌘Enter to Run │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  1. TARGET CONFIGURATION                                                               │
│  Target Type:  [ 🌐 Web Application (HTTP/S) ▼ ]                                       │
│  Target Value: [ http://mock-target-lab:8080                                  ]       │
│  Presets:      [ ⚡ Quick Lab Demo ]  [ 🧪 DVWA / OWASP Juice Shop ]  [ 🌐 Custom IP ] │
│                                                                                        │
│  2. AUTHORIZED SCOPE DEFINITION (YAML)                                                 │
│  ┌─ Scope Document ───────────────────────────────┐ ┌─ Real-Time Policy Inspection ───┐│
│  │ 1  schema_version: "1.0"                       │ │ ✓ SCOPE VALID & CERTIFIED       ││
│  │ 2  assessment_id: judge-demo-01                │ │ • Allowed Hosts: 192.168.100.5  ││
│  │ 3  targets:                                    │ │ • Allowed Subnets: 1             ││
│  │ 4    allowed_hosts: ["192.168.100.5"]          │ │ • Permitted Ports: 80, 8080     ││
│  │ 5  ports:                                      │ │ • Denied Ports: 22, 25 (RFC1918)││
│  │ 6    allowed_ports: [80, 8080]                 │ │ • Rebinding Guard: Active       ││
│  │ 7  actions:                                    │ │ • Zero Conflicts Detected       ││
│  │ 8    allowed_categories: ["network_recon", ..] │ └─────────────────────────────────┘│
│  └────────────────────────────────────────────────┘                                    │
│                                                                                        │
│  3. OBJECTIVE & EXECUTION LIMITS                                                       │
│  Objective Strategy: [ Service Discovery & Confirmed CVE Verification ▼ ]              │
│  Max Iterations: [ 8 ]     Max Concurrency: [ 2 ]    [✓] Simulation Sandbox Safe Mode  │
│                                                                                        │
│  [ Cancel ]                                       [ 🚀 Launch Authorized Assessment ]  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
- **Real-Time Client Scope Linter:** As the user types YAML, the right-hand inspection card renders allowed vs denied boundaries dynamically. If YAML syntax is broken, it displays an instant red banner with exact line and column errors.
- **Demo Presets:** One-click fill button for the hackathon judge lab fixture so judges never have to copy-paste manually.

---

### 4.3 Screen 3: Live Assessment Room (`/assessments/[id]`)
**Target Impression:** *"I can watch the autonomous agent think, probe, and verify findings live."*

- **Top Bifrost Telemetry Bar (Sticky HUD):**
  - Target URL with copy button.
  - Status Badge (`RUNNING`, `PAUSED`, `COMPLETED`).
  - Active Model: `Anthropic Claude 3.5 Sonnet` via `Bifrost Gateway`.
  - Token Counter (live incrementing counter) + Gateway Latency (`320ms`).
  - Action Controls:
    - **`[ ⏸ Pause ]`**: Cleanly freezes the LangGraph loop and commits state to `graph_checkpoints`.
    - **`[ ▶ Resume ]`**: Reloads the checkpoint and continues streaming.
    - **`[ ⏹ Cancel ]`**: Gracefully terminates subprocess process groups.
    - **`[ 📄 PDF Report ]`**: One-click download of the cryptographic deliverable.
- **Split-Screen Layout (50/50 Desktop):**
  - **Left Pane — Live Audit Timeline (SSE Stream):**
    - Smooth scrolling feed of agent events with distinct icons:
      - 🔍 `recon_completed`: Discovered ports and services.
      - 🤖 `action_proposed`: LLM suggested next probe tool and target.
      - 🛡️ `action_approved`: Deterministic policy firewall verified host and port allowlist.
      - 🚫 `action_blocked`: Policy firewall intercepted an out-of-scope attempt (amber highlight).
      - ⚡ `tool_completed`: Subprocess finished; raw stdout stored in Evidence Vault.
      - 🎯 `finding_verified`: Zero-hallucination finding confirmed with evidence reference.
  - **Right Pane — Topology & Proof-Carrying Findings:**
    - **Target Topology Card:** Grid of discovered ports (e.g. `8080/tcp http Apache 2.4.49`) with protocol pills.
    - **Verified Findings Board:** Cards with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`), CVE identifiers (`CVE-2021-41773`), verification probe used, and clickable `ev-xxxxx` evidence link that jumps directly to the raw proof in Screen 4.

---

### 4.4 Screen 4: Evidence Vault & Cryptographic Inspector (`/assessments/[id]/evidence`)
**Target Impression:** *"Zero hallucination is real. Here is the exact cryptographic evidence."*

- **Split-Screen Dual Inspector:**
  - **Left Sidebar:** List of captured artifacts (`ev-20261105-001.raw`, `ev-20261105-002.raw`) with executing tool icon (`nmap`, `nuclei`, `zap`, `tavily`), exact UTC timestamp, and SHA-256 fingerprint prefix.
  - **Right Main Inspector:**
    - Cryptographic Integrity Header:
      - `SHA-256: 7f8a92...b412` (Green shield icon: `Verified Matches Disk Digest`).
      - Redaction Indicator: `2 sensitive tokens sanitized by SecretRedactor`.
    - Content Viewer: Monospace, syntax-highlighted display of the raw tool stdout/stderr.
    - Redacted tokens are highlighted in golden badge tags (`[REDACTED_API_KEY]`, `[REDACTED_PASSWORD]`).
    - One-click "Copy Raw Output" and "Download .raw File" buttons.

---

### 4.5 Screen 5: Client-Ready Executive Report Reader (`/assessments/[id]/report`)
**Target Impression:** *"This is a CISO-ready deliverable generated automatically in 60 seconds."*

- **Executive Header:** Company logo, assessment target, risk score gauge (e.g. `8.8 / 10 HIGH RISK`), scan duration, and compliance stamps.
- **Interactive Report Sections:**
  1. **Executive Summary:** Plain-English risk narrative written by the orchestrator.
  2. **Discovered Attack Surface Table:** Services, versions, and verified response headers.
  3. **Verified Vulnerabilities Detail:** Detailed cards with CVSS 3.1 score, affected URL/port, non-destructive reproduction steps (`curl` command block with copy button), and Tavily remediation guidance.
  4. **Audit Chain of Custody:** Table of all cryptographic hashes ensuring the report has not been tampered with.
- **Deliverable Actions:**
  - `[ Download Official PDF ]`: Streams the binary PDF generated by ARGUS.
  - `[ View HTML Report ]`: Opens full standalone styled HTML in a new tab.
  - `[ Copy Markdown ]`: Copies clean markdown directly to clipboard.

---

## 5. Next.js SSE Stream Hook Architecture

The dashboard maintains zero heavy state libraries (no Redux/Zustand overhead) by using an optimized React 19 hook:

```typescript
// apps/web/src/lib/useAssessmentStream.ts
import { useState, useEffect, useRef, useCallback } from 'react';
import { AssessmentDetail, AssessmentEvent } from './types';

export function useAssessmentStream(assessmentId: string | null) {
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<
    'CONNECTING' | 'LIVE' | 'PAUSED' | 'COMPLETED' | 'DISCONNECTED'
  >('CONNECTING');
  const eventSourceRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<number>(0);

  const fetchLatestState = useCallback(async () => {
    if (!assessmentId) return;
    try {
      const res = await fetch(`/api/v1/assessments/${assessmentId}`);
      if (res.ok) {
        const data: AssessmentDetail = await res.json();
        setAssessment(data);
        if (data.is_terminal) {
          setConnectionStatus('COMPLETED');
        } else if (data.status === 'PAUSED') {
          setConnectionStatus('PAUSED');
        }
      }
    } catch (err) {
      console.error('Failed to poll assessment state', err);
    }
  }, [assessmentId]);

  useEffect(() => {
    if (!assessmentId) return;

    fetchLatestState();

    const connectSSE = () => {
      const url = `/api/v1/assessments/${assessmentId}/events`;
      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onopen = () => setConnectionStatus('LIVE');

      const handleEvent = (e: MessageEvent, eventType: string) => {
        try {
          const payload = JSON.parse(e.data);
          const evt: AssessmentEvent = {
            id: e.lastEventId ? parseInt(e.lastEventId, 10) : Date.now(),
            eventType,
            data: payload,
            timestamp: new Date().toISOString(),
          };
          if (e.lastEventId) {
            lastEventIdRef.current = parseInt(e.lastEventId, 10);
          }
          setEvents((prev) => [...prev, evt]);
          fetchLatestState();
        } catch {
          // Heartbeat or non-json message
        }
      };

      const eventNames = [
        'assessment_created',
        'assessment_started',
        'scope_validated',
        'recon_completed',
        'action_proposed',
        'action_approved',
        'action_blocked',
        'tool_completed',
        'finding_verified',
        'assessment_paused',
        'assessment_resumed',
        'report_generated',
        'assessment_completed',
        'assessment_failed',
        'cancel_requested',
        'node_transition',
      ];

      eventNames.forEach((name) => {
        es.addEventListener(name, (e) => handleEvent(e as MessageEvent, name));
      });

      es.onerror = () => {
        setConnectionStatus('DISCONNECTED');
        es.close();
      };
    };

    connectSSE();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, [assessmentId, fetchLatestState]);

  return { assessment, events, connectionStatus, refresh: fetchLatestState };
}
```

---

## 6. Acceptance Criteria for "Wow-Factor" Validation

1. **`test_executive_dashboard_kpis`**: Dashboard renders within 300ms, displaying active/historical assessments and live Bifrost telemetry counters.
2. **`test_realtime_scope_preview`**: Editing YAML in the launcher validates within 100ms client-side, showing green allowed host chips and red conflict alerts on invalid input.
3. **`test_live_sse_room_updates`**: While assessment runs, node cards animate into the audit timeline in real-time without page reloads or layout shift.
4. **`test_interactive_pause_and_resume`**: Clicking `[Pause]` updates UI status to `PAUSED` and freezes log updates; clicking `[Resume]` restores streaming from the checkpoint.
5. **`test_evidence_vault_inspection`**: Clicking a finding's evidence ID opens the Evidence Inspector displaying the sanitized raw output with SHA-256 match confirmation.
6. **`test_pdf_download_integration`**: Clicking `[Download PDF]` downloads a valid PDF binary with correct content type `application/pdf`.

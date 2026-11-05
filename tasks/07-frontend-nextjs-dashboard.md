# Track 07 Tasks — Next.js Cyber Defense & Judge Dashboard

**Goal:** Build a production-grade, "wow-factor" Next.js 15+ cybersecurity operations dashboard for ARGUS that allows hackathon judges to launch assessments, monitor real-time AI execution with Bifrost telemetry, pause/resume graph execution, inspect cryptographic evidence, and download client-ready PDF reports.

---

## Task Distribution & Subagent Checklist

| Task ID | Description | Target Files | Dependencies |
|---|---|---|---|
| **TASK-07-01** | Next.js 15 Foundation & Cyber Theme Tokens | `apps/web/package.json`, `tailwind.config.ts`, `layout.tsx` | None |
| **TASK-07-02** | Type Contracts & Real-Time SSE Stream Hook | `apps/web/src/lib/types.ts`, `api.ts`, `useAssessmentStream.ts` | TASK-07-01 |
| **TASK-07-03** | Screen 1: Executive Dashboard & Target Surface Map | `apps/web/src/app/page.tsx`, `KpiCardGrid.tsx`, `AssessmentsTable.tsx` | TASK-07-02 |
| **TASK-07-04** | Screen 2: High-Octane Launcher with Live Scope Linter | `apps/web/src/app/new/page.tsx`, `ScopeYamlEditor.tsx`, `ScopeValidatorBadge.tsx` | TASK-07-02 |
| **TASK-07-05** | Screen 3: Live Assessment Room & Bifrost HUD | `apps/web/src/app/assessments/[id]/page.tsx`, `BifrostHUD.tsx`, `AuditTimeline.tsx` | TASK-07-02 |
| **TASK-07-06** | Screen 4: Evidence Vault & Cryptographic Inspector | `apps/web/src/app/assessments/[id]/evidence/page.tsx`, `HexEvidenceViewer.tsx` | TASK-07-02 |
| **TASK-07-07** | Screen 5: Client-Ready Report & Deliverable Suite | `apps/web/src/app/assessments/[id]/report/page.tsx` | TASK-07-05 |
| **TASK-07-08** | Multi-Stage Next.js Dockerfile & Compose Integration | `infrastructure/docker/web.Dockerfile`, `docker-compose.yml` | All |

---

### TASK-07-01: Next.js 15 Foundation & Cyber Theme Tokens
- **Objective:** Initialize the `apps/web` project structure with Next.js 15 (App Router), React 19, Tailwind CSS v4, Lucide React icons, and custom cyber dark theme styling.
- **Key Specifications:**
  - Background: `#050811` (Deep Space Navy) with subtle radial grid overlay.
  - Card panels: `#0b1220` with glassmorphic border `rgba(56, 85, 148, 0.25)`.
  - Accent colors:
    - Verified/Safe: `#10b981` (Emerald)
    - Critical Vulnerability: `#f43f5e` (Rose neon)
    - High Severity: `#fb923c` (Tangerine)
    - Policy Blocked: `#f59e0b` (Amber alert)
    - Active Probe / Scan: `#06b6d4` (Cyan laser)
    - Bifrost Gateway / AI: `#8b5cf6` (Electric violet)
  - Layout: `TopNav` featuring ARGUS glowing emblem, connection status badge, and demo preset selector.

---

### TASK-07-02: Type Contracts & Real-Time SSE Stream Hook
- **Objective:** Create type-safe interfaces and an auto-reconnecting SSE hook supporting `Last-Event-ID` sequential event replay.
- **Key Specifications:**
  - `types.ts`: Mirror backend Pydantic models (`AssessmentDetail`, `AssessmentTarget`, `Finding`, `EvidenceArtifact`, `AssessmentEvent`).
  - `api.ts`: Wrapper for FastAPI endpoints (`createAssessment`, `startAssessment`, `pauseAssessment`, `resumeAssessment`, `cancelAssessment`, `getFindings`, `getRawEvidence`, `getReportPdfUrl`).
  - `useAssessmentStream.ts`:
    - Auto-reconnect with exponential backoff on disconnect.
    - Captures all 16 standard event types (`assessment_created`, `scope_validated`, `recon_completed`, `action_approved`, `action_blocked`, `tool_completed`, `finding_verified`, `assessment_paused`, `assessment_resumed`, `report_generated`, `assessment_completed`).
    - Exposes `{ assessment, events, connectionStatus, refresh }`.

---

### TASK-07-03: Screen 1 — Executive Dashboard & Threat Surface Map (`/`)
- **Objective:** Build the primary command landing page.
- **Key Specifications:**
  - **4 KPI Micro-Cards:**
    1. Total Assessments Conducted (with success rate pill).
    2. Discovered Attack Surface (unique IPs, subnets, and active ports).
    3. Confirmed Vulnerabilities (zero-hallucination finding count broken down by Critical, High, Medium).
    4. Bifrost Gateway Efficiency (total tokens consumed, average latency, and cumulative run cost).
  - **Historical Assessments Table:**
    - Columns: ID, Target URL, Status Chip (`READY`, `RUNNING`, `PAUSED`, `COMPLETED`, `CANCELLED`), Findings Count, Created Date, Actions.
    - Quick actions: "View Live Stream" button, "Download PDF" button.
    - Instant search filter and status tabs.
    - Prominent `[+ Launch Assessment]` button.

---

### TASK-07-04: Screen 2 — High-Octane Launcher with Real-Time Scope Linter (`/new`)
- **Objective:** Build the assessment configuration interface with live client-side validation.
- **Key Specifications:**
  - **Target Config:** Select protocol (HTTP/HTTPS/TCP), input target URL/IP, and one-click quick presets (`⚡ Mock Lab Demo`, `🌐 OWASP Juice Shop`, `🧪 Custom`).
  - **Monaco/Prism Scope YAML Editor:**
    - Live client-side syntax linter with line numbers.
    - Right-hand **Scope Certification Card** dynamically calculates:
      - Allowed hosts count (`✓ 1 host allowed`).
      - Allowed port ranges (`✓ 80, 8080 allowed`).
      - Prohibited ports check (`✓ 22, 25 strictly blocked`).
      - Scope expiration date check.
  - **Strategy & Mode Options:** Objective picker (`discover_services`, `severity_threshold`, `find_cve`, `multi_step`), iteration slider, and clearly labelled **Simulation Safe Sandbox** toggle.

---

### TASK-07-05: Screen 3 — Live Assessment Room & Bifrost HUD (`/assessments/[id]`)
- **Objective:** Build the centerpiece live streaming interface where judges watch the autonomous agent work.
- **Key Specifications:**
  - **Bifrost Telemetry HUD:**
    - Model: `Claude 3.5 Sonnet` via `Bifrost Gateway`.
    - Live Tokens Ticker: Cumulative tokens consumed.
    - Latency pill: Round-trip request time (`320ms`).
    - Run Cost: Live estimated cost based on token usage.
  - **Execution Controls:**
    - `[ ⏸ Pause ]`: Freezes execution and stores graph checkpoint.
    - `[ ▶ Resume ]`: Resumes streaming from saved checkpoint.
    - `[ ⏹ Cancel ]`: Gracefully cancels and preserves state.
    - `[ 📄 Download PDF ]`: One-click client report download.
  - **Left Pane — Interactive Audit Timeline:**
    - Animated cards for each event (`scope_validated`, `recon`, `action_approved`, `action_blocked` in amber, `tool_completed`, `finding_verified`).
    - Expandable cards showing action parameters, tool commands, and rationale.
  - **Right Pane — Topology & Proof-Carrying Findings:**
    - Port and service chips with version banners.
    - Finding cards with severity badges, CVSS score, verification probe, and clickable evidence link (`ev-xxxxx`).

---

### TASK-07-06: Screen 4 — Evidence Vault & Cryptographic Inspector (`/assessments/[id]/evidence`)
- **Objective:** Prove the "zero hallucination" claim by displaying immutable cryptographic proof.
- **Key Specifications:**
  - **Artifact Explorer (Left Sidebar):**
    - List of evidence artifacts with tool icons (`nmap`, `nuclei`, `zap`), timestamp, and SHA-256 hash preview.
  - **Cryptographic Inspector (Right Main View):**
    - Top Verification Banner: Green shield `✓ SHA-256 Digest Confirmed: 7f8a92...`
    - Secret Redaction Badge: `2 sensitive tokens sanitized by SecretRedactor`.
    - Syntax-highlighted viewer of the raw tool output with line numbers.
    - One-click copy and raw file download button.

---

### TASK-07-07: Screen 5 — Client-Ready Executive Report Reader (`/assessments/[id]/report`)
- **Objective:** Display the executive report generated by `ReportGenerator`.
- **Key Specifications:**
  - Executive posture score gauge (e.g. `8.8 / 10 HIGH RISK`).
  - Table of Contents sidebar for fast navigation.
  - Attack surface inventory table.
  - Finding cards with non-destructive `curl` reproduction commands.
  - Tavily-enriched CVE remediation advisories with official citations.
  - Floating action bar with `[ Download Official PDF ]`, `[ View Standalone HTML ]`, and `[ Copy Markdown ]`.

---

### TASK-07-08: Multi-Stage Next.js Dockerfile & Compose Integration
- **Objective:** Package the Next.js application into the Docker stack without breaking the fast offline judge workflow.
- **Key Specifications:**
  - Multi-stage Dockerfile (`infrastructure/docker/web.Dockerfile`) with standalone output mode.
  - Update `docker-compose.yml` to run `argus-web` on port `3000` with reverse-proxy connection to `argus-api` on port `8000`.
  - Maintain the fallback static dashboard for zero-dependency offline environments.

---

## Verification Criteria
- All screens responsive down to 1024px tablet screens.
- Zero layout shifting during continuous SSE event stream.
- Zero unescaped HTML / XSS vulnerabilities when displaying tool output.
- Next.js TypeScript check (`tsc --noEmit`) passes with 0 errors.


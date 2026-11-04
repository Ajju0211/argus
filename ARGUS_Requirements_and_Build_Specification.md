# ARGUS --- Autonomous Penetration Testing Platform

## Hackathon Requirements and Product Specification

**Document status:** Proposed build specification\
**Hackathon:** Geek Room / Global AI Hackathon 2026\
**Selected challenge:** Track A --- Challenge 03, Autonomous Pentesting
Agent\
**Build and submission window:** 1--15 November 2026\
**Team:** 2 people\
**Primary implementation environment:** macOS, Apple Silicon MacBook Pro
M1 Pro, 16 GB RAM\
**Required integrations:** Bifrost by Maxim AI and Tavily\
**Working product name:** ARGUS (name, domain and trademark availability
have not been verified)

------------------------------------------------------------------------

# 1. Executive summary

ARGUS is an autonomous security-testing platform for **authorized,
isolated penetration-testing labs**. A user supplies a target, an
explicit scope, and an assessment objective. ARGUS validates the scope,
discovers permitted assets and services using real security tools,
interprets the results, plans and executes permitted tests, adapts when
actions fail, verifies potential findings, and produces an
evidence-backed report.

ARGUS is not intended to be an unrestricted hacking agent or a
replacement for every professional penetration tester. The hackathon
build will demonstrate a controlled, repeatable autonomous assessment
workflow against supplied or locally created labs.

**Product principle:** Every action must be authorized, every confirmed
finding must have evidence, and every assessment must be explainable
through an inspectable execution history.

## 1.1 Product positioning

**ARGUS --- Autonomous Security Testing. Verified by Evidence.**

ARGUS differentiates itself from a thin AI wrapper around scanners
through: - Adaptive test planning based on actual tool output. -
Deterministic scope enforcement before execution and network-level
containment. - Recovery from failed tools, unavailable providers and
inconclusive tests. - Explicit distinction between potential and
verified vulnerabilities. - Evidence-linked findings and reproducible
reports.

## 1.2 Success definition

The hackathon MVP is successful when a judge can provide a previously
unseen but authorized lab target, scope and objective; ARGUS can
interpret the input, perform permitted reconnaissance, select and run
suitable checks, adapt to at least one failure, verify at least one
finding where the lab contains one, and generate a client-ready
report---without executing an out-of-scope action.

This is a target for implementation and evaluation, not a claim that the
product already achieves it.

------------------------------------------------------------------------

# 2. Challenge requirements and compliance

The published Challenge 03 brief requires ARGUS to:

1.  Enumerate only authorized hosts, ports, services and versions using
    real tools.
2.  Interpret tool output, choose next actions and recover from failed
    attempts.
3.  Complete the defined lab objective, including multi-step movement
    where explicitly allowed.
4.  Respect the scope file strictly; out-of-scope access is an automatic
    failure.
5.  Produce a client-ready report with findings, evidence, severity and
    remediation.

The combined-track brief also requires meaningful use of **both Bifrost
and Tavily**.

## 2.1 Requirement-to-implementation mapping

  -----------------------------------------------------------------------
  Challenge requirement   ARGUS implementation    Acceptance evidence
  ----------------------- ----------------------- -----------------------
  Authorized enumeration  Scope-aware web and     Tool logs show only
                          network adapters        in-scope targets

  Interpret tool output   Parsers normalize tool  Agent decision
                          output into typed       references parsed
                          observations            observations

  Choose next actions     Stateful agent creates  Recorded plan and
                          structured test         selected action
                          proposals               

  Recover from failure    Retry/replan policy     Injected failure
                          with bounded attempts   followed by safe
                                                  recovery

  Complete lab objective  Objective evaluator     Repeatable objective
                          checks defined success  result
                          conditions              

  Multi-step movement     Explicitly authorized,  Demonstration only when
  when allowed            lab-specific capability scope permits
                          adapter                 

  Strict scope compliance Deterministic policy    Out-of-scope test is
                          engine plus network     blocked
                          egress controls         

  Client-ready report     Report generator        Report includes
                                                  findings, evidence,
                                                  severity and
                                                  remediation

  Meaningful Bifrost use  All model requests      Provider
                          route through Bifrost   routing/fallback and
                                                  usage logs

  Meaningful Tavily use   Version- and            Source URLs, titles,
                          finding-linked security retrieval timestamps
                          research                and relevance
  -----------------------------------------------------------------------

## 2.2 Important interpretation

The brief says judges supply the isolated lab, scope and goals, and that
the target, scope and goal may be unfamiliar. It does not specify the
exact target technology, lab delivery format, credentials, objective
types or per-assessment judging time limit.

Therefore: - Do not hardcode ARGUS to one lab, hostname, IP address or
vulnerability. - Treat the scope and objective as runtime inputs. - Keep
target adapters configurable. - Ask organizers for clarification on
target types, delivery format, credentials/access method and whether
exploitation is required for all objectives or only when explicitly
permitted. - Do not assume Challenge 05 is confirmed; the published
brief marks it provisional.

------------------------------------------------------------------------

# 3. Scope of the hackathon MVP

## 3.1 In scope

### Shared assessment engine

-   Create an assessment from target, scope and objective.
-   Validate and normalize scope before any tool runs.
-   Discover permitted assets and services.
-   Normalize tool output into structured observations.
-   Use an AI model to interpret observations and propose next actions.
-   Check every proposed action against deterministic policy.
-   Execute only registered tools with typed arguments.
-   Persist assessment state and execution history.
-   Recover from bounded tool/model failures.
-   Verify findings using a separate verification step.
-   Store raw artifacts and evidence metadata.
-   Generate a report with findings, evidence, severity, remediation and
    limitations.
-   Use Bifrost for all model access.
-   Use Tavily for relevant security research.

### Initial target adapters

**Web and API adapter** - HTTP/HTTPS reachability checks. - Technology
and header identification. - Endpoint discovery within the supplied
scope. - Passive web security checks. - Controlled, non-destructive
vulnerability checks. - Authentication-aware checks only when valid
credentials and permission are supplied.

**Linux/network adapter** - In-scope host discovery. - In-scope port
enumeration. - Service and version identification. - Safe,
service-specific checks. - Limited lab-specific multi-step objective
support only when explicitly authorized.

Both adapters use the same assessment engine, scope policy, evidence
model and report format.

## 3.2 Out of scope for the hackathon MVP

-   Public Internet or real-world scanning.
-   Testing systems without explicit authorization.
-   Unrestricted arbitrary shell execution by the model.
-   Denial-of-service or destructive testing.
-   Malware deployment, persistence or stealth.
-   Credential theft, brute-force campaigns or password cracking.
-   Unrestricted lateral movement.
-   Autonomous exploit generation against arbitrary targets.
-   Cloud-wide account or infrastructure discovery.
-   Production multi-tenant SaaS operations.
-   Kubernetes, Kafka, microservices or distributed infrastructure.
-   Building a large multi-agent swarm.
-   Claiming that a scanner result proves exploitability.

Any additional capability must be explicitly authorized by the supplied
scope and safe for the isolated lab.

## 3.3 Prioritization

  -----------------------------------------------------------------------
  Priority                            Capability
  ----------------------------------- -----------------------------------
  P0 --- required                     Scope validation, recon, tool
                                      registry, agent loop, Bifrost,
                                      Tavily, evidence, verification,
                                      recovery, report

  P1 --- if time permits              Basic live dashboard, limited
                                      multi-step lab objective,
                                      authentication-aware testing

  P2 --- after hackathon              Advanced attack graph, more
                                      adapters, team workflows, scheduled
                                      assessments, enterprise
                                      integrations
  -----------------------------------------------------------------------

P0 features must work end-to-end. A polished UI must not take priority
over a working assessment engine.

------------------------------------------------------------------------

# 4. Users and primary workflow

## 4.1 Initial users

-   Hackathon judge evaluating an unfamiliar authorized lab.
-   Security tester running a repeatable assessment in an isolated
    environment.
-   Developer or security engineer reviewing evidence and remediation.

## 4.2 Primary workflow

1.  User creates an assessment.
2.  User supplies target(s), scope, objective, optional credentials and
    execution limits.
3.  ARGUS validates the scope and refuses invalid or ambiguous
    authorization.
4.  ARGUS performs permitted reconnaissance.
5.  Tool adapters return normalized observations and store raw
    artifacts.
6.  The agent interprets observations and proposes a structured next
    action.
7.  The deterministic policy engine approves or rejects the proposal.
8.  An approved tool adapter executes the action.
9.  The agent analyzes the result and chooses to verify, replan, retry
    within limits or stop.
10. The verifier classifies findings.
11. ARGUS generates a report and preserves the assessment history.

## 4.3 User-visible assessment states

`DRAFT → VALIDATING → READY → RUNNING → PAUSED / FAILED / COMPLETED / CANCELLED`

A partial report must be available when the assessment stops because of
time, iteration, provider or tool limits.

------------------------------------------------------------------------

# 5. Scope and safety requirements

Scope enforcement is a release-blocking requirement.

## 5.1 Scope document

Use a versioned JSON or YAML schema. A scope document should contain:

  -----------------------------------------------------------------------
  Field                               Description
  ----------------------------------- -----------------------------------
  `assessment_id`                     Unique assessment identifier

  `targets`                           Explicit hostnames, IPs or CIDR
                                      ranges

  `ports`                             Explicit allowed ports or ranges

  `protocols`                         Explicit allowed protocols

  `allowed_actions`                   Permitted action categories

  `denied_actions`                    Explicitly prohibited action
                                      categories

  `credentials_ref`                   Reference to securely stored,
                                      optional credentials

  `expires_at`                        Authorization expiry

  `max_duration_seconds`              Maximum assessment duration

  `max_requests_per_second`           Request-rate ceiling

  `max_concurrency`                   Maximum simultaneous tool actions

  `tool_timeouts`                     Per-tool timeout limits

  `redirect_policy`                   Whether redirects are allowed and
                                      how each destination is checked

  `notes`                             Human-readable constraints
  -----------------------------------------------------------------------

Do not store plaintext passwords in the scope file, logs, model prompts
or reports. Use a secret reference and redact sensitive values.

## 5.2 Enforcement layers

**Application policy** - Validate target, port, protocol and action
before execution. - Reject missing, malformed, expired or ambiguous
scope. - Re-check every action, including retries and redirects. -
Revalidate resolved IP addresses against allowed targets. - Enforce
rate, concurrency, duration and tool timeout limits. - Record policy
decisions and reasons.

**Network containment** - Run tools inside a dedicated isolated lab
network. - Deny outbound access by default. - Permit only the lab
destinations explicitly authorized for the assessment. - Do not use
Docker host networking. - Bind local dashboard/API ports to `127.0.0.1`
during development. - Ensure child processes are terminated on
cancellation or timeout.

Application validation alone is not sufficient. Network-level controls
are required as a second boundary.

## 5.3 Mandatory safety behavior

-   If scope validation fails, no tool may run.
-   If authorization expires, stop new actions.
-   If a target resolves to an unauthorized address, block it.
-   If a redirect points outside scope, block the redirect.
-   If a proposed action is denied, record it and do not execute it.
-   If policy state cannot be determined, fail closed.
-   A blocked action must never be silently rewritten into a different
    action.
-   Every executed tool action must be attributable to an assessment and
    scope version.

------------------------------------------------------------------------

# 6. Functional requirements

## FR-01 Assessment management

-   Create, list and inspect assessments.
-   Start, pause, resume and cancel an assessment.
-   Persist state across process restarts.
-   Prevent duplicate starts for the same active assessment.

## FR-02 Scope validation

-   Parse the supplied scope.
-   Validate target syntax, ports, actions and expiry.
-   Normalize hostnames and networks.
-   Detect invalid or conflicting rules.
-   Produce a clear validation result.

## FR-03 Reconnaissance

-   Discover only authorized hosts, ports and services.
-   Discover web technologies and endpoints within scope.
-   Use real tools rather than fabricated model output.
-   Store raw output as artifacts.
-   Normalize findings into a common observation schema.

## FR-04 Agent planning

-   Accept a defined objective.
-   Interpret normalized observations.
-   Produce a structured test proposal with rationale, target, tool,
    arguments and expected evidence.
-   Select the next action based on prior results.
-   Stop when the objective is met or limits are reached.

## FR-05 Controlled execution

-   Execute only registered tool operations.
-   Validate typed arguments.
-   Re-check scope immediately before execution.
-   Enforce timeouts and resource limits.
-   Capture exit status, standard output, standard error and timestamps.

## FR-06 Adaptive recovery

-   Detect tool timeout, unavailable tool, malformed output, empty
    result and provider error.
-   Retry only when retry policy permits.
-   Use bounded retries and avoid repeating identical failed actions
    indefinitely.
-   Replan using available observations when possible.
-   Pause or produce a partial report when recovery is not possible.

## FR-07 Research

-   Use Tavily to research relevant technologies, versions,
    vulnerabilities and remediation.
-   Prefer official vendor advisories and authoritative security
    references.
-   Store source URL, title, retrieval timestamp and relevance.
-   Distinguish retrieved intelligence from target evidence.
-   Never mark a vulnerability confirmed solely because a CVE matches a
    version.

## FR-08 Finding verification

Each finding must have one status: - `POTENTIAL` - `CONFIRMED` -
`REJECTED` - `UNVERIFIABLE`

A confirmed finding requires a verification method and evidence. Scanner
output alone is insufficient.

## FR-09 Evidence

-   Store raw tool artifacts outside the agent prompt/state.
-   Give each artifact a stable evidence ID.
-   Record SHA-256 hash, tool/version, timestamp, assessment ID and
    target.
-   Link findings to one or more evidence IDs.
-   Redact credentials, session tokens and other secrets.

## FR-10 Reporting

The report must include: - Assessment summary and objective. - Scope and
authorization summary. - Assessment time and tools used. - Discovered
assets and services. - Executive summary. - Findings with severity and
confidence/status. - Evidence references and verification method. -
Business/technical impact where supportable. - Remediation guidance. -
Limitations, blocked actions and unverified items. - Overall objective
outcome.

## FR-11 Bifrost integration

-   Route every model request through Bifrost.
-   Configure model/provider routing.
-   Configure at least one fallback path where available.
-   Record model, provider, latency, token usage and errors.
-   Apply a per-assessment model budget before sending requests.
-   Preserve assessment state across provider failover.
-   Do not log secrets or unnecessarily sensitive target data.

## FR-12 Tavily integration

-   Research based on observed technologies, versions and findings.
-   Use research to inform test planning and remediation.
-   Store citations and retrieval metadata.
-   Clearly distinguish research sources from evidence gathered from the
    target.

------------------------------------------------------------------------

# 7. Non-functional requirements and acceptance targets

These are proposed engineering targets for the MVP, not external
guarantees.

  -----------------------------------------------------------------------
  Quality                             Requirement / target
  ----------------------------------- -----------------------------------
  Safety                              Zero out-of-scope tool executions
                                      in all tests

  Authorization                       No tool execution before successful
                                      scope validation

  Evidence                            100% of confirmed findings linked
                                      to evidence

  Auditability                        Every tool action has an event and
                                      execution record

  Reliability                         Recover from at least one injected
                                      tool failure

  Provider resilience                 Demonstrate one Bifrost fallback or
                                      a clearly handled provider outage

  Repeatability                       Three documented lab configurations

  Evaluation                          At least five repeatable scenarios
                                      per lab configuration where
                                      feasible

  Performance                         Configurable assessment time, tool
                                      timeout and iteration limits

  Resource use                        Run one lab at a time on the 16 GB
                                      development machine

  Maintainability                     Typed API contracts and modular
                                      adapters

  Portability                         Reproducible Docker-based local
                                      setup

  Privacy                             Redact credentials and secrets from
                                      logs, prompts and reports
  -----------------------------------------------------------------------

Do not claim an acceptance target is met until the corresponding test
has passed and its result is recorded.

------------------------------------------------------------------------

# 8. Architecture

## 8.1 Architecture style

Use a **modular monolith with ports-and-adapters boundaries**: - One
FastAPI application. - One stateful LangGraph orchestration engine. -
Separate target adapters for web/API and network services. - A
deterministic policy module independent of the model. - SQLite for
metadata and checkpointing. - Local artifact storage for raw evidence.

Do not introduce microservices for this two-person, 11-day MVP.

## 8.2 Logical components

1.  **Web UI:** assessment creation, live status, findings, evidence and
    report.
2.  **API:** assessment lifecycle and read endpoints.
3.  **Scope and policy engine:** authorization and action checks.
4.  **Agent orchestrator:** planning, execution coordination, recovery
    and stopping.
5.  **Tool registry:** typed, allowlisted tool operations.
6.  **Target adapters:** web/API and network discovery/testing.
7.  **Bifrost client:** model gateway.
8.  **Tavily client:** security research.
9.  **Evidence store:** raw artifacts and metadata.
10. **Finding verifier:** status and evidence validation.
11. **Report generator:** client-ready output.
12. **Persistence:** assessment records, events and graph checkpoints.

## 8.3 Architecture diagram

``` mermaid
flowchart TD
    U[User / Judge] --> UI[Next.js Dashboard]
    UI --> API[FastAPI]
    API --> S[Scope and Policy Engine]
    S --> G[LangGraph Agent]
    G --> B[Bifrost Model Gateway]
    G --> T[Tavily Research]
    G --> R[Tool Registry]
    R --> W[Web and API Adapter]
    R --> N[Network Adapter]
    W --> E[Evidence Store]
    N --> E
    E --> V[Finding Verifier]
    V --> P[Report Generator]
    API --> DB[(SQLite)]
    G --> DB
    P --> DB
```

------------------------------------------------------------------------

# 9. Agent design

## 9.1 Orchestration pattern

Use one stateful LangGraph workflow, not a swarm of independent agents.

The model proposes structured actions. Deterministic application code
validates and executes them. The model never receives unrestricted shell
access.

## 9.2 State schema

Suggested state fields:

``` python
class AssessmentState(TypedDict):
    assessment_id: str
    objective: dict
    scope_id: str
    scope_version: str
    status: str

    discovered_assets: list
    discovered_services: list
    observations: list
    research_refs: list

    test_plan: list
    current_task: dict | None
    executed_tests: list
    evidence_refs: list
    findings: list

    current_iteration: int
    max_iterations: int
    started_at: str
    deadline_at: str | None

    last_error: dict | None
    stop_reason: str | None
```

Do not put large raw scanner output into graph state. Store it as an
artifact and put only an evidence reference in state.

## 9.3 Workflow

``` mermaid
flowchart TD
    A[Validate Scope] -->|Valid| B[Reconnaissance]
    A -->|Invalid| X[Stop]
    B --> C[Normalize Observations]
    C --> D[Research Relevant Intelligence]
    D --> E[Create Test Plan]
    E --> F[Policy Check]
    F -->|Denied| G[Record Blocked Action]
    F -->|Approved| H[Execute Registered Tool]
    H --> I[Analyze Result]
    I --> J[Verify Finding]
    J --> K{Objective met or limit reached?}
    K -->|No, continue| E
    K -->|Yes| L[Generate Report]
    G --> E
    H -->|Recoverable failure| M[Recovery / Replan]
    M --> E
    H -->|Unrecoverable failure| L
```

## 9.4 Structured action proposal

An action proposal should include: - Action ID. - Target. - Adapter and
registered operation name. - Typed arguments. - Reason for the action. -
Observation/evidence references that justify it. - Expected output or
evidence. - Estimated risk category. - Requested timeout.

The policy engine must independently validate the proposal. The model's
own assertion that an action is safe is not authorization.

## 9.5 Recovery policy

-   Retry transient failures only within a small configured limit.
-   Do not retry scope-denied actions.
-   Do not repeat the same failed action indefinitely.
-   On malformed tool output, preserve the artifact, mark parsing
    failure and choose a safe next step.
-   On model-provider failure, use Bifrost fallback if configured.
-   If all providers fail, pause or stop safely and preserve state.
-   On timeout, terminate the child process and record the timeout.
-   On cancellation, stop active child processes and prevent new
    actions.

------------------------------------------------------------------------

# 10. Tooling and integrations

Use tools as controlled adapters, not as unrestricted command execution.

  -----------------------------------------------------------------------
  Tool / service          Purpose                 MVP usage
  ----------------------- ----------------------- -----------------------
  Nmap                    Network discovery and   Structured XML output;
                          service fingerprinting  only explicit
                                                  authorized targets

  OWASP ZAP               Web application         Passive baseline and
                          security testing        carefully selected
                                                  non-destructive checks

  Nuclei                  Template-based checks   Pinned, curated,
                                                  non-destructive
                                                  templates; structured
                                                  JSONL output

  Tavily                  Security intelligence   Research relevant
                                                  advisories and
                                                  remediation

  Bifrost                 Model gateway           All LLM requests,
                                                  routing, fallback and
                                                  usage logging

  LangGraph               Stateful orchestration  Agent workflow and
                                                  checkpointing

  FastAPI                 Backend API             Assessment lifecycle

  SQLite                  Metadata and            Local persistence
                          checkpoints             

  Docker                  Isolated lab and tool   Dedicated network and
                          runtime                 resource limits
  -----------------------------------------------------------------------

Tool versions and selected templates must be pinned for reproducible
evaluations. Store tool versions with assessment records.

------------------------------------------------------------------------

# 11. API contracts

Initial API surface:

  Method   Endpoint                              Purpose
  -------- ------------------------------------- -------------------
  POST     `/api/v1/assessments`                 Create assessment
  GET      `/api/v1/assessments`                 List assessments
  GET      `/api/v1/assessments/{id}`            Assessment detail
  POST     `/api/v1/assessments/{id}/start`      Start assessment
  POST     `/api/v1/assessments/{id}/pause`      Pause assessment
  POST     `/api/v1/assessments/{id}/resume`     Resume assessment
  POST     `/api/v1/assessments/{id}/cancel`     Cancel assessment
  GET      `/api/v1/assessments/{id}/events`     Stream events
  GET      `/api/v1/assessments/{id}/findings`   List findings
  GET      `/api/v1/assessments/{id}/evidence`   List evidence
  GET      `/api/v1/assessments/{id}/report`     Retrieve report

## 11.1 Assessment creation input

Illustrative shape; finalize with Pydantic contracts before parallel
implementation:

``` json
{
  "name": "Authorized lab assessment",
  "target": {
    "type": "web",
    "value": "http://lab-target"
  },
  "scope": {
    "scope_document_id": "scope-001"
  },
  "objective": {
    "description": "Assess the authorized application and report verified findings"
  },
  "limits": {
    "max_duration_seconds": 1800,
    "max_iterations": 12,
    "max_concurrency": 2
  }
}
```

Do not use this illustrative hostname against a real system. The actual
target must be supplied by the authorized lab and validated against its
scope.

## 11.2 Event types

-   `assessment_created`
-   `scope_validated`
-   `assessment_started`
-   `recon_started`
-   `recon_completed`
-   `research_completed`
-   `plan_created`
-   `action_approved`
-   `action_blocked`
-   `tool_started`
-   `tool_completed`
-   `tool_failed`
-   `finding_detected`
-   `finding_verified`
-   `finding_rejected`
-   `assessment_paused`
-   `assessment_completed`
-   `assessment_failed`
-   `report_generated`

Events should contain IDs and concise structured metadata, not secrets
or full sensitive tool output.

------------------------------------------------------------------------

# 12. Data model

Initial entities/tables:

-   `assessments`
-   `scope_documents`
-   `assets`
-   `services`
-   `observations`
-   `tool_executions`
-   `evidence_artifacts`
-   `findings`
-   `finding_evidence`
-   `assessment_events`
-   `research_sources`
-   `graph_checkpoints`
-   `reports`

Use stable IDs and foreign keys. Store raw artifacts on disk and
metadata in SQLite. Keep credentials in a separate secret mechanism; do
not store them in ordinary assessment JSON.

## 12.1 Finding schema

A finding should include:

-   `finding_id`
-   `assessment_id`
-   `title`
-   `description`
-   `affected_asset`
-   `affected_service`
-   `severity`
-   `confidence`
-   `status`
-   `verification_method`
-   `impact`
-   `remediation`
-   `evidence_ids`
-   `research_source_ids`
-   `created_at`

Severity should use a documented scale such as Informational, Low,
Medium, High and Critical. Do not assign a high severity solely from a
model's opinion. Explain the basis and uncertainty.

## 12.2 Evidence schema

-   `evidence_id`
-   `assessment_id`
-   `target`
-   `tool_name`
-   `tool_version`
-   `artifact_path`
-   `sha256`
-   `captured_at`
-   `content_type`
-   `redaction_status`
-   `metadata`

------------------------------------------------------------------------

# 13. Frontend requirements

Build a functional, restrained interface. Do not spend the first days
polishing visual design.

## Screen 1 --- Assessments

-   Recent assessments.
-   Status and objective.
-   Start a new assessment.

## Screen 2 --- New assessment

-   Target type and target input.
-   Scope file selection.
-   Objective.
-   Optional credential reference.
-   Execution limits.
-   Scope validation result before start.

## Screen 3 --- Live assessment

-   Current stage.
-   Discovered assets and services.
-   Tool execution history.
-   Structured agent decision summaries.
-   Approved and blocked actions.
-   Findings and evidence references.
-   Pause, resume and cancel controls.

Do not display hidden model chain-of-thought. Display concise structured
reasons, policy decisions and evidence.

## Screen 4 --- Findings

-   Severity and verification status.
-   Affected asset.
-   Evidence links.
-   Remediation.
-   Research sources.

## Screen 5 --- Report

-   Executive summary.
-   Scope and methodology.
-   Assets and services.
-   Findings.
-   Evidence.
-   Remediation.
-   Limitations.
-   Downloadable PDF.

------------------------------------------------------------------------

# 14. Repository structure

Suggested monorepo:

``` text
argus/
├── apps/
│   ├── api/
│   │   ├── routes/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── main.py
│   └── web/
│       ├── app/
│       ├── components/
│       ├── features/
│       └── lib/
├── packages/
│   └── contracts/
│       ├── assessment.py
│       ├── scope.py
│       ├── actions.py
│       ├── findings.py
│       └── events.py
├── engine/
│   ├── graph.py
│   ├── state.py
│   ├── nodes/
│   ├── prompts/
│   └── recovery.py
├── core/
│   ├── scope/
│   ├── policy/
│   ├── executor/
│   ├── evidence/
│   ├── findings/
│   └── reporting/
├── integrations/
│   ├── bifrost/
│   ├── tavily/
│   └── security_tools/
│       ├── nmap/
│       ├── zap/
│       └── nuclei/
├── infrastructure/
│   ├── docker/
│   ├── labs/
│   ├── configs/
│   └── scripts/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── evaluation/
│   └── fixtures/
├── docs/
│   ├── architecture.md
│   ├── safety-model.md
│   ├── evaluation.md
│   ├── demo-runbook.md
│   └── decisions/
├── artifacts/
├── .env.example
├── docker-compose.yml
├── pyproject.toml
├── package.json
└── README.md
```

Do not create empty modules for every future idea. Add folders as the
implementation needs them.

------------------------------------------------------------------------

# 15. Testing and evaluation strategy

## 15.1 Lab configurations

**Lab A --- Web application** - One intentionally vulnerable
application. - Defined in-scope hostname and ports. - At least one
known, safely verifiable finding.

**Lab B --- Linux/network** - One isolated Linux host. - Several
deliberately exposed services. - Defined authorized ports and a known
service-level test objective.

**Lab C --- Multi-host** - Multiple isolated authorized hosts. - A web
service and another service. - A multi-step objective only where the
scope explicitly permits it.

Use isolated Docker networks or isolated VMs. Do not expose lab targets
to public networks. Start with one lab and make it pass before adding
the others.

## 15.2 Required test scenarios

1.  Valid scope permits an authorized discovery action.
2.  Invalid or expired scope prevents all tool execution.
3.  Out-of-scope hostname or IP is blocked.
4.  DNS resolution to an unauthorized IP is blocked.
5.  Redirect to an out-of-scope destination is blocked.
6.  Tool timeout is recorded and handled.
7.  Malformed tool output does not crash the assessment.
8.  Repeated failed action is bounded.
9.  Irrelevant CVE research does not become a confirmed finding.
10. False-positive scanner result is rejected or marked unverified.
11. Bifrost provider failure triggers fallback or safe pause.
12. All model providers unavailable preserves state and stops safely.
13. Cancellation terminates active tool processes.
14. Iteration/time limit produces a partial report.
15. Every confirmed finding has evidence and a verification method.

## 15.3 Evaluation metrics

-   Objective completion rate.
-   Number of out-of-scope tool executions (target: zero).
-   Precision of confirmed findings.
-   False-positive rejection rate.
-   Recovery success rate.
-   Evidence completeness.
-   Tool calls per assessment.
-   Model tokens and cost per assessment.
-   Assessment duration.
-   Percentage of runs producing a valid report.

Run each scenario repeatedly where practical. Save test configuration,
output and result so the demo is reproducible.

------------------------------------------------------------------------

# 16. Two-person ownership

## Developer 1 --- Agent and security engine

Owns: - Scope and policy engine. - Tool registry and adapters. -
LangGraph orchestration. - Bifrost integration. - Tavily integration. -
Evidence capture and finding verification. - Recovery and evaluation
tests.

## Developer 2 --- Product and platform

Owns: - Pydantic/API contracts in collaboration with Developer 1. -
FastAPI assessment lifecycle. - SQLite persistence and events. - Next.js
dashboard. - Report UI and PDF generation. - Docker lab setup and
reproducible demo.

## Integration rules

-   Agree on Pydantic contracts before parallel work.
-   Use feature branches and small pull requests.
-   Integrate at least once daily.
-   Every feature must have a test.
-   Every agent action must be inspectable.
-   A feature is complete only when it works end-to-end.
-   Avoid last-minute interface or schema changes without coordinating
    both developers.

------------------------------------------------------------------------

# 17. Execution milestones: 4--15 November

  -----------------------------------------------------------------------
  Date                                Primary deliverable
  ----------------------------------- -----------------------------------
  Nov 4                               Confirm requirements, architecture,
                                      API contracts, scope schema and
                                      first lab

  Nov 5                               Scope validator, policy checks,
                                      tool registry and real authorized
                                      discovery

  Nov 6                               Web/network adapters and normalized
                                      observations

  Nov 7                               LangGraph workflow, structured
                                      actions, Bifrost integration and
                                      persistence

  Nov 8                               ZAP/Nuclei integration and
                                      structured results

  Nov 9                               Tavily research, evidence store and
                                      finding verification

  Nov 10                              Adaptive loop, bounded retries,
                                      recovery and limits

  Nov 11                              Dashboard integrated with live
                                      assessment events

  Nov 12                              PDF report, provider fallback,
                                      pause/resume and scope tests

  Nov 13                              Lab configurations, failure
                                      injection and evaluation

  Nov 14                              Hardening, documentation, demo
                                      rehearsal and bug fixes

  Nov 15                              Feature freeze, final validation
                                      and submission
  -----------------------------------------------------------------------

## 17.1 First 48 hours

Do these before building a polished dashboard:

1.  Create the repository and development environment.
2.  Agree on the assessment, scope, action, event and finding contracts.
3.  Implement the scope parser and deterministic policy checks.
4.  Start one isolated lab.
5.  Execute one real reconnaissance tool through the controlled tool
    registry.
6.  Save raw output as an artifact and normalize it.
7.  Prove that an out-of-scope action is blocked.
8.  Commit the working vertical slice.

If this vertical slice is not working by the end of the first two days,
reduce scope immediately.

------------------------------------------------------------------------

# 18. Development environment and resource limits

Development machine: Apple Silicon M1 Pro, 16 GB RAM, 512 GB storage.

Recommended constraints: - Use ARM64-compatible Docker images where
available. - Run one lab at a time. - Start with Docker Desktop resource
allocation around 4 CPUs and 6 GB RAM, then adjust based on actual
memory pressure. - Avoid a heavy Kali VM and local LLM for the MVP. -
Use hosted model access through Bifrost. - Keep SQLite and local
artifact storage. - Limit tool concurrency initially to two. - Set
explicit timeouts and process cleanup. - Keep sufficient disk space for
Docker images and evidence artifacts.

------------------------------------------------------------------------

# 19. Product roadmap beyond the hackathon

The hackathon build should establish a credible core, not attempt the
entire commercial roadmap.

## Phase 1 --- Autonomous assessment engine

-   Scope-aware reconnaissance.
-   Controlled web and network testing.
-   Adaptive planning and recovery.
-   Verified findings and evidence-backed reports.

## Phase 2 --- Professional security workflows

-   Reusable assessment templates.
-   Team collaboration and role-based access.
-   Authenticated testing workflows.
-   Report customization.
-   Integrations with issue trackers and security workflows.

## Phase 3 --- Continuous security validation

-   Scheduled authorized assessments.
-   Regression testing.
-   Change detection.
-   Remediation verification.
-   Historical security posture.

## Phase 4 --- Enterprise platform

-   Multi-tenant architecture and isolation.
-   Enterprise identity and audit controls.
-   Central policy management.
-   CI/CD integrations.
-   Retention and compliance controls.
-   Scalable execution workers.

Do not implement these future phases during the 11-day hackathon unless
all P0 acceptance criteria are already satisfied.

------------------------------------------------------------------------

# 20. Risks and mitigations

  -----------------------------------------------------------------------
  Risk                    Impact                  Mitigation
  ----------------------- ----------------------- -----------------------
  Unknown judging lab     Agent may not support   Runtime scope/objective
                          target                  contracts and adapters

  Excessive scope         Incomplete product      P0/P1/P2 prioritization
                                                  and feature freeze

  Unsafe model action     Automatic failure       Deterministic policy
                                                  and network containment

  Scanner false positives Untrustworthy report    Separate verification
                                                  and explicit finding
                                                  statuses

  Tool output             Agent errors            Version pinning and
  inconsistency                                   normalized parsers

  Bifrost/provider outage Assessment stops        Fallback, checkpointing
                                                  and safe pause

  Irrelevant Tavily       Incorrect conclusions   Match research to
  research                                        observed versions and
                                                  label uncertainty

  M1 resource limits      Slow or unstable labs   One lab at a time, low
                                                  concurrency, ARM64
                                                  images

  Frontend consumes time  Engine remains          API-first contracts and
                          incomplete              basic UI until vertical
                                                  slice works

  Unclear organizer       Wrong feature           Ask targeted questions
  expectations            investment              and keep adapters
                                                  configurable
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 21. Open questions for organizers

The published brief already confirms that judges supply the isolated
lab, scope and objective. Do not ask those questions again.

Ask only for details not answered in the brief:

1.  What target types should participants prepare for: web applications,
    APIs, Linux hosts, network services, or a combination?
2.  What delivery/access mechanism should participants expect: Docker
    environment, VM, private IP/VPN, or another format?
3.  Are credentials supplied when the lab requires authenticated
    testing?
4.  Does every assessment require successful exploitation, or is
    identification and verification sufficient unless the objective
    explicitly requires a multi-step path?

Do not delay the first implementation while waiting for answers. Keep
the target adapters configurable.

------------------------------------------------------------------------

# 22. Submission checklist

## Product

-   [ ] Working project and reproducible demo.
-   [ ] Repository with setup instructions.
-   [ ] Architecture overview.
-   [ ] Clear selection of Challenge 03.
-   [ ] Documented Bifrost integration.
-   [ ] Documented Tavily integration.

## Safety

-   [ ] Isolated lab only.
-   [ ] Scope validation before execution.
-   [ ] Application and network-level enforcement.
-   [ ] Out-of-scope regression tests pass.
-   [ ] Credentials and secrets are redacted.
-   [ ] No unrestricted arbitrary shell execution.

## Agent

-   [ ] Real tool-based reconnaissance.
-   [ ] Structured interpretation and planning.
-   [ ] Controlled action execution.
-   [ ] At least one adaptive decision.
-   [ ] At least one recovery scenario.
-   [ ] Finding verification.
-   [ ] Evidence-linked report.

## Evaluation

-   [ ] Lab setup documented.
-   [ ] Test scenarios documented.
-   [ ] Results and measurements saved.
-   [ ] Known limitations disclosed.
-   [ ] Demo rehearsed from a clean start.

## Final submission

-   [ ] README and installation steps verified.
-   [ ] Demo video or walkthrough prepared if required.
-   [ ] Repository and demo links work.
-   [ ] Submission follows the official event instructions.
-   [ ] Final version submitted before the published deadline.

------------------------------------------------------------------------

# 23. Final engineering decisions

1.  Build a modular monolith, not microservices.
2.  Use one stateful LangGraph engine, not a multi-agent swarm.
3.  Support web/API and network targets through separate adapters.
4.  Make scope enforcement deterministic and independent of the LLM.
5.  Never allow the LLM to execute arbitrary shell commands.
6.  Use real tools and preserve their raw output as evidence.
7.  Treat scanner detections as potential until verified.
8.  Use Bifrost for all model requests and demonstrate meaningful
    reliability behavior.
9.  Use Tavily for relevant security research and remediation grounding.
10. Prioritize one complete, repeatable assessment over a large feature
    list.
11. Do not claim capabilities that have not passed evaluation.
12. Keep the long-term product roadmap separate from the hackathon
    delivery scope.

**Final product decision:** Build ARGUS as a lab-agnostic,
scope-enforced autonomous security-testing platform. The hackathon
deliverable is a reliable assessment workflow with two target adapters,
adaptive testing, recovery, evidence-backed verification and reporting.
Expand only after that core works.

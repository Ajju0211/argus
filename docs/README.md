# ARGUS Master Documentation

This directory contains the master requirements, architectural specifications, and design history for the ARGUS Autonomous Penetration Testing Platform.

---

## Documents

| Document | Description |
|---|---|
| **[`PROJECT_EXPLAINED.md`](PROJECT_EXPLAINED.md)** | **Master System Walkthrough & Plain-English Guide:** Explains what ARGUS is, how it works from every perspective, what is currently live, how data flows, and how network redirection works. |
| **[`BIFROST_TAVILY_MODEL_LOOP.md`](BIFROST_TAVILY_MODEL_LOOP.md)** | **Bifrost + Tavily Deep Dive:** How to connect LLM providers inside Bifrost, how models are selected, how Tavily is triggered, and exactly what happens inside each LangGraph loop iteration — including current implementation gaps and fixes. |
| **[`BIFROST_AND_TAVILY_GUIDE.md`](BIFROST_AND_TAVILY_GUIDE.md)** | Operations guide for running and verifying the Bifrost gateway and Tavily integration across local and Docker environments. |
| **[`ARGUS_Requirements_and_Build_Specification.md`](ARGUS_Requirements_and_Build_Specification.md)** | The comprehensive master specification for Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03). Contains full functional requirements, compliance rules, risks, and roadmap. |
| **[`ARGUS_MVP_ARCHITECTURE_SPEC.md`](ARGUS_MVP_ARCHITECTURE_SPEC.md)** | The architectural blueprint for the MVP: Ports-and-Adapters modular monolith, LangGraph state machine, data models, and 11-day build breakdown. |

---

## Modular Specifications

For modular, actionable specifications broken down by capability, see the **[`specs/`](../specs/README.md)** directory:
- `specs/00-overview-and-scope.md`
- `specs/01-safety-and-policy-engine.md`
- `specs/02-agent-orchestrator-and-recovery.md`
- `specs/03-tool-engine-and-adapters.md`
- `specs/04-evidence-vault-and-verification.md`
- `specs/05-sponsor-integrations.md`
- `specs/06-api-contracts-and-persistence.md`
- `specs/07-frontend-and-judge-dashboard.md`
- `specs/08-testing-evaluation-and-labs.md`
- `specs/09-team-plan-and-milestones.md`

Implementation status is tracked in [`tasks/remediation/README.md`](../tasks/remediation/README.md), not in this index.


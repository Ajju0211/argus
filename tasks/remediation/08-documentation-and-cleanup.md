# Track 08 — Documentation & Schema Cleanup

**Priority:** P2 (Documentation hygiene and consistency)  
**Status:** COMPLETED & VERIFIED (D-01 through D-08)

---

## Subtask D-01: Fix Spec Links
- **Action:** Replaced every `file:///Users/...` absolute link in `specs/README.md` and
  `tasks/remediation/README.md` with relative repository Markdown links.
- **Verification:** `grep -RIn "file:///Users" specs docs README.md tasks` returns no
  live links (only the historical review text in `specs/10`).

## Subtask D-02: Reconcile Architecture Status Labels
- **Action:** Removed mixed per-file statuses from `docs/README.md` and pointed readers
  to the single source of truth, `tasks/remediation/README.md`.
- **Verification:** No stale `(Implemented)` / `(Updated)` labels remain in the docs index.

## Subtask D-03: Scope Schema Unification
- **Action:** The canonical schema remains `packages/contracts/scope.py`. It now includes
  `credentials_ref`, `max_duration_seconds`, `tool_timeouts`, port ranges, and the
  `authorized_chain` envelope. Documentation snippets that disagreed are marked as
  illustrative pseudocode.
- **Verification:** `mypy core engine integrations packages` passes; scope normalization
  tests cover aliases, ranges, scalar targets, and unknown-field rejection.

## Subtask D-04: Resolve the Multi-Step Movement Contradiction
- **Action:** Clarified `specs/00-overview-and-scope.md`: unbounded or unauthorized lateral
  movement is out of scope, while bounded, explicitly authorized multi-step verification
  via `authorized_chain` is permitted. The post-hackathon roadmap now says "Unbounded
  Lateral Movement".
- **Verification:** The wording matches the Track 03 L-04 implementation and the
  `authorized_chain` policy tests.

## Subtask D-05: Fix the Timeline Inconsistency
- **Action:** Standardized the language: the hackathon submission window is 1–15 November
  2026 and the implementation sprint runs 4–15 November 2026.
- **Verification:** `docs/ARGUS_MVP_ARCHITECTURE_SPEC.md` and
  `specs/09-team-plan-and-milestones.md` use the same framing.

## Subtask D-06: Unify the Scope Schema Across Documents
- **Action:** Confirmed the contract already exposes `credentials_ref`,
  `max_duration_seconds`, `tool_timeouts`, port ranges (`"8000-8100"`), and chain
  authorization. No duplicate schema was introduced.
- **Verification:** `tests/unit/test_lab_agnostic_targets.py` and
  `tests/unit/test_track03_hardening.py`.

## Subtask D-07: Consolidate the 15-Test Lists
- **Action:** `specs/08-testing-evaluation-and-labs.md` is now explicitly authoritative.
  The master specification's section 15.2 mirrors its fifteen scenario names and links
  back to the matrix.
- **Verification:** Both documents now list the same 15 scenarios.

## Subtask D-08: Correct the Bifrost Spec and `.env.example`
- **Action:** Completed in Track 02 work: the client uses the verified OpenAI-compatible
  `/chat/completions` interface, removes invented per-request fallback headers from the
  contract, and documents gateway-level failover. `.env.example` matches the settings.
- **Verification:** `tests/integration/test_bifrost_client.py`, `tests/unit/test_config.py`.

# Track 05 — Reporting & Deliverables

**Priority:** P1 (Essential client-ready output for penetration testing assessment)  
**Status:** COMPLETED & VERIFIED (11/11 report tests in `tests/unit/test_report_generator.py`; full suite 178/178 passing)

---

## Subtask E-03: Markdown Executive Penetration Test Report Generator
- **Files:** `core/reporting/report_generator.py`, `core/reporting/__init__.py`, `engine/graph.py`, `engine/state.py`
- **Previous Behavior:** `report_node()` only set `status` and `chain_summary`. No report was generated.
- **Action Taken:**
  1. Implemented `ReportGenerator.generate_markdown_report(assessment_state, scope, evidence_vault)`.
  2. Added the professional report structure:
     - Executive Summary & Risk Posture
     - Assessment Scope & Authorization (including bounded chain authorization)
     - Methodology and executed actions
     - Discovered Attack Surface (assets, ports, services, versions)
     - Verified Findings table (severity, confidence, CVE, CVSS, verification method, evidence hash)
     - Detailed Finding Breakdowns (description, impact, reproduction, remediation, evidence)
     - Tavily external intelligence citations
     - Audit Trail & Telemetry (budget, blocked actions, chain, Bifrost telemetry)
     - Limitations & False Positives
     - Evidence Appendix
  3. Evidence integrity is re-checked through `EvidenceVault.verify_integrity()` on every
     report generation. Tampered or missing evidence is reported as `INTEGRITY FAILURE` or
     `MISSING`, never silently trusted.
  4. The full report is passed through `SecretRedactor` before it is written.
  5. `report_node()` now generates the Markdown report, writes it to
     `{evidence_vault}/{assessment_id}/report.md`, and returns `report_markdown` /
     `report_path` in state. Report failures never crash a completed assessment; a labelled
     fallback notice is emitted instead.
  6. `AssessmentState` now carries `simulation_mode`, `report_markdown`, `report_path`, and
     `telemetry`. `AssessmentOrchestrator.run()` stamps the simulation flag so a simulated
     run can never be reported as live (C-05).
- **Verification:** `test_report_includes_all_professional_sections`,
  `test_report_surfaces_tampered_evidence`, `test_report_labels_simulation_mode`,
  `test_partial_report_documents_limitations`, `test_report_redacts_secrets_in_reproduction_steps`,
  `test_negative_scan_is_not_reported_as_proof_of_absence`, and
  `test_report_node_writes_markdown_and_updates_state` all pass.

---

## Subtask E-05: PDF Report Deliverable Generation
- **Files:** `core/reporting/pdf_exporter.py`
- **Previous Behavior:** Not implemented.
- **Action Taken:**
  1. Added a dependency-free Markdown-to-PDF renderer. It produces a valid paginated
     PDF 1.4 document with a title, Helvetica typography, page numbers, and ASCII-safe
     text, so a judge can generate a deliverable from a clean checkout without WeasyPrint,
     wkhtmltopdf, or a browser toolchain.
  2. Added a styled, print-friendly HTML exporter with ARGUS branding for browser
     presentation or future dashboard embedding.
  3. Reproduction steps are emitted inside a code block and the whole report is redacted
     before export, so credentials and tokens never reach a deliverable.
- **Verification:** `test_html_report_is_styled_and_escaped` and
  `test_pdf_report_is_a_valid_paginated_document` pass.

---

## Verification Commands

```bash
.venv/bin/pytest -q tests/unit/test_report_generator.py tests/unit/test_demo_run.py
.venv/bin/pytest -q
.venv/bin/ruff check core/reporting engine/graph.py engine/state.py \
  scripts/demo_run.py tests/unit/test_report_generator.py tests/unit/test_demo_run.py
.venv/bin/mypy core engine integrations packages
```

**Expected results:** report/demo tests pass, full suite passes, ruff clean, mypy clean.

---

## Limitations

- The PDF renderer is intentionally text-first and dependency-free. Rich typography,
  embedded images, and clickable tables should use the HTML deliverable or a future
  WeasyPrint/Playwright export path.
- Bifrost telemetry is rendered when present in state. The current synchronous gateway
  wrapper discards per-call telemetry after validation; persisting it into state is a
  follow-up integration item.

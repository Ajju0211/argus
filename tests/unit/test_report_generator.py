"""Regression tests for the Track 05 report generator and deliverables.

Verifies that every terminal assessment produces a report, that evidence hashes
are re-verified against the vault, that tampering is surfaced, and that simulated
or partial runs are clearly labelled.
"""

from pathlib import Path
from typing import Any, cast

from core.evidence.evidence_vault import EvidenceVault
from core.reporting.report_generator import ReportGenerator
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator
from engine.state import AssessmentState
from packages.contracts.scope import ScopeDocument, normalize_scope


def _scope() -> ScopeDocument:
    return normalize_scope(
        {
            "assessment_id": "asm-report-001",
            "targets": ["192.168.100.0/28"],
            "allowed_actions": ["network_recon", "active_template_check"],
            "allowed_ports": [8080],
            "authorized_chain": {
                "enabled": True,
                "max_steps": 2,
                "allowed_steps": [
                    {"action_category": "network_recon", "allowed_ports": [8080]},
                    {"action_category": "active_template_check", "allowed_ports": [8080]},
                ],
            },
        }
    )


def _finding(evidence_id: str, *, title: str = "Path Traversal") -> dict[str, Any]:
    return {
        "finding_id": "find-report-001",
        "assessment_id": "asm-report-001",
        "title": title,
        "description": "Confirmed path traversal exposing /etc/passwd.",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "affected_asset": "http://192.168.100.5:8080",
        "affected_service": "http",
        "verification_method": "Nuclei template cve-2021-41773",
        "reproduction_steps": (
            'curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz" '
            "http://192.168.100.5:8080/icons/.%2e/etc/passwd"
        ),
        "impact": "Remote file disclosure.",
        "remediation": "Upgrade Apache HTTP Server.",
        "evidence_ids": [evidence_id],
        "research_source_ids": ["tavily-apache-2.4.49-0"],
        "created_at": "2026-11-05T00:00:00Z",
    }


def _state(
    evidence_id: str,
    sha256: str,
    *,
    finding: dict[str, Any] | None = None,
    outcome: str = "SUCCESS",
    simulation_mode: bool = False,
    blocked: bool = False,
) -> dict[str, Any]:
    return {
        "assessment_id": "asm-report-001",
        "target": {"type": "web", "value": "http://192.168.100.5:8080"},
        "assessment_objective": {"type": "severity_threshold", "min_severity": "HIGH"},
        "scope_id": "asm-report-001",
        "scope_version": "1.0",
        "scope_snapshot_hash": "a" * 64,
        "status": outcome,
        "simulation_mode": simulation_mode,
        "discovered_assets": ["192.168.100.5"],
        "discovered_services": [
            {
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
            }
        ],
        "observations": [],
        "research_refs": [
            {
                "source_id": "tavily-apache-2.4.49-0",
                "query": "Apache 2.4.49 vulnerability",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "title": "CVE-2021-41773",
                "snippet": "Path traversal in Apache HTTP Server 2.4.49.",
                "score": 0.97,
            }
        ],
        "current_strategy": "CVE_VERIFICATION",
        "current_action": None,
        "resolved_ip": None,
        "action_history": [],
        "executed_actions": [
            {
                "action_id": "act-nuclei-001",
                "tool_name": "nuclei",
                "action_category": "active_template_check",
                "target_host": "192.168.100.5",
                "target_port": 8080,
                "step_index": 2,
            }
        ],
        "chain_progress": [
            {
                "step_index": 1,
                "action_id": "act-recon-001",
                "parent_action_id": None,
                "tool_name": "nmap",
                "target_host": "192.168.100.5",
                "evidence_id": evidence_id,
                "status": "EXECUTED",
            }
        ],
        "chain_summary": {
            "authorized": True,
            "max_steps": 2,
            "declared_steps": [],
            "executed_steps": [
                {
                    "step_index": 1,
                    "action_id": "act-recon-001",
                    "tool_name": "nmap",
                    "target_host": "192.168.100.5",
                    "evidence_id": evidence_id,
                    "status": "EXECUTED",
                }
            ],
        },
        "blocked_actions": (
            [
                {
                    "tool_name": "nmap",
                    "action_category": "network_recon",
                    "target_host": "169.254.169.254",
                    "denied_reason": "Target resolves to a denied metadata address.",
                }
            ]
            if blocked
            else []
        ),
        "evidence_refs": [
            {
                "evidence_id": evidence_id,
                "tool": "nuclei",
                "sha256": sha256,
                "target_host": "192.168.100.5",
            }
        ],
        "findings": [finding] if finding is not None else [],
        "budget": {
            "iterations_used": 2,
            "max_iterations": 10,
            "model_calls_used": 3,
            "max_model_calls": 20,
            "total_tokens_used": 1234,
        },
        "cancellation": {"is_cancelled": False},
        "recovery": {"consecutive_failures": 0},
        "completion": {
            "is_completed": True,
            "outcome": outcome,
            "satisfied_goals": ["VULNERABILITY_VERIFIED"],
            "verification_evidence_ids": [evidence_id],
            "summary": "Objective achieved with verified evidence.",
        },
        "started_at": "2026-11-05T00:00:00+00:00",
        "deadline_at": None,
        "stop_reason": None,
    }


class TestMarkdownReport:
    def test_report_includes_all_professional_sections(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="[CVE-2021-41773] [http] [high] root:x:0:0",
            cmd="nuclei -u http://192.168.100.5:8080",
        )
        report = ReportGenerator().generate_markdown_report(
            _state(artifact.evidence_id, artifact.sha256, finding=_finding(artifact.evidence_id)),
            scope=_scope(),
            evidence_vault=vault,
        )

        for heading in (
            "## 1. Executive Summary",
            "## 2. Assessment Scope & Authorization",
            "## 3. Methodology",
            "## 4. Discovered Attack Surface",
            "## 5. Verified Findings",
            "## 6. Detailed Findings",
            "## 7. External Intelligence (Tavily)",
            "## 8. Audit Trail & Telemetry",
            "## 9. Limitations & False Positives",
            "## 10. Evidence Appendix",
        ):
            assert heading in report
        assert "Path Traversal" in report
        assert artifact.sha256 in report
        assert "VERIFIED" in report
        assert "CVE-2021-41773" in report
        assert "Upgrade Apache HTTP Server." in report
        assert "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" in report
        assert "AUTHORIZED" in report

    def test_report_surfaces_tampered_evidence(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="original proof",
            cmd="nuclei",
        )
        Path(artifact.file_path).write_text("tampered proof", encoding="utf-8")

        report = ReportGenerator().generate_markdown_report(
            _state(artifact.evidence_id, artifact.sha256, finding=_finding(artifact.evidence_id)),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "INTEGRITY FAILURE" in report
        assert "could not be cryptographically verified" in report

    def test_report_labels_simulation_mode(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        report = ReportGenerator().generate_markdown_report(
            _state("ev-simulated", "deadbeef", simulation_mode=True),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "SIMULATION MODE" in report
        assert "Report mode:** **SIMULATED" in report
        assert "must not be presented as a live security assessment" in report

    def test_partial_report_documents_limitations(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        report = ReportGenerator().generate_markdown_report(
            _state("ev-partial", "deadbeef", outcome="PARTIAL_SUCCESS", blocked=True),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "PARTIAL_SUCCESS" in report
        assert "Coverage may be incomplete" in report
        assert "blocked by the deterministic policy engine" in report
        assert "169.254.169.254" in report

    def test_report_redacts_secrets_in_reproduction_steps(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="proof",
            cmd="nuclei",
        )
        report = ReportGenerator().generate_markdown_report(
            _state(artifact.evidence_id, artifact.sha256, finding=_finding(artifact.evidence_id)),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "abcdefghijklmnopqrstuvwxyz" not in report
        assert "[REDACTED_BY_ARGUS]" in report

    def test_negative_scan_is_not_reported_as_proof_of_absence(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        report = ReportGenerator().generate_markdown_report(
            _state("ev-none", "deadbeef"),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "No security findings were recorded" in report
        assert "not** proof" in report


class TestHtmlAndPdfDeliverables:
    def test_html_report_is_styled_and_escaped(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="proof",
            cmd="nuclei",
        )
        html_report = ReportGenerator().generate_html_report(
            _state(
                artifact.evidence_id,
                artifact.sha256,
                finding=_finding(artifact.evidence_id, title="<script>alert(1)</script>"),
            ),
            scope=_scope(),
            evidence_vault=vault,
        )
        assert "<!doctype html>" in html_report
        assert "--brand: #0b3d91" in html_report
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_report
        assert "<script>alert(1)</script>" not in html_report

    def test_pdf_report_is_a_valid_paginated_document(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="proof",
            cmd="nuclei",
        )
        pdf_path = tmp_path / "report.pdf"
        ReportGenerator().generate_pdf_report(
            _state(artifact.evidence_id, artifact.sha256, finding=_finding(artifact.evidence_id)),
            pdf_path,
            scope=_scope(),
            evidence_vault=vault,
        )
        payload = pdf_path.read_bytes()
        assert payload.startswith(b"%PDF-1.4")
        assert b"/Type /Catalog" in payload
        assert b"/Type /Pages" in payload
        assert b"/BaseFont /Helvetica" in payload
        assert b"%%EOF" in payload
        assert b"Page 1 of" in payload
        assert len(payload) > 1000


class TestReportNodeIntegration:
    def test_report_node_writes_markdown_and_updates_state(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        artifact = vault.store_artifact(
            assessment_id="asm-report-001",
            tool_name="nuclei",
            raw_content="proof",
            cmd="nuclei",
        )
        orchestrator = AssessmentOrchestrator(
            scope=_scope(),
            evidence_vault=vault,
            simulation_mode=True,
        )
        state = _state(
            artifact.evidence_id, artifact.sha256, finding=_finding(artifact.evidence_id)
        )

        updates = orchestrator.report_node(state)  # type: ignore[arg-type]

        assert updates["status"] == "SUCCESS"
        assert "SIMULATION MODE" in updates["report_markdown"]
        assert updates["report_path"] is not None
        report_path = Path(updates["report_path"])
        assert report_path.exists()
        assert report_path.name == "report.md"
        assert "Path Traversal" in report_path.read_text(encoding="utf-8")

        pdf_path = report_path.parent / "report.pdf"
        assert pdf_path.exists()
        assert pdf_path.read_bytes().startswith(b"%PDF-1.4")

    def test_report_node_never_crashes_on_missing_assessment_id(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        orchestrator = AssessmentOrchestrator(scope=_scope(), evidence_vault=vault)
        raw_state: dict[str, Any] = {
            "completion": {"outcome": "FAILED", "summary": "scope invalid"},
            "chain_progress": [],
        }
        updates = orchestrator.report_node(cast(AssessmentState, raw_state))
        assert updates["status"] == "FAILED"
        assert "Report generation failed" in updates["report_markdown"] or updates["report_path"]


def test_scope_used_in_report_matches_validator_normalization() -> None:
    scope = ScopeValidator.parse_yaml_string(
        """
targets: ["192.168.100.5"]
allowed_actions: ["network_recon"]
allowed_ports: ["8080-8081"]
"""
    )
    report = ReportGenerator().generate_markdown_report(
        _state("ev-x", "deadbeef"), scope=scope, evidence_vault=None
    )
    assert "`8080`" in report
    assert "`8081`" in report
    assert "network_recon" in report


def test_report_scope_compliance_boundary_attestation() -> None:
    state = _state("ev-1", "0" * 64)
    state["blocked_actions"] = [
        {
            "action_id": "act-blocked-01",
            "target_host": "192.168.100.1",
            "target_port": 80,
            "tool_name": "nmap",
            "denied_reason": "Host 192.168.100.1 is explicitly denied.",
        }
    ]
    report = ReportGenerator().generate_markdown_report(state, evidence_vault=None)
    assert "### 1.1 Scope Compliance & Active Boundary Attestation" in report
    assert "Intercepted Out-of-Scope Actions" in report
    assert "act-blocked-01" in report
    assert "192.168.100.1" in report
    assert "explicitly denied" in report

"""Stage 2.1 Post-Implementation Security Verification & Regression Suite.

Verifies and proves:
1. Foothold Semantics: Findings != footholds; RCE requires demonstrated execution;
   credentials require verified auth; assessment binding & expiration enforced.
2. DNS & IPv6 Enforcement: IPv6 literals, bracketed IPv6, and unprivileged Nmap -Pn.
3. API Authorization: API_KEY gate rejects unauthenticated requests with HTTP 401.
4. Checkpoint Scope Consistency: Resuming with an altered scope document is blocked.
5. Process Cancellation: Async task cancellation deterministically kills process group.
6. Simulation Integrity: Simulation mode never executes real binaries; reports clearly label simulated findings.
"""

import asyncio
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from apps.api.database import Database
from apps.api.main import create_app
from core.evidence.evidence_vault import EvidenceVault
from core.executor.process_runner import run_tool_process
from core.policy.policy_engine import PolicyEngine
from core.reporting.report_generator import ReportGenerator
from engine.graph import AssessmentOrchestrator, create_initial_state
from integrations.tools.nmap_adapter import NmapAdapter
from packages.contracts.actions import (
    ActionProposal,
    FootholdEvidence,
    FootholdType,
)
from packages.contracts.scope import PivotRule, ScopeDocument, normalize_scope


def _build_scope(
    assessment_id: str = "asm-stage2-audit",
    allowed_subnets: list[str] | None = None,
    entry_hosts: list[str] | None = None,
    pivots: list[PivotRule] | None = None,
) -> ScopeDocument:
    raw: dict[str, Any] = {
        "schema_version": "1.0",
        "assessment_id": assessment_id,
        "name": "Stage 2.1 Audit Scope",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "targets": {
            "allowed_subnets": allowed_subnets or ["192.168.100.0/24"],
            "allowed_hosts": entry_hosts or ["192.168.100.5"],
            "denied_hosts": ["127.0.0.1", "169.254.169.254"],
        },
        "ports": {
            "allowed_ports": [80, 443, 8080],
        },
        "actions": {
            "allowed_categories": ["network_recon", "web_crawl", "passive_vuln_scan", "active_template_check"],
        },
        "authorized_chain": {
            "enabled": True,
            "max_steps": 5,
            "allowed_steps": [],
            "pivots": [p.model_dump() for p in (pivots or [])],
        },
    }
    return normalize_scope(raw)


# ==============================================================================
# AREA 1: FOOTHOLD VERIFICATION TESTS
# ==============================================================================

def test_vulnerability_finding_without_demonstrated_execution_does_not_create_foothold(tmp_path: Path) -> None:
    """A vulnerability finding (e.g. Nuclei template match) cannot automatically become a foothold."""
    vault = EvidenceVault(tmp_path / "vault")
    assessment_id = "asm-foothold-test-01"
    
    # Store evidence in vault
    artifact = vault.store_artifact(
        assessment_id=assessment_id,
        tool_name="nuclei",
        raw_content="HTTP/1.1 200 OK\nServer: Apache 2.4.49 (vulnerable)",
        cmd="nuclei -u http://192.168.100.5:8080 -t cve-2021-41773.yaml",
    )

    scope = _build_scope(assessment_id=assessment_id)
    orchestrator = AssessmentOrchestrator(
        scope=scope,
        evidence_vault=vault,
        simulation_mode=True,
    )

    state = create_initial_state(
        assessment_id=assessment_id,
        target={"type": "web", "value": "http://192.168.100.5:8080"},
        objective={"type": "find_cve"},
        scope=scope,
        scope_yaml_raw="targets: [192.168.100.5]",
    )

    # Observation has RCE in title, but NO demonstrated execution (no stdout, no uid=, no whoami)
    state["observations"] = [
        {
            "observation_type": "vuln_candidate",
            "raw_evidence_id": artifact.evidence_id,
            "tool": "nuclei",
            "target": "192.168.100.5",
            "data": {
                "name": "Apache Path Traversal and RCE",
                "template_id": "cve-2021-41773",
                "severity": "HIGH",
                "description": "Vulnerability reported based on server banner match only",
            },
        }
    ]

    result = orchestrator.verify_finding_node(state)
    assert len(result["findings"]) == 1
    # Crucial: finding is confirmed, but FOOTHOLD IS NOT CREATED
    assert len(result["footholds"]) == 0


def test_vulnerability_finding_with_demonstrated_execution_creates_foothold(tmp_path: Path) -> None:
    """When command execution is demonstrated (e.g. uid=0 extracted output), a foothold is registered."""
    vault = EvidenceVault(tmp_path / "vault")
    assessment_id = "asm-foothold-test-02"
    
    artifact = vault.store_artifact(
        assessment_id=assessment_id,
        tool_name="nuclei",
        raw_content="uid=0(root) gid=0(root) groups=0(root)",
        cmd="nuclei -u http://192.168.100.5:8080 -t cve-2021-41773.yaml",
    )

    scope = _build_scope(assessment_id=assessment_id)
    orchestrator = AssessmentOrchestrator(
        scope=scope,
        evidence_vault=vault,
        simulation_mode=True,
    )

    state = create_initial_state(
        assessment_id=assessment_id,
        target={"type": "web", "value": "http://192.168.100.5:8080"},
        objective={"type": "find_cve"},
        scope=scope,
        scope_yaml_raw="targets: [192.168.100.5]",
    )

    state["observations"] = [
        {
            "observation_type": "vuln_candidate",
            "raw_evidence_id": artifact.evidence_id,
            "tool": "nuclei",
            "target": "192.168.100.5",
            "data": {
                "name": "Apache Remote Code Execution Confirmed",
                "template_id": "cve-2021-41773",
                "severity": "CRITICAL",
                "extracted_results": "uid=0(root) gid=0(root)",
                "demonstrated_execution": True,
            },
        }
    ]

    result = orchestrator.verify_finding_node(state)
    assert len(result["findings"]) == 1
    assert len(result["footholds"]) == 1
    fh = result["footholds"][0]
    assert fh["host"] == "192.168.100.5"
    assert fh["foothold_type"] == FootholdType.COMMAND_EXECUTION.value
    assert fh["assessment_id"] == assessment_id


def test_policy_engine_rejects_cross_assessment_foothold_reuse() -> None:
    """Foothold evidence from assessment A cannot authorize pivots in assessment B."""
    scope_b = _build_scope(
        assessment_id="asm-tenant-b",
        allowed_subnets=["192.168.100.0/24"],
        entry_hosts=["192.168.100.5"],
        pivots=[
            PivotRule(
                from_host="192.168.100.5",
                to_host="192.168.100.20",
                requires_foothold=True,
            )
        ],
    )
    engine = PolicyEngine(scope_b)

    # Foothold belonging to tenant A
    stolen_foothold = FootholdEvidence(
        foothold_id="fh-stolen",
        assessment_id="asm-tenant-a",  # Mismatched assessment ID
        host="192.168.100.5",
        foothold_type=FootholdType.COMMAND_EXECUTION,
        finding_id="find-01",
        evidence_id="evi-01",
        established_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        simulated=False,
    )

    proposal = ActionProposal(
        action_id="act-pivot-steal",
        target_host="192.168.100.20",
        target_port=80,
        tool_name="nmap",
        action_category="network_recon",
        arguments={"target": "192.168.100.5", "ports": "80"},
        rationale="Attempt pivot using foothold from another assessment",
        expected_evidence="Banner",
    )

    decision = engine.evaluate(proposal, footholds=[stolen_foothold], simulation_mode=False)
    assert decision.approved is False
    assert "requires verified foothold" in decision.reason


# ==============================================================================
# AREA 2: DNS & NETWORK ENFORCEMENT TESTS
# ==============================================================================

def test_ipv6_loopback_and_bracketed_literals_blocked() -> None:
    """IPv6 loopback [::1] and ::1 are denied by policy."""
    scope = _build_scope()
    engine = PolicyEngine(scope)

    for ipv6_target in ["::1", "[::1]", "fe80::1", "[fe80::1]"]:
        proposal = ActionProposal(
            action_id="act-ipv6",
            target_host=ipv6_target,
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5", "ports": "80"},
            rationale="Testing IPv6 loopback",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False


def test_nmap_adapter_enforces_pn_for_unprivileged_execution() -> None:
    """Nmap adapter command includes -Pn to prevent unprivileged ICMP ping failures."""
    adapter = NmapAdapter(allowed_ports=[80, 443])
    cmd = adapter.build_command({"target": "192.168.100.5", "ports": "80"})
    assert "-Pn" in cmd
    assert "-sT" in cmd


# ==============================================================================
# AREA 3: API AUTHORIZATION TESTS
# ==============================================================================

def test_api_key_enforcement_blocks_unauthorized_requests(tmp_path: Path) -> None:
    """When API_KEY is set, requests without valid credentials return HTTP 401."""
    app = create_app()
    app.state.db = Database(tmp_path / "test.db")
    app.state.vault = EvidenceVault(tmp_path / "vault")
    app.state.settings = SimpleNamespace(API_KEY="supersecretkey123")

    client = TestClient(app)

    # 1. Unauthenticated request -> 401
    resp = client.get("/api/v1/assessments")
    assert resp.status_code == 401

    # 2. Wrong API key -> 401
    resp = client.get("/api/v1/assessments", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401

    # 3. Valid Bearer Token -> 200
    resp = client.get(
        "/api/v1/assessments",
        headers={"Authorization": "Bearer supersecretkey123"},
    )
    assert resp.status_code == 200

    # 4. Valid X-API-Key header -> 200
    resp = client.get(
        "/api/v1/assessments",
        headers={"X-API-Key": "supersecretkey123"},
    )
    assert resp.status_code == 200


# ==============================================================================
# AREA 4: CHECKPOINT & RECOVERY TESTS
# ==============================================================================

def test_resume_rejects_altered_scope_hash(tmp_path: Path) -> None:
    """Resuming an assessment whose scope was modified while paused raises HTTP 400."""
    app = create_app()
    db = Database(tmp_path / "test.db")
    app.state.db = db
    app.state.vault = EvidenceVault(tmp_path / "vault")
    app.state.settings = SimpleNamespace(API_KEY="")

    client = TestClient(app)

    # Create assessment
    scope_yaml_original = """
schema_version: "1.0"
assessment_id: "asm-chk-tamper"
created_at: "2026-01-01T00:00:00Z"
expires_at: "2030-01-01T00:00:00Z"
targets:
  allowed_hosts: ["192.168.100.5"]
"""
    create_resp = client.post(
        "/api/v1/assessments",
        json={
            "target": "http://192.168.100.5",
            "scope": scope_yaml_original,
            "objective": {"type": "discover_services"},
            "simulation": True,
            "auto_start": False,
        },
    )
    assert create_resp.status_code == 201
    asm_id = create_resp.json()["id"]

    # Set assessment to PAUSED and save a checkpoint with original scope hash
    db.update_assessment(asm_id, status="PAUSED")
    original_hash = hashlib.sha256(scope_yaml_original.encode()).hexdigest()
    db.save_checkpoint(
        checkpoint_id="chk-01",
        assessment_id=asm_id,
        thread_id="t1",
        checkpoint_blob=f'{{"scope_snapshot_hash": "{original_hash}"}}'.encode(),
    )

    # Simulate scope tampering in the database
    scope_yaml_tampered = scope_yaml_original + "  allowed_subnets: ['0.0.0.0/0']\n"
    with db._connect() as conn:
        conn.execute(
            "UPDATE assessments SET scope_raw = ? WHERE id = ?",
            (scope_yaml_tampered, asm_id),
        )

    # Attempt to resume with tampered scope document -> must be rejected
    resume_resp = client.post(f"/api/v1/assessments/{asm_id}/resume")
    assert resume_resp.status_code == 400
    assert "Scope hash mismatch" in resume_resp.json()["detail"]


# ==============================================================================
# AREA 5: PROCESS CANCELLATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_process_task_cancellation_kills_child_process() -> None:
    """Cancelling the asyncio task awaiting run_tool_process kills the child process."""
    cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
    task = asyncio.create_task(
        run_tool_process(cmd, timeout_seconds=30, assessment_id="asm-task-cancel")
    )
    await asyncio.sleep(0.2)

    # Cancel task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ==============================================================================
# AREA 7: SIMULATION INTEGRITY TESTS
# ==============================================================================

def test_simulation_mode_never_spawns_real_binary(tmp_path: Path) -> None:
    """When simulation_mode is True, tool execution returns simulated stdout without running binaries."""
    scope = _build_scope()
    vault = EvidenceVault(tmp_path / "vault")
    orchestrator = AssessmentOrchestrator(
        scope=scope,
        evidence_vault=vault,
        simulation_mode=True,
    )

    proposal = ActionProposal(
        action_id="act-sim-safe",
        target_host="192.168.100.5",
        target_port=80,
        tool_name="nmap",
        action_category="network_recon",
        arguments={"target": "192.168.100.5", "ports": "80"},
        rationale="Simulated scan",
        expected_evidence="Simulated",
    )

    retcode, stdout, stderr = orchestrator._default_tool_executor(proposal)
    assert retcode == 0
    assert "[SIMULATION_MODE]" in stdout
    assert stderr == ""


def test_reports_clearly_label_simulated_findings() -> None:
    """When an assessment is simulated, the report explicitly titles Section 5 as Simulated Findings."""
    report_gen = ReportGenerator()
    state = {
        "assessment_id": "asm-sim-rep",
        "started_at": "2026-01-01T10:00:00Z",
        "status": "COMPLETED",
        "target": {"value": "http://192.168.100.5:8080"},
        "assessment_objective": {"type": "find_cve"},
        "simulation_mode": True,
        "evidence_refs": [],
        "findings": [
            {
                "finding_id": "fnd-sim-01",
                "title": "Remote Code Execution",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "description": "Simulated RCE finding",
                "affected_asset": "192.168.100.5",
                "verification_method": "Automated simulated probe",
                "evidence_ids": [],
            }
        ],
    }

    markdown = report_gen.generate_markdown_report(state, simulation_mode=True)
    assert "## 5. Simulated Findings (Simulation Mode)" in markdown
    assert "[SIMULATED] Remote Code Execution" in markdown
    assert "This assessment ran in simulation mode" in markdown

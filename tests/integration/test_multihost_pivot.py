"""End-to-End Integration Test for Multi-Host Lateral Pivot & Foothold Enforcement (SEC-01, SEC-06).

Verifies the complete multi-host pivot lifecycle:
1. Entry host 192.168.100.5 is authorized for initial targeting.
2. Targeting internal host 192.168.100.10 fails closed when no foothold exists.
3. Establishing and verifying a foothold on 192.168.100.5 unlocks authorized pivot to 192.168.100.10.
4. Out-of-scope/unauthorized attempts (e.g. gateway 192.168.100.1) are blocked and attested in the Merkle audit ledger.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.evidence.evidence_vault import EvidenceVault
from core.evidence.ledger import AssessmentLedger
from core.policy.policy_engine import PolicyEngine
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, create_initial_state
from packages.contracts.actions import (
    ActionProposal,
    FootholdEvidence,
    FootholdType,
)
from packages.contracts.scope import PivotRule, ScopeDocument

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def pivot_scope() -> ScopeDocument:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    base_scope = ScopeValidator.parse_yaml_file(yaml_path)

    # Configure pivot rule: from 192.168.100.5 -> 192.168.100.10
    pivot = PivotRule(
        from_host="192.168.100.5",
        to_host="192.168.100.10",
        requires_foothold=True,
        allowed_categories=["network_recon", "web_crawl"],
        allowed_ports=[80, 443, 8080],
    )

    return base_scope.model_copy(
        update={
            "authorized_chain": base_scope.authorized_chain.model_copy(
                update={"enabled": True, "pivots": [pivot]}
            )
        }
    )


class TestMultiHostPivotIntegration:
    """Integration test suite for multi-host pivot gating and ledger audit."""

    def test_direct_internal_target_fails_closed_without_foothold(
        self, pivot_scope: ScopeDocument
    ) -> None:
        """Targeting internal host 192.168.100.10 without a foothold is denied."""
        engine = PolicyEngine(pivot_scope)

        proposal = ActionProposal(
            action_id="act-pivot-fail",
            target_host="192.168.100.10",
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"ports": "80"},
            rationale="Attempting unauthenticated pivot scan",
            expected_evidence="Port state",
        )

        decision = engine.evaluate(proposal, footholds=[], simulation_mode=False)
        assert decision.approved is False
        assert "requires verified foothold on '192.168.100.5'" in decision.reason

    def test_foothold_unlocks_internal_pivot(self, pivot_scope: ScopeDocument) -> None:
        """Acquiring a valid foothold on 192.168.100.5 authorizes pivot targeting 192.168.100.10."""
        engine = PolicyEngine(pivot_scope)

        # 1. Proposal against entry host succeeds
        entry_proposal = ActionProposal(
            action_id="act-entry-01",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"ports": "8080"},
            rationale="Initial scanning on perimeter entry host",
            expected_evidence="Service banner",
        )
        assert engine.evaluate(entry_proposal).approved is True

        # 2. Foothold on entry host is established
        foothold = FootholdEvidence(
            foothold_id="fh-entry-01",
            assessment_id=pivot_scope.assessment_id,
            host="192.168.100.5",
            foothold_type=FootholdType.COMMAND_EXECUTION,
            finding_id="find-rce-001",
            evidence_id="ev-rce-proof-01",
            established_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            simulated=False,
        )

        # 3. Pivot proposal against internal host is now authorized
        pivot_proposal = ActionProposal(
            action_id="act-pivot-ok",
            target_host="192.168.100.10",
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"ports": "80"},
            rationale="Scanning internal target via authorized pivot",
            expected_evidence="Service banner",
        )
        decision = engine.evaluate(pivot_proposal, footholds=[foothold], simulation_mode=False)
        assert decision.approved is True
        assert decision.resolved_ip == "192.168.100.10"

    def test_denied_target_recorded_in_merkle_audit_ledger(
        self, pivot_scope: ScopeDocument, tmp_path: Path
    ) -> None:
        """Actions blocked by policy (e.g. gateway 192.168.100.1) are appended to Merkle ledger."""
        vault = EvidenceVault(tmp_path / "vault")
        ledger_dir = tmp_path / "vault" / pivot_scope.assessment_id
        ledger_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = ledger_dir / "ledger.jsonl"

        orchestrator = AssessmentOrchestrator(
            scope=pivot_scope,
            evidence_vault=vault,
            simulation_mode=True,
        )

        # Create state with an action attempting to scan denied gateway 192.168.100.1
        state = create_initial_state(
            assessment_id=pivot_scope.assessment_id,
            target={"type": "network", "value": "192.168.100.5"},
            objective={"find_cve": True},
            scope=pivot_scope,
            scope_yaml_raw="",
        )

        blocked_proposal = ActionProposal(
            action_id="act-gateway-probe",
            target_host="192.168.100.1",
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"ports": "80"},
            rationale="Unauthorized probe of network gateway",
            expected_evidence="None",
        )
        state["current_action"] = blocked_proposal.model_dump()

        # Run policy gate node
        res = orchestrator.policy_gate_node(state)
        assert res["current_action"] is None
        assert len(res["blocked_actions"]) == 1
        assert "explicitly denied" in res["blocked_actions"][0]["denied_reason"]

        # Verify record in Merkle ledger
        ledger = AssessmentLedger(ledger_path, assessment_id=pivot_scope.assessment_id)
        records = ledger.records()
        assert len(records) >= 1
        denial_record = records[-1]
        assert denial_record["tier"] == "T1_POLICY"
        assert denial_record["event"] == "policy_denial"
        assert denial_record["target_host"] == "192.168.100.1"
        assert denial_record["action_id"] == "act-gateway-probe"
        assert "explicitly denied" in denial_record["denial_reason"]

        # Verify Merkle integrity of the ledger
        valid, _msg = ledger.verify_ledger_integrity()
        assert valid is True

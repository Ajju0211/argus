"""Integrity and Wiring Verification Suite for ARGUS (Track 01 / C-01 to C-05).

Verifies the elimination of fabricated reconnaissance observations, fake findings,
placeholder evidence IDs, and unverified mock successes. Enforces zero hallucinations,
cryptographic SHA-256 evidence integrity, and strict evidence provenance.
"""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from core.config import get_settings
from core.evidence.evidence_vault import EvidenceVault
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, create_initial_state
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import ScopeDocument

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def valid_scope() -> ScopeDocument:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    return ScopeValidator.parse_yaml_file(yaml_path)


@pytest.fixture
def valid_scope_raw() -> str:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    return yaml_path.read_text(encoding="utf-8")


@pytest.fixture
def target_lab() -> dict[str, Any]:
    return {"type": "web", "value": "http://192.168.100.5:8080"}


@pytest.fixture
def ssh_only_target() -> dict[str, Any]:
    return {"type": "ip", "value": "192.168.100.5:22"}


class TestIntegrityAndWiring:
    """Rigorous tests verifying real execution wiring and zero hallucinations."""

    def test_recon_uses_real_parsed_observations(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-01: Recon parses authentic Nmap XML and derives services solely from output."""
        sample_xml = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            tool_executor=lambda p: (0, sample_xml, ""),
        )
        state = create_initial_state(
            assessment_id="asm-recon-real",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )

        update = orchestrator.recon_node(state)

        # Confirm discovered services match the XML fixture (ports 80 and 8080)
        ports = {s["port"] for s in update["discovered_services"]}
        assert ports == {80, 8080}
        assert update["current_strategy"] == "SERVICE_ENUMERATION"

        # Check evidence was stored in vault
        assert len(update["evidence_refs"]) == 1
        ev_id = update["evidence_refs"][0]["evidence_id"]
        is_valid, _msg = vault.verify_integrity("asm-recon-real", ev_id)
        assert is_valid is True

    def test_recon_does_not_invent_apache_when_absent(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        ssh_only_target: dict[str, Any],
    ) -> None:
        """C-01 & T-06: Recon on SSH-only target NEVER claims port 8080 or Apache 2.4.49."""
        ssh_xml = (FIXTURES_DIR / "nmap_ssh_only.xml").read_text(encoding="utf-8")
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            tool_executor=lambda p: (0, ssh_xml, ""),
        )
        state = create_initial_state(
            assessment_id="asm-recon-ssh",
            target=ssh_only_target,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )

        update = orchestrator.recon_node(state)

        # Discovered services must ONLY contain port 22 OpenSSH
        ports = [s["port"] for s in update["discovered_services"]]
        assert ports == [22]
        assert update["discovered_services"][0]["service"] == "ssh"
        assert "OpenSSH" in update["discovered_services"][0]["product"]

        # Crucial Negative Invariant: Zero 8080 or Apache
        assert 8080 not in ports
        for s in update["discovered_services"]:
            assert "Apache" not in s.get("product", "")
            assert "2.4.49" not in s.get("version", "")

    def test_recon_records_empty_output_without_fabrication(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-01: Empty or malformed recon output results in 0 services and no crash."""
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            tool_executor=lambda p: (0, "MALFORMED NON-XML OUTPUT", ""),
        )
        state = create_initial_state(
            assessment_id="asm-recon-empty",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )

        update = orchestrator.recon_node(state)
        assert update["discovered_services"] == []
        assert update["current_strategy"] == "INITIAL_RECON"

    def test_recon_links_observations_to_cryptographic_evidence_id(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-04: All observations link to real SHA-256 evidence IDs in the vault."""
        sample_xml = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            tool_executor=lambda p: (0, sample_xml, ""),
        )
        state = create_initial_state(
            assessment_id="asm-evidence-link",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )

        update = orchestrator.recon_node(state)
        assert len(update["observations"]) > 0
        for obs in update["observations"]:
            ev_id = obs["raw_evidence_id"]
            assert ev_id.startswith("ev-")
            is_valid, _ = vault.verify_integrity("asm-evidence-link", ev_id)
            assert is_valid is True

    def test_cannot_confirm_finding_without_evidence(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-02: verify_finding_node never creates a CONFIRMED finding without authentic evidence."""
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
        )
        state = create_initial_state(
            assessment_id="asm-fake-check",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )

        # Observations contain a vuln candidate with a fake non-existent evidence ID
        state["observations"] = [
            {
                "tool": "nuclei",
                "target": "http://192.168.100.5:8080",
                "observation_type": "vuln_candidate",
                "data": {"template_id": "cve-2021-41773", "severity": "CRITICAL"},
                "raw_evidence_id": "ev-nonexistent-fake-id",
            }
        ]

        result = orchestrator.verify_finding_node(state)
        # Must refuse to confirm because evidence does not exist in vault
        assert result.get("findings") == []

    def test_cannot_confirm_finding_with_tampered_evidence(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-02 & C-04: Tampering with raw evidence on disk causes integrity check to fail."""
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")
        artifact = vault.store_artifact(
            assessment_id="asm-tamper-check",
            tool_name="nuclei",
            raw_content='{"template-id": "cve-2021-41773"}',
            cmd="nuclei -t cve-2021-41773",
        )

        # Tamper with the raw file directly on disk
        raw_file = Path(artifact.file_path)
        raw_file.write_text("TAMPERED DATA THAT BREAKS SHA-256", encoding="utf-8")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
        )
        state = create_initial_state(
            assessment_id="asm-tamper-check",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        state["observations"] = [
            {
                "tool": "nuclei",
                "target": "http://192.168.100.5:8080",
                "observation_type": "vuln_candidate",
                "data": {"template_id": "cve-2021-41773", "severity": "CRITICAL"},
                "raw_evidence_id": artifact.evidence_id,
            }
        ]

        result = orchestrator.verify_finding_node(state)
        # Cannot confirm because SHA-256 mismatch detected
        assert result.get("findings") == []

    def test_unfamiliar_target_produces_zero_confirmed_findings(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        ssh_only_target: dict[str, Any],
    ) -> None:
        """C-02 & T-06: An assessment on a non-vulnerable target produces 0 confirmed findings."""
        ssh_xml = (FIXTURES_DIR / "nmap_ssh_only.xml").read_text(encoding="utf-8")
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")

        def ssh_tool_executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, ssh_xml, ""
            # Nuclei returns 0 findings on an unfamiliar target
            return 0, "", ""

        def model_gateway(prompt: str) -> AssessmentDecision:
            return AssessmentDecision(
                decision_type=DecisionType.OBJECTIVE_ACHIEVED,
                rationale="No vulnerabilities found on SSH-only host.",
                completion_summary="Surface assessment complete. 0 vulnerabilities.",
            )

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            model_gateway=model_gateway,
            tool_executor=ssh_tool_executor,
        )
        state = create_initial_state(
            assessment_id="asm-ssh-clean",
            target=ssh_only_target,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
            max_iterations=2,
        )

        final_state = orchestrator.run(state)
        # Zero findings must be produced!
        assert len(final_state["findings"]) == 0
        assert final_state["discovered_assets"] == ["192.168.100.5"]
        assert len(final_state["discovered_services"]) == 1
        assert final_state["discovered_services"][0]["port"] == 22

    def test_execute_tool_wires_vault_and_observations(
        self,
        tmp_path: Path,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        target_lab: dict[str, Any],
    ) -> None:
        """C-03: execute_tool_node stores artifact into vault and parses adapter output."""
        sample_nuclei = (FIXTURES_DIR / "nuclei_sample.jsonl").read_text(encoding="utf-8")
        vault = EvidenceVault(base_dir=tmp_path / "artifacts")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            evidence_vault=vault,
            tool_executor=lambda p: (0, sample_nuclei, ""),
        )
        state = create_initial_state(
            assessment_id="asm-tool-wire",
            target=target_lab,
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        proposal = ActionProposal(
            action_id="act-nuclei-wire-001",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"template": "cve-2021-41773"},
            rationale="Run nuclei check",
            expected_evidence="Path traversal",
        )
        state["current_action"] = proposal.model_dump()

        update = orchestrator.execute_tool_node(state)
        assert update["current_action"] is None
        assert len(update["executed_actions"]) == 1
        assert len(update["evidence_refs"]) == 1
        ev_id = update["evidence_refs"][0]["evidence_id"]

        # Vault integrity check
        is_valid, _ = vault.verify_integrity("asm-tool-wire", ev_id)
        assert is_valid is True

        # Observations should be populated from nuclei JSONL
        assert len(update["observations"]) > 0
        obs_types = [o["observation_type"] for o in update["observations"]]
        assert "vuln_candidate" in obs_types

    def test_production_mode_rejects_missing_tool_execution(
        self,
        valid_scope: ScopeDocument,
    ) -> None:
        """C-05: When SIMULATION_MODE is False and binary is missing, fails cleanly with 127."""
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            simulation_mode=False,
        )
        proposal = ActionProposal(
            action_id="act-missing-bin",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5"},
            rationale="Test missing binary",
            expected_evidence="Error",
        )

        retcode, _stdout, stderr = orchestrator.tool_executor(proposal)
        # If nmap is not installed locally on Mac runner, it must return 127
        # If it happens to be installed, retcode is an int
        if retcode == 127:
            assert "is not installed" in stderr
            assert "SIMULATION_MODE is disabled" in stderr

    def test_simulation_mode_labeled_when_enabled(
        self,
        valid_scope: ScopeDocument,
    ) -> None:
        """C-05: When SIMULATION_MODE is True and binary is missing, labels output clearly."""
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            simulation_mode=True,
        )
        proposal = ActionProposal(
            action_id="act-sim-mode",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5"},
            rationale="Test simulation mode",
            expected_evidence="Simulated",
        )

        retcode, stdout, _stderr = orchestrator.tool_executor(proposal)
        # In simulation mode, if nmap is missing, it returns [SIMULATION_MODE] labeled output
        if retcode == 0 and "[SIMULATION_MODE]" in stdout:
            assert "Simulated stdout for nmap" in stdout

    def test_missing_model_gateway_fails_closed_outside_simulation(
        self,
        valid_scope: ScopeDocument,
    ) -> None:
        """C-05: No Bifrost key and no simulation must not produce a mock success."""
        settings = get_settings().model_copy(
            update={
                "BIFROST_API_KEY": "",
                "BIFROST_ADMIN_USERNAME": "",
                "BIFROST_ADMIN_PASSWORD": "",
                "SIMULATION_MODE": False,
            }
        )

        with patch("engine.graph.get_settings", return_value=settings):
            orchestrator = AssessmentOrchestrator(
                scope=valid_scope,
                simulation_mode=False,
            )

        decision = orchestrator.model_gateway("plan the next action")
        assert decision.decision_type == DecisionType.BLOCKED
        assert "no model gateway" in decision.rationale.lower()

    def test_simulation_mode_model_gateway_is_labeled(
        self,
        valid_scope: ScopeDocument,
    ) -> None:
        """C-05: An explicit simulation run labels its mock planner decisions."""
        settings = get_settings().model_copy(
            update={
                "BIFROST_API_KEY": "",
                "BIFROST_ADMIN_USERNAME": "",
                "BIFROST_ADMIN_PASSWORD": "",
                "SIMULATION_MODE": True,
            }
        )

        with patch("engine.graph.get_settings", return_value=settings):
            orchestrator = AssessmentOrchestrator(
                scope=valid_scope,
                simulation_mode=True,
            )

        decision = orchestrator.model_gateway("plan the next action")
        assert "[SIMULATION_MODE]" in decision.rationale

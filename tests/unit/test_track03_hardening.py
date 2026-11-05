"""Regression tests for the Track 03 gaps found during the post-completion audit.

Covers flexible scope normalization, exact/verified flag goals, bounded multi-step
authorization, chain-aware duplicate detection, and target-safe evidence chaining.
"""

from typing import Any, cast

import pytest

from core.evidence.evidence_vault import EvidenceVault
from core.policy.policy_engine import PolicyEngine
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, extract_target_spec
from engine.nodes.evaluate_completion import evaluate_completion
from engine.state import AssessmentState
from packages.contracts.actions import ActionProposal, DecisionType
from packages.contracts.scope import normalize_scope


def _completion(
    objective: dict[str, Any],
    *,
    observations: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    chain_progress: list[dict[str, Any]] | None = None,
    verified_evidence_ids: set[str] | None = None,
) -> dict[str, Any]:
    return evaluate_completion(
        objective=objective,
        findings=findings or [],
        discovered_assets=["192.168.100.5"],
        discovered_services=[{"port": 8080, "service": "http"}],
        budget={"iterations_used": 1, "max_iterations": 10},
        cancellation={"is_cancelled": False},
        recovery={"consecutive_failures": 0},
        observations=observations,
        chain_progress=chain_progress,
        verified_evidence_ids=verified_evidence_ids,
    )


def _chain_scope_raw() -> dict[str, Any]:
    return {
        "targets": ["192.168.100.5", "192.168.100.0/28"],
        "allowed_actions": ["network_recon", "active_template_check"],
        "allowed_ports": [8080],
        "authorized_chain": {
            "enabled": True,
            "max_steps": 2,
            "allowed_steps": [
                {
                    "action_category": "network_recon",
                    "allowed_hosts": ["192.168.100.5"],
                    "allowed_ports": [8080],
                },
                {
                    "action_category": "active_template_check",
                    "allowed_hosts": ["192.168.100.5"],
                    "allowed_ports": [8080],
                },
            ],
        },
    }


def _chain_step_proposal(
    *, step_index: int, action_category: str, target_host: str = "192.168.100.5"
) -> ActionProposal:
    return ActionProposal(
        action_id=f"act-chain-{step_index}",
        parent_action_id="act-chain-1" if step_index > 1 else None,
        step_index=step_index,
        target_host=target_host,
        target_port=8080,
        tool_name="nmap" if action_category == "network_recon" else "nuclei",
        action_category=action_category,
        arguments=(
            {"ports": "8080"}
            if action_category == "network_recon"
            else {"target": f"http://{target_host}:8080"}
        ),
        rationale="Bounded chain step",
        expected_evidence="Per-step evidence",
    )


class TestTargetExtractionEdgeCases:
    def test_extract_scheme_less_ipv6_with_port_and_path(self) -> None:
        spec = extract_target_spec("[2001:db8::1]:9090/metrics")
        assert spec["host"] == "2001:db8::1"
        assert spec["port"] == 9090
        assert spec["path"] == "/metrics"

    def test_extract_scheme_less_host_with_path(self) -> None:
        spec = extract_target_spec("demo.lab.internal/app")
        assert spec["host"] == "demo.lab.internal"
        assert spec["path"] == "/app"
        assert spec["port"] is None


class TestScopeNormalizationHardening:
    def test_scalar_target_string_is_normalized(self) -> None:
        scope = normalize_scope({"targets": "http://lab-target.local:8080"})
        assert scope.targets.allowed_hosts == ["lab-target.local"]
        assert scope.ports.allowed_ports == [8080]
        assert scope.actions.allowed_categories == ["network_recon"]

    def test_top_level_target_aliases_are_normalized(self) -> None:
        scope = normalize_scope(
            {
                "allowed_hosts": ["lab-target.local"],
                "allowed_subnets": ["192.168.100.0/28"],
                "allowed_ports": [8080],
            }
        )
        assert scope.targets.allowed_hosts == ["lab-target.local"]
        assert scope.targets.allowed_subnets == ["192.168.100.0/28"]
        assert scope.ports.allowed_ports == [8080]

    def test_harmless_extra_metadata_is_accepted(self) -> None:
        scope = normalize_scope(
            {
                "targets": ["http://lab-target.local:8080"],
                "environment": "judge-lab",
                "metadata": {"harness": "geek-room"},
            }
        )
        assert scope.targets.allowed_hosts == ["lab-target.local"]

    def test_unknown_security_field_fails_clearly(self) -> None:
        with pytest.raises(ValueError, match="Unsupported scope field"):
            normalize_scope(
                {
                    "targets": ["http://lab-target.local:8080"],
                    "silently_allow_everything": True,
                }
            )

    def test_invalid_comma_port_token_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid port specification"):
            normalize_scope(
                {
                    "targets": ["http://lab-target.local:8080"],
                    "ports": {"allowed_ports": "80,abc,443"},
                }
            )

    def test_parse_yaml_string_normalizes_aliases(self) -> None:
        yaml_content = """
targets:
  allowed_hosts: ["lab-target.local"]
allowed_actions: ["network_recon"]
allowed_ports: ["8000-8002"]
"""
        scope = ScopeValidator.parse_yaml_string(yaml_content)
        assert scope.actions.allowed_categories == ["network_recon"]
        assert scope.ports.allowed_ports == [8000, 8001, 8002]

    def test_parse_yaml_string_accepts_harmless_metadata(self) -> None:
        yaml_content = """
targets: ["http://lab-target.local:8080"]
environment: judge-lab
description: "Judge supplied lab scope"
"""
        scope = ScopeValidator.parse_yaml_string(yaml_content)
        assert scope.targets.allowed_hosts == ["lab-target.local"]


class TestFlagObjectiveHardening:
    def test_flag_goal_does_not_treat_descriptive_text_as_capture(self) -> None:
        observations = [
            {
                "raw_evidence_id": "ev-flag-text",
                "data": {"description": "no flag present on this page"},
            },
            {
                "raw_evidence_id": "ev-flag-header",
                "data": {"name": "flags_header"},
            },
        ]
        evaluation = _completion(
            {"type": "flag"},
            observations=observations,
            verified_evidence_ids={"ev-flag-text", "ev-flag-header"},
        )
        assert evaluation["is_completed"] is False
        assert evaluation["outcome"] == "IN_PROGRESS"

    def test_flag_goal_requires_a_matching_flag_pattern(self) -> None:
        observations = [
            {
                "raw_evidence_id": "ev-flag-real",
                "data": {"extracted_results": ["FLAG{argus_2026}"]},
            }
        ]
        evaluation = _completion(
            {"type": "flag"},
            observations=observations,
            verified_evidence_ids={"ev-flag-real"},
        )
        assert evaluation["is_completed"] is True
        assert evaluation["verification_evidence_ids"] == ["ev-flag-real"]

    def test_flag_goal_requires_verified_evidence(self) -> None:
        observations = [
            {
                "raw_evidence_id": "ev-not-in-vault",
                "data": {"extracted_results": ["FLAG{argus_2026}"]},
            }
        ]
        unverified = _completion(
            {"type": "flag"},
            observations=observations,
            verified_evidence_ids={"some-other-id"},
        )
        assert unverified["is_completed"] is False

        missing = _completion({"type": "flag"}, observations=observations)
        assert missing["is_completed"] is False


class TestMultiStepAuthorization:
    def test_fingerprint_distinguishes_chain_steps(self) -> None:
        first = _chain_step_proposal(step_index=1, action_category="network_recon")
        second = _chain_step_proposal(step_index=2, action_category="network_recon")
        assert first.fingerprint() != second.fingerprint()

    def test_chain_step_requires_explicit_scope_authorization(self) -> None:
        scope = normalize_scope(
            {
                "targets": ["192.168.100.5", "192.168.100.0/28"],
                "allowed_actions": ["network_recon"],
                "allowed_ports": [8080],
            }
        )
        decision = PolicyEngine(scope).evaluate(
            _chain_step_proposal(step_index=1, action_category="network_recon")
        )
        assert decision.approved is False
        assert "explicit scope authorization" in decision.reason.lower()

    def test_authorized_chain_steps_are_approved(self) -> None:
        engine = PolicyEngine(normalize_scope(_chain_scope_raw()))
        step_one = engine.evaluate(
            _chain_step_proposal(step_index=1, action_category="network_recon")
        )
        step_two = engine.evaluate(
            _chain_step_proposal(step_index=2, action_category="active_template_check")
        )
        assert step_one.approved is True
        assert step_two.approved is True

    def test_chain_step_outside_declared_host_is_blocked(self) -> None:
        engine = PolicyEngine(normalize_scope(_chain_scope_raw()))
        decision = engine.evaluate(
            _chain_step_proposal(
                step_index=2,
                action_category="active_template_check",
                target_host="192.168.100.6",
            )
        )
        assert decision.approved is False
        assert "does not authorize target" in decision.reason.lower()

    def test_chain_step_outside_declared_step_count_is_blocked(self) -> None:
        engine = PolicyEngine(normalize_scope(_chain_scope_raw()))
        decision = engine.evaluate(
            _chain_step_proposal(step_index=3, action_category="network_recon")
        )
        assert decision.approved is False
        assert "outside the authorized range" in decision.reason.lower()

    def test_chain_step_wrong_category_is_blocked(self) -> None:
        engine = PolicyEngine(normalize_scope(_chain_scope_raw()))
        decision = engine.evaluate(
            _chain_step_proposal(step_index=1, action_category="active_template_check")
        )
        assert decision.approved is False
        assert "permits action category" in decision.reason.lower()

    def test_multi_step_completion_requires_verified_evidence_per_step(self) -> None:
        objective = {"type": "multi_step", "required_steps": ["recon", "verify"]}
        progress = [
            {
                "step_index": 1,
                "action_id": "act-recon",
                "evidence_id": "ev-recon",
                "status": "EXECUTED",
            }
        ]
        finding = {
            "confidence": "CONFIRMED",
            "evidence_ids": ["ev-verify"],
        }

        unverified = _completion(
            objective,
            findings=[finding],
            chain_progress=progress,
            verified_evidence_ids=set(),
        )
        assert unverified["is_completed"] is False

        verified = _completion(
            objective,
            findings=[finding],
            chain_progress=progress,
            verified_evidence_ids={"ev-recon", "ev-verify"},
        )
        assert verified["is_completed"] is True
        assert verified["outcome"] == "SUCCESS"
        assert set(verified["verification_evidence_ids"]) == {"ev-recon", "ev-verify"}

    def test_recon_for_multi_step_objective_is_blocked_without_chain_scope(
        self, tmp_path: Any
    ) -> None:
        scope = normalize_scope(
            {
                "targets": ["192.168.100.5", "192.168.100.0/28"],
                "allowed_actions": ["network_recon"],
                "allowed_ports": [8080],
            }
        )
        executed: list[ActionProposal] = []

        def _record_tool(proposal: ActionProposal) -> tuple[int, str, str]:
            executed.append(proposal)
            return (0, "", "")

        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            tool_executor=_record_tool,
            simulation_mode=True,
        )
        state: dict[str, Any] = {
            "assessment_id": "asm-chain-denied",
            "target": {"value": "http://192.168.100.5:8080"},
            "assessment_objective": {
                "type": "multi_step",
                "required_steps": ["recon", "verify"],
            },
            "available_tools": [{"tool_name": "nmap", "categories": ["network_recon"]}],
            "discovered_assets": [],
            "discovered_services": [],
            "observations": [],
            "evidence_refs": [],
            "action_history": [],
            "executed_actions": [],
            "chain_progress": [],
            "blocked_actions": [],
            "current_strategy": "INITIAL_RECON",
        }

        updates = graph.recon_node(state)  # type: ignore[arg-type]
        assert executed == []
        assert updates["current_strategy"] == "BLOCKED"
        assert len(updates["blocked_actions"]) == 1

    def test_recon_for_authorized_chain_records_step_evidence(self, tmp_path: Any) -> None:
        scope = normalize_scope(_chain_scope_raw())
        xml_out = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="192.168.100.5"/>
<ports>
<port protocol="tcp" portid="8080">
<state state="open"/>
<service name="http" product="Lab" version="1.0"/>
</port>
</ports>
</host>
</nmaprun>"""
        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            tool_executor=lambda proposal: (0, xml_out, ""),
            simulation_mode=True,
        )
        state: dict[str, Any] = {
            "assessment_id": "asm-chain-authorized",
            "target": {"value": "http://192.168.100.5:8080"},
            "assessment_objective": {
                "type": "multi_step",
                "required_steps": ["recon", "verify"],
            },
            "available_tools": [{"tool_name": "nmap", "categories": ["network_recon"]}],
            "discovered_assets": [],
            "discovered_services": [],
            "observations": [],
            "evidence_refs": [],
            "action_history": [],
            "executed_actions": [],
            "chain_progress": [],
            "blocked_actions": [],
            "current_strategy": "INITIAL_RECON",
        }

        updates = graph.recon_node(state)  # type: ignore[arg-type]
        assert updates["chain_progress"][0]["step_index"] == 1
        assert updates["chain_progress"][0]["evidence_id"]
        assert updates["chain_progress"][0]["target_host"] == "192.168.100.5"

    def test_report_node_includes_chain_authorization_summary(self) -> None:
        scope = normalize_scope(_chain_scope_raw())
        graph = AssessmentOrchestrator(scope=scope, simulation_mode=True)
        raw_state: dict[str, Any] = {
            "completion": {"outcome": "SUCCESS"},
            "chain_progress": [{"step_index": 1, "evidence_id": "ev-1"}],
        }
        updates = graph.report_node(cast(AssessmentState, raw_state))
        assert updates["chain_summary"]["authorized"] is True
        assert updates["chain_summary"]["executed_steps"][0]["evidence_id"] == "ev-1"


class TestEvidenceProvenance:
    def test_finding_does_not_chain_evidence_from_another_target(self, tmp_path: Any) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        scope = normalize_scope(
            {
                "targets": ["192.168.100.0/28"],
                "allowed_actions": ["network_recon", "active_template_check"],
                "allowed_ports": [8080],
            }
        )
        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            simulation_mode=True,
        )

        recon_a = vault.store_artifact(
            assessment_id="asm-cross-target",
            tool_name="nmap",
            raw_content="8080/tcp open http on host A",
            cmd="nmap 192.168.100.5",
        )
        recon_b = vault.store_artifact(
            assessment_id="asm-cross-target",
            tool_name="nmap",
            raw_content="8080/tcp open http on host B",
            cmd="nmap 192.168.100.6",
        )
        verify_b = vault.store_artifact(
            assessment_id="asm-cross-target",
            tool_name="nuclei",
            raw_content="[CVE-2024-XXXX] [http] [critical] http://192.168.100.6:8080",
            cmd="nuclei -u http://192.168.100.6:8080",
        )

        state: dict[str, Any] = {
            "assessment_id": "asm-cross-target",
            "target": {"value": "http://192.168.100.6:8080"},
            "evidence_refs": [
                {
                    "evidence_id": recon_a.evidence_id,
                    "tool": "nmap",
                    "sha256": recon_a.sha256,
                    "target_host": "192.168.100.5",
                },
                {
                    "evidence_id": recon_b.evidence_id,
                    "tool": "nmap",
                    "sha256": recon_b.sha256,
                    "target_host": "192.168.100.6",
                },
                {
                    "evidence_id": verify_b.evidence_id,
                    "tool": "nuclei",
                    "sha256": verify_b.sha256,
                    "target_host": "192.168.100.6",
                },
            ],
            "observations": [
                {
                    "observation_type": "vuln_candidate",
                    "tool": "nuclei",
                    "raw_evidence_id": verify_b.evidence_id,
                    "target": "192.168.100.6",
                    "data": {
                        "name": "CVE-2024-XXXX",
                        "severity": "CRITICAL",
                        "template_id": "cve-2024-xxxx",
                        "matched_at": "http://192.168.100.6:8080",
                    },
                }
            ],
            "findings": [],
        }

        updates = graph.verify_finding_node(state)  # type: ignore[arg-type]
        finding = updates["findings"][0]
        assert recon_b.evidence_id in finding["evidence_ids"]
        assert recon_a.evidence_id not in finding["evidence_ids"]
        assert finding["confidence"] == "CONFIRMED"

    def test_finding_remains_confirmable_without_discovery_metadata(self, tmp_path: Any) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        scope = normalize_scope(
            {
                "targets": ["192.168.100.0/28"],
                "allowed_actions": ["active_template_check"],
                "allowed_ports": [8080],
            }
        )
        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            simulation_mode=True,
        )
        verify = vault.store_artifact(
            assessment_id="asm-legacy",
            tool_name="nuclei",
            raw_content="[CVE-2024-YYYY] [http] [high]",
            cmd="nuclei",
        )
        state: dict[str, Any] = {
            "assessment_id": "asm-legacy",
            "target": {"value": "http://192.168.100.6:8080"},
            "evidence_refs": [
                {
                    "evidence_id": verify.evidence_id,
                    "tool": "nuclei",
                    "sha256": verify.sha256,
                }
            ],
            "observations": [
                {
                    "observation_type": "vuln_candidate",
                    "tool": "nuclei",
                    "raw_evidence_id": verify.evidence_id,
                    "target": "192.168.100.6",
                    "data": {"name": "CVE-2024-YYYY", "severity": "HIGH"},
                }
            ],
            "findings": [],
        }
        updates = graph.verify_finding_node(state)  # type: ignore[arg-type]
        assert updates["findings"][0]["confidence"] == "CONFIRMED"


def test_chain_step_decision_type_remains_typed() -> None:
    """Sanity check that the new contract fields do not alter decision enums."""
    assert DecisionType.EXECUTE_ACTION.value == "EXECUTE_ACTION"

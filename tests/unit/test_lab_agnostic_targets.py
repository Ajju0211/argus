"""Unit tests for Track 03: Lab-Agnostic Targets & Objectives (L-01 to L-04).

Covers:
- L-01: Arbitrary target extraction (ports, schemes, paths, IPv6 literals).
- L-02: Flexible judge scope normalization, port ranges, and wildcard host matching.
- L-03: Generic objective evaluations (discover_services, flag, severity threshold, fail-closed unknown).
- L-04: Multi-step action chaining and evidence provenance preservation.
"""

from typing import Any

import pytest

from core.evidence.evidence_vault import EvidenceVault
from core.findings.finding_verifier import FindingVerifier
from core.policy.policy_engine import PolicyEngine
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, extract_target_spec
from engine.nodes.evaluate_completion import evaluate_completion
from packages.contracts.actions import ActionProposal
from packages.contracts.scope import PortConfig, ScopeDocument, normalize_scope


class TestLabAgnosticTargetExtraction:
    """L-01: Target host, port, scheme, and path extraction from arbitrary specs."""

    def test_extract_url_with_explicit_port_and_path(self) -> None:
        spec = extract_target_spec("http://192.168.1.100:3000/app/login")
        assert spec["host"] == "192.168.1.100"
        assert spec["port"] == 3000
        assert spec["scheme"] == "http"
        assert spec["path"] == "/app/login"

    def test_extract_https_url_default_port_443(self) -> None:
        spec = extract_target_spec("https://demo.lab.internal")
        assert spec["host"] == "demo.lab.internal"
        assert spec["port"] == 443
        assert spec["scheme"] == "https"
        assert spec["path"] == ""

    def test_extract_http_url_default_port_80(self) -> None:
        spec = extract_target_spec("http://demo.lab.internal")
        assert spec["host"] == "demo.lab.internal"
        assert spec["port"] == 80
        assert spec["scheme"] == "http"

    def test_extract_ipv6_literal_with_port(self) -> None:
        spec = extract_target_spec("http://[2001:db8::1]:8080/metrics")
        assert spec["host"] == "2001:db8::1"
        assert spec["port"] == 8080
        assert spec["scheme"] == "http"
        assert spec["path"] == "/metrics"

    def test_extract_bare_ipv6_with_bracket_and_port(self) -> None:
        spec = extract_target_spec("[2001:db8::1]:9090")
        assert spec["host"] == "2001:db8::1"
        assert spec["port"] == 9090
        assert spec["scheme"] == "tcp"

    def test_extract_bare_ipv6_without_port(self) -> None:
        spec = extract_target_spec("2001:db8::1")
        assert spec["host"] == "2001:db8::1"
        assert spec["port"] is None
        assert spec["scheme"] == "tcp"

    def test_extract_host_and_port_string(self) -> None:
        spec = extract_target_spec("10.0.1.20:8443")
        assert spec["host"] == "10.0.1.20"
        assert spec["port"] == 8443
        assert spec["scheme"] == "tcp"

    def test_extract_target_from_dict_spec(self) -> None:
        spec = extract_target_spec({"url": "http://target.local:5000", "port": 5000})
        assert spec["host"] == "target.local"
        assert spec["port"] == 5000
        assert spec["scheme"] == "http"

    def test_recon_node_routes_to_extracted_target_port(self, tmp_path: Any) -> None:
        scope_data = {
            "targets": ["192.168.1.0/24", "192.168.1.100"],
            "allowed_actions": ["network_recon"],
            "allowed_ports": [3000],
        }
        scope = normalize_scope(scope_data)
        executed_proposals: list[ActionProposal] = []

        xml_out = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="192.168.1.100"/>
<ports>
<port protocol="tcp" portid="3000">
<state state="open"/>
<service name="http" product="NodeJS" version="20.0"/>
</port>
</ports>
</host>
</nmaprun>"""

        def mock_executor(proposal: ActionProposal) -> tuple[int, str, str]:
            executed_proposals.append(proposal)
            return (0, xml_out, "")

        vault = EvidenceVault(base_dir=tmp_path / "vault")
        verifier = FindingVerifier()
        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            finding_verifier=verifier,
            tool_executor=mock_executor,
            simulation_mode=True,
        )

        initial_state = {
            "assessment_id": "asm-test-l01",
            "target": {"value": "http://192.168.1.100:3000/app"},
            "assessment_objective": {"type": "discover_services"},
            "scope_id": scope.assessment_id,
            "scope_yaml_hash": "testhash",
            "available_tools": [{"tool_name": "nmap", "categories": ["network_recon"]}],
            "discovered_assets": [],
            "discovered_services": [],
            "observations": [],
            "findings": [],
            "evidence_refs": [],
            "action_history": [],
            "blocked_actions": [],
            "current_action": None,
            "current_strategy": "INITIAL_RECON",
            "recovery": {
                "consecutive_failures": 0,
                "max_consecutive_failures": 3,
                "strategy_switch_count": 0,
            },
            "cancellation": {"is_cancelled": False, "reason": None},
            "budget": {
                "iterations_used": 0,
                "max_iterations": 10,
                "model_calls_used": 0,
                "max_model_calls": 10,
            },
            "completion": {"is_completed": False, "outcome": "IN_PROGRESS", "summary": ""},
            "research_refs": [],
            "executed_actions": [],
            "status": "RUNNING",
        }

        updates = graph.recon_node(initial_state)  # type: ignore[arg-type]
        assert len(executed_proposals) == 1
        assert executed_proposals[0].target_host == "192.168.1.100"
        assert executed_proposals[0].target_port == 3000
        assert executed_proposals[0].arguments.get("ports") == "3000"
        assert len(updates["discovered_services"]) >= 1


class TestFlexibleJudgeScopeNormalization:
    """L-02: Flexible judge-supplied scope formats and normalization."""

    def test_port_config_range_expansion(self) -> None:
        cfg = PortConfig.model_validate({"allowed_ports": ["8000-8004", 443]})
        assert cfg.allowed_ports == [443, 8000, 8001, 8002, 8003, 8004]

    def test_port_config_comma_separated_expansion(self) -> None:
        cfg = PortConfig.model_validate({"allowed_ports": "80,443,8080"})
        assert cfg.allowed_ports == [80, 443, 8080]

    def test_normalize_scope_minimal_dict(self) -> None:
        raw = {"targets": ["http://target.local:8080"]}
        doc = normalize_scope(raw)
        assert isinstance(doc, ScopeDocument)
        assert doc.targets.allowed_hosts == ["target.local"]
        assert 8080 in doc.ports.allowed_ports
        assert "network_recon" in doc.actions.allowed_categories

    def test_normalize_scope_with_aliases_and_subnets(self) -> None:
        raw = {
            "targets": ["192.168.10.0/24", "https://api.internal:8443"],
            "allowed_actions": ["network_recon", "web_crawl"],
            "allowed_ports": ["8443", "443"],
        }
        doc = ScopeValidator.normalize_scope(raw)
        assert "192.168.10.0/24" in doc.targets.allowed_subnets
        assert "api.internal" in doc.targets.allowed_hosts
        assert doc.ports.allowed_ports == [443, 8443]
        assert doc.actions.allowed_categories == ["network_recon", "web_crawl"]

    def test_normalize_scope_ipv6_literal(self) -> None:
        raw = {"targets": ["[2001:db8::1]:8080"]}
        doc = normalize_scope(raw)
        assert "2001:db8::1" in doc.targets.allowed_hosts
        assert 8080 in doc.ports.allowed_ports

    def test_wildcard_hostname_matching_in_policy_engine(self) -> None:
        raw = {
            "targets": ["*.lab.internal", "192.168.100.0/24"],
            "allowed_actions": ["network_recon"],
            "allowed_ports": [80, 443],
        }
        doc = normalize_scope(raw)
        engine = PolicyEngine(doc)

        # Wildcard matches target host and resolves to IP inside subnet
        with pytest.MonkeyPatch().context() as m:
            m.setattr(engine, "_resolve_host", lambda host: "192.168.100.50")
            proposal = ActionProposal(
                action_id="act-wildcard-1",
                target_host="app.lab.internal",
                target_port=443,
                tool_name="nmap",
                action_category="network_recon",
                arguments={},
                rationale="Accessing authorized wildcard host",
                expected_evidence="Service banner",
            )
            decision = engine.evaluate(proposal)
            assert decision.approved is True
            assert decision.resolved_ip == "192.168.100.50"


class TestGenericObjectiveEvaluation:
    """L-03: Generic objective evaluation across arbitrary evaluation goals."""

    def test_discover_services_objective_succeeds_without_cve(self) -> None:
        objective = {"type": "discover_services", "required_hosts": 1}
        evaluation = evaluate_completion(
            objective=objective,
            findings=[],  # Zero findings / CVEs
            discovered_assets=["192.168.1.100"],
            discovered_services=[{"port": 80, "service": "http"}],
            budget={"iterations_used": 1, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
        )
        assert evaluation["is_completed"] is True
        assert evaluation["outcome"] == "SUCCESS"
        assert "HOST_DISCOVERY_COMPLETED" in evaluation["satisfied_goals"]
        assert "SERVICES_ENUMERATED" in evaluation["satisfied_goals"]

    def test_flag_capture_objective_succeeds_when_flag_found(self) -> None:
        objective = {"type": "flag", "flag": "FLAG{argus_sec_challenge_2026}"}
        observations = [
            {
                "observation_type": "web_probe",
                "tool": "nuclei",
                "raw_evidence_id": "ev-flag-99",
                "data": {"extracted_results": ["FLAG{argus_sec_challenge_2026}"]},
            }
        ]
        evaluation = evaluate_completion(
            objective=objective,
            findings=[],
            discovered_assets=["192.168.1.50"],
            discovered_services=[{"port": 8080, "service": "http"}],
            budget={"iterations_used": 2, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
            observations=observations,
            verified_evidence_ids={"ev-flag-99"},
        )
        assert evaluation["is_completed"] is True
        assert evaluation["outcome"] == "SUCCESS"
        assert "FLAG_CAPTURED" in evaluation["satisfied_goals"]
        assert "ev-flag-99" in evaluation["verification_evidence_ids"]

    def test_severity_threshold_objective(self) -> None:
        objective = {"type": "severity_threshold", "min_severity": "HIGH"}

        # Case 1: Only MEDIUM finding -> IN_PROGRESS
        med_finding = {
            "finding_id": "find-1",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "evidence_ids": ["ev-1"],
        }
        eval_med = evaluate_completion(
            objective=objective,
            findings=[med_finding],
            discovered_assets=["10.0.0.1"],
            discovered_services=[],
            budget={"iterations_used": 2, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
        )
        assert eval_med["is_completed"] is False
        assert eval_med["outcome"] == "IN_PROGRESS"

        # Case 2: CRITICAL finding -> SUCCESS
        crit_finding = {
            "finding_id": "find-2",
            "confidence": "CONFIRMED",
            "severity": "CRITICAL",
            "evidence_ids": ["ev-2"],
        }
        eval_crit = evaluate_completion(
            objective=objective,
            findings=[crit_finding],
            discovered_assets=["10.0.0.1"],
            discovered_services=[],
            budget={"iterations_used": 3, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
        )
        assert eval_crit["is_completed"] is True
        assert eval_crit["outcome"] == "SUCCESS"

    def test_unknown_objective_type_fails_closed(self) -> None:
        objective = {"type": "arbitrary_nonexistent_goal_xyz"}
        evaluation = evaluate_completion(
            objective=objective,
            findings=[],
            discovered_assets=["10.0.0.1"],
            discovered_services=[],
            budget={"iterations_used": 1, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
        )
        assert evaluation["is_completed"] is True
        assert evaluation["outcome"] == "FAILED"
        assert "unknown or unsupported" in evaluation["summary"].lower()


class TestMultiStepVerificationChaining:
    """L-04: Multi-step chained verification and provenance tracking."""

    def test_action_proposal_step_index_and_parent_action_id(self) -> None:
        proposal = ActionProposal(
            action_id="act-step-002",
            parent_action_id="act-step-001",
            step_index=2,
            target_host="192.168.1.10",
            target_port=80,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"target": "http://192.168.1.10/login"},
            rationale="Follow-up active verification probe based on recon",
            expected_evidence="Proof of vulnerability",
        )
        data = proposal.model_dump()
        assert data["parent_action_id"] == "act-step-001"
        assert data["step_index"] == 2

    def test_multi_step_objective_evaluation(self) -> None:
        objective = {"type": "multi_step", "required_steps": ["recon", "verify"]}
        confirmed_finding = {
            "finding_id": "f-1",
            "confidence": "CONFIRMED",
            "evidence_ids": ["ev-recon", "ev-verify"],
        }

        chain_progress = [
            {
                "step_index": 1,
                "action_id": "act-recon-001",
                "evidence_id": "ev-recon",
                "status": "EXECUTED",
            }
        ]

        # Step 1: Only recon complete
        eval_step1 = evaluate_completion(
            objective=objective,
            findings=[],
            discovered_assets=["192.168.1.1"],
            discovered_services=[{"port": 80, "service": "http"}],
            budget={"iterations_used": 1, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
            chain_progress=chain_progress,
            verified_evidence_ids={"ev-recon", "ev-verify"},
        )
        assert eval_step1["is_completed"] is False
        assert eval_step1["outcome"] == "IN_PROGRESS"

        # Step 2: Recon + finding verified
        eval_step2 = evaluate_completion(
            objective=objective,
            findings=[confirmed_finding],
            discovered_assets=["192.168.1.1"],
            discovered_services=[{"port": 80, "service": "http"}],
            budget={"iterations_used": 2, "max_iterations": 10},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
            chain_progress=chain_progress,
            verified_evidence_ids={"ev-recon", "ev-verify"},
        )
        assert eval_step2["is_completed"] is True
        assert eval_step2["outcome"] == "SUCCESS"
        assert "MULTI_STEP_CHAIN_COMPLETED" in eval_step2["satisfied_goals"]

    def test_verify_finding_chains_discovery_and_active_evidence(self, tmp_path: Any) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        verifier = FindingVerifier()
        scope_data = {"targets": ["http://target.local:8080"]}
        scope = normalize_scope(scope_data)
        graph = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            finding_verifier=verifier,
            simulation_mode=True,
        )

        # Store initial discovery evidence and secondary verification evidence
        art_recon = vault.store_artifact(
            assessment_id="asm-chain-01",
            tool_name="nmap",
            raw_content="8080/tcp open http Apache",
            cmd="nmap target.local",
        )
        art_verify = vault.store_artifact(
            assessment_id="asm-chain-01",
            tool_name="nuclei",
            raw_content="[CVE-2024-XXXX] [http] [critical] http://target.local:8080",
            cmd="nuclei -u http://target.local:8080",
        )

        state = {
            "assessment_id": "asm-chain-01",
            "target": {"value": "http://target.local:8080"},
            "evidence_refs": [
                {"evidence_id": art_recon.evidence_id, "tool": "nmap", "sha256": art_recon.sha256},
                {
                    "evidence_id": art_verify.evidence_id,
                    "tool": "nuclei",
                    "sha256": art_verify.sha256,
                },
            ],
            "observations": [
                {
                    "observation_type": "vuln_candidate",
                    "tool": "nuclei",
                    "raw_evidence_id": art_verify.evidence_id,
                    "target": "http://target.local:8080",
                    "data": {
                        "name": "CVE-2024-XXXX",
                        "severity": "CRITICAL",
                        "template_id": "cve-2024-xxxx",
                        "matched_at": "http://target.local:8080",
                    },
                }
            ],
            "findings": [],
        }

        updates = graph.verify_finding_node(state)  # type: ignore[arg-type]
        findings = updates["findings"]
        assert len(findings) == 1
        f = findings[0]
        assert f["confidence"] == "CONFIRMED"
        # Provenance invariant: both discovery evidence and active verification evidence are chained!
        assert art_recon.evidence_id in f["evidence_ids"]
        assert art_verify.evidence_id in f["evidence_ids"]

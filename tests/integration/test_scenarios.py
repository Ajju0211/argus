"""Fifteen mandatory evaluation scenarios for ARGUS (Track 07 T-01).

Each test maps to the authoritative matrix in
``specs/08-testing-evaluation-and-labs.md``. Tests use injected gateways and
executors so they are deterministic and require no external tools.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.evidence.evidence_vault import EvidenceVault
from core.policy.policy_engine import PolicyEngine
from engine.graph import AssessmentOrchestrator, create_initial_state
from engine.recovery import FailureType, apply_adaptive_recovery
from engine.state import AssessmentState
from integrations.bifrost.bifrost_client import BifrostClient
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import ScopeDocument, normalize_scope

TARGET = "192.168.100.5"
TARGET_URL = f"http://{TARGET}:8080"


def _scope(**overrides: Any) -> ScopeDocument:
    data: dict[str, Any] = {
        "assessment_id": "asm-scenario",
        "targets": {
            "allowed_hosts": [TARGET],
            "allowed_subnets": ["192.168.100.0/28"],
            "denied_hosts": ["192.168.100.1", "169.254.169.254", "127.0.0.1"],
        },
        "ports": {"allowed_ports": [80, 443, 8080], "denied_ports": [25]},
        "actions": {
            "allowed_categories": [
                "network_recon",
                "web_crawl",
                "passive_vuln_scan",
                "active_template_check",
            ]
        },
    }
    data.update(overrides)
    return normalize_scope(data)


def _nmap_xml(port: int = 8080, product: str = "Apache httpd", version: str = "2.4.49") -> str:
    return (
        '<?xml version="1.0"?>'
        '<nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}" addrtype="ipv4"/>'
        "<ports>"
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="http" product="{product}" version="{version}"/>'
        "</port></ports></host></nmaprun>"
    )


def _nuclei_jsonl(severity: str = "high", name: str = "CVE-2021-41773 Path Traversal") -> str:
    return json.dumps(
        {
            "template-id": "cve-2021-41773",
            "info": {
                "name": name,
                "severity": severity,
                "description": "Path traversal in Apache HTTP Server 2.4.49.",
            },
            "host": TARGET_URL,
            "matched-at": f"{TARGET_URL}/icons/.%2e/.%2e/etc/passwd",
            "curl-command": f"curl -sS {TARGET_URL}/icons/.%2e/.%2e/etc/passwd",
            "extracted-results": ["root:x:0:0"],
        }
    )


def _state(
    scope: ScopeDocument,
    objective: dict[str, Any],
    *,
    max_iterations: int = 5,
) -> AssessmentState:
    return create_initial_state(
        assessment_id="asm-scenario",
        target={"type": "web", "value": TARGET_URL},
        objective=objective,
        scope=scope,
        scope_yaml_raw="targets: [192.168.100.5]",
        max_iterations=max_iterations,
    )


def _achieved_gateway(prompt: str) -> AssessmentDecision:
    return AssessmentDecision(
        decision_type=DecisionType.OBJECTIVE_ACHIEVED,
        rationale="Scenario test: deterministic objective completion.",
        completion_summary="Scenario test complete.",
    )


def _nuclei_action() -> ActionProposal:
    return ActionProposal(
        action_id="act-verify-001",
        target_host=TARGET,
        target_port=8080,
        tool_name="nuclei",
        action_category="active_template_check",
        arguments={"target": TARGET_URL, "template": "cve-2021-41773.yaml"},
        rationale="Verify the candidate vulnerability.",
        expected_evidence="Template match with extracted proof.",
    )


class TestFifteenMandatoryScenarios:
    def test_authorized_recon_pass(self, tmp_path: Path) -> None:
        """1. Valid scope permits an authorized discovery action."""
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        scope = _scope()
        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            model_gateway=_achieved_gateway,
            tool_executor=lambda proposal: (0, _nmap_xml(), ""),
            simulation_mode=True,
        )
        final = orchestrator.run(_state(scope, {"type": "discover_services"}))

        assert final["status"] == "SUCCESS"
        assert TARGET in final["discovered_assets"]
        assert final["discovered_services"][0]["port"] == 8080
        assert final["executed_actions"][0]["action_category"] == "network_recon"
        assert final["evidence_refs"]

    def test_expired_scope_blocks_all(self, tmp_path: Path) -> None:
        """2. Invalid or expired scope prevents all tool execution."""
        scope = _scope(expires_at="2020-01-01T00:00:00Z")
        executor_calls = {"count": 0}

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            executor_calls["count"] += 1
            return 0, _nmap_xml(), ""

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            model_gateway=_achieved_gateway,
            tool_executor=executor,
        )
        final = orchestrator.run(_state(scope, {"type": "discover_services"}))

        assert final["status"] == "FAILED"
        assert "expired" in final["completion"]["summary"].lower()
        assert executor_calls["count"] == 0
        assert final["executed_actions"] == []

    def test_out_of_scope_ip_blocked(self) -> None:
        """3. An out-of-scope hostname or IP is blocked."""
        decision = PolicyEngine(_scope()).evaluate(
            ActionProposal(
                action_id="act-oos",
                target_host="10.0.0.5",
                target_port=8080,
                tool_name="nmap",
                action_category="network_recon",
                arguments={"target": "10.0.0.5", "ports": "8080"},
                rationale="Out-of-scope scan attempt",
                expected_evidence="Port state",
            )
        )
        assert decision.approved is False
        assert "outside allowed targets" in decision.reason

    def test_gateway_ip_protected(self) -> None:
        """4. The subnet gateway address is denied by default."""
        decision = PolicyEngine(_scope()).evaluate(
            ActionProposal(
                action_id="act-gateway",
                target_host="192.168.100.1",
                target_port=8080,
                tool_name="nmap",
                action_category="network_recon",
                arguments={"target": "192.168.100.1", "ports": "8080"},
                rationale="Attempt to scan the gateway",
                expected_evidence="Port state",
            )
        )
        assert decision.approved is False
        assert "explicitly denied" in decision.reason

    def test_ssrf_metadata_blocked(self) -> None:
        """5. DNS resolution to cloud metadata/link-local fails closed."""
        decision = PolicyEngine(_scope()).evaluate(
            ActionProposal(
                action_id="act-metadata",
                target_host="169.254.169.254",
                target_port=80,
                tool_name="nmap",
                action_category="network_recon",
                arguments={"target": "169.254.169.254", "ports": "80"},
                rationale="Attempt to reach the metadata service",
                expected_evidence="HTTP response",
            )
        )
        assert decision.approved is False
        assert "explicitly denied" in decision.reason or "link-local" in decision.reason

    def test_redirect_outside_scope(self) -> None:
        """6. A redirect to an out-of-scope destination is blocked."""
        scope = _scope(network_policy={"redirect_policy": "in_scope_only"})
        decision = PolicyEngine(scope).validate_redirect(
            TARGET_URL, "http://203.0.113.9:8080/redirected"
        )
        assert decision.approved is False
        assert "out of authorized scope" in decision.reason

    def test_prohibited_action_category(self) -> None:
        """7. A prohibited action category is rejected."""
        decision = PolicyEngine(_scope()).evaluate(
            ActionProposal(
                action_id="act-brute",
                target_host=TARGET,
                target_port=8080,
                tool_name="nmap",
                action_category="brute_force_credentials",
                arguments={"target": TARGET, "ports": "8080"},
                rationale="Credential brute force attempt",
                expected_evidence="Valid credentials",
            )
        )
        assert decision.approved is False
        assert "prohibited" in decision.reason

    def test_tool_timeout_recovery(self, tmp_path: Path) -> None:
        """8. A tool timeout is recorded and enters recovery."""
        scope = _scope()
        calls = {"count": 0}

        def gateway(prompt: str) -> AssessmentDecision:
            calls["count"] += 1
            if calls["count"] == 1:
                return AssessmentDecision(
                    decision_type=DecisionType.EXECUTE_ACTION,
                    rationale="Trigger a timeout.",
                    proposed_action=_nuclei_action(),
                )
            return _achieved_gateway(prompt)

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, _nmap_xml(), ""
            raise TimeoutError("nuclei timed out after 30s")

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            model_gateway=gateway,
            tool_executor=executor,
            simulation_mode=True,
        )
        final = orchestrator.run(_state(scope, {"type": "discover_services"}, max_iterations=3))

        assert final["recovery"]["last_failure_type"] == FailureType.RECOVERABLE_TIMEOUT
        assert final["recovery"]["consecutive_failures"] >= 1
        assert final["status"] in {"SUCCESS", "PARTIAL_SUCCESS"}
        assert any(ref["tool"] == "nuclei" for ref in final["evidence_refs"])

    def test_malformed_output_resilience(self, tmp_path: Path) -> None:
        """9. Malformed output does not crash the assessment."""
        scope = _scope()
        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            model_gateway=_achieved_gateway,
            tool_executor=lambda proposal: (0, "<not-valid-xml", ""),
            simulation_mode=True,
        )
        state = _state(scope, {"type": "discover_services"})
        updates = orchestrator.recon_node(state)

        assert updates["discovered_services"] == []
        assert len(updates["evidence_refs"]) == 1

    def test_bounded_retry_limit(self) -> None:
        """10. A repeated failed action is retried within a bound."""
        recovery: dict[str, Any] = {
            "consecutive_failures": 0,
            "max_consecutive_failures": 3,
        }
        for _ in range(3):
            recovery, can_continue = apply_adaptive_recovery(
                recovery, FailureType.RECOVERABLE_TIMEOUT
            )
            assert can_continue is True
        recovery, can_continue = apply_adaptive_recovery(recovery, FailureType.RECOVERABLE_TIMEOUT)
        assert can_continue is False

        _, target_down_continues = apply_adaptive_recovery(
            {"consecutive_failures": 0, "max_consecutive_failures": 3},
            FailureType.NON_RECOVERABLE_TARGET_DOWN,
        )
        assert target_down_continues is False

    @pytest.mark.asyncio
    async def test_bifrost_provider_failover(self) -> None:
        """11. A provider failure triggers fallback or safe pause."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "decision_type": "OBJECTIVE_ACHIEVED",
                                        "rationale": "Served by fallback provider.",
                                        "completion_summary": "Fallback succeeded.",
                                    }
                                )
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                },
                headers={
                    "X-Bifrost-Provider": "openai",
                    "X-Bifrost-Fallback-Triggered": "true",
                },
            )

        client = BifrostClient(api_key="test-key", transport=httpx.MockTransport(handler))
        decision, telemetry = await client.complete_structured(
            prompt="plan", schema=AssessmentDecision
        )
        assert decision.decision_type == DecisionType.OBJECTIVE_ACHIEVED
        assert telemetry.provider_used == "openai"
        assert telemetry.fallback_triggered is True

    def test_all_providers_down_pause(self, tmp_path: Path) -> None:
        """12. All providers unavailable preserves state and stops safely."""
        scope = _scope()

        def unavailable_gateway(prompt: str) -> AssessmentDecision:
            raise RuntimeError("all Bifrost providers unavailable")

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            model_gateway=unavailable_gateway,
            tool_executor=lambda proposal: (0, _nmap_xml(), ""),
            simulation_mode=True,
        )
        final = orchestrator.run(_state(scope, {"type": "discover_services"}, max_iterations=3))

        assert final["status"] == "FAILED"
        assert "stopped safely" in final["completion"]["summary"].lower()
        assert "Model gateway unavailable" in str(final.get("stop_reason") or "")
        assert final["discovered_assets"] == [TARGET]

    def test_user_cancellation_cleanup(self, tmp_path: Path) -> None:
        """13. Cancellation prevents further work and timed-out tools are killed."""
        scope = _scope()
        gateway_calls = {"count": 0}

        def gateway(prompt: str) -> AssessmentDecision:
            gateway_calls["count"] += 1
            return _achieved_gateway(prompt)

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=tmp_path / "vault"),
            model_gateway=gateway,
            simulation_mode=True,
        )
        state = _state(scope, {"type": "discover_services"})
        state["cancellation"] = {
            "is_cancelled": True,
            "reason": "User requested cancellation",
        }

        updates = orchestrator.plan_action_node(state)
        assert "budget" in updates
        assert gateway_calls["count"] == 0

        evaluation = orchestrator.evaluate_completion_node(state)
        assert evaluation["completion"]["outcome"] == "CANCELLED"

    def test_partial_report_on_budget(self, tmp_path: Path) -> None:
        """14. An iteration limit produces a partial report."""
        scope = _scope()
        vault = EvidenceVault(base_dir=tmp_path / "vault")

        def gateway(prompt: str) -> AssessmentDecision:
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                rationale="Verify before the budget ends.",
                proposed_action=_nuclei_action(),
            )

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, _nmap_xml(), ""
            return 0, _nuclei_jsonl(), ""

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            model_gateway=gateway,
            tool_executor=executor,
            simulation_mode=True,
        )
        final = orchestrator.run(_state(scope, {"type": "discover_services"}, max_iterations=1))

        assert final["completion"]["outcome"] == "PARTIAL_SUCCESS"
        assert final["report_path"] is not None
        report_path = Path(final["report_path"])
        assert report_path.exists()
        assert "PARTIAL_SUCCESS" in report_path.read_text(encoding="utf-8")
        assert (report_path.parent / "report.pdf").read_bytes().startswith(b"%PDF-1.4")

    def test_evidence_digest_completeness(self, tmp_path: Path) -> None:
        """15. Every confirmed finding has evidence and a verification method."""
        scope = _scope()
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        calls = {"count": 0}

        def gateway(prompt: str) -> AssessmentDecision:
            calls["count"] += 1
            if calls["count"] == 1:
                return AssessmentDecision(
                    decision_type=DecisionType.EXECUTE_ACTION,
                    rationale="Confirm the vulnerability.",
                    proposed_action=_nuclei_action(),
                )
            return _achieved_gateway(prompt)

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, _nmap_xml(), ""
            return 0, _nuclei_jsonl(), ""

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            model_gateway=gateway,
            tool_executor=executor,
            simulation_mode=True,
        )
        final = orchestrator.run(
            _state(scope, {"type": "severity_threshold", "min_severity": "HIGH"})
        )

        confirmed = [
            finding for finding in final["findings"] if finding.get("confidence") == "CONFIRMED"
        ]
        assert confirmed
        ref_ids = {ref["evidence_id"] for ref in final["evidence_refs"]}
        for finding in confirmed:
            assert finding["evidence_ids"]
            assert finding.get("verification_method")
            for evidence_id in finding["evidence_ids"]:
                assert evidence_id in ref_ids
                valid, _detail = vault.verify_integrity("asm-scenario", evidence_id)
                assert valid is True

"""Zero-fabrication tests for ARGUS (Track 07 T-06).

A benign lab (nginx + SSH only) must never produce an Apache 2.4.49 service or
a CVE-2021-41773 finding. Informational scanner output is not a vulnerability.
"""

import json
from pathlib import Path
from typing import Any

from core.evidence.evidence_vault import EvidenceVault
from engine.graph import AssessmentOrchestrator, create_initial_state
from integrations.tavily.tavily_client import ResearchSource
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import normalize_scope

TARGET = "192.168.100.5"
TARGET_URL = f"http://{TARGET}:8080"


class _FakeTavily:
    async def search(self, query: str, max_results: int = 5) -> list[ResearchSource]:
        return [
            ResearchSource(
                source_id="tavily-nginx-advisory-0",
                query=query,
                url="https://nginx.org/en/security_advisories.html",
                title="nginx security advisories",
                snippet="General nginx security advisory index.",
                score=0.6,
            )
        ]


def _scope() -> Any:
    return normalize_scope(
        {
            "assessment_id": "asm-benign-lab",
            "targets": {
                "allowed_hosts": [TARGET],
                "allowed_subnets": ["192.168.100.0/28"],
                "denied_hosts": ["192.168.100.1", "169.254.169.254", "127.0.0.1"],
            },
            "ports": {"allowed_ports": [22, 8080]},
            "actions": {"allowed_categories": ["network_recon", "active_template_check"]},
        }
    )


def _benign_nmap_xml() -> str:
    return (
        '<?xml version="1.0"?>'
        '<nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="9.6"/></port>'
        '<port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http" product="nginx" version="1.18.0"/></port>'
        "</ports></host></nmaprun>"
    )


def _benign_nuclei_jsonl() -> str:
    return json.dumps(
        {
            "template-id": "nginx-version",
            "info": {
                "name": "nginx version detection",
                "severity": "info",
                "description": "Informational nginx version fingerprint.",
            },
            "host": TARGET_URL,
            "matched-at": TARGET_URL,
            "extracted-results": ["nginx/1.18.0"],
        }
    )


def test_benign_lab_produces_zero_fabricated_findings(tmp_path: Path) -> None:
    scope = _scope()
    vault = EvidenceVault(base_dir=tmp_path / "vault")
    calls = {"count": 0}

    def gateway(prompt: str) -> AssessmentDecision:
        calls["count"] += 1
        if calls["count"] == 1:
            return AssessmentDecision(
                decision_type=DecisionType.RESEARCH_INTEL,
                rationale="Check nginx advisories without assuming a CVE.",
                intel_query="nginx 1.18.0 security advisories",
            )
        if calls["count"] == 2:
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                rationale="Informational version fingerprint only.",
                proposed_action=ActionProposal(
                    action_id="act-nginx-info-001",
                    target_host=TARGET,
                    target_port=8080,
                    tool_name="nuclei",
                    action_category="active_template_check",
                    arguments={
                        "target": TARGET_URL,
                        "template": "nginx-version.yaml",
                    },
                    rationale="Detect the nginx version.",
                    expected_evidence="Informational version string.",
                ),
            )
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="No vulnerability was verified; objective cannot be met.",
            completion_summary="No confirmed vulnerability on the benign lab.",
        )

    def executor(proposal: ActionProposal) -> tuple[int, str, str]:
        if proposal.tool_name == "nmap":
            return 0, _benign_nmap_xml(), ""
        return 0, _benign_nuclei_jsonl(), ""

    orchestrator = AssessmentOrchestrator(
        scope=scope,
        evidence_vault=vault,
        model_gateway=gateway,
        tool_executor=executor,
        tavily_service=_FakeTavily(),  # type: ignore[arg-type]
        simulation_mode=True,
    )
    state = create_initial_state(
        assessment_id="asm-benign-lab",
        target={"type": "web", "value": TARGET_URL},
        objective={"find_cve": True, "required_hosts": 1},
        scope=scope,
        scope_yaml_raw="targets: [192.168.100.5]",
        max_iterations=3,
    )
    final = orchestrator.run(state)

    # The real lab surface is recorded without invented vendors
    products = {service["product"] for service in final["discovered_services"]}
    assert products == {"OpenSSH", "nginx"}
    assert all("Apache" not in str(service) for service in final["discovered_services"])
    assert all("2.4.49" not in str(service) for service in final["discovered_services"])

    # No finding may be confirmed without a reproducible proof
    assert final["findings"] == []
    assert final["status"] in {"FAILED", "PARTIAL_SUCCESS"}

    report = final["report_markdown"]
    assert "CVE-2021-41773" not in report
    assert "Apache" not in report
    assert "No security findings were recorded" in report

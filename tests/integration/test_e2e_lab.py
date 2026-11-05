"""End-to-end controlled lab integration test for ARGUS (Track 07 T-03).

Runs the orchestrator against a real local HTTP server that behaves like an
Apache 2.4.49 path-traversal target. The planner invokes Tavily research, then a
Nuclei-style verification probe; ARGUS must capture cryptographic evidence and
confirm the finding autonomously.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

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
TRAVERSAL_PATH = "/icons/.%2e/.%2e/.%2e/etc/passwd"


class _ApacheLikeHandler(BaseHTTPRequestHandler):
    """Minimal vulnerable-lab server with an Apache 2.4.49 banner."""

    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"

    def do_GET(self) -> None:
        if self.path.startswith("/icons") or "etc/passwd" in self.path:
            body = b"root:x:0:0:root:/root:/bin/bash\n"
            content_type = "text/plain"
        else:
            body = b"<html><body>ARGUS authorized lab target</body></html>"
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Silences per-request stderr noise during tests."""


@pytest.fixture
def lab_server() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApacheLikeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _FakeTavily:
    def __init__(self) -> None:
        self.queries: list[str] = []

    async def search(self, query: str, max_results: int = 5) -> list[ResearchSource]:
        self.queries.append(query)
        return [
            ResearchSource(
                source_id="tavily-cve-2021-41773-0",
                query=query,
                url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                title="CVE-2021-41773: Path Traversal in Apache HTTP Server 2.4.49",
                snippet="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
                score=0.98,
            )
        ]


def _scope() -> Any:
    return normalize_scope(
        {
            "assessment_id": "asm-e2e-lab",
            "targets": {
                "allowed_hosts": [TARGET],
                "allowed_subnets": ["192.168.100.0/28"],
                "denied_hosts": ["192.168.100.1", "169.254.169.254", "127.0.0.1"],
            },
            "ports": {"allowed_ports": [8080], "denied_ports": [25]},
            "actions": {"allowed_categories": ["network_recon", "active_template_check"]},
            "network_policy": {"redirect_policy": "strict_same_host"},
        }
    )


def _nmap_xml() -> str:
    return (
        '<?xml version="1.0"?>'
        '<nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http" product="Apache httpd" version="2.4.49"/>'
        "</port></ports></host></nmaprun>"
    )


def _nuclei_jsonl() -> str:
    return json.dumps(
        {
            "template-id": "cve-2021-41773",
            "info": {
                "name": "CVE-2021-41773 Path Traversal",
                "severity": "high",
                "description": "Apache HTTP Server 2.4.49 path traversal permits file disclosure.",
            },
            "host": TARGET_URL,
            "matched-at": TARGET_URL + TRAVERSAL_PATH,
            "curl-command": f"curl -sS {TARGET_URL}{TRAVERSAL_PATH}",
            "extracted-results": ["root:x:0:0"],
        }
    )


def test_autonomous_lab_discovery_research_verification_and_report(
    tmp_path: Path, lab_server: int
) -> None:
    scope = _scope()
    vault = EvidenceVault(base_dir=tmp_path / "vault")
    tavily = _FakeTavily()
    base_url = f"http://127.0.0.1:{lab_server}"
    executor_targets: list[str] = []
    calls = {"count": 0}

    def gateway(prompt: str) -> AssessmentDecision:
        calls["count"] += 1
        if calls["count"] == 1:
            return AssessmentDecision(
                decision_type=DecisionType.RESEARCH_INTEL,
                rationale="Apache 2.4.49 warrants CVE research.",
                intel_query="Apache 2.4.49 CVE-2021-41773 path traversal",
            )
        if calls["count"] == 2:
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                rationale="Confirm the candidate path traversal.",
                proposed_action=ActionProposal(
                    action_id="act-nuclei-lab-001",
                    target_host=TARGET,
                    target_port=8080,
                    tool_name="nuclei",
                    action_category="active_template_check",
                    arguments={
                        "target": TARGET_URL,
                        "template": "cve-2021-41773.yaml",
                    },
                    rationale="Verify CVE-2021-41773 with a pinned template.",
                    expected_evidence="Extracted /etc/passwd proof.",
                ),
            )
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="Verified finding satisfies the objective.",
            completion_summary="Confirmed the lab vulnerability.",
        )

    def executor(proposal: ActionProposal) -> tuple[int, str, str]:
        executor_targets.append(proposal.target_host)
        if proposal.tool_name == "nmap":
            # Confirm the real lab banner, then emit Nmap-shaped XML.
            response = httpx.get(f"{base_url}/", timeout=5.0)
            assert "Apache/2.4.49" in response.headers.get("server", "")
            return 0, _nmap_xml(), ""
        if proposal.tool_name == "nuclei":
            response = httpx.get(f"{base_url}{TRAVERSAL_PATH}", timeout=5.0)
            if "root:x:0:0" in response.text:
                return 0, _nuclei_jsonl(), ""
            return 1, "", "Traversal check did not return passwd content"
        return 0, "", ""

    orchestrator = AssessmentOrchestrator(
        scope=scope,
        evidence_vault=vault,
        model_gateway=gateway,
        tool_executor=executor,
        tavily_service=tavily,  # type: ignore[arg-type]
        simulation_mode=True,
    )
    state = create_initial_state(
        assessment_id="asm-e2e-lab",
        target={"type": "web", "value": TARGET_URL},
        objective={"type": "severity_threshold", "min_severity": "HIGH"},
        scope=scope,
        scope_yaml_raw="targets: [192.168.100.5]",
        max_iterations=6,
    )
    final = orchestrator.run(state)

    # Autonomous discovery and research
    assert TARGET in final["discovered_assets"]
    assert final["discovered_services"][0]["product"] == "Apache httpd"
    assert tavily.queries
    assert final["research_refs"][0]["source_id"] == "tavily-cve-2021-41773-0"

    # Verification produced exactly one confirmed finding backed by vault evidence
    assert final["status"] == "SUCCESS"
    assert len(final["findings"]) == 1
    finding = final["findings"][0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["severity"] == "HIGH"
    assert "CVE-2021-41773" in finding["title"]
    assert finding["verification_method"]
    assert finding["evidence_ids"]

    for evidence_id in finding["evidence_ids"]:
        valid, _detail = vault.verify_integrity("asm-e2e-lab", evidence_id)
        assert valid is True

    raw_proofs = [
        vault.read_artifact_content("asm-e2e-lab", evidence_id)
        for evidence_id in finding["evidence_ids"]
    ]
    assert any("root:x:0:0" in (proof or "") for proof in raw_proofs)

    # Every executed action stayed on the authorized host
    assert executor_targets
    assert set(executor_targets) == {TARGET}

    # Client-ready report references the finding and the research source
    assert final["report_path"] is not None
    report = Path(final["report_path"]).read_text(encoding="utf-8")
    assert "CVE-2021-41773" in report
    assert "tavily-cve-2021-41773-0" in report
    assert "SIMULATION MODE" in report

"""Integration tests for the FastAPI assessment API and SSE telemetry (A-01)."""

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.contracts.actions import AssessmentDecision, DecisionType

TARGET = "192.168.100.5"
TARGET_URL = f"http://{TARGET}:8080"

SCOPE_YAML = f"""
schema_version: "1.0"
assessment_id: api-test
targets:
  allowed_hosts: ["{TARGET}"]
  allowed_subnets: ["192.168.100.0/28"]
  denied_hosts: ["169.254.169.254", "127.0.0.1"]
ports:
  allowed_ports: [8080]
  denied_ports: [25]
actions:
  allowed_categories: ["network_recon", "active_template_check"]
"""


def _nmap_xml() -> str:
    return (
        '<?xml version="1.0"?>'
        '<nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http" product="Lab Service" version="1.0"/>'
        "</port></ports></host></nmaprun>"
    )


def _achieved(prompt: str) -> AssessmentDecision:
    return AssessmentDecision(
        decision_type=DecisionType.OBJECTIVE_ACHIEVED,
        rationale="API test completion.",
        completion_summary="API test assessment complete.",
    )


def _client(tmp_path: Path, **kwargs: Any) -> TestClient:
    app = create_app(
        database_path=tmp_path / "argus.db",
        artifacts_dir=tmp_path / "artifacts",
        simulation_default=True,
        model_gateway=_achieved,
        tool_executor=lambda proposal: (0, _nmap_xml(), ""),
        **kwargs,
    )
    return TestClient(app)


def _launch(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "target": TARGET_URL,
        "scope": SCOPE_YAML,
        "objective": {"type": "discover_services", "required_hosts": 1},
        "simulation": True,
        "max_iterations": 3,
    }
    payload.update(overrides)
    response = client.post("/api/v1/assessments", json=payload)
    assert response.status_code in {201, 202}, response.text
    return cast(dict[str, Any], response.json())


def _wait(client: TestClient, assessment_id: str, timeout: float = 5.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = cast(dict[str, Any], client.get(f"/api/v1/assessments/{assessment_id}").json())
        if last.get("is_terminal"):
            return last
        time.sleep(0.05)
    raise AssertionError(f"Assessment did not finish in time: {last}")


class TestAssessmentApi:
    def test_create_execute_and_fetch(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            created = _launch(client)
            assessment_id = created["assessment_id"]
            assert created["status"] in {"QUEUED", "RUNNING"}
            assert created["simulation"] is True

            final = _wait(client, assessment_id)
            assert final["status"] == "SUCCESS"
            assert final["outcome"] == "SUCCESS"
            assert final["discovered_assets"] == [TARGET]
            assert final["discovered_services"][0]["port"] == 8080
            assert final["evidence_refs"]
            assert final["report_url"]
            assert final["report_pdf_url"]

            markdown = client.get(f"/api/v1/assessments/{assessment_id}/report?format=md")
            assert markdown.status_code == 200
            assert "# ARGUS Security Assessment Report" in markdown.text
            assert "SIMULATION MODE" in markdown.text

            pdf = client.get(f"/api/v1/assessments/{assessment_id}/report?format=pdf")
            assert pdf.status_code == 200
            assert pdf.content.startswith(b"%PDF-1.4")

            html = client.get(f"/api/v1/assessments/{assessment_id}/report?format=html")
            assert html.status_code == 200
            assert "<!doctype html>" in html.text.lower()

    def test_sse_stream_replays_node_transitions(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            assessment_id = _launch(client)["assessment_id"]
            _wait(client, assessment_id)

            response = client.get(f"/api/v1/assessments/{assessment_id}/events")
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            body = response.text
            assert "event: assessment_started" in body
            assert "event: node_transition" in body
            assert "event: assessment_completed" in body
            assert "validate_scope" in body
            assert "recon" in body
            assert "report" in body

    def test_cancel_stops_at_safe_boundary(self, tmp_path: Path) -> None:
        def slow_executor(proposal: Any) -> tuple[int, str, str]:
            time.sleep(0.4)
            return 0, _nmap_xml(), ""

        app = create_app(
            database_path=tmp_path / "argus.db",
            artifacts_dir=tmp_path / "artifacts",
            simulation_default=True,
            model_gateway=_achieved,
            tool_executor=slow_executor,
        )
        with TestClient(app) as client:
            assessment_id = _launch(client)["assessment_id"]
            cancelled = client.post(f"/api/v1/assessments/{assessment_id}/cancel")
            assert cancelled.status_code == 200
            final = _wait(client, assessment_id, timeout=5.0)
            assert final["status"] == "CANCELLED"
            assert final["outcome"] == "CANCELLED"

            # Cancelling a terminal assessment is idempotent.
            again = client.post(f"/api/v1/assessments/{assessment_id}/cancel")
            assert again.status_code == 200

    def test_live_mode_fails_closed_without_bifrost(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            client.app.state.settings = SimpleNamespace(BIFROST_API_KEY="")  # type: ignore[attr-defined]
            response = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope": SCOPE_YAML,
                    "objective": {"type": "discover_services"},
                    "simulation": False,
                },
            )
            assert response.status_code == 503
            assert "ARGUS_BIFROST_API_KEY" in response.json()["detail"]

    def test_invalid_scope_is_rejected(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            response = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope": "targets: [192.168.100.5]\nunexpected_field: true\n",
                    "simulation": True,
                },
            )
            assert response.status_code in {400, 422}
            assert "Invalid scope" in response.json()["detail"]

    def test_expired_scope_is_rejected(self, tmp_path: Path) -> None:
        expired_scope = SCOPE_YAML + "\nexpires_at: '2020-01-01T00:00:00Z'\n"
        with _client(tmp_path) as client:
            response = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope": expired_scope,
                    "simulation": True,
                },
            )
            assert response.status_code in {400, 422}
            assert "expired" in response.json()["detail"].lower()

    def test_missing_assessment_returns_404(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            assert client.get("/api/v1/assessments/asm-missing").status_code == 404
            assert client.get("/api/v1/assessments/asm-missing/events").status_code == 404
            assert client.get("/api/v1/assessments/asm-missing/report").status_code == 404


class TestDashboardAndHeaders:
    def test_dashboard_is_served_with_security_headers(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            response = client.get("/")
            assert response.status_code == 200
            assert "ARGUS" in response.text
            assert "Launch Authorized Assessment" in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    def test_health_and_list_endpoints(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            assert client.get("/healthz").json()["status"] == "ok"
            assessment_id = _launch(client)["assessment_id"]
            _wait(client, assessment_id)
            listed = client.get("/api/v1/assessments").json()
            assert any(item["assessment_id"] == assessment_id for item in listed)

"""Integration tests for Spec 06 — API Contracts and Persistence Layer.

Verifies:
1. test_create_assessment_valid_scope: Valid YAML returns HTTP 201 with status READY (auto_start=False).
2. test_create_assessment_invalid_scope: Malformed scope returns HTTP 422 with validation errors.
3. test_start_assessment: POST /start launches runner and returns status RUNNING.
4. test_sse_event_streaming: Subscribing to /events receives sequential JSON events.
5. test_pause_and_resume: Pausing cleanly saves checkpoint; resuming resumes from checkpoint state.
6. test_findings_endpoint: GET /findings returns List[Finding].
7. test_evidence_raw_and_path_traversal: GET /evidence/{id} streams raw file, blocks traversal attacks.
8. test_report_pdf_and_json: GET /report returns JSON when requested, /report/pdf returns PDF bytes.
"""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.contracts.actions import AssessmentDecision, DecisionType
from packages.contracts.findings import ConfidenceLevel, Finding, SeverityLevel

TARGET = "192.168.100.5"
TARGET_URL = f"http://{TARGET}:8080"

VALID_SCOPE_YAML = f"""
schema_version: "1.0"
assessment_id: spec06-test
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


def _mock_nmap_xml() -> str:
    return (
        '<?xml version="1.0"?>'
        '<nmaprun><host><status state="up"/>'
        f'<address addr="{TARGET}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/>'
        '<service name="http" product="Lab Service" version="1.0"/>'
        "</port></ports></host></nmaprun>"
    )


def _achieved_gateway(prompt: str) -> AssessmentDecision:
    return AssessmentDecision(
        decision_type=DecisionType.OBJECTIVE_ACHIEVED,
        rationale="Spec 06 test completion.",
        completion_summary="Spec 06 assessment completed.",
    )


def _create_test_client(tmp_path: Path, **kwargs: Any) -> TestClient:
    app = create_app(
        database_path=tmp_path / "argus.db",
        artifacts_dir=tmp_path / "artifacts",
        simulation_default=True,
        model_gateway=_achieved_gateway,
        tool_executor=lambda proposal: (0, _mock_nmap_xml(), ""),
        **kwargs,
    )
    return TestClient(app)


def _wait_for_status(
    client: TestClient, assessment_id: str, target_statuses: set[str], timeout: float = 5.0
) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        res = client.get(f"/api/v1/assessments/{assessment_id}")
        assert res.status_code == 200
        last = cast(dict[str, Any], res.json())
        if last.get("status") in target_statuses:
            return last
        time.sleep(0.05)
    raise AssertionError(f"Did not reach {target_statuses} in time: {last}")


class TestSpec06ApiContracts:
    def test_create_assessment_valid_scope(self, tmp_path: Path) -> None:
        """1. test_create_assessment_valid_scope: Valid YAML returns HTTP 201 with status READY."""
        with _create_test_client(tmp_path) as client:
            payload = {
                "name": "Staged Web Scan",
                "target": {"type": "web", "value": TARGET_URL},
                "scope_yaml": VALID_SCOPE_YAML,
                "objective": "discover_services",
                "auto_start": False,
                "simulation": True,
            }
            response = client.post("/api/v1/assessments", json=payload)
            assert response.status_code == 201, response.text
            data = response.json()
            assert data["status"] == "READY"
            assert data["id"].startswith("asm-")
            assert data["name"] == "Staged Web Scan"
            assert data["target"]["value"] == TARGET_URL

    def test_create_assessment_invalid_scope(self, tmp_path: Path) -> None:
        """2. test_create_assessment_invalid_scope: Malformed scope returns HTTP 422 with validation errors."""
        with _create_test_client(tmp_path) as client:
            payload = {
                "name": "Bad Scope Scan",
                "target": {"type": "web", "value": TARGET_URL},
                "scope_yaml": "invalid: yaml: [broken: {",
                "objective": "discover_services",
                "simulation": True,
            }
            response = client.post("/api/v1/assessments", json=payload)
            assert response.status_code == 422
            detail = response.json().get("detail", "")
            assert "scope" in str(detail).lower() or "yaml" in str(detail).lower()

    def test_start_assessment(self, tmp_path: Path) -> None:
        """3. Launch staged assessment via POST /api/v1/assessments/{id}/start."""
        with _create_test_client(tmp_path) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "name": "Start Test",
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": False,
                    "simulation": True,
                },
            )
            assert create_resp.status_code == 201
            assessment_id = create_resp.json()["id"]
            assert create_resp.json()["status"] == "READY"

            # Start execution
            start_resp = client.post(f"/api/v1/assessments/{assessment_id}/start")
            assert start_resp.status_code == 200
            assert start_resp.json()["status"] == "RUNNING"

            # Verify it reaches terminal completion
            final = _wait_for_status(
                client, assessment_id, {"SUCCESS", "COMPLETED", "PARTIAL_SUCCESS"}
            )
            assert final["status"] in {"SUCCESS", "COMPLETED"}

    def test_sse_event_streaming(self, tmp_path: Path) -> None:
        """4. Subscribing to /events receives sequential JSON events with Last-Event-ID replay."""
        with _create_test_client(tmp_path) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": True,
                    "simulation": True,
                },
            )
            assert create_resp.status_code in {201, 202}
            assessment_id = create_resp.json()["id"]

            _wait_for_status(client, assessment_id, {"SUCCESS", "COMPLETED"})

            stream_resp = client.get(f"/api/v1/assessments/{assessment_id}/events")
            assert stream_resp.status_code == 200
            assert stream_resp.headers["content-type"].startswith("text/event-stream")
            text = stream_resp.text
            assert "event: assessment_created" in text
            assert "event: assessment_started" in text
            assert "event: assessment_completed" in text

            # Replay with Last-Event-ID header
            replay_resp = client.get(
                f"/api/v1/assessments/{assessment_id}/events",
                headers={"Last-Event-ID": "1"},
            )
            assert replay_resp.status_code == 200
            assert "text/event-stream" in replay_resp.headers["content-type"]

    def test_pause_and_resume(self, tmp_path: Path) -> None:
        """5. test_pause_and_resume: Pausing cleanly saves checkpoint; resuming resumes."""

        def slow_executor(proposal: Any) -> tuple[int, str, str]:
            time.sleep(0.3)
            return 0, _mock_nmap_xml(), ""

        app = create_app(
            database_path=tmp_path / "argus.db",
            artifacts_dir=tmp_path / "artifacts",
            simulation_default=True,
            model_gateway=_achieved_gateway,
            tool_executor=slow_executor,
        )
        with TestClient(app) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": True,
                    "simulation": True,
                },
            )
            assessment_id = create_resp.json()["id"]

            # Request pause
            pause_resp = client.post(f"/api/v1/assessments/{assessment_id}/pause")
            assert pause_resp.status_code == 200
            assert pause_resp.json()["status"] == "PAUSED"

            # Checkpoint should be in the database
            db = app.state.db
            checkpoint = db.get_latest_checkpoint(assessment_id)
            assert checkpoint is not None
            assert checkpoint["assessment_id"] == assessment_id
            assert len(checkpoint["checkpoint_blob"]) > 0

            # Verify assessment state is PAUSED
            current = client.get(f"/api/v1/assessments/{assessment_id}").json()
            assert current["status"] == "PAUSED"

            # Resume execution
            resume_resp = client.post(f"/api/v1/assessments/{assessment_id}/resume")
            assert resume_resp.status_code == 200
            assert resume_resp.json()["status"] == "RUNNING"

            # Ensure it completes successfully
            final = _wait_for_status(client, assessment_id, {"SUCCESS", "COMPLETED"})
            assert final["status"] in {"SUCCESS", "COMPLETED"}

    def test_findings_endpoint(self, tmp_path: Path) -> None:
        """6. GET /api/v1/assessments/{id}/findings returns list of findings."""
        with _create_test_client(tmp_path) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": False,
                    "simulation": True,
                },
            )
            assessment_id = create_resp.json()["id"]

            db = client.app.state.db  # type: ignore[attr-defined]
            finding = Finding(
                finding_id="find-spec06-001",
                assessment_id=assessment_id,
                title="Exposed Test Admin Interface",
                description="Unauthenticated administrative console exposed on port 8080",
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.POTENTIAL,
                affected_asset=TARGET,
                affected_service="http (Lab Service 1.0)",
                verification_method="HTTP banner and path probing",
                reproduction_steps="curl -I http://192.168.100.5:8080/admin",
                impact="Potential unauthorized administrative configuration change",
                remediation="Restrict access to authorized administrative networks",
                created_at=datetime.now(UTC),
            )
            db.save_finding(assessment_id, finding.model_dump(mode="json"))

            res = client.get(f"/api/v1/assessments/{assessment_id}/findings")
            assert res.status_code == 200
            findings = res.json()
            assert len(findings) == 1
            assert findings[0]["finding_id"] == "find-spec06-001"
            assert findings[0]["severity"] == "HIGH"

    def test_evidence_raw_and_path_traversal(self, tmp_path: Path) -> None:
        """7. GET /api/v1/assessments/{id}/evidence/{ev_id} streams raw file, blocks traversal attacks."""
        with _create_test_client(tmp_path) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": True,
                    "simulation": True,
                },
            )
            assessment_id = create_resp.json()["id"]
            _wait_for_status(client, assessment_id, {"SUCCESS", "COMPLETED"})

            state = client.get(f"/api/v1/assessments/{assessment_id}").json()
            evidence_refs = state.get("evidence_refs", [])
            assert len(evidence_refs) > 0
            ev_id = evidence_refs[0].get("evidence_id") or evidence_refs[0].get("id")

            # Valid evidence retrieval
            res = client.get(f"/api/v1/assessments/{assessment_id}/evidence/{ev_id}")
            assert res.status_code == 200
            assert "text/plain" in res.headers["content-type"]
            assert len(res.text) > 0

            # Path traversal attempt should fail
            bad_res = client.get(
                f"/api/v1/assessments/{assessment_id}/evidence/..%2F..%2Fetc%2Fpasswd"
            )
            assert bad_res.status_code in {400, 404}

    def test_report_pdf_and_json(self, tmp_path: Path) -> None:
        """8. GET /report returns JSON or markdown; GET /report/pdf returns PDF bytes."""
        with _create_test_client(tmp_path) as client:
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target": TARGET_URL,
                    "scope_yaml": VALID_SCOPE_YAML,
                    "auto_start": True,
                    "simulation": True,
                },
            )
            assessment_id = create_resp.json()["id"]
            _wait_for_status(client, assessment_id, {"SUCCESS", "COMPLETED"})

            # Report format=json
            json_report = client.get(f"/api/v1/assessments/{assessment_id}/report?format=json")
            assert json_report.status_code == 200
            data = json_report.json()
            assert "markdown" in data
            assert "# ARGUS Security Assessment Report" in data["markdown"]

            # Report format=pdf
            pdf_report = client.get(f"/api/v1/assessments/{assessment_id}/report/pdf")
            assert pdf_report.status_code == 200
            assert pdf_report.headers["content-type"] == "application/pdf"
            assert pdf_report.content.startswith(b"%PDF-1.4")

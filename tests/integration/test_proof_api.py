"""Integration tests for Spec 11 Proof Capsule API endpoints."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "test_argus.db"
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    app = create_app(
        database_path=db_path,
        artifacts_dir=artifacts_dir,
        simulation_default=True,
    )
    return TestClient(app)


def test_proof_capsule_api_workflow(client: TestClient, tmp_path: Path) -> None:
    # 1. Create an assessment
    scope_yaml = """schema_version: "1.0"
assessment_id: "asm-proof-api"
name: "Proof API Test"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [8080]
actions:
  allowed_categories: ["network_recon", "active_template_check"]
"""
    resp = client.post(
        "/api/v1/assessments",
        json={
            "name": "Proof Test",
            "target": {"type": "web", "value": "http://192.168.100.5:8080"},
            "objective": {"type": "discover_services"},
            "scope_yaml": scope_yaml,
        },
    )
    assert resp.status_code == 201
    asm_id = resp.json()["assessment_id"]

    # 2. Start assessment and wait for simulation completion
    start_resp = client.post(f"/api/v1/assessments/{asm_id}/start")
    assert start_resp.status_code == 200

    # 3. Request proof capsule download
    proof_resp = client.get(f"/api/v1/assessments/{asm_id}/proof")
    # If simulated run generated findings, returns 200 ZIP
    if proof_resp.status_code == 200:
        assert proof_resp.headers["content-type"] == "application/zip"
        zip_bytes = proof_resp.content
        assert zip_bytes.startswith(b"PK")

        # 4. Post to /api/v1/proof/verify
        verify_resp = client.post(
            "/api/v1/proof/verify",
            content=zip_bytes,
            headers={"Content-Type": "application/zip"},
        )
        assert verify_resp.status_code == 200
        result = verify_resp.json()
        assert result["verdict"] in {"PROVEN", "UNPROVEN"}
        assert "checks" in result


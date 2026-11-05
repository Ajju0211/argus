"""Unit test suite for ARGUS Tool Engine & Security Adapters (Module 03).

Verifies strict typing, command parameterization, injection prevention,
defused XML parsing, JSONL streaming parsing, and process lifecycle cleanup.
"""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from core.executor.process_runner import run_tool_process
from core.executor.tool_registry import ToolRegistry
from integrations.tools.base import NormalizedObservation
from integrations.tools.nmap_adapter import NmapAdapter
from integrations.tools.nuclei_adapter import NucleiAdapter
from integrations.tools.zap_adapter import ZapAdapter

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestNormalizedObservation:
    """Verifies contracts for normalized observations."""

    def test_immutable_observation_creation(self) -> None:
        obs = NormalizedObservation(
            tool="nmap",
            target="192.168.100.5",
            observation_type="open_port",
            data={"port": 8080, "service": "http", "version": "Apache 2.4.49"},
            severity_hint="INFO",
            raw_evidence_id="ev-12345",
        )
        assert obs.tool == "nmap"
        assert obs.target == "192.168.100.5"
        assert obs.data["port"] == 8080
        assert obs.severity_hint == "INFO"

        # Immutability: direct mutation must trigger ValidationError
        with pytest.raises(ValidationError):
            obs.__setattr__("target", "altered")


class TestToolRegistry:
    """Verifies dynamic tool registration and capability discovery."""

    def test_register_and_retrieve_tool(self) -> None:
        registry = ToolRegistry()
        nmap = NmapAdapter()
        registry.register(nmap)

        retrieved = registry.get("nmap")
        assert retrieved is not None
        assert retrieved.tool_name == "nmap"

    def test_unknown_tool_returns_none(self) -> None:
        registry = ToolRegistry()
        assert registry.get("nonexistent_tool") is None

    def test_find_by_capability(self) -> None:
        registry = ToolRegistry()
        nmap = NmapAdapter()
        nuclei = NucleiAdapter()
        registry.register(nmap)
        registry.register(nuclei)

        recon_tools = registry.find_by_capability("network_recon")
        assert any(t.tool_name == "nmap" for t in recon_tools)

        vuln_tools = registry.find_by_capability("cve_verification")
        assert any(t.tool_name == "nuclei" for t in vuln_tools)

    def test_export_descriptors_for_orchestrator(self) -> None:
        registry = ToolRegistry()
        registry.register(NmapAdapter())
        registry.register(NucleiAdapter())

        descriptors = registry.export_descriptors()
        assert len(descriptors) == 2
        tool_names = [d["tool_name"] for d in descriptors]
        assert "nmap" in tool_names
        assert "nuclei" in tool_names
        assert all("risk_level" in d for d in descriptors)
        assert all("capabilities" in d for d in descriptors)


class TestNmapAdapter:
    """Verifies Nmap argument validation, command building, and safe XML parsing."""

    def test_safe_command_building(self) -> None:
        adapter = NmapAdapter()
        cmd = adapter.build_command({"target": "192.168.100.5", "ports": "80,8080"})

        # Must be unprivileged TCP connect scan with XML stdout
        assert cmd[0] == "nmap"
        assert "-sT" in cmd
        assert "-sV" in cmd
        assert "-T4" in cmd
        assert "--open" in cmd
        assert "-oX" in cmd
        assert "-" in cmd
        assert "-p" in cmd
        assert "80,8080" in cmd
        assert cmd[-1] == "192.168.100.5"

    def test_rejects_dangerous_arguments(self) -> None:
        adapter = NmapAdapter()

        dangerous_payloads: list[dict[str, Any]] = [
            {"target": "192.168.100.5", "ports": "80; rm -rf /"},
            {"target": "192.168.100.5", "extra_flags": "--script=vuln"},
            {"target": "192.168.100.5", "ports": "80 | cat /etc/passwd"},
            {"target": "192.168.100.5", "target_file": "/tmp/hosts"},
        ]

        for payload in dangerous_payloads:
            assert adapter.validate_args(payload) is False
            with pytest.raises(ValueError):
                adapter.build_command(payload)

    def test_nmap_xml_parser(self) -> None:
        adapter = NmapAdapter()
        xml_file = FIXTURES_DIR / "nmap_sample.xml"
        raw_xml = xml_file.read_text(encoding="utf-8")

        observations = adapter.parse_output(raw_xml, evidence_id="ev-nmap-01")

        assert len(observations) >= 3  # host + 2 open ports
        types = [obs.observation_type for obs in observations]
        assert "host_discovered" in types
        assert "open_port" in types
        assert "service_version" in types

        # Check port 8080 parsed details
        p8080 = next(
            obs
            for obs in observations
            if obs.observation_type == "open_port" and obs.data.get("port") == 8080
        )
        assert p8080.data["service"] == "http"
        assert "Apache" in p8080.data.get("product", "")
        assert p8080.data.get("version") == "2.4.49"
        assert p8080.raw_evidence_id == "ev-nmap-01"


class TestNucleiAdapter:
    """Verifies Nuclei template safety and JSONL parsing."""

    def test_safe_command_building(self) -> None:
        adapter = NucleiAdapter(templates_dir="/templates/pinned")
        cmd = adapter.build_command(
            {
                "target": "http://192.168.100.5:8080",
                "template": "cve-2021-41773.yaml",
            }
        )

        assert cmd[0] == "nuclei"
        assert "-u" in cmd
        assert "http://192.168.100.5:8080" in cmd
        assert "-t" in cmd
        assert "/templates/pinned/cve-2021-41773.yaml" in cmd
        assert "-j" in cmd
        assert "-silent" in cmd
        assert "-disable-redirects" in cmd
        assert "-ni" in cmd
        assert "-duc" in cmd

    def test_rejects_path_traversal_templates(self) -> None:
        adapter = NucleiAdapter(templates_dir="/templates/pinned")

        malicious_inputs = [
            {"target": "http://lab:8080", "template": "../../etc/passwd"},
            {"target": "http://lab:8080", "template": "/absolute/path/bad.yaml"},
            {"target": "http://lab:8080; reboot", "template": "safe.yaml"},
        ]

        for payload in malicious_inputs:
            assert adapter.validate_args(payload) is False
            with pytest.raises(ValueError):
                adapter.build_command(payload)

    def test_nuclei_jsonl_parser(self) -> None:
        adapter = NucleiAdapter()
        jsonl_file = FIXTURES_DIR / "nuclei_sample.jsonl"
        raw_jsonl = jsonl_file.read_text(encoding="utf-8")

        observations = adapter.parse_output(raw_jsonl, evidence_id="ev-nuclei-01")

        assert len(observations) == 2
        cve_obs = next(obs for obs in observations if obs.observation_type == "vuln_candidate")
        assert cve_obs.data["template_id"] == "CVE-2021-41773"
        assert cve_obs.severity_hint == "CRITICAL"
        assert "curl_command" in cve_obs.data
        assert cve_obs.raw_evidence_id == "ev-nuclei-01"


class TestZapAdapter:
    """Verifies ZAP baseline report parsing and severity mapping."""

    def test_zap_json_parser(self) -> None:
        adapter = ZapAdapter()
        json_file = FIXTURES_DIR / "zap_sample.json"
        raw_json = json_file.read_text(encoding="utf-8")

        observations = adapter.parse_output(raw_json, evidence_id="ev-zap-01")

        assert len(observations) == 2
        severities = {obs.severity_hint for obs in observations}
        assert "MEDIUM" in severities
        assert "LOW" in severities
        assert any("Content Security Policy" in obs.data.get("name", "") for obs in observations)


@pytest.mark.asyncio
class TestProcessRunner:
    """Verifies subprocess execution, timeout isolation, and process-group termination."""

    async def test_successful_command_execution(self) -> None:
        retcode, stdout, stderr = await run_tool_process(
            ["echo", "argus_execution_test"], timeout_seconds=5
        )
        assert retcode == 0
        assert "argus_execution_test" in stdout
        assert stderr == ""

    async def test_process_timeout_kills_cleanly(self) -> None:
        with pytest.raises(TimeoutError) as exc_info:
            await run_tool_process(["sleep", "10"], timeout_seconds=1)
        assert "timed out" in str(exc_info.value).lower()

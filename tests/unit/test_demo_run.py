"""Regression tests for the lab-agnostic ARGUS demo runner.

Guards against the old behavior of hardcoding Apache 2.4.49, port 8080, or
CVE-2021-41773, and verifies that live mode fails closed without a gateway.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import demo_run


def test_simulated_demo_is_lab_agnostic(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = demo_run.main(
        [
            "--simulated",
            "--objective",
            "discover_services",
            "--output-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert exit_code == 0
    assert "SIMULATION" in output
    assert "SIMULATION_MODE" in output
    assert "Apache 2.4.49" not in output
    assert "CVE-2021-41773" not in output
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.pdf").exists()
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF-1.4")


def test_simulated_demo_uses_scope_defined_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        """
targets: ["127.0.0.1"]
allowed_actions: ["network_recon"]
allowed_ports: [3000]
""",
        encoding="utf-8",
    )
    exit_code = demo_run.main(
        [
            "--simulated",
            "--scope",
            str(scope_path),
            "--objective",
            "discover_services",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "http://127.0.0.1:3000" in output
    assert "8080" not in output


def test_simulated_severity_demo_has_no_hardcoded_cve(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = demo_run.main(
        [
            "--simulated",
            "--objective",
            "severity_threshold",
            "--min-severity",
            "HIGH",
            "--output-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert exit_code == 0
    assert "Simulated Lab Check" in output
    assert "CVE-" not in output


def test_live_mode_fails_closed_without_bifrost(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        demo_run,
        "get_settings",
        lambda: SimpleNamespace(BIFROST_API_KEY="", ARTIFACTS_DIR=Path("./artifacts")),
    )
    exit_code = demo_run.main(["--objective", "discover_services"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "requires ARGUS_BIFROST_API_KEY" in captured.err
    assert "--simulated" in captured.err


def test_resolve_target_prefers_scope_port() -> None:
    from packages.contracts.scope import normalize_scope

    scope = normalize_scope(
        {"targets": ["lab.local"], "allowed_ports": [3000], "allowed_actions": ["network_recon"]}
    )
    assert demo_run._resolve_target(scope, None) == "http://lab.local:3000"


def test_simulated_nmap_output_has_no_vendor_claims() -> None:
    xml = demo_run._simulated_nmap_xml("192.0.2.10", 3000)
    assert "Apache" not in xml
    assert "2.4.49" not in xml
    assert 'portid="3000"' in xml

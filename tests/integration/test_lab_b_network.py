"""Integration tests for Spec 08 Section 3.2: Lab B Multi-Service Host.

Tests multi-port enumeration, banner extraction, and service categorization
against an isolated multi-service host simulating FTP (vsftpd 2.3.4) and SSH (OpenSSH).
"""

import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from core.evidence.evidence_vault import EvidenceVault
from engine.graph import AssessmentOrchestrator, create_initial_state
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import normalize_scope

LAB_B_HOST = "192.168.100.10"


class MockLabBServer:
    """Multi-service test server mimicking Lab B (FTP on 2121, SSH on 2222)."""

    def __init__(self, ftp_port: int, ssh_port: int) -> None:
        self.ftp_port = ftp_port
        self.ssh_port = ssh_port
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._running = True
        t_ftp = threading.Thread(target=self._run_ftp, daemon=True)
        t_ssh = threading.Thread(target=self._run_ssh, daemon=True)
        self._threads = [t_ftp, t_ssh]
        t_ftp.start()
        t_ssh.start()
        time.sleep(0.1)

    def stop(self) -> None:
        self._running = False

    def _run_ftp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.ftp_port))
        sock.listen(5)
        sock.settimeout(0.5)
        while self._running:
            try:
                conn, _ = sock.accept()
                conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()

    def _run_ssh(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.ssh_port))
        sock.listen(5)
        sock.settimeout(0.5)
        while self._running:
            try:
                conn, _ = sock.accept()
                conn.sendall(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n")
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()


def _lab_b_nmap_xml(ftp_port: int = 21, ssh_port: int = 22) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
    <status state="up" reason="syn-ack"/>
    <address addr="{LAB_B_HOST}" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="{ftp_port}">
            <state state="open" reason="syn-ack"/>
            <service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10"/>
        </port>
        <port protocol="tcp" portid="{ssh_port}">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.4p1 Debian 5+deb11u3" method="probed" conf="10"/>
        </port>
    </ports>
</host>
</nmaprun>
"""


def _lab_b_scope(ftp_port: int = 21, ssh_port: int = 22) -> Any:
    return normalize_scope(
        {
            "schema_version": "1.0",
            "assessment_id": "asm-lab-b-eval",
            "name": "Lab B Multi-Service Host Assessment",
            "targets": {
                "allowed_hosts": [LAB_B_HOST],
                "allowed_subnets": ["192.168.100.0/24"],
                "denied_hosts": ["192.168.100.1"],
            },
            "ports": {
                "allowed_ports": [ftp_port, ssh_port],
                "denied_ports": [25],
            },
            "actions": {
                "allowed_categories": ["network_recon", "service_fingerprint"],
            },
        }
    )


class TestLabBMultiServiceIntegration:
    """Evaluation against Lab B multi-service host (Spec 08 Section 3.2)."""

    def test_multi_port_recon_and_service_categorization(self, tmp_path: Path) -> None:
        scope = _lab_b_scope(ftp_port=21, ssh_port=22)
        vault = EvidenceVault(base_dir=tmp_path / "vault")

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, _lab_b_nmap_xml(ftp_port=21, ssh_port=22), ""
            return 0, "", ""

        def model_gateway(prompt: str) -> AssessmentDecision:
            return AssessmentDecision(
                decision_type=DecisionType.OBJECTIVE_ACHIEVED,
                rationale="Lab B multi-service reconnaissance complete.",
                completion_summary="Discovered vsftpd 2.3.4 on FTP and OpenSSH on SSH.",
            )

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=vault,
            model_gateway=model_gateway,
            tool_executor=executor,
            simulation_mode=True,
        )

        initial_state = create_initial_state(
            assessment_id="asm-lab-b-eval",
            target={"type": "network", "value": LAB_B_HOST},
            objective={"type": "discover_services"},
            scope=scope,
            scope_yaml_raw=f"targets: [{LAB_B_HOST}]",
            max_iterations=3,
        )

        final = orchestrator.run(initial_state)

        assert final["status"] == "SUCCESS"
        assert LAB_B_HOST in final["discovered_assets"]

        services = {s["port"]: s for s in final["discovered_services"]}
        assert 21 in services
        assert 22 in services

        ftp_svc = services[21]
        assert ftp_svc["service"] == "ftp"
        assert ftp_svc.get("product") == "vsftpd"
        assert ftp_svc.get("version") == "2.3.4"

        ssh_svc = services[22]
        assert ssh_svc["service"] == "ssh"
        assert "OpenSSH" in ssh_svc.get("product", "")

        # Verify evidence refs are preserved
        assert len(final["evidence_refs"]) >= 1
        evidence_id = final["evidence_refs"][0]["evidence_id"]
        valid, _ = vault.verify_integrity("asm-lab-b-eval", evidence_id)
        assert valid is True

    def test_live_socket_banner_extraction_protocol(self) -> None:
        """Verifies low-level banner grabbing against running mock socket daemon."""
        server = MockLabBServer(ftp_port=21219, ssh_port=22219)
        server.start()
        try:
            # Banner check FTP
            with socket.create_connection(("127.0.0.1", 21219), timeout=2) as s:
                ftp_banner = s.recv(1024).decode("utf-8")
                assert "220 (vsFTPd 2.3.4)" in ftp_banner

            # Banner check SSH
            with socket.create_connection(("127.0.0.1", 22219), timeout=2) as s:
                ssh_banner = s.recv(1024).decode("utf-8")
                assert "SSH-2.0-OpenSSH_8.4p1" in ssh_banner
        finally:
            server.stop()


"""Nmap Security Adapter for ARGUS.

Executes unprivileged TCP connect scans with deterministic XML output.
Parses structured observations safely using defusedxml to mitigate XXE vulnerabilities.
"""

import re
from typing import Any

import defusedxml.ElementTree as ET
from pydantic import ValidationError, model_validator

from integrations.tools.base import BaseToolArgs, NormalizedObservation, ToolAdapter

# Allowed port list pattern: e.g. "80", "80,443", "80-100", "80,8080-8090"
PORT_SPEC_REGEX = re.compile(r"^[0-9,\-]+$")

# Denied flags that could cause arbitrary execution or out-of-band writes
DISALLOWED_FLAGS = {
    "--script",
    "-sC",
    "--interactive",
    "-oG",
    "-oN",
    "-oS",
    "-iL",
    "-iR",
    "--resume",
    "--stylesheet",
    "--datadir",
}


def parse_port_spec(ports_str: str) -> list[int]:
    """Expands comma-separated and hyphenated port specifications into an integer list."""
    ports: list[int] = []
    for item in ports_str.split(","):
        item_str = item.strip()
        if not item_str:
            continue
        if "-" in item_str:
            start_s, end_s = item_str.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range '{item_str}'")
            ports.extend(range(start, end + 1))
        else:
            p = int(item_str)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is out of valid range (1-65535)")
            ports.append(p)
    return ports


class NmapArgs(BaseToolArgs):
    """Strict schema for Nmap execution arguments (X-04)."""

    target: str | None = None
    target_host: str | None = None
    ports: str | None = None
    flags: str | None = None
    allowed_ports: list[int] | None = None

    @model_validator(mode="after")
    def validate_nmap_params(self) -> "NmapArgs":
        target = (self.target or self.target_host or "").strip()
        if not target:
            raise ValueError("Target host must not be empty")

        # Reject command injection characters
        if any(c in target for c in [";", "&", "|", "`", "$", "(", ")", "\n", "\r", " "]):
            raise ValueError(f"Dangerous characters detected in target '{target}'")

        if self.ports is not None:
            p_str = str(self.ports).strip()
            if not p_str or not PORT_SPEC_REGEX.match(p_str):
                raise ValueError(f"Invalid ports specification: '{self.ports}'")
            # Verify ports are parseable integers within 1-65535
            parse_port_spec(p_str)

        if self.flags is not None:
            val_str = str(self.flags).lower()
            if any(flag in val_str for flag in DISALLOWED_FLAGS):
                raise ValueError(f"Disallowed flag in flags: '{self.flags}'")

        return self


class NmapAdapter(ToolAdapter):
    """Adapter for Nmap network reconnaissance and port enumeration."""

    def __init__(self, allowed_ports: list[int] | None = None) -> None:
        self._allowed_ports: list[int] | None = (
            sorted(set(allowed_ports)) if allowed_ports else None
        )

    @property
    def args_schema(self) -> type[NmapArgs]:
        return NmapArgs

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def capabilities(self) -> list[str]:
        return ["network_recon", "host_discovery", "port_scan", "service_fingerprint"]

    @property
    def categories(self) -> list[str]:
        return ["network_recon"]

    @property
    def risk_level(self) -> str:
        return "LOW"

    def validate_args(self, args: dict[str, Any]) -> bool:
        """Validates Nmap execution parameters against schema and port allowlist constraints (X-01, X-04)."""
        try:
            parsed = NmapArgs.model_validate(args)
        except (ValidationError, ValueError):
            return False

        effective_allowed = (
            set(parsed.allowed_ports)
            if parsed.allowed_ports is not None
            else (set(self._allowed_ports) if self._allowed_ports is not None else None)
        )

        if parsed.ports is not None:
            try:
                requested_ports = parse_port_spec(parsed.ports)
            except ValueError:
                return False

            # If an allowlist is configured, all requested ports must be contained in the allowlist (X-01)
            if effective_allowed is not None and not all(
                p in effective_allowed for p in requested_ports
            ):
                return False
        else:
            # Without ports parameter, Nmap would scan default 1,000 ports.
            # Must reject unless allowlisted ports are configured to constrain the scan (X-01).
            if effective_allowed is None:
                return False

        return True

    def build_command(self, args: dict[str, Any]) -> list[str]:
        """Builds an unprivileged TCP connect scan command with XML stdout output (X-01)."""
        if not self.validate_args(args):
            raise ValueError(f"Invalid or dangerous arguments for Nmap: {args}")

        parsed = NmapArgs.model_validate(args)
        target = str(parsed.target or parsed.target_host or "").strip()

        effective_allowed = (
            parsed.allowed_ports if parsed.allowed_ports is not None else self._allowed_ports
        )

        ports = str(parsed.ports).strip() if parsed.ports is not None else ""
        if not ports and effective_allowed:
            ports = ",".join(str(p) for p in sorted(effective_allowed))

        # Deterministic base scan command
        cmd = [
            "nmap",
            "-sT",  # Unprivileged TCP Connect scan
            "-sV",  # Service version detection
            "-T4",  # Aggressive timing for lab responsiveness
            "--open",  # Return open ports only
            "-oX",  # Output XML format
            "-",  # To stdout
        ]

        if ports:
            cmd.extend(["-p", ports])

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, evidence_id: str) -> list[NormalizedObservation]:
        """Parses Nmap XML output safely using defusedxml."""
        observations: list[NormalizedObservation] = []
        clean_xml = raw_output.strip()

        if not clean_xml:
            return observations

        try:
            root = ET.fromstring(clean_xml)
        except (ET.ParseError, ValueError, KeyError):
            # Non-XML output or malformed XML
            return observations

        for host in root.findall("host"):
            # Check host status
            status_elem = host.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                continue

            # Extract address
            addr_elem = host.find("address")
            target_ip = addr_elem.get("addr", "") if addr_elem is not None else "unknown"

            # Extract hostnames
            hostnames: list[str] = []
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostnames.append(name)

            # Emit host discovery observation
            observations.append(
                NormalizedObservation(
                    tool=self.tool_name,
                    target=target_ip,
                    observation_type="host_discovered",
                    data={
                        "ip": target_ip,
                        "status": "up",
                        "hostnames": hostnames,
                    },
                    severity_hint="INFO",
                    raw_evidence_id=evidence_id,
                )
            )

            # Extract open ports and services
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    try:
                        port_id = int(port_elem.get("portid", "0"))
                    except ValueError:
                        continue

                    proto = port_elem.get("protocol", "tcp")
                    service_elem = port_elem.find("service")

                    service_name = (
                        service_elem.get("name", "unknown")
                        if service_elem is not None
                        else "unknown"
                    )
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    extrainfo = (
                        service_elem.get("extrainfo", "") if service_elem is not None else ""
                    )

                    # Emit open_port observation
                    observations.append(
                        NormalizedObservation(
                            tool=self.tool_name,
                            target=target_ip,
                            observation_type="open_port",
                            data={
                                "port": port_id,
                                "protocol": proto,
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "extrainfo": extrainfo,
                            },
                            severity_hint="INFO",
                            raw_evidence_id=evidence_id,
                        )
                    )

                    # If product or version exists, emit service_version observation
                    if product or version:
                        observations.append(
                            NormalizedObservation(
                                tool=self.tool_name,
                                target=target_ip,
                                observation_type="service_version",
                                data={
                                    "port": port_id,
                                    "service": service_name,
                                    "product": product,
                                    "version": version,
                                    "banner": f"{product} {version} {extrainfo}".strip(),
                                },
                                severity_hint="INFO",
                                raw_evidence_id=evidence_id,
                            )
                        )

        return observations

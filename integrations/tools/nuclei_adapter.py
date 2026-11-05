"""Nuclei Security Adapter for ARGUS.

Executes template-based vulnerability verification against pinned, non-destructive
templates and parses line-delimited JSON (JSONL) outputs into typed observations.
"""

import json
from typing import Any

from pydantic import ValidationError, model_validator

from integrations.tools.base import BaseToolArgs, NormalizedObservation, ToolAdapter


class NucleiArgs(BaseToolArgs):
    """Strict schema for Nuclei execution arguments (X-04)."""

    target: str | None = None
    target_url: str | None = None
    template: str
    tags: str | None = None
    severity: str | None = None

    @model_validator(mode="after")
    def validate_nuclei_params(self) -> "NucleiArgs":
        target = (self.target or self.target_url or "").strip()
        if not target:
            raise ValueError("Target URL must not be empty")

        if any(c in target for c in [";", "&", "|", "`", "$", "(", ")", "\n", "\r", " "]):
            raise ValueError(f"Dangerous characters in target '{target}'")

        template = self.template.strip()
        if not template:
            raise ValueError("Template must not be empty")

        if ".." in template or template.startswith(("/", "\\")):
            raise ValueError(f"Directory traversal or absolute path disallowed: '{template}'")

        if not template.endswith((".yaml", ".yml")):
            raise ValueError(f"Template must be a YAML file: '{template}'")

        return self


class NucleiAdapter(ToolAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""

    def __init__(self, templates_dir: str = "/templates/pinned") -> None:
        self._templates_dir = templates_dir.rstrip("/")

    @property
    def args_schema(self) -> type[NucleiArgs]:
        return NucleiArgs

    @property
    def tool_name(self) -> str:
        return "nuclei"

    @property
    def capabilities(self) -> list[str]:
        return ["cve_verification", "vuln_scan", "template_check"]

    @property
    def categories(self) -> list[str]:
        return ["active_template_check", "passive_vuln_scan"]

    @property
    def risk_level(self) -> str:
        return "MEDIUM"

    def validate_args(self, args: dict[str, Any]) -> bool:
        """Validates Nuclei target URL and pinned template parameter against schema (X-04)."""
        try:
            NucleiArgs.model_validate(args)
            return True
        except (ValidationError, ValueError):
            return False

    def build_command(self, args: dict[str, Any]) -> list[str]:
        """Builds safe Nuclei execution command with pinned template path, -ni, and -duc (X-03)."""
        if not self.validate_args(args):
            raise ValueError(f"Invalid or dangerous arguments for Nuclei: {args}")

        parsed = NucleiArgs.model_validate(args)
        target = str(parsed.target or parsed.target_url or "").strip()
        template = parsed.template.strip()
        template_path = f"{self._templates_dir}/{template}"

        cmd = [
            "nuclei",
            "-u",
            target,
            "-t",
            template_path,
            "-j",  # Line-delimited JSON output
            "-silent",  # Suppress banner and progress bars
            "-disable-redirects",  # Never follow redirects outside the authorized scope
            "-ni",  # Disable out-of-band interaction / Interactsh (X-03)
            "-duc",  # Disable update check (X-03)
        ]

        if parsed.tags:
            cmd.extend(["-tags", parsed.tags])
        if parsed.severity:
            cmd.extend(["-severity", parsed.severity.lower()])

        return cmd

    def parse_output(self, raw_output: str, evidence_id: str) -> list[NormalizedObservation]:
        """Parses Nuclei JSONL output into normalized vulnerability observations."""
        observations: list[NormalizedObservation] = []

        for line in raw_output.splitlines():
            clean_line = line.strip()
            if not clean_line or not clean_line.startswith("{"):
                continue

            try:
                record = json.loads(clean_line)
            except json.JSONDecodeError:
                continue

            template_id = record.get("template-id") or record.get("template", "unknown")
            info = record.get("info", {})
            name = info.get("name", template_id)
            severity = str(info.get("severity", "info")).upper()
            matched_at = record.get("matched-at", record.get("host", ""))
            target = record.get("host", matched_at)
            curl_cmd = record.get("curl-command")
            extracted = record.get("extracted-results", [])

            obs_type = (
                "vuln_candidate"
                if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                else "service_info"
            )

            observations.append(
                NormalizedObservation(
                    tool=self.tool_name,
                    target=target,
                    observation_type=obs_type,
                    data={
                        "template_id": template_id,
                        "name": name,
                        "severity": severity,
                        "matched_at": matched_at,
                        "description": info.get("description", ""),
                        "curl_command": curl_cmd,
                        "extracted_results": extracted,
                    },
                    severity_hint=severity,
                    raw_evidence_id=evidence_id,
                )
            )

        return observations

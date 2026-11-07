"""OWASP ZAP Baseline Security Adapter for ARGUS.

Executes passive web application baseline audits and parses structured JSON reports
into normalized vulnerability and configuration candidate observations.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError, model_validator

from integrations.tools.base import BaseToolArgs, NormalizedObservation, ToolAdapter


class ZapArgs(BaseToolArgs):
    """Strict schema for OWASP ZAP execution arguments (X-04)."""

    target: str | None = None
    target_url: str | None = None
    report_path: str | None = None
    max_crawl_minutes: int = 5

    @model_validator(mode="before")
    @classmethod
    def normalize_zap_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            if "url" in d and "target" not in d and "target_url" not in d:
                d["target"] = d["url"]
            return d
        return data

    @model_validator(mode="after")
    def validate_zap_params(self) -> "ZapArgs":
        target = (self.target or self.target_url or "").strip()
        if not target:
            raise ValueError("Target URL must not be empty")

        if any(c in target for c in [";", "&", "|", "`", "$", "(", ")", "\n", "\r", " "]):
            raise ValueError(f"Dangerous characters in target '{target}'")

        if not target.startswith(("http://", "https://")):
            raise ValueError("Target must use http:// or https:// scheme")

        if self.report_path:
            p = str(self.report_path)
            if any(c in p for c in [";", "&", "|", "`", "$", "(", ")", "\n", "\r", " "]):
                raise ValueError(f"Dangerous characters in report path '{p}'")

        if not (1 <= self.max_crawl_minutes <= 60):
            raise ValueError("max_crawl_minutes must be between 1 and 60")

        return self


class ZapAdapter(ToolAdapter):
    """Adapter for OWASP ZAP Baseline Web Application Vulnerability Scanner."""

    @property
    def args_schema(self) -> type[ZapArgs]:
        return ZapArgs

    @property
    def tool_name(self) -> str:
        return "zap"

    @property
    def capabilities(self) -> list[str]:
        return ["web_crawl", "passive_vuln_scan", "header_audit"]

    @property
    def categories(self) -> list[str]:
        return ["web_crawl", "passive_vuln_scan"]

    @property
    def risk_level(self) -> str:
        return "LOW"

    def validate_args(self, args: dict[str, Any]) -> bool:
        """Validates target URL and parameters for ZAP scan against schema (X-04)."""
        try:
            ZapArgs.model_validate(args)
            return True
        except (ValidationError, ValueError):
            return False

    def build_command(self, args: dict[str, Any]) -> list[str]:
        """Builds safe command to execute ZAP baseline container with JSON report (X-02, X-04)."""
        if not self.validate_args(args):
            raise ValueError(f"Invalid or dangerous arguments for ZAP: {args}")

        parsed = ZapArgs.model_validate(args)
        target = str(parsed.target or parsed.target_url or "").strip()
        report_file = parsed.report_path or "report.json"

        # ZAP baseline scan executing against target with JSON report output
        return [
            "zap-baseline.py",
            "-t",
            target,
            "-J",
            report_file,
            "-m",
            str(parsed.max_crawl_minutes),
        ]

    def collect_report_to_vault(
        self,
        report_path: Path | str,
        vault: Any,
        assessment_id: str,
        target: str = "",
        cleanup: bool = True,
    ) -> tuple[str, list[NormalizedObservation]]:
        """Reads ZAP JSON report from filesystem, stores directly into vault, and parses observations (X-02).

        Guarantees deterministic cleanup of local temporary report files in finally block.
        """
        path_obj = Path(report_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"ZAP report file not found at: {path_obj}")

        try:
            content = path_obj.read_text(encoding="utf-8")
            cmd = (
                f"zap-baseline.py -t {target} -J {path_obj.name}"
                if target
                else f"zap-baseline.py -J {path_obj.name}"
            )
            artifact = vault.store_artifact(
                assessment_id=assessment_id,
                tool_name=self.tool_name,
                raw_content=content,
                cmd=cmd,
                metadata={"source_file": str(path_obj)},
            )
            observations = self.parse_output(content, evidence_id=artifact.evidence_id)
            return artifact.evidence_id, observations
        finally:
            if cleanup and path_obj.exists():
                try:
                    path_obj.unlink()
                except OSError:
                    pass

    def parse_output(self, raw_output: str, evidence_id: str) -> list[NormalizedObservation]:
        """Parses ZAP JSON report format into normalized observations."""
        observations: list[NormalizedObservation] = []
        clean_json = raw_output.strip()

        if not clean_json:
            return observations

        try:
            report = json.loads(clean_json)
        except json.JSONDecodeError:
            return observations

        # Map ZAP riskdesc / riskcode to standard severity levels
        risk_map = {
            "3": "HIGH",
            "2": "MEDIUM",
            "1": "LOW",
            "0": "INFO",
        }

        sites = report.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            site_name = site.get("@name", "unknown")
            alerts = site.get("alerts", [])

            for alert in alerts:
                riskcode = str(alert.get("riskcode", "0"))
                riskdesc = alert.get("riskdesc", "")

                # Derive severity from riskdesc (format: "Risk (Confidence)") or fallback to riskcode
                clean_risk = riskdesc.split("(")[0].strip().upper()
                if clean_risk in ["HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"]:
                    severity = "INFO" if clean_risk == "INFORMATIONAL" else clean_risk
                else:
                    severity = risk_map.get(riskcode, "INFO")

                name = alert.get("name", alert.get("alert", "ZAP Finding"))
                desc = alert.get("desc", "")
                solution = alert.get("solution", "")
                cweid = alert.get("cweid", "")
                instances = alert.get("instances", [])

                observations.append(
                    NormalizedObservation(
                        tool=self.tool_name,
                        target=site_name,
                        observation_type="vuln_candidate",
                        data={
                            "name": name,
                            "plugin_id": alert.get("pluginid"),
                            "description": desc,
                            "solution": solution,
                            "cwe_id": cweid,
                            "risk_desc": riskdesc,
                            "instance_count": len(instances),
                        },
                        severity_hint=severity,
                        raw_evidence_id=evidence_id,
                    )
                )

        return observations

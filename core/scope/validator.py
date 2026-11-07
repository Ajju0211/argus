"""Scope Validator implementation for ARGUS.

Handles safe multi-format parsing, schema conformance checking,
semantic validation, and pre-flight read-back generation (Spec 12).
"""

import hashlib
import ipaddress
import json
import re
import urllib.parse
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from packages.contracts.actions import ExploitChainObjective, MinimumProofType
from packages.contracts.scope import ScopeDocument, compute_scope_hash, normalize_scope

MAX_SCOPE_BYTES = 1024 * 1024  # 1MB size cap (SEC-01 Anti-DoS)


class ScopeReadBackBudget(BaseModel):
    max_iterations: int = 8
    max_duration_minutes: int = 30


class ScopeReadBackSummaryData(BaseModel):
    authorized_targets: list[str] = Field(default_factory=list)
    allowed_subnets: list[str] = Field(default_factory=list)
    denied_boundaries: list[str] = Field(default_factory=list)
    permitted_ports: list[int] = Field(default_factory=list)
    permitted_actions: list[str] = Field(default_factory=list)
    multi_host_pivoting: bool = False
    objective: dict[str, Any] = Field(default_factory=dict)
    budget: ScopeReadBackBudget = Field(default_factory=ScopeReadBackBudget)


class ScopeReadBackSummary(BaseModel):
    assessment_name: str
    scope_hash: str
    parsed_format: str
    parsing_confidence: str  # "DETERMINISTIC" | "HEURISTIC"
    summary: ScopeReadBackSummaryData
    warnings: list[str] = Field(default_factory=list)


class ScopeParseResult(BaseModel):
    is_valid: bool
    scope_hash: str | None = None
    format_detected: str = "UNKNOWN"
    parsing_confidence: str = "DETERMINISTIC"
    scope_document: ScopeDocument | None = None
    read_back: ScopeReadBackSummary | None = None
    normalized_yaml: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScopeValidator:
    """Validates scope documents against contracts, invariants, and pre-flight authorization rules."""

    @classmethod
    def normalize_scope(cls, raw_data: dict[str, Any] | ScopeDocument | str) -> ScopeDocument:
        """Normalizes unstructured or aliased scope specifications into a valid ScopeDocument (L-02)."""
        return normalize_scope(raw_data)

    @classmethod
    def parse_yaml_file(cls, path: Path | str) -> ScopeDocument:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Scope file not found at: {file_path}")

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            raise ValueError(f"Failed to read scope file: {e}") from e

        return cls.parse_yaml_string(content)

    @classmethod
    def parse_yaml_string(cls, yaml_content: str) -> ScopeDocument:
        raw_data: Any = None
        yaml_err: Exception | None = None
        try:
            raw_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            yaml_err = e

        if not isinstance(raw_data, dict):
            fallback_dict, _ = cls._parse_heuristic_prose(yaml_content)
            if fallback_dict is not None:
                raw_data = fallback_dict
            elif yaml_err is not None:
                raise ValueError(f"Malformed YAML format: {yaml_err}") from yaml_err
            else:
                raise TypeError("Scope YAML root must be a dictionary")

        try:
            return normalize_scope(raw_data)
        except ValidationError as e:
            raise ValueError(f"Scope schema validation failed: {e}") from e


    @classmethod
    def _extract_bare_url_or_host(cls, text: str) -> dict[str, Any] | None:
        """Derives minimal contract if input is a bare URL or single host/port string."""
        clean = text.strip()
        if "\n" in clean or " " in clean:
            return None

        # Matches http://... or https://...
        if clean.startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(clean)
            if not parsed.hostname:
                return None
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return {
                "schema_version": "1.0",
                "assessment_id": f"asm-url-{uuid.uuid4().hex[:8]}",
                "name": f"Assessment-{parsed.hostname}",
                "targets": {
                    "allowed_hosts": [parsed.hostname],
                    "allowed_subnets": [],
                    "denied_hosts": [],
                },
                "ports": {
                    "allowed_ports": [port],
                    "denied_ports": [],
                },
                "actions": {
                    "allowed_categories": [
                        "network_recon",
                        "web_crawl",
                        "active_template_check",
                    ]
                },
                "network_policy": {"redirect_policy": "strict_same_host"},
            }

        # Matches host:port
        if ":" in clean and not clean.startswith("[") and clean.count(":") == 1:
            parts = clean.split(":")
            host, port_str = parts[0].strip(), parts[1].strip()
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                return {
                    "schema_version": "1.0",
                    "assessment_id": f"asm-host-{uuid.uuid4().hex[:8]}",
                    "name": f"Assessment-{host}",
                    "targets": {
                        "allowed_hosts": [host],
                        "allowed_subnets": [],
                        "denied_hosts": [],
                    },
                    "ports": {
                        "allowed_ports": [int(port_str)],
                        "denied_ports": [],
                    },
                    "actions": {
                        "allowed_categories": [
                            "network_recon",
                            "web_crawl",
                            "active_template_check",
                        ]
                    },
                }

        return None

    @classmethod
    def _parse_heuristic_prose(cls, text: str) -> tuple[dict[str, Any] | None, list[str]]:
        """Extracts allowed & denied hosts, subnets, and ports from freeform prose or markdown checklists.

        Applies negative boundary rules: sentences containing qualifiers like 'do not touch',
        'exclude', or 'out of scope' map entities to denied_hosts and denied_ports.
        """
        warnings: list[str] = []
        negative_markers = (
            "do not touch",
            "don't touch",
            "out of scope",
            "exclude",
            "excluded",
            "denied",
            "forbidden",
            "prohibited",
            "skip",
            "avoid",
            "never",
        )

        allowed_hosts: set[str] = set()
        denied_hosts: set[str] = set()
        allowed_subnets: set[str] = set()
        allowed_ports: set[int] = set()
        denied_ports: set[int] = set()

        # Split into sentences or lines without breaking IPv4 dots
        segments = re.split(r"[\r\n;]+|(?<=[a-zA-Z\)])\.\s*|\.\s+(?=[A-Z])", text)
        found_any = False

        for segment in segments:
            seg = segment.strip()
            if not seg:
                continue

            is_negative = any(m in seg.lower() for m in negative_markers)

            # Subnets
            subnets = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", seg)
            for sn in subnets:
                allowed_subnets.add(sn.rstrip(".,;"))
                found_any = True

            # IP Addresses
            all_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", seg)
            for ip in all_ips:
                clean_ip = ip.rstrip(".,;")
                if any(clean_ip in sn for sn in subnets):
                    continue
                if is_negative:
                    denied_hosts.add(clean_ip)
                else:
                    allowed_hosts.add(clean_ip)
                found_any = True

            # Domain names
            domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", seg)
            for d in domains:
                clean_d = d.rstrip(".,;")
                d_lower = clean_d.lower()
                if d_lower not in {
                    "schema_version",
                    "yaml",
                    "json",
                    "md",
                    "com",
                    "net",
                    "org",
                    "example.com",
                }:
                    if is_negative:
                        denied_hosts.add(clean_d)
                    else:
                        allowed_hosts.add(clean_d)
                    found_any = True

            # Ports: strip IP literals first so octets are not mistaken for port numbers
            seg_no_ips = re.sub(
                r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", " ", seg
            )
            seg_no_ips_lower = seg_no_ips.lower()
            if "port" in seg_no_ips_lower:
                port_matches = re.findall(
                    r"(?:ports?)\s*[:#]?\s*([0-9\s,and\-]+)", seg_no_ips, re.IGNORECASE
                )
                chunks = port_matches if port_matches else [seg_no_ips]
                for chunk in chunks:
                    for num in re.findall(r"\b\d{1,5}\b", chunk):
                        val = int(num)
                        if 1 <= val <= 65535:
                            if is_negative:
                                denied_ports.add(val)
                            else:
                                allowed_ports.add(val)
                            found_any = True

        if not found_any:
            return None, warnings

        # Objective detection in prose
        raw_obj: dict[str, Any] | None = None
        lower_full = text.lower()
        if "exploit_chain" in lower_full or "rce" in lower_full or "proof" in lower_full:
            proof = MinimumProofType.DATA_EXPOSURE
            if "code_execution" in lower_full or "rce" in lower_full or "command execution" in lower_full:
                proof = MinimumProofType.CODE_EXECUTION
            elif "auth_bypass" in lower_full or "admin login" in lower_full:
                proof = MinimumProofType.AUTH_BYPASS
            elif "canary" in lower_full:
                proof = MinimumProofType.SIMULATED_CANARY
            raw_obj = {
                "type": "exploit_chain",
                "minimum_proof": proof.value,
                "target_asset": sorted(allowed_hosts)[0] if allowed_hosts else None,
            }

        scope_dict: dict[str, Any] = {
            "schema_version": "1.0",
            "assessment_id": f"asm-heuristic-{uuid.uuid4().hex[:8]}",
            "name": "Judge Scope Intake",
            "targets": {
                "allowed_hosts": sorted(allowed_hosts),
                "allowed_subnets": sorted(allowed_subnets),
                "denied_hosts": sorted(denied_hosts),
            },
            "ports": {
                "allowed_ports": sorted(allowed_ports) or [80, 443, 8080, 8443],
                "denied_ports": sorted(denied_ports),
            },
            "actions": {
                "allowed_categories": [
                    "network_recon",
                    "web_crawl",
                    "passive_vuln_scan",
                    "active_template_check",
                ]
            },
        }
        if raw_obj:
            scope_dict["objective"] = raw_obj

        return scope_dict, warnings

    @classmethod
    def _parse_markdown(cls, text: str) -> tuple[dict[str, Any] | None, str, list[str]]:
        """Parses markdown files, preferring embedded yaml/json code blocks, falling back to heuristics."""
        warnings: list[str] = []

        # Check for fenced code blocks (```yaml ... ``` or ```json ... ```)
        yaml_blocks = re.findall(r"```(?:yaml|yml)\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
        for block in yaml_blocks:
            try:
                parsed = yaml.safe_load(block)
                if isinstance(parsed, dict) and any(
                    k in parsed for k in ("targets", "allowed_hosts", "target", "ports")
                ):
                    return parsed, "DETERMINISTIC", warnings
            except Exception:
                pass

        json_blocks = re.findall(r"```json\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
        for block in json_blocks:
            try:
                parsed = json.loads(block)
                if isinstance(parsed, dict) and any(
                    k in parsed for k in ("targets", "allowed_hosts", "target", "ports")
                ):
                    return parsed, "DETERMINISTIC", warnings
            except Exception:
                pass

        # Fallback to heuristic prose / checklist extraction
        extracted, heuristic_warnings = cls._parse_heuristic_prose(text)
        warnings.extend(heuristic_warnings)
        return extracted, "HEURISTIC", warnings

    @classmethod
    def parse_input(
        cls,
        raw_content: str | bytes,
        filename: str | None = None,
        default_objective: str | dict[str, Any] | None = None,
    ) -> ScopeParseResult:
        """Parses arbitrary file content or pasted text into a validated ScopeDocument and read-back summary.

        Enforces:
        - Strict size cap (≤ 1MB).
        - Format classification (YAML, JSON, Markdown, Prose Heuristics, Bare URL).
        - Zero-network sandbox during intake.
        - Fail-closed ambiguity and collision checks (SEC-01).
        """
        # 1. Size cap guard (SEC-01 Anti-DoS)
        content_bytes = (
            raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
        )
        if len(content_bytes) > MAX_SCOPE_BYTES:
            return ScopeParseResult(
                is_valid=False,
                format_detected="UNKNOWN",
                parsing_confidence="DETERMINISTIC",
                errors=[
                    f"Scope payload size ({len(content_bytes)} bytes) exceeds the strict 1MB limit ({MAX_SCOPE_BYTES} bytes)."
                ],
            )

        content_str = content_bytes.decode("utf-8", errors="replace").strip()
        if not content_str:
            return ScopeParseResult(
                is_valid=False,
                format_detected="EMPTY",
                errors=["Scope content is empty."],
            )

        format_detected = "PLAINTEXT"
        confidence = "DETERMINISTIC"
        parsed_dict: dict[str, Any] | None = None
        warnings: list[str] = []
        errors: list[str] = []

        ext = Path(filename).suffix.lower() if filename else ""

        # 2. Check for bare URL or host:port
        bare_url_dict = cls._extract_bare_url_or_host(content_str)
        if bare_url_dict is not None and not ext.endswith((".yaml", ".yml", ".json")):
            parsed_dict = bare_url_dict
            format_detected = "BARE_URL"
            confidence = "DETERMINISTIC"

        # 3. Detect JSON
        if parsed_dict is None and (
            ext == ".json"
            or content_str.startswith("{")
            or (content_str.startswith("[") and not content_str.startswith("- "))
        ):
            try:
                data = json.loads(content_str)
                if isinstance(data, dict):
                    parsed_dict = data
                    format_detected = "JSON"
                    confidence = "DETERMINISTIC"
                elif isinstance(data, list):
                    parsed_dict = {"targets": {"allowed_hosts": data}}
                    format_detected = "JSON"
                    confidence = "DETERMINISTIC"
            except Exception:
                pass

        # 4. Detect Markdown
        if parsed_dict is None and (
            ext in (".md", ".markdown")
            or re.search(r"^#{1,6}\s+", content_str, re.MULTILINE)
            or "```" in content_str
        ):
            md_dict, md_conf, md_warn = cls._parse_markdown(content_str)
            if md_dict is not None:
                parsed_dict = md_dict
                format_detected = "MARKDOWN"
                confidence = md_conf
                warnings.extend(md_warn)

        # 5. Detect YAML
        if parsed_dict is None and (ext in (".yaml", ".yml") or ":" in content_str):
            try:
                data = yaml.safe_load(content_str)
                if isinstance(data, dict):
                    parsed_dict = data
                    format_detected = "YAML"
                    confidence = "DETERMINISTIC"
            except Exception:
                pass

        # 6. Fallback: Plaintext Prose Heuristic
        if parsed_dict is None:
            heuristic_dict, heuristic_warn = cls._parse_heuristic_prose(content_str)
            if heuristic_dict is not None:
                parsed_dict = heuristic_dict
                format_detected = "PLAINTEXT"
                confidence = "HEURISTIC"
                warnings.extend(heuristic_warn)

        if parsed_dict is None:
            return ScopeParseResult(
                is_valid=False,
                format_detected="UNKNOWN",
                parsing_confidence="DETERMINISTIC",
                errors=["Unable to parse scope input into a recognizable targets format."],
            )

        # 7. Normalize into ScopeDocument schema
        extracted_obj = parsed_dict.get("objective")
        scope_doc: ScopeDocument | None = None
        try:
            scope_doc = normalize_scope(parsed_dict)
        except Exception as exc:
            return ScopeParseResult(
                is_valid=False,
                format_detected=format_detected,
                parsing_confidence=confidence,
                errors=[f"Scope schema validation failed: {exc}"],
            )

        # 8. Semantic validation & invariant checks (SEC-01)
        valid, failure_reason = cls.validate_scope_document(scope_doc, enforce_duration_limit=True)
        if not valid:
            return ScopeParseResult(
                is_valid=False,
                format_detected=format_detected,
                parsing_confidence=confidence,
                errors=[failure_reason],
            )

        # 9. Objective Resolution & Read-Back Summary
        scope_hash = compute_scope_hash(scope_doc)
        normalized_yaml = yaml.dump(scope_doc.model_dump(mode="json"), sort_keys=False)

        # Handle objective
        active_objective: dict[str, Any]
        if extracted_obj and isinstance(extracted_obj, dict):
            active_objective = extracted_obj
        elif default_objective and isinstance(default_objective, dict):
            active_objective = default_objective
        elif default_objective and isinstance(default_objective, str):
            active_objective = {"type": default_objective}
        else:
            active_objective = {
                "type": "find_cve",
                "minimum_proof": None,
                "description": "Vulnerability Identification Only (Passive Recon + Active Templates)",
                "requires_operator_upgrade": True,
            }
            warnings.append(
                "No explicit objective found in scope file. Defaulting to vulnerability identification only (find_cve). Operator confirmation required to upgrade to active exploitation."
            )

        read_back_summary = ScopeReadBackSummary(
            assessment_name=scope_doc.name,
            scope_hash=scope_hash,
            parsed_format=format_detected,
            parsing_confidence=confidence,
            summary=ScopeReadBackSummaryData(
                authorized_targets=scope_doc.targets.allowed_hosts,
                allowed_subnets=scope_doc.targets.allowed_subnets,
                denied_boundaries=list(
                    dict.fromkeys(
                        scope_doc.targets.denied_hosts
                        + [str(p) for p in scope_doc.ports.denied_ports]
                        + ["169.254.169.254", "127.0.0.1"]
                    )
                ),
                permitted_ports=scope_doc.ports.allowed_ports,
                permitted_actions=scope_doc.actions.allowed_categories,
                multi_host_pivoting=scope_doc.authorized_chain.enabled,
                objective=active_objective,
                budget=ScopeReadBackBudget(
                    max_iterations=8,
                    max_duration_minutes=(
                        scope_doc.max_duration_seconds // 60
                        if scope_doc.max_duration_seconds
                        else 30
                    ),
                ),
            ),
            warnings=warnings,
        )

        return ScopeParseResult(
            is_valid=True,
            scope_hash=scope_hash,
            format_detected=format_detected,
            parsing_confidence=confidence,
            scope_document=scope_doc,
            read_back=read_back_summary,
            normalized_yaml=normalized_yaml,
            errors=[],
            warnings=warnings,
        )

    @classmethod
    def validate_scope_document(
        cls, scope: ScopeDocument, enforce_duration_limit: bool = False
    ) -> tuple[bool, str]:
        """Check semantic validity, such as authorization expiry, conflicts, and default-denied infrastructure."""
        now = datetime.now(UTC)
        expires_at = scope.expires_at

        # Ensure timezone comparison is safe
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        created_at = scope.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        if now > expires_at:
            return (
                False,
                f"Scope authorization expired at {expires_at.isoformat()} (current UTC: {now.isoformat()})",
            )

        if not scope.targets.allowed_hosts and not scope.targets.allowed_subnets:
            return False, "Scope document contains no authorized hosts or subnets"

        if not scope.ports.allowed_ports:
            return False, "Scope document specifies no allowed ports"

        if not scope.actions.allowed_categories:
            return False, "Scope document defines no allowed action categories"

        # SEC-01 Collision Invariants: allowed vs denied overlap = Ambiguity REJECT
        conflicting_hosts = set(scope.targets.allowed_hosts).intersection(
            set(scope.targets.denied_hosts)
        )
        if conflicting_hosts:
            conflict = sorted(conflicting_hosts)[0]
            return (
                False,
                f"Ambiguity detected: Host '{conflict}' appears in both allowed_hosts and denied_hosts.",
            )

        conflicting_ports = set(scope.ports.allowed_ports).intersection(
            set(scope.ports.denied_ports)
        )
        if conflicting_ports:
            conflict_port = sorted(conflicting_ports)[0]
            return (
                False,
                f"Ambiguity detected: Port {conflict_port} appears in both allowed_ports and denied_ports.",
            )

        # Prohibit default-denied infrastructure in allowed_hosts
        prohibited_host_literals = {"127.0.0.1", "localhost", "::1", "169.254.169.254"}
        for host in scope.targets.allowed_hosts:
            if host.lower() in prohibited_host_literals:
                return (
                    False,
                    f"Scope attempts to authorize default-denied host '{host}': "
                    "loopback, localhost, and cloud metadata are prohibited.",
                )

        # Prohibit default-denied infrastructure from allowed_subnets
        default_denied_v4: list[ipaddress.IPv4Network] = [
            ipaddress.IPv4Network("127.0.0.0/8"),
            ipaddress.IPv4Network("169.254.0.0/16"),
            ipaddress.IPv4Network("224.0.0.0/4"),
        ]
        default_denied_v6: list[ipaddress.IPv6Network] = [
            ipaddress.IPv6Network("::1/128"),
            ipaddress.IPv6Network("fe80::/10"),
        ]
        for s in scope.targets.allowed_subnets:
            try:
                net = ipaddress.ip_network(s, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    for denied_net in default_denied_v4:
                        if net.subnet_of(denied_net) or denied_net.subnet_of(net):
                            return (
                                False,
                                f"Scope attempts to authorize default-denied infrastructure '{s}': "
                                "loopback, link-local, and multicast are prohibited.",
                            )
                elif isinstance(net, ipaddress.IPv6Network):
                    for denied_net_v6 in default_denied_v6:
                        if net.subnet_of(denied_net_v6) or denied_net_v6.subnet_of(net):
                            return (
                                False,
                                f"Scope attempts to authorize default-denied infrastructure '{s}': "
                                "loopback, link-local, and multicast are prohibited.",
                            )
            except ValueError:
                return False, f"Invalid subnet format in scope: '{s}'"

        # Pivot Edge Referential Integrity
        if scope.authorized_chain and scope.authorized_chain.pivots:
            allowed_entry = set(scope.targets.allowed_hosts)
            known_pivot_destinations = {p.to_host for p in scope.authorized_chain.pivots}
            for p in scope.authorized_chain.pivots:
                if (
                    p.from_host not in allowed_entry
                    and p.from_host not in known_pivot_destinations
                ):
                    return (
                        False,
                        f"Pivot rule from_host '{p.from_host}' has no authorized entry point or foothold origin in scope.",
                    )

        # Temporal limit: max 7 days duration (Spec 12)
        if enforce_duration_limit and (expires_at - created_at) > timedelta(days=7, hours=1):
            return False, "Scope authorization duration cannot exceed 7 days"

        return True, "Scope document is valid and active"

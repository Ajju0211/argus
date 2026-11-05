"""Scope Contract Definitions for ARGUS.

Defines the immutable Pydantic schema for authorized assessment scopes.
Enforces strict typing, input validation at boundaries, and extra field rejection.
"""

import ipaddress
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TargetConfig(BaseModel):
    """Host and IP range permissions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_hosts: list[str] = Field(
        ..., description="Explicit hostnames or IP addresses authorized for assessment"
    )
    allowed_subnets: list[str] = Field(
        default_factory=list,
        description="CIDR notation subnets authorized for assessment (e.g. 192.168.100.0/28)",
    )
    denied_hosts: list[str] = Field(
        default_factory=list,
        description="Explicit hostnames or IPs prohibited from any interaction",
    )

    @field_validator("allowed_subnets")
    @classmethod
    def validate_subnets(cls, subnets: list[str]) -> list[str]:
        for subnet in subnets:
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR subnet format '{subnet}': {e}") from e
        return subnets


class PortConfig(BaseModel):
    """Port access permissions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_ports: list[int] = Field(..., description="List of authorized TCP/UDP ports")
    denied_ports: list[int] = Field(default_factory=list, description="Explicitly prohibited ports")

    @field_validator("allowed_ports", "denied_ports", mode="before")
    @classmethod
    def parse_and_expand_ports(cls, v: Any) -> list[int]:
        """Expands port ranges ('8000-8100') and comma-separated port strings into integer lists."""
        if v is None:
            return []
        items = v if isinstance(v, list) else [v]
        expanded: set[int] = set()
        for item in items:
            if isinstance(item, int):
                expanded.add(item)
            elif isinstance(item, str):
                item_str = item.strip()
                if "-" in item_str:
                    parts = item_str.split("-")
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        start, end = int(parts[0]), int(parts[1])
                        if start > end or (end - start) > 1000:
                            raise ValueError(
                                f"Invalid or excessively broad port range '{item_str}' (max 1000 ports)"
                            )
                        expanded.update(range(start, end + 1))
                    else:
                        raise ValueError(f"Invalid port range format '{item_str}'")
                elif "," in item_str:
                    for sub in item_str.split(","):
                        sub = sub.strip()
                        if not sub.isdigit():
                            raise ValueError(
                                f"Invalid port specification '{item_str}' "
                                f"(offending token: '{sub or '<empty>'}')"
                            )
                        expanded.add(int(sub))
                elif item_str.isdigit():
                    expanded.add(int(item_str))
                else:
                    raise ValueError(f"Unrecognized port specification '{item}'")
            else:
                raise TypeError(f"Unsupported port type: {type(item)}")
        return sorted(expanded)

    @field_validator("allowed_ports", "denied_ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is out of valid range (1-65535)")
        return ports


class ProtocolConfig(BaseModel):
    """Permitted network transport protocols."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: list[str] = Field(default=["http", "https", "tcp"])
    denied: list[str] = Field(default=["udp", "icmp", "dns-zone-transfer"])


class ActionConfig(BaseModel):
    """Categorized tool and action permissions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_categories: list[str] = Field(
        ...,
        description="Action categories permitted by scope, e.g. network_recon, web_crawl, active_template_check",
    )
    prohibited_categories: list[str] = Field(
        default=[
            "denial_of_service",
            "brute_force_credentials",
            "arbitrary_command_injection",
            "lateral_movement",
            "privilege_escalation",
        ],
        description="Action categories strictly prohibited from execution",
    )


class RateLimitsConfig(BaseModel):
    """Operational throttles and timeouts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_requests_per_second: int = Field(default=20, ge=1, le=100)
    max_concurrency: int = Field(default=2, ge=1, le=10)
    tool_timeout_seconds: int = Field(default=180, ge=10, le=600)


class NetworkPolicyConfig(BaseModel):
    """Network-level routing constraints."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    redirect_policy: str = Field(
        default="strict_same_host",
        description="Policy for following HTTP redirects: strict_same_host, in_scope_only, block_all",
    )
    allow_external_dns: bool = Field(
        default=False, description="Whether to permit DNS resolution against non-local servers"
    )


class ChainStepConfig(BaseModel):
    """One explicitly authorized step in a bounded multi-step chain (L-04)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_category: str = Field(..., description="Action category permitted for this step")
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts this step may target; empty means any globally in-scope host",
    )
    allowed_ports: list[int] = Field(
        default_factory=list,
        description="Ports this step may use; empty means any globally allowed port",
    )


class ChainConfig(BaseModel):
    """Explicit authorization envelope for bounded multi-step assessment movement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Whether the scope explicitly authorizes multi-step chain actions",
    )
    max_steps: int = Field(default=3, ge=1, le=10)
    allowed_steps: list[ChainStepConfig] = Field(default_factory=list)


class ScopeDocument(BaseModel):
    """Complete, immutable scope document for an assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0")
    assessment_id: str
    name: str = Field(default="Authorized Security Assessment")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(days=1))
    targets: TargetConfig
    ports: PortConfig
    protocols: ProtocolConfig = Field(default_factory=ProtocolConfig)
    actions: ActionConfig
    authorized_chain: ChainConfig = Field(
        default_factory=ChainConfig,
        description="Explicit authorization for bounded multi-step chained actions (L-04)",
    )
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    network_policy: NetworkPolicyConfig = Field(default_factory=NetworkPolicyConfig)
    notes: str | None = None
    credentials_ref: str | None = Field(
        default=None, description="Reference to authorized credentials vault or secret key"
    )
    max_duration_seconds: int | None = Field(
        default=None, description="Scope-specified execution time limit in seconds"
    )
    tool_timeouts: dict[str, int] = Field(
        default_factory=dict, description="Per-tool execution timeout overrides"
    )


_HARMLESS_SCOPE_EXTRAS = frozenset(
    {
        "annotations",
        "comments",
        "description",
        "environment",
        "harness",
        "judge",
        "lab",
        "metadata",
        "organization",
        "owner",
        "scope_name",
        "tags",
        "version",
    }
)
_SCOPE_FIELDS = frozenset(ScopeDocument.model_fields)


def _as_list(value: Any) -> list[Any]:
    """Wraps scalar aliases into a list without treating strings as iterables."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _extract_targets(items: list[Any]) -> tuple[list[str], list[str], list[int]]:
    """Extracts hosts, CIDRs, and referenced ports from flexible target entries."""
    allowed_hosts: list[str] = []
    allowed_subnets: list[str] = []
    extracted_ports: list[int] = []

    for item in items:
        explicit_port: Any = None
        if isinstance(item, dict):
            s_val = str(item.get("value") or item.get("host") or item.get("url") or "").strip()
            explicit_port = item.get("port")
        else:
            s_val = str(item).strip()

        if explicit_port is not None:
            try:
                extracted_ports.append(int(explicit_port))
            except (TypeError, ValueError):
                pass

        if not s_val:
            continue

        # CIDR notation is only a subnet when it actually parses as a network.
        if "/" in s_val and not s_val.startswith(("http://", "https://")):
            try:
                ipaddress.ip_network(s_val, strict=False)
                allowed_subnets.append(s_val)
                continue
            except ValueError:
                pass

        if "://" in s_val:
            parsed = urllib.parse.urlsplit(s_val)
            if parsed.hostname:
                allowed_hosts.append(parsed.hostname)
            if parsed.port:
                extracted_ports.append(parsed.port)
            elif parsed.scheme.lower() == "http":
                extracted_ports.append(80)
            elif parsed.scheme.lower() == "https":
                extracted_ports.append(443)
        elif s_val.startswith("["):
            # IPv6 literal with optional port and path: [2001:db8::1]:8080/path
            if "]:" in s_val:
                host_part, port_part = s_val.split("]:", 1)
                allowed_hosts.append(host_part.lstrip("["))
                port_token = port_part.split("/", 1)[0]
                if port_token.isdigit():
                    extracted_ports.append(int(port_token))
            else:
                allowed_hosts.append(s_val.strip("[]").split("/", 1)[0])
        elif ":" in s_val:
            # Bare IPv6 address, or host:port[/path].
            try:
                ip_obj = ipaddress.ip_address(s_val)
                allowed_hosts.append(str(ip_obj))
            except ValueError:
                host_part, port_part = s_val.rsplit(":", 1)
                allowed_hosts.append(host_part)
                port_token = port_part.split("/", 1)[0]
                if port_token.isdigit():
                    extracted_ports.append(int(port_token))
        else:
            # Scheme-less hostname with optional path.
            allowed_hosts.append(s_val.split("/", 1)[0])

    return (
        list(dict.fromkeys(allowed_hosts)),
        list(dict.fromkeys(allowed_subnets)),
        extracted_ports,
    )


def _normalize_nested_aliases(
    data: dict[str, Any], aliases: dict[str, str], list_fields: tuple[str, ...]
) -> dict[str, Any]:
    """Renames nested aliases and ensures list-typed fields are lists."""
    normalized = dict(data)
    for old, new in aliases.items():
        if old in normalized and new not in normalized:
            normalized[new] = normalized.pop(old)
    for field in list_fields:
        if field in normalized:
            normalized[field] = _as_list(normalized[field])
    return normalized


def normalize_scope(raw_scope_data: dict[str, Any] | ScopeDocument | str) -> ScopeDocument:
    """Normalizes raw judge-supplied or unstructured scope specifications into ScopeDocument (L-02).

    Supports:
    - scalar, list, or dict `targets` (URLs, host:port, CIDRs, IPv6 literals)
    - top-level `target` / `allowed_hosts` / `allowed_subnets` aliases
    - `allowed_actions` / `permitted_actions` / `action_categories` aliases
    - `allowed_ports` / `target_ports` aliases and port ranges
    - harmless metadata fields that are not part of the security contract
    """
    import yaml

    if isinstance(raw_scope_data, ScopeDocument):
        return raw_scope_data

    if isinstance(raw_scope_data, str):
        parsed = yaml.safe_load(raw_scope_data)
        if not isinstance(parsed, dict):
            raise TypeError("Parsed scope YAML must produce a dictionary")
        data = dict(parsed)
    elif isinstance(raw_scope_data, dict):
        data = dict(raw_scope_data)
    else:
        raise TypeError(f"Unsupported scope input format: {type(raw_scope_data)}")

    # 0. Drop harmless metadata before strict scope-field validation.
    for key in list(data):
        if key not in _SCOPE_FIELDS and key in _HARMLESS_SCOPE_EXTRAS:
            data.pop(key)

    # 1. Normalize top-level target aliases.
    top_hosts = data.pop("allowed_hosts", None)
    top_subnets = data.pop("allowed_subnets", None)
    top_denied = data.pop("denied_hosts", None)
    top_target = data.pop("target", None)
    has_top_targets = any(
        value is not None for value in (top_hosts, top_subnets, top_denied, top_target)
    )
    if "targets" in data and has_top_targets:
        raise ValueError(
            "Specify targets either under 'targets' or as top-level "
            "'target'/'allowed_hosts'/'allowed_subnets'/'denied_hosts', not both."
        )
    if "targets" not in data:
        if top_target is not None:
            data["targets"] = top_target
        elif has_top_targets:
            data["targets"] = {
                "allowed_hosts": _as_list(top_hosts),
                "allowed_subnets": _as_list(top_subnets),
                "denied_hosts": _as_list(top_denied),
            }

    extracted_ports: list[int] = []

    # 2. Normalize targets (dict, scalar, or list).
    raw_targets = data.get("targets")
    if isinstance(raw_targets, dict):
        data["targets"] = _normalize_nested_aliases(
            raw_targets,
            {"hosts": "allowed_hosts", "subnets": "allowed_subnets", "denied": "denied_hosts"},
            ("allowed_hosts", "allowed_subnets", "denied_hosts"),
        )
        nested = data["targets"]
        nested.setdefault("allowed_hosts", [])
        nested.setdefault("allowed_subnets", [])
        nested.setdefault("denied_hosts", [])
    elif raw_targets is not None:
        hosts, subnets, extracted_ports = _extract_targets(_as_list(raw_targets))
        data["targets"] = {
            "allowed_hosts": hosts,
            "allowed_subnets": subnets,
            "denied_hosts": [],
        }

    # 3. Normalize action aliases.
    action_aliases = [
        data.pop(name, None)
        for name in ("allowed_actions", "permitted_actions", "action_categories")
    ]
    alias_actions = next((value for value in action_aliases if value is not None), None)
    raw_actions = data.get("actions")
    if raw_actions is not None and alias_actions is not None:
        raise ValueError("Specify actions either under 'actions' or via an alias, not both.")
    if raw_actions is None:
        data["actions"] = {"allowed_categories": _as_list(alias_actions) or ["network_recon"]}
    elif isinstance(raw_actions, list):
        data["actions"] = {"allowed_categories": raw_actions}
    elif isinstance(raw_actions, dict):
        normalized_actions = _normalize_nested_aliases(
            raw_actions,
            {"allowed": "allowed_categories", "prohibited": "prohibited_categories"},
            ("allowed_categories", "prohibited_categories"),
        )
        normalized_actions.setdefault("allowed_categories", ["network_recon"])
        data["actions"] = normalized_actions

    # 4. Normalize port aliases.
    allowed_ports_alias = data.pop("allowed_ports", None)
    target_ports_alias = data.pop("target_ports", None)
    alias_ports = allowed_ports_alias if allowed_ports_alias is not None else target_ports_alias
    raw_ports = data.get("ports")
    if raw_ports is not None and alias_ports is not None:
        raise ValueError("Specify ports either under 'ports' or via an alias, not both.")
    if raw_ports is None:
        if alias_ports is not None:
            data["ports"] = {"allowed_ports": alias_ports}
        elif extracted_ports:
            data["ports"] = {"allowed_ports": extracted_ports}
        else:
            data["ports"] = {"allowed_ports": [80, 443]}
    elif isinstance(raw_ports, (list, str, int)):
        data["ports"] = {"allowed_ports": raw_ports}
    elif isinstance(raw_ports, dict):
        normalized_ports = _normalize_nested_aliases(
            raw_ports,
            {"allowed": "allowed_ports", "denied": "denied_ports"},
            ("allowed_ports", "denied_ports"),
        )
        normalized_ports.setdefault("allowed_ports", [80, 443])
        data["ports"] = normalized_ports

    # 5. Normalize chain aliases.
    chain_aliases = [data.pop(name, None) for name in ("chain", "multi_step")]
    alias_chain = next((value for value in chain_aliases if value is not None), None)
    if alias_chain is not None:
        if "authorized_chain" in data:
            raise ValueError(
                "Specify multi-step authorization either under 'authorized_chain' "
                "or via an alias, not both."
            )
        data["authorized_chain"] = (
            {"enabled": bool(alias_chain)} if isinstance(alias_chain, bool) else alias_chain
        )

    # 6. Default assessment ID if omitted.
    if "assessment_id" not in data:
        data["assessment_id"] = f"asm-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

    # 7. Reject unknown fields rather than silently dropping security-relevant input.
    unknown = sorted(key for key in data if key not in _SCOPE_FIELDS)
    if unknown:
        raise ValueError(
            f"Unsupported scope field(s): {', '.join(unknown)}. "
            "Remove them or place non-security metadata under 'metadata'."
        )

    # 8. Build and validate ScopeDocument.
    return ScopeDocument.model_validate(data)

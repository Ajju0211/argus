"""Scope Validator implementation for ARGUS.

Handles safe YAML parsing, schema conformance checking, and semantic validation.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from packages.contracts.scope import ScopeDocument, normalize_scope


class ScopeValidator:
    """Validates scope YAML documents against contracts and temporal constraints."""

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
        try:
            raw_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML format: {e}") from e

        if not isinstance(raw_data, dict):
            raise TypeError("Scope YAML root must be a dictionary")

        # Route through the normalization layer so judge-supplied aliases, scalar
        # targets, port ranges, and harmless metadata are handled consistently.
        try:
            return normalize_scope(raw_data)
        except ValidationError as e:
            raise ValueError(f"Scope schema validation failed: {e}") from e

    @classmethod
    def validate_scope_document(cls, scope: ScopeDocument) -> tuple[bool, str]:
        """Check semantic validity, such as authorization expiry, conflicts, and default-denied infrastructure."""
        import ipaddress

        now = datetime.now(UTC)
        expires_at = scope.expires_at

        # Ensure timezone comparison is safe
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

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

        # S-10: Reject default-denied infrastructure from allowed_subnets (loopback, link-local, multicast)
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
                            reason = (
                                f"Scope attempts to authorize default-denied infrastructure '{s}': "
                                "loopback, link-local, and multicast are prohibited."
                            )
                            return False, reason
                elif isinstance(net, ipaddress.IPv6Network):
                    for denied_net_v6 in default_denied_v6:
                        if net.subnet_of(denied_net_v6) or denied_net_v6.subnet_of(net):
                            reason = (
                                f"Scope attempts to authorize default-denied infrastructure '{s}': "
                                "loopback, link-local, and multicast are prohibited."
                            )
                            return False, reason
            except ValueError:
                return False, f"Invalid subnet format in scope: '{s}'"

        return True, "Scope document is valid and active"

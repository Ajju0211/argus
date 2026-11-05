"""Dynamic Tool Registry Subsystem for ARGUS.

Enables discovery, capability querying, and registration of security tool adapters
without hardcoding tool references into the orchestration workflow.
"""

from typing import Any

from integrations.tools.base import ToolAdapter


class SecurityConfigurationError(ValueError):
    """Raised when a tool adapter fails registration security gate checks."""


class ToolRegistry:
    """Registry maintaining available sandboxed security tool adapters."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """Registers a tool adapter after verifying security gate constraints (S-05)."""
        name = adapter.tool_name.strip().lower()
        if not name:
            raise ValueError("Tool adapter name cannot be empty")

        # Security Gate 1: Check required capabilities and categories
        if not adapter.capabilities:
            raise SecurityConfigurationError(f"Tool adapter '{name}' must declare capabilities")
        if not adapter.categories:
            raise SecurityConfigurationError(f"Tool adapter '{name}' must declare categories")

        valid_risks = {"LOW", "MEDIUM", "HIGH"}
        if adapter.risk_level.upper() not in valid_risks:
            raise SecurityConfigurationError(
                f"Tool adapter '{name}' has invalid risk_level '{adapter.risk_level}'; must be in {valid_risks}"
            )

        # Security Gate 2: Verify injection resistance
        dangerous_test_args = {"target": "127.0.0.1; rm -rf /", "probe": "`whoami`"}
        if adapter.validate_args(dangerous_test_args):
            raise SecurityConfigurationError(
                f"Tool adapter '{name}' failed security gate: validate_args permitted dangerous shell injection tokens"
            )

        self._tools[name] = adapter

    def get(self, tool_name: str) -> ToolAdapter | None:
        """Retrieves a registered tool adapter by name, or None if not found."""
        return self._tools.get(tool_name.strip().lower())

    def list_tools(self) -> list[ToolAdapter]:
        """Returns all registered tool adapters."""
        return list(self._tools.values())

    def find_by_capability(self, capability: str) -> list[ToolAdapter]:
        """Finds all tools offering a specific capability or category."""
        target = capability.strip().lower()
        matches: list[ToolAdapter] = []
        for tool in self._tools.values():
            tool_caps = [c.lower() for c in tool.capabilities]
            tool_cats = [c.lower() for c in tool.categories]
            if target in tool_caps or target in tool_cats:
                matches.append(tool)
        return matches

    def export_descriptors(self) -> list[dict[str, Any]]:
        """Exports JSON-compatible descriptors for all registered tools."""
        return [tool.get_descriptor() for tool in self._tools.values()]


def get_default_registry() -> ToolRegistry:
    """Creates a pre-configured registry loaded with standard security adapters."""
    from integrations.tools.nmap_adapter import NmapAdapter
    from integrations.tools.nuclei_adapter import NucleiAdapter
    from integrations.tools.zap_adapter import ZapAdapter

    registry = ToolRegistry()
    registry.register(NmapAdapter())
    registry.register(NucleiAdapter())
    registry.register(ZapAdapter())
    return registry

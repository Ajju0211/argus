"""Base Tool Adapter and Observation Contracts for ARGUS.

Defines the normalized data interfaces and abstract base class for all
sandboxed external security tools (Nmap, Nuclei, ZAP).
"""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NormalizedObservation(BaseModel):
    """Normalized structured observation extracted from unstructured tool output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(
        ..., description="Tool name that produced this observation (e.g. nmap, nuclei, zap)"
    )
    target: str = Field(
        ..., description="Target host, IP, or URL (e.g. 192.168.100.5, http://lab:8080)"
    )
    observation_type: str = Field(
        ...,
        description="Type of observation: host_discovered | open_port | service_version | vuln_candidate",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured attributes (port, service, banner, cve, url, etc.)",
    )
    severity_hint: str | None = Field(
        default=None,
        description="Preliminary severity level: INFO | LOW | MEDIUM | HIGH | CRITICAL",
    )
    raw_evidence_id: str = Field(
        ..., description="Reference pointer to raw SHA-256 evidence artifact in vault"
    )


class BaseToolArgs(BaseModel):
    """Base class for all strictly typed tool argument schemas (X-04)."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolAdapter(ABC):
    """Abstract interface that all security tool adapters must implement."""

    @property
    def args_schema(self) -> type[BaseModel] | None:
        """Pydantic model schema for strictly validating tool arguments (X-04)."""
        return None

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Registered identifier for the tool (e.g. 'nmap', 'nuclei')."""

    @property
    @abstractmethod
    def capabilities(self) -> list[str]:
        """List of capabilities provided by this tool (e.g. 'network_recon', 'cve_verification')."""

    @property
    @abstractmethod
    def categories(self) -> list[str]:
        """Scope categories matching this tool (e.g. 'network_recon', 'active_template_check')."""

    @property
    @abstractmethod
    def risk_level(self) -> str:
        """Execution risk classification: LOW | MEDIUM | HIGH."""

    @abstractmethod
    def validate_args(self, args: dict[str, Any]) -> bool:
        """Validates tool parameters against command injection and disallowed inputs."""

    @abstractmethod
    def build_command(self, args: dict[str, Any]) -> list[str]:
        """Generates safe argv string array for subprocess execution.

        Must raise ValueError if validate_args returns False.
        """

    @abstractmethod
    def parse_output(self, raw_output: str, evidence_id: str) -> list[NormalizedObservation]:
        """Parses stdout/stderr into typed normalized observations."""

    def get_descriptor(self) -> dict[str, Any]:
        """Exports tool metadata for dynamic LangGraph orchestrator discovery."""
        desc: dict[str, Any] = {
            "tool_name": self.tool_name,
            "capabilities": self.capabilities,
            "categories": self.categories,
            "risk_level": self.risk_level,
        }
        if self.args_schema:
            desc["args_schema"] = self.args_schema.model_json_schema()
        return desc

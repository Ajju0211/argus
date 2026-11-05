"""Telemetry and Cost Tracking Models for Maxim AI Bifrost.

Captures token usage, provider failover routing, and latency metrics for
every model completion to power the hackathon judge dashboard.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class BifrostTelemetry(BaseModel):
    """Telemetry data captured for a single Bifrost model completion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_used: str = Field(
        ..., description="Upstream provider that served the request (anthropic, openai)"
    )
    model_used: str = Field(
        ..., description="Specific model identifier utilized (e.g. claude-3-5-sonnet-20241022)"
    )
    prompt_tokens: int = Field(default=0, ge=0, description="Input tokens billed")
    completion_tokens: int = Field(default=0, ge=0, description="Output tokens generated")
    total_tokens: int = Field(default=0, ge=0, description="Total tokens consumed")
    latency_ms: int = Field(
        default=0, ge=0, description="Round-trip request latency in milliseconds"
    )
    fallback_triggered: bool = Field(
        default=False, description="Whether automated failover to the secondary provider occurred"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of completion",
    )

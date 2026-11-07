"""Request and response contracts for the ARGUS API (Spec 06)."""

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class AssessmentTarget(BaseModel):
    """Target contract representing web or network targets."""

    type: str = Field(default="web", description="Target type: 'web' or 'network'")
    value: str = Field(..., min_length=1, description="URL or IP, e.g. 'http://192.168.100.5:8080'")

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("target value must not be empty")
        if any(char in clean for char in ("\n", "\r", "\x00")):
            raise ValueError("target value must not contain control characters")
        return clean


class AssessmentLimits(BaseModel):
    """Execution boundaries and limits."""

    max_duration_seconds: int = Field(default=1800, ge=1)
    max_iterations: int = Field(default=15, ge=1, le=50)
    max_concurrency: int = Field(default=2, ge=1, le=10)


class ScopeParseRequest(BaseModel):
    """Payload for parsing arbitrary scope content without launching an assessment."""

    file_content: str | None = Field(default=None, description="Raw scope file content or pasted text")
    content: str | None = Field(default=None, description="Alias for file_content")
    filename: str | None = Field(default=None, description="Optional filename for format hints")
    content_type: str | None = Field(default=None, description="Optional MIME type")

    @model_validator(mode="after")
    def resolve_content(self) -> "ScopeParseRequest":
        if not self.file_content and self.content:
            self.file_content = self.content
        return self


class ScopeParseResponse(BaseModel):
    """Standardized response from the deterministic scope parser (Spec 12)."""

    is_valid: bool
    scope_hash: str | None = None
    format_detected: str = "UNKNOWN"
    parsing_confidence: str = "DETERMINISTIC"
    read_back: dict[str, Any] | None = None
    normalized_yaml: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AssessmentCreate(BaseModel):
    """Payload for launching or staging an authorized assessment."""

    name: str | None = None
    target: AssessmentTarget | str = Field(
        ..., description="Target URL, host, or host:port or AssessmentTarget"
    )
    scope: str | dict[str, Any] | None = Field(
        default=None, description="Authorized scope YAML text or an equivalent scope object"
    )
    scope_yaml: str | None = Field(default=None, description="Authorized scope YAML text")
    scope_document: dict[str, Any] | None = Field(
        default=None, description="Optional pre-parsed canonical ScopeDocument JSON payload"
    )
    imported_scope_hash: str | None = Field(
        default=None, description="Cryptographic SHA-256 hash of pre-parsed scope"
    )
    auto_confirm: bool = Field(
        default=False,
        description="Whether to auto-authorize scope pre-flight (for automated CI/CD judging)",
    )
    objective: str | dict[str, Any] = Field(
        default_factory=lambda: {"type": "discover_services", "required_hosts": 1}
    )
    limits: AssessmentLimits | None = None
    simulation: bool | None = Field(
        default=None,
        description="Force simulation mode. Defaults to server ARGUS_SIMULATION_MODE.",
    )
    auto_start: bool = Field(
        default=True,
        description="Whether to immediately launch execution or stage as READY.",
    )
    max_iterations: int = Field(default=10, ge=1, le=50)

    @field_validator("target", mode="before")
    @classmethod
    def parse_target(cls, value: Any) -> Any:
        if isinstance(value, str):
            clean = value.strip()
            if not clean:
                raise ValueError("target must not be empty")
            if any(char in clean for char in ("\n", "\r", "\x00")):
                raise ValueError("target must not contain control characters")
            target_type = "web" if clean.startswith(("http://", "https://")) else "network"
            return AssessmentTarget(type=target_type, value=clean)
        return value

    @model_validator(mode="after")
    def validate_inputs(self) -> "AssessmentCreate":
        if not self.scope and not self.scope_yaml and not self.scope_document:
            raise ValueError("Either 'scope', 'scope_yaml', or 'scope_document' must be provided.")
        if self.limits is not None and self.max_iterations == 10:
            self.max_iterations = self.limits.max_iterations
        if not self.name:
            target_val = (
                self.target.value if isinstance(self.target, AssessmentTarget) else str(self.target)
            )
            self.name = f"Assessment-{target_val}"
        return self


class AssessmentDetail(BaseModel):
    """Full assessment state matching Spec 06 contracts."""

    id: str
    name: str = ""
    status: str
    target: AssessmentTarget
    objective: str | dict[str, Any]
    discovered_assets: list[str] = Field(default_factory=list)
    discovered_services: list[dict[str, Any]] = Field(default_factory=list)
    total_findings: int = 0
    created_at: str
    completed_at: str | None = None

    # Extended attributes for dashboard & backwards compatibility
    assessment_id: str | None = None
    outcome: str | None = None
    summary: str | None = None
    error: str | None = None
    simulation: bool = False
    updated_at: str | None = None
    report_url: str | None = None
    report_pdf_url: str | None = None
    findings: list[Any] = Field(default_factory=list)
    evidence_refs: list[Any] = Field(default_factory=list)
    blocked_actions: list[Any] = Field(default_factory=list)
    telemetry: list[Any] = Field(default_factory=list)
    budget: dict[str, Any] = Field(default_factory=dict)
    is_terminal: bool = False
    langfuse_trace_id: str | None = None
    langfuse_session_id: str | None = None
    langfuse_configured: bool = False

    @model_validator(mode="after")
    def sync_id_and_summary(self) -> "AssessmentDetail":
        if not self.assessment_id:
            self.assessment_id = self.id
        if not self.id and self.assessment_id:
            self.id = self.assessment_id
        if not self.total_findings and self.findings:
            self.total_findings = len(self.findings)
        return self


# Backward-compatible alias
AssessmentSummary = AssessmentDetail


class StatusResponse(BaseModel):
    """Generic status response for lifecycle actions."""

    status: str

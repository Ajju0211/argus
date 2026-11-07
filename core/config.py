"""Global Configuration and Settings Management for ARGUS.

Follows backend-patterns and 12-Factor App design:
- Configuration is loaded from environment variables and optional .env file.
- Single source of truth for global constants, feature flags, limits, and paths.
- Zero hardcoded secrets with strict typing via pydantic-settings.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Immutable application-wide settings and feature flags."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_prefix="ARGUS_", extra="ignore", frozen=True
    )

    # -------------------------------------------------------------
    # Environment & Logging
    # -------------------------------------------------------------
    ENV: str = Field(default="development", description="development | test | production")
    LOG_LEVEL: str = Field(default="INFO", description="DEBUG | INFO | WARNING | ERROR")
    API_KEY: str = Field(
        default="", description="Operator API key for API endpoint authentication (SEC-05)"
    )
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed browser origins for the API (JSON list in ARGUS_CORS_ORIGINS)",
    )

    # -------------------------------------------------------------
    # Storage & Persistence Paths
    # -------------------------------------------------------------
    BASE_DIR: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent,
        description="Root project path",
    )
    ARTIFACTS_DIR: Path = Field(
        default=Path("./artifacts"), description="Local directory for raw cryptographic tool logs"
    )
    DB_PATH: Path = Field(
        default=Path("./argus.db"),
        description="SQLite database path used by the FastAPI assessment store",
    )
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///argus.db",
        description="Database connection URL for FastAPI and SQLite persistence",
    )

    # -------------------------------------------------------------
    # Execution Budgets & Timeouts
    # -------------------------------------------------------------
    DEFAULT_MAX_DURATION_SECONDS: int = Field(default=1800, ge=60, le=7200)
    DEFAULT_MAX_ITERATIONS: int = Field(default=20, ge=1, le=100)
    DEFAULT_MAX_MODEL_CALLS: int = Field(default=40, ge=1, le=200)
    DEFAULT_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=10)
    DEFAULT_TOOL_TIMEOUT_SECONDS: int = Field(default=120, ge=5, le=600)
    MAX_CONSECUTIVE_FAILURES: int = Field(default=3, ge=1, le=10)

    # -------------------------------------------------------------
    # Sponsor Gateway: Maxim AI Bifrost (Self-Hosted Open-Source)
    # -------------------------------------------------------------
    BIFROST_API_KEY: str = Field(
        default="",
        description="Bifrost Virtual Key (e.g. sk-bf-* or sk-bf-local for self-hosted instances)",
    )
    BIFROST_ADMIN_USERNAME: str = Field(
        default="",
        validation_alias=AliasChoices("ARGUS_BIFROST_ADMIN_USERNAME", "BIFROST_ADMIN_USERNAME"),
        description="Admin username for Bifrost HTTP Basic auth (e.g. admin)",
    )
    BIFROST_ADMIN_PASSWORD: str = Field(
        default="",
        validation_alias=AliasChoices("ARGUS_BIFROST_ADMIN_PASSWORD", "BIFROST_ADMIN_PASSWORD"),
        description="Admin password for Bifrost HTTP Basic auth",
    )
    BIFROST_BASE_URL: str = Field(
        default="http://localhost:8080/v1",
        description="Self-hosted open-source Bifrost proxy base URL (http://localhost:8080/v1)",
    )
    BIFROST_PRIMARY_MODEL: str = Field(
        default="anthropic/claude-3-5-sonnet-20241022",
        description="Provider-prefixed primary model (e.g. anthropic/claude-3-5-sonnet-20241022)",
    )
    BIFROST_FALLBACK_MODEL: str = Field(
        default="openai/gpt-4o",
        description="Provider-prefixed fallback model on provider outage (e.g. openai/gpt-4o)",
    )

    # -------------------------------------------------------------
    # Sponsor Gateway: Tavily Security Intelligence
    # -------------------------------------------------------------
    TAVILY_API_KEY: str = Field(
        default="", description="Tavily Search API Key for CVE & Advisory lookups"
    )

    # -------------------------------------------------------------
    # Observability: Langfuse (Tracing, Metrics, Tool & AI Tracking)
    # -------------------------------------------------------------
    LANGFUSE_PUBLIC_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("ARGUS_LANGFUSE_PUBLIC_KEY", "LANGFUSE_PUBLIC_KEY"),
        description="Langfuse public key (pk-lf-...)",
    )
    LANGFUSE_SECRET_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("ARGUS_LANGFUSE_SECRET_KEY", "LANGFUSE_SECRET_KEY"),
        description="Langfuse secret key (sk-lf-...)",
    )
    LANGFUSE_HOST: str = Field(
        default="https://cloud.langfuse.com",
        validation_alias=AliasChoices(
            "ARGUS_LANGFUSE_HOST",
            "LANGFUSE_HOST",
            "LANGFUSE_BASEURL",
            "ARGUS_LANGFUSE_BASEURL",
            "LANGFUSE_BASE_URL",
            "ARGUS_LANGFUSE_BASE_URL",
        ),
        description="Langfuse host URL (e.g. https://cloud.langfuse.com or self-hosted endpoint)",
    )
    LANGFUSE_ENABLED: bool = Field(
        default=True,
        validation_alias=AliasChoices("ARGUS_LANGFUSE_ENABLED", "LANGFUSE_ENABLED"),
        description="Feature flag: Enable Langfuse tracing when credentials are present",
    )

    # -------------------------------------------------------------
    # Security Policy & Firewall Defaults
    # -------------------------------------------------------------
    FORBIDDEN_ARG_TOKENS: tuple[str, ...] = (
        ";",
        "&&",
        "||",
        "`",
        "$(",
        ">",
        "<",
        "|",
        "--exec",
        "--script=vuln",
    )
    PROHIBITED_CATEGORIES: tuple[str, ...] = (
        "denial_of_service",
        "brute_force_credentials",
        "arbitrary_command_injection",
        "lateral_movement",
        "privilege_escalation",
    )

    # -------------------------------------------------------------
    # Feature Flags
    # -------------------------------------------------------------
    SIMULATION_MODE: bool = Field(
        default=False,
        description="Feature flag: Allow simulated tool outputs in non-production environments",
    )
    ENABLE_TAVILY_RESEARCH: bool = Field(
        default=True, description="Feature flag: Enable context-driven CVE lookups via Tavily"
    )
    ENABLE_PROVIDER_FALLBACK: bool = Field(
        default=True, description="Feature flag: Automatically fail over LLM models via Bifrost"
    )
    STRICT_SCOPE_ENFORCEMENT: bool = Field(
        default=True, description="Feature flag: Mandatory deterministic pre-execution scope checks"
    )
    ENABLE_PROOF_LEDGER: bool = Field(
        default=True,
        description="Feature flag: Record executed actions in append-only Merkle ledger and enforce T2 inclusion proofs",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Returns a cached singleton instance of Settings."""
    return Settings()

"""Global Configuration and Settings Management for ARGUS.

Follows backend-patterns and 12-Factor App design:
- Configuration is loaded from environment variables and optional .env file.
- Single source of truth for global constants, feature flags, limits, and paths.
- Zero hardcoded secrets with strict typing via pydantic-settings.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
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
    # Sponsor Gateway: Maxim AI Bifrost
    # -------------------------------------------------------------
    BIFROST_API_KEY: str = Field(default="", description="Maxim AI Bifrost API Gateway Key")
    BIFROST_BASE_URL: str = Field(
        default="https://bifrost.maxim.ai/v1", description="Bifrost proxy base URL"
    )
    BIFROST_PRIMARY_MODEL: str = Field(
        default="claude-3-5-sonnet-20241022", description="Default high-intelligence primary model"
    )
    BIFROST_FALLBACK_MODEL: str = Field(
        default="gpt-4o", description="Secondary fallback model on provider outage"
    )

    # -------------------------------------------------------------
    # Sponsor Gateway: Tavily Security Intelligence
    # -------------------------------------------------------------
    TAVILY_API_KEY: str = Field(
        default="", description="Tavily Search API Key for CVE & Advisory lookups"
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Returns a cached singleton instance of Settings."""
    return Settings()

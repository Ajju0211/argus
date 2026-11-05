"""Unit Tests for ARGUS Configuration Subsystem.

Verifies environment variable loading, override behavior, feature flags,
and singleton immutability per backend-patterns.
"""

import os

from core.config import Settings, get_settings


class TestConfiguration:
    """Test suite verifying central configuration management."""

    def test_default_settings_loaded(self) -> None:
        settings = get_settings()
        assert settings.ENV in ("development", "test", "production")
        assert settings.LOG_LEVEL == "INFO"
        assert settings.DEFAULT_MAX_ITERATIONS == 20
        assert settings.DEFAULT_MAX_DURATION_SECONDS == 1800
        assert settings.DEFAULT_TOOL_TIMEOUT_SECONDS == 120
        assert settings.MAX_CONSECUTIVE_FAILURES == 3

    def test_feature_flags_defaults(self) -> None:
        settings = get_settings()
        assert settings.SIMULATION_MODE is False
        assert settings.ENABLE_TAVILY_RESEARCH is True
        assert settings.ENABLE_PROVIDER_FALLBACK is True
        assert settings.STRICT_SCOPE_ENFORCEMENT is True

    def test_sponsor_gateway_defaults(self) -> None:
        settings = get_settings()
        assert settings.BIFROST_BASE_URL == "https://bifrost.maxim.ai/v1"
        assert "claude" in settings.BIFROST_PRIMARY_MODEL
        assert "gpt" in settings.BIFROST_FALLBACK_MODEL

    def test_forbidden_tokens_tuple(self) -> None:
        settings = get_settings()
        assert ";" in settings.FORBIDDEN_ARG_TOKENS
        assert "&&" in settings.FORBIDDEN_ARG_TOKENS
        assert "--script=vuln" in settings.FORBIDDEN_ARG_TOKENS
        assert "denial_of_service" in settings.PROHIBITED_CATEGORIES

    def test_environment_variable_override(self) -> None:
        os.environ["ARGUS_LOG_LEVEL"] = "DEBUG"
        os.environ["ARGUS_DEFAULT_MAX_ITERATIONS"] = "35"
        os.environ["ARGUS_ENABLE_TAVILY_RESEARCH"] = "false"

        try:
            custom_settings = Settings()
            assert custom_settings.LOG_LEVEL == "DEBUG"
            assert custom_settings.DEFAULT_MAX_ITERATIONS == 35
            assert custom_settings.ENABLE_TAVILY_RESEARCH is False
        finally:
            del os.environ["ARGUS_LOG_LEVEL"]
            del os.environ["ARGUS_DEFAULT_MAX_ITERATIONS"]
            del os.environ["ARGUS_ENABLE_TAVILY_RESEARCH"]

    def test_settings_singleton_caching(self) -> None:
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

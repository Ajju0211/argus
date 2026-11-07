"""Unit tests for hardened process runner and subprocess sanitization (P0.2, P0.4)."""

import asyncio
import sys

import pytest

from core.executor.process_runner import (
    get_sanitized_env,
    run_tool_process,
    terminate_active_processes,
)


def test_get_sanitized_env_strips_sensitive_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-sensitive-12345")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-secret")
    monkeypatch.setenv("ARGUS_DATABASE_URL", "sqlite:///sensitive.db")
    monkeypatch.setenv("JWT_SECRET", "super-secret-key")
    monkeypatch.setenv("DB_PASSWORD", "admin123")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("LANG", "en_US.UTF-8")

    env = get_sanitized_env()

    # Safe vars preserved
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["LANG"] == "en_US.UTF-8"
    assert env["HOME"] == "/tmp"
    assert env["TMPDIR"] == "/tmp"

    # Sensitive vars excluded
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "ARGUS_DATABASE_URL",
        "JWT_SECRET",
        "DB_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
    ):
        assert key not in env


def test_get_sanitized_env_filters_extra_env() -> None:
    extra = {
        "CUSTOM_TOOL_FLAG": "1",
        "LEAKED_API_KEY": "leaked",
        "SECRET_TOKEN": "token",
    }
    env = get_sanitized_env(extra_env=extra)
    assert env["CUSTOM_TOOL_FLAG"] == "1"
    assert "LEAKED_API_KEY" not in env
    assert "SECRET_TOKEN" not in env


@pytest.mark.asyncio
async def test_subprocess_does_not_inherit_parent_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_LEAK_TEST_KEY", "leaked-secret-value-123")

    # Command runs python to check if SECRET_LEAK_TEST_KEY exists in child environment
    cmd = [
        sys.executable,
        "-c",
        "import os; print('PRESENT' if 'SECRET_LEAK_TEST_KEY' in os.environ else 'ABSENT')",
    ]
    retcode, stdout, _stderr = await run_tool_process(cmd, timeout_seconds=5)
    assert retcode == 0
    assert "ABSENT" in stdout.strip()


@pytest.mark.asyncio
async def test_process_registry_and_termination() -> None:
    assessment_id = "test-asm-process-abort"

    # Launch a background long-running command
    cmd = [sys.executable, "-c", "import time; time.sleep(30)"]

    task = asyncio.create_task(
        run_tool_process(cmd, timeout_seconds=30, assessment_id=assessment_id)
    )

    # Allow process to start
    await asyncio.sleep(0.3)

    # Terminate active processes for assessment
    terminated_count = terminate_active_processes(assessment_id)
    assert terminated_count >= 1

    # Task should finish or raise
    try:
        retcode, _stdout, _stderr = await asyncio.wait_for(task, timeout=3.0)
        # Should have non-zero or negative return code due to SIGTERM/SIGKILL
        assert retcode != 0
    except (asyncio.CancelledError, TimeoutError, OSError):
        pass

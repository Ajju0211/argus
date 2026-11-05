"""Integration test suite for Maxim AI Bifrost Model Gateway (Module 05).

Verifies multi-provider routing, Claude 3.5 Sonnet primary path,
GPT-4o fallback resilience, structured Pydantic completion, and telemetry logging.
"""

import json
from typing import Any

import httpx
import pytest

from integrations.bifrost.bifrost_client import BifrostAPIError, BifrostClient
from integrations.bifrost.telemetry import BifrostTelemetry
from packages.contracts.actions import (
    AssessmentDecision,
    DecisionType,
)


@pytest.fixture
def sample_decision_json() -> str:
    return json.dumps(
        {
            "decision_type": "EXECUTE_ACTION",
            "rationale": "Port 8080 open; enumerating Apache version",
            "proposed_action": {
                "action_id": "act-bifrost-001",
                "target_host": "192.168.100.5",
                "target_port": 8080,
                "tool_name": "nmap",
                "action_category": "network_recon",
                "arguments": {"flags": "-sV -p 8080"},
                "rationale": "Banner discovery on port 8080",
                "expected_evidence": "Apache version banner",
                "timeout_seconds": 60,
            },
            "intel_query": None,
            "completion_summary": None,
        }
    )


class TestBifrostClient:
    """Verifies Bifrost model gateway functionality using mock HTTP transports."""

    @pytest.mark.asyncio
    async def test_successful_structured_completion(self, sample_decision_json: str) -> None:
        """Verifies primary Claude 3.5 Sonnet completion and telemetry extraction."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/v1/chat/completions"
            assert request.headers.get("Authorization") == "Bearer test-bifrost-key"
            assert request.headers.get("X-Bifrost-Fallback") == "gpt-4o"

            body = json.loads(request.content.decode("utf-8"))
            assert body["model"] == "claude-3-5-sonnet-20241022"

            response_data: dict[str, Any] = {
                "id": "chatcmpl-test-01",
                "model": "claude-3-5-sonnet-20241022",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": sample_decision_json,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 350,
                    "completion_tokens": 120,
                    "total_tokens": 470,
                },
            }
            headers = {
                "X-Bifrost-Provider": "anthropic",
                "X-Bifrost-Fallback-Triggered": "false",
            }
            return httpx.Response(200, json=response_data, headers=headers)

        transport = httpx.MockTransport(handler)
        client = BifrostClient(
            api_key="test-bifrost-key",
            base_url="https://bifrost.maxim.ai/v1",
            transport=transport,
        )

        decision, telemetry = await client.complete_structured(
            prompt="Analyze open ports and propose next step.",
            schema=AssessmentDecision,
        )

        # Assert structured decision parsed into Pydantic model
        assert isinstance(decision, AssessmentDecision)
        assert decision.decision_type == DecisionType.EXECUTE_ACTION
        assert decision.proposed_action is not None
        assert decision.proposed_action.tool_name == "nmap"

        # Assert telemetry
        assert isinstance(telemetry, BifrostTelemetry)
        assert telemetry.provider_used == "anthropic"
        assert telemetry.model_used == "claude-3-5-sonnet-20241022"
        assert telemetry.prompt_tokens == 350
        assert telemetry.completion_tokens == 120
        assert telemetry.total_tokens == 470
        assert telemetry.fallback_triggered is False
        assert telemetry.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_fallback_resilience(self, sample_decision_json: str) -> None:
        """Verifies automatic fallback to GPT-4o when primary provider experiences outage."""

        def handler(request: httpx.Request) -> httpx.Response:
            response_data: dict[str, Any] = {
                "id": "chatcmpl-fallback-01",
                "model": "gpt-4o",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": sample_decision_json,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 380,
                    "completion_tokens": 115,
                    "total_tokens": 495,
                },
            }
            # Bifrost returns response from secondary provider
            headers = {
                "X-Bifrost-Provider": "openai",
                "X-Bifrost-Fallback-Triggered": "true",
            }
            return httpx.Response(200, json=response_data, headers=headers)

        transport = httpx.MockTransport(handler)
        client = BifrostClient(
            api_key="test-bifrost-key",
            transport=transport,
        )

        decision, telemetry = await client.complete_structured(
            prompt="Plan next action after timeout.",
            schema=AssessmentDecision,
        )

        assert decision.decision_type == DecisionType.EXECUTE_ACTION
        assert telemetry.provider_used == "openai"
        assert telemetry.model_used == "gpt-4o"
        assert telemetry.fallback_triggered is True

    @pytest.mark.asyncio
    async def test_markdown_fence_stripping(self, sample_decision_json: str) -> None:
        """Verifies JSON enclosed in markdown code fences is cleaned and parsed."""
        fenced_content = f"```json\n{sample_decision_json}\n```"

        def handler(request: httpx.Request) -> httpx.Response:
            response_data: dict[str, Any] = {
                "choices": [{"message": {"content": fenced_content}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
            return httpx.Response(200, json=response_data)

        transport = httpx.MockTransport(handler)
        client = BifrostClient(api_key="test-key", transport=transport)

        decision, _ = await client.complete_structured(prompt="test", schema=AssessmentDecision)
        assert decision.decision_type == DecisionType.EXECUTE_ACTION

    @pytest.mark.asyncio
    async def test_api_error_handling(self) -> None:
        """Verifies 4xx and 5xx responses raise BifrostAPIError with context."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"message": "Invalid Bifrost API Key"}})

        transport = httpx.MockTransport(handler)
        client = BifrostClient(api_key="bad-key", transport=transport)

        with pytest.raises(BifrostAPIError, match="401"):
            await client.complete_structured(prompt="test", schema=AssessmentDecision)

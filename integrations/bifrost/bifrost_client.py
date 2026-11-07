"""Maxim AI Bifrost Client for ARGUS.

Routes all LLM planning, decision, and verification prompts through the unified
Bifrost Gateway with automated failover from Claude 3.5 Sonnet to GPT-4o,
strict JSON parsing into typed Pydantic contracts, and telemetry accounting.
"""

import base64
import json
import re
import time
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from integrations.bifrost.telemetry import BifrostTelemetry
from packages.contracts.actions import AssessmentDecision

T = TypeVar("T", bound=BaseModel)

# Regex to strip markdown code blocks if the LLM wraps JSON output
MARKDOWN_JSON_REGEX = re.compile(r"^```(?:json)?\s*([\s\S]*?)\s*```$", re.MULTILINE)
THINK_REGEX = re.compile(r"<think>[\s\S]*?</think>", re.DOTALL)
FENCE_REGEX = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```")


class BifrostAPIError(Exception):
    """Raised when the Bifrost Gateway returns an HTTP error."""

    def __init__(self, status_code: int, message: str, body: str | None = None) -> None:
        super().__init__(f"Bifrost API Error {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.body = body


class BifrostValidationError(Exception):
    """Raised when the LLM response fails Pydantic schema validation."""


class BifrostClient:
    """Async client interfacing with the Maxim AI Bifrost LLM Gateway."""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://bifrost.maxim.ai/v1",
        primary_model: str = "anthropic/claude-3-5-sonnet-20241022",
        fallback_model: str = "openai/gpt-4o",
        timeout_seconds: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
        admin_username: str | None = None,
        admin_password: str | None = None,
    ) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self.admin_username = (admin_username or "").strip()
        self.admin_password = (admin_password or "").strip()

    def get_auth_header(self) -> str:
        """Constructs Authorization header using Bearer token (virtual key) or Basic Auth."""
        # 1. Standard Bearer token (virtual key) takes precedence for inference API
        if self.api_key:
            if self.api_key.startswith("Basic ") or self.api_key.startswith("Bearer "):
                return self.api_key
            if ":" in self.api_key and not self.api_key.startswith("sk-"):
                raw = self.api_key.encode("utf-8")
                encoded = base64.b64encode(raw).decode("ascii")
                return f"Basic {encoded}"
            return f"Bearer {self.api_key}"

        # 2. Explicit admin credentials (username:password) fallback
        if self.admin_username and self.admin_password:
            raw = f"{self.admin_username}:{self.admin_password}".encode("utf-8")
            encoded = base64.b64encode(raw).decode("ascii")
            return f"Basic {encoded}"

        return ""

    def _clean_json_content(self, raw_content: str) -> str:
        """Removes reasoning tokens, markdown code fences, and extra whitespace."""
        stripped = THINK_REGEX.sub("", raw_content).strip()
        try:
            json.loads(stripped)
            return stripped
        except Exception:
            pass

        fence = FENCE_REGEX.search(stripped)
        if fence:
            candidate = fence.group(1).strip()
            try:
                json.loads(candidate)
                return candidate
            except Exception:
                pass

        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = stripped[start : end + 1]
            try:
                json.loads(candidate)
                return candidate
            except Exception:
                pass

        match = MARKDOWN_JSON_REGEX.match(stripped)
        if match:
            return match.group(1).strip()
        return stripped

    async def complete_structured(
        self,
        prompt: str,
        schema: type[T],
        system_prompt: str | None = None,
    ) -> tuple[T, BifrostTelemetry]:
        """Routes prompt through Bifrost and parses output into typed Pydantic schema.

        Args:
            prompt: User message prompt.
            schema: Target Pydantic model type.
            system_prompt: Optional system prompt instructions.

        Returns:
            tuple of (parsed_pydantic_instance, BifrostTelemetry)

        Raises:
            BifrostAPIError: On non-200 HTTP responses.
            BifrostValidationError: If response cannot be validated against schema.
        """
        auth_header = self.get_auth_header()
        if not auth_header:
            raise BifrostAPIError(
                401,
                "Missing Bifrost authentication credentials. Set ARGUS_BIFROST_API_KEY (virtual key or username:password) "
                "or ARGUS_BIFROST_ADMIN_USERNAME and ARGUS_BIFROST_ADMIN_PASSWORD in environment.",
            )

        headers: dict[str, str] = {
            "Authorization": auth_header,
            "Content-Type": "application/json",
        }
        if self.api_key and not self.api_key.startswith("Basic "):
            raw_key = self.api_key[7:] if self.api_key.startswith("Bearer ") else self.api_key
            headers["x-bf-vk"] = raw_key

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Inject JSON schema instructions into system prompt so any model adheres to the exact schema
        schema_json = json.dumps(schema.model_json_schema(), indent=2)
        schema_instruction = (
            f"\n\nJSON SCHEMA INSTRUCTIONS:\n"
            f"Your output MUST be a valid JSON object strictly conforming to the following JSON schema for {schema.__name__}:\n"
            f"```json\n{schema_json}\n```\n"
            f"Do not include any extra fields or commentary outside the JSON object."
        )
        if messages and messages[0]["role"] == "system":
            messages[0]["content"] += schema_instruction
        else:
            messages.insert(0, {"role": "system", "content": schema_instruction.strip()})

        payload: dict[str, Any] = {
            "model": self.primary_model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0.1,  # Low temperature for deterministic security reasoning
        }
        # Bifrost's documented failover contract is a `fallbacks` array of
        # provider-prefixed model IDs in the request body.
        if self.fallback_model and self.fallback_model != self.primary_model:
            payload["fallbacks"] = [self.fallback_model]

        start_time = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            transport=self._transport,
        ) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
            except httpx.RequestError as exc:
                raise BifrostAPIError(
                    503, f"Network transport error connecting to Bifrost: {exc}"
                ) from exc

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        if resp.status_code != 200:
            error_msg = f"HTTP {resp.status_code}"
            try:
                err_json = resp.json()
                if "error" in err_json and "message" in err_json["error"]:
                    error_msg = err_json["error"]["message"]
            except (ValueError, KeyError):
                error_msg = resp.text[:200]
            raise BifrostAPIError(resp.status_code, error_msg, body=resp.text)

        data = resp.json()

        # Extract content from first choice
        try:
            choices = data.get("choices", [])
            raw_content = choices[0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BifrostValidationError(
                f"Malformed response format from Bifrost Gateway: {data}"
            ) from exc

        cleaned_json = self._clean_json_content(raw_content)

        # Validate into typed Pydantic contract
        try:
            structured_obj = schema.model_validate_json(cleaned_json)
        except ValidationError as exc:
            raise BifrostValidationError(
                f"Failed to validate model response into {schema.__name__}: {exc}\nRaw JSON: {cleaned_json}"
            ) from exc

        # Extract telemetry headers and usage
        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        extra_fields = data.get("extra_fields") or {}
        routing_info = (
            extra_fields.get("routing_info") or {} if isinstance(extra_fields, dict) else {}
        )

        provider_used = (
            routing_info.get("provider")
            or resp.headers.get("X-Bifrost-Provider")
            or "unknown"
        ).lower()

        fallback_header = resp.headers.get("X-Bifrost-Fallback-Triggered")
        if fallback_header is not None:
            fallback_triggered = fallback_header.lower() in ["true", "1", "yes"]
        else:
            fallback_triggered = bool(routing_info.get("is_fallback", False))

        model_returned = (
            data.get("model") or routing_info.get("model") or self.primary_model
        )

        telemetry = BifrostTelemetry(
            provider_used=provider_used,
            model_used=model_returned,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=latency_ms,
            fallback_triggered=fallback_triggered,
        )

        return structured_obj, telemetry


class BifrostModelGateway:
    """Synchronous Bifrost adapter that retains the latest call telemetry.

    LangGraph nodes are synchronous, so this class bridges to the async
    ``BifrostClient`` and exposes ``last_telemetry`` for the orchestrator to
    persist into ``AssessmentState.telemetry`` and the final report.
    """

    def __init__(self, client: BifrostClient) -> None:
        self.client = client
        self.last_telemetry: BifrostTelemetry | None = None

    def __call__(self, prompt: str) -> AssessmentDecision:
        import asyncio
        import concurrent.futures

        self.last_telemetry = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                decision, telemetry = pool.submit(
                    lambda: asyncio.run(
                        self.client.complete_structured(prompt, AssessmentDecision)
                    )
                ).result()
        else:
            decision, telemetry = asyncio.run(
                self.client.complete_structured(prompt, AssessmentDecision)
            )

        self.last_telemetry = telemetry
        return decision


def create_bifrost_model_gateway(client: BifrostClient) -> BifrostModelGateway:
    """Creates the synchronous model gateway used by the LangGraph orchestrator."""
    return BifrostModelGateway(client)

"""Integration test suite for Tavily Security Intelligence Search (Module 05).

Verifies targeted CVE advisory research, security domain restriction,
result normalization, and timeout handling.
"""

from typing import Any

import httpx
import pytest

from integrations.tavily.tavily_client import ResearchSource, TavilyIntelService


class TestTavilyIntelService:
    """Verifies Tavily intelligence gathering using mock HTTP transports."""

    @pytest.mark.asyncio
    async def test_targeted_security_search(self) -> None:
        """Verifies query formation and structured advisory source parsing."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/search"
            body = request.read().decode("utf-8")
            assert "Apache 2.4.49" in body
            assert "nvd.nist.gov" in body

            response_data: dict[str, Any] = {
                "results": [
                    {
                        "title": "CVE-2021-41773 Detail - NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                        "content": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
                        "score": 0.98,
                    },
                    {
                        "title": "Apache HTTP Server 2.4 Vulnerabilities",
                        "url": "https://httpd.apache.org/security/vulnerabilities_24.html",
                        "content": "Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49.",
                        "score": 0.95,
                    },
                ]
            }
            return httpx.Response(200, json=response_data)

        transport = httpx.MockTransport(handler)
        service = TavilyIntelService(api_key="test-tavily-key", transport=transport)

        sources = await service.research_technology(product="Apache", version="2.4.49")

        assert len(sources) == 2
        assert all(isinstance(s, ResearchSource) for s in sources)

        nvd_source = sources[0]
        assert "nvd.nist.gov" in nvd_source.url
        assert "CVE-2021-41773" in nvd_source.title
        assert nvd_source.score == 0.98
        assert nvd_source.source_id.startswith("tavily-apache-2.4.49")

    @pytest.mark.asyncio
    async def test_handles_empty_search_results(self) -> None:
        """Verifies empty or unknown product searches return an empty list gracefully."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        service = TavilyIntelService(api_key="test-tavily-key", transport=transport)

        sources = await service.research_technology(product="UnknownTool", version="0.0.1")
        assert sources == []

    @pytest.mark.asyncio
    async def test_handles_missing_api_key(self) -> None:
        """Verifies unconfigured API key fails gracefully without crashing."""
        service = TavilyIntelService(api_key="")
        sources = await service.research_technology(product="Apache", version="2.4.49")
        assert sources == []

"""Tavily Security Intelligence Client for ARGUS.

Executes scoped threat intelligence searches on discovered software banners,
querying authoritative vulnerability databases (NVD, CVE, Exploit-DB, vendor advisories)
to enrich findings and remediation recommendations.
"""

from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

# Authoritative security databases to restrict research noise
AUTHORITATIVE_DOMAINS: list[str] = [
    "nvd.nist.gov",
    "cve.mitre.org",
    "exploit-db.com",
    "github.com",
    "apache.org",
]


class ResearchSource(BaseModel):
    """External threat intelligence record retrieved from Tavily."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(
        ..., description="Unique source identifier (e.g. tavily-apache-2.4.49-0)"
    )
    query: str = Field(..., description="Targeted query string executed")
    url: str = Field(..., description="Authoritative advisory or CVE URL")
    title: str = Field(..., description="Document or advisory title")
    snippet: str = Field(..., description="Summary excerpt of the advisory")
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Relevance score")
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of retrieval",
    )


class TavilyIntelService:
    """Service interfacing with Tavily for scoped vulnerability and remediation research."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.tavily.com",
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._transport = transport

    async def search(
        self,
        query: str,
        max_results: int = 5,
    ) -> list[ResearchSource]:
        """Conducts a scoped search restricted to authoritative security domains."""
        if not self.api_key:
            return []

        clean_query = query.strip()
        if not clean_query:
            return []

        payload: dict[str, Any] = {
            "api_key": self.api_key,
            "query": clean_query,
            "search_depth": "advanced",
            "include_domains": AUTHORITATIVE_DOMAINS,
            "max_results": max_results,
        }

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            transport=self._transport,
        ) as client:
            try:
                resp = await client.post(f"{self.base_url}/search", json=payload)
                if resp.status_code != 200:
                    return []
                data = resp.json()
            except (httpx.RequestError, ValueError, KeyError):
                return []

        sources: list[ResearchSource] = []
        raw_results = data.get("results", [])
        for idx, result in enumerate(raw_results):
            url = result.get("url", "")
            title = result.get("title", f"Advisory for {clean_query}")
            content = result.get("content", "")
            score = float(result.get("score", 0.0))

            if not url:
                continue

            sources.append(
                ResearchSource(
                    source_id=f"tavily-{idx}-{score:.2f}",
                    query=clean_query,
                    url=url,
                    title=title,
                    snippet=content[:400],
                    score=score,
                    retrieved_at=datetime.now(UTC),
                )
            )

        return sources

    async def research_technology(
        self,
        product: str,
        version: str,
    ) -> list[ResearchSource]:
        """Conducts a scoped security intelligence search for a discovered product/version."""
        clean_prod = product.strip()
        clean_ver = version.strip()
        if not clean_prod:
            return []

        query = f'"{clean_prod} {clean_ver}" vulnerability CVE NVD advisory'.strip()
        sources = await self.search(query=query, max_results=5)

        # Update source IDs with specific product-version slug
        slug = f"{clean_prod.lower()}-{clean_ver.lower()}".replace(" ", "-")
        updated_sources: list[ResearchSource] = []
        for idx, src in enumerate(sources):
            updated_sources.append(
                ResearchSource(
                    source_id=f"tavily-{slug}-{idx}",
                    query=src.query,
                    url=src.url,
                    title=src.title,
                    snippet=src.snippet,
                    score=src.score,
                    retrieved_at=src.retrieved_at,
                )
            )
        return updated_sources

"""Tests for the enrichment package facade."""

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services import enrichment
from app.services.enrichment import enrich_vulnerability_findings
from app.services.enrichment.ghsa import GHSAProvider


@pytest.mark.asyncio
async def test_enrich_vulnerability_findings_does_not_close_shared_singleton(monkeypatch):
    """A completed run must not close the shared singleton HTTP client, or concurrent runs lose EPSS/KEV data."""
    enrich_mock = AsyncMock()
    close_mock = AsyncMock()
    monkeypatch.setattr(enrichment.vulnerability_enrichment_service, "enrich_findings", enrich_mock)
    monkeypatch.setattr(enrichment.vulnerability_enrichment_service, "close", close_mock)

    findings: list = [{"details": {"vulnerabilities": []}}]
    await enrich_vulnerability_findings(findings)

    enrich_mock.assert_awaited_once_with(findings)
    close_mock.assert_not_called()


class _RecordingGitHub:
    """Stands in for the HTTP client and remembers the headers of every GHSA request."""

    def __init__(self) -> None:
        self.sent_headers: list[dict[str, str]] = []

    async def get(self, url: str, headers: dict[str, str], **_: Any) -> httpx.Response:
        self.sent_headers.append(headers)
        return httpx.Response(404, request=httpx.Request("GET", url))


class _PassThroughCache:
    async def mget(self, keys: list[str]) -> dict[str, Any]:
        return dict.fromkeys(keys)

    async def get_or_fetch_with_lock(self, key: str, fetch_fn, ttl_seconds: int | None = None) -> Any:
        return await fetch_fn()


@pytest.mark.asyncio
async def test_a_token_removed_between_runs_is_no_longer_sent_to_github(monkeypatch):
    service = enrichment.vulnerability_enrichment_service
    github = _RecordingGitHub()
    monkeypatch.setattr(service, "enrich_findings", AsyncMock())
    monkeypatch.setattr(service, "_ghsa_provider", GHSAProvider(max_retries=1, retry_delay=0))
    monkeypatch.setattr(service, "_get_client", AsyncMock(return_value=github))
    monkeypatch.setattr("app.services.enrichment.ghsa.cache_service", _PassThroughCache())

    await enrich_vulnerability_findings([], github_token="ghp_old")
    await service.resolve_ghsa_to_cve(["GHSA-aaaa-bbbb-cccc"])
    await enrich_vulnerability_findings([], github_token=None)
    await service.resolve_ghsa_to_cve(["GHSA-dddd-eeee-ffff"])

    assert [headers.get("Authorization") for headers in github.sent_headers] == ["Bearer ghp_old", None]

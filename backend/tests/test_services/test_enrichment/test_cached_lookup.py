"""Tests for how the EPSS and GHSA providers read their batch cache hits."""

from typing import Any

import pytest

from app.core.cache import CacheKeys
from app.schemas.enrichment import EPSSData, GHSAData
from app.services.enrichment.epss import EPSSProvider
from app.services.enrichment.ghsa import GHSAProvider


class _FakeCache:
    """Answers mget like CacheService: one entry per distinct key, None for a miss."""

    def __init__(self, stored: dict[str, Any]) -> None:
        self.stored = stored

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        return {key: self.stored.get(key) for key in keys}


def _epss(cve: str, score: float) -> dict[str, Any]:
    return EPSSData(cve=cve, epss_score=score, percentile=50.0, date="2026-09-01").model_dump()


@pytest.fixture
def epss_with_one_cached_score(monkeypatch):
    stored = {CacheKeys.epss("CVE-2024-0002"): _epss("CVE-2024-0002", 0.9)}
    monkeypatch.setattr("app.services.enrichment.epss.cache_service", _FakeCache(stored))
    fetched: list[str] = []

    async def fake_fetch(_client, missing, _result):
        fetched.extend(missing)

    provider = EPSSProvider()
    monkeypatch.setattr(provider, "_fetch_and_cache_batches", fake_fetch)
    return provider, fetched


@pytest.mark.asyncio
async def test_each_cve_reads_its_own_cached_epss_score(epss_with_one_cached_score):
    provider, fetched = epss_with_one_cached_score

    result = await provider.load_epss_scores(None, ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"])

    assert list(result) == ["CVE-2024-0002"]
    assert result["CVE-2024-0002"].epss_score == 0.9
    assert fetched == ["CVE-2024-0001", "CVE-2024-0003"]


@pytest.mark.asyncio
async def test_a_repeated_cve_does_not_shift_the_next_cves_epss_score(epss_with_one_cached_score):
    provider, fetched = epss_with_one_cached_score

    result = await provider.load_epss_scores(None, ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"])

    assert list(result) == ["CVE-2024-0002"]
    assert result["CVE-2024-0002"].epss_score == 0.9
    assert set(fetched) == {"CVE-2024-0001"}


@pytest.mark.asyncio
async def test_each_ghsa_id_reads_its_own_cached_advisory(monkeypatch):
    cached = GHSAData(ghsa_id="GHSA-bbbb", cve_id="CVE-2024-0002").model_dump()
    monkeypatch.setattr("app.services.enrichment.ghsa.cache_service", _FakeCache({CacheKeys.ghsa("GHSA-bbbb"): cached}))
    provider = GHSAProvider(max_retries=1, retry_delay=0)

    async def fake_fetch(_client, ghsa_id):
        return GHSAData(ghsa_id=ghsa_id, cve_id=f"CVE-FETCHED-{ghsa_id}")

    monkeypatch.setattr(provider, "fetch_ghsa_advisory", fake_fetch)

    result = await provider.resolve_ghsa_to_cve(None, ["GHSA-aaaa", "GHSA-aaaa", "GHSA-bbbb"])

    assert result["GHSA-bbbb"].cve_id == "CVE-2024-0002"
    assert result["GHSA-aaaa"].cve_id == "CVE-FETCHED-GHSA-aaaa"

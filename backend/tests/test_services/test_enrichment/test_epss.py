"""EPSS scores from FIRST.org: what is cached, what is fetched, and when the answer is incomplete."""

import asyncio

import httpx
import pytest

from app.core.cache import CacheKeys, CacheTTL
from app.schemas.enrichment import EPSSData
from app.services.enrichment.service import vulnerability_enrichment_service
from tests.helpers.enrichment import FIRST_HOST, Upstreams, epss_page, serve_enrichment

_SCORED = "CVE-2021-44228"
_UNSCORED = "CVE-2026-99999"


async def _load(*cves: str) -> tuple[dict[str, EPSSData], bool]:
    return await vulnerability_enrichment_service._epss_provider.load_epss_scores(list(cves))


async def _ttl(cache, cve: str) -> int:
    return await cache._client.ttl(cache._make_key(CacheKeys.epss(cve)))


@pytest.mark.asyncio
async def test_a_cve_without_a_score_is_not_asked_for_again_within_the_hour(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(scores={_SCORED: 0.94}))

    first = await _load(_SCORED, _UNSCORED)
    second = await _load(_SCORED, _UNSCORED)

    assert len(seen) == 1
    assert first == second
    scores, complete = second
    assert complete is True
    assert list(scores) == [_SCORED]
    assert CacheTTL.NEGATIVE_RESULT - 5 < await _ttl(fake_cache, _UNSCORED) <= CacheTTL.NEGATIVE_RESULT
    assert await _ttl(fake_cache, _SCORED) > CacheTTL.NEGATIVE_RESULT


@pytest.mark.asyncio
async def test_a_failed_batch_is_reported_and_nothing_of_it_is_cached(fake_cache, monkeypatch):
    serve_enrichment(monkeypatch, fake_cache, Upstreams(down=frozenset({FIRST_HOST})))

    scores, complete = await _load(_SCORED, _UNSCORED)

    assert (scores, complete) == ({}, False)
    assert list((await fake_cache.mget([CacheKeys.epss(_SCORED), CacheKeys.epss(_UNSCORED)])).values()) == [None] * 2


@pytest.mark.asyncio
async def test_uncached_batches_are_fetched_side_by_side(fake_cache, monkeypatch):
    live = peak = 0

    async def answer(request: httpx.Request) -> httpx.Response:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return httpx.Response(200, json=epss_page({}))

    seen = serve_enrichment(monkeypatch, fake_cache, answer)

    await _load(*(f"CVE-2026-{n:05d}" for n in range(250)))

    assert len(seen) == 3
    assert peak == 3


@pytest.mark.asyncio
async def test_each_cve_reads_its_own_cached_epss_score(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams())
    cached = EPSSData(cve=_SCORED, epss_score=0.9, percentile=50.0, date="2026-09-01")
    await fake_cache.set(CacheKeys.epss(_SCORED), cached.model_dump())

    scores, _ = await _load(_UNSCORED, _UNSCORED, _SCORED)

    assert scores == {_SCORED: cached}
    assert [set(r.url.params["cve"].split(",")) for r in seen] == [{_UNSCORED}]

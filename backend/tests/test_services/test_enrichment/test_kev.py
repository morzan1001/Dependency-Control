import asyncio
import time

import httpx
import pytest

from app.core.cache import CacheKeys, CacheTTL
from app.core.config import settings
from app.services.enrichment.service import vulnerability_enrichment_service
from tests.helpers.enrichment import CISA_HOST, Upstreams, serve_enrichment

_LOG4SHELL = "CVE-2021-44228"
_PAST_THE_MEMO = 16 * 60


def _clock(monkeypatch) -> list[float]:
    """time.monotonic, moved forward by the returned offset; asyncio keeps reading a clock that still ticks."""
    offset = [0.0]
    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + offset[0])
    return offset


async def _load():
    return await vulnerability_enrichment_service._kev_provider.load_kev_catalog()


@pytest.mark.asyncio
async def test_catalog_entries_are_keyed_by_the_cisa_cve_id_field(fake_cache, monkeypatch):
    """CISA spells it `cveID`; any other spelling silently empties the whole catalog."""
    serve_enrichment(monkeypatch, fake_cache, Upstreams(kev=(_LOG4SHELL,)))

    catalog = await _load()

    assert list(catalog) == [_LOG4SHELL]
    entry = catalog[_LOG4SHELL]
    assert (entry.date_added, entry.due_date) == ("2021-12-10", "2021-12-24")
    assert entry.required_action == "Apply updates per vendor instructions."
    assert entry.known_ransomware_use is True


@pytest.mark.asyncio
@pytest.mark.parametrize("upstream", [Upstreams(), Upstreams(down=frozenset({CISA_HOST}))], ids=["empty", "down"])
async def test_a_catalog_that_could_not_be_read_is_unavailable_and_not_cached(fake_cache, monkeypatch, upstream):
    """Caching an empty catalog would blind every scan for the whole KEV TTL."""
    serve_enrichment(monkeypatch, fake_cache, upstream)

    assert await _load() is None
    assert await fake_cache.get(CacheKeys.kev_catalog()) is None


@pytest.mark.asyncio
async def test_a_leftover_negative_cache_entry_reads_as_unavailable(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(kev=(_LOG4SHELL,)))
    await fake_cache.set(CacheKeys.kev_catalog(), {}, CacheTTL.NEGATIVE_RESULT)

    assert await _load() is None
    assert seen == []


@pytest.mark.asyncio
async def test_the_catalog_is_kept_in_process_between_calls(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(kev=(_LOG4SHELL,)))
    first = await _load()
    await fake_cache._client.delete(fake_cache._make_key(CacheKeys.kev_catalog()))

    assert await _load() == first
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_a_failed_refresh_keeps_the_last_catalog_and_is_retried_a_minute_later(fake_cache, monkeypatch):
    cisa_down = [False]
    healthy = Upstreams(kev=(_LOG4SHELL,))
    seen = serve_enrichment(monkeypatch, fake_cache, lambda r: httpx.Response(503) if cisa_down[0] else healthy(r))
    offset = _clock(monkeypatch)
    first = await _load()
    await fake_cache._client.delete(fake_cache._make_key(CacheKeys.kev_catalog()))
    cisa_down[0] = True
    offset[0] += _PAST_THE_MEMO

    assert await _load() == first
    failed_refresh = len(seen)
    assert failed_refresh > 1
    assert await _load() == first
    assert len(seen) == failed_refresh

    offset[0] += 61
    assert await _load() == first
    assert len(seen) > failed_refresh


@pytest.mark.asyncio
async def test_a_catalog_that_never_loaded_is_not_asked_for_again_within_the_minute(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(down=frozenset({CISA_HOST})))

    assert await _load() is None
    asked = len(seen)
    assert await _load() is None
    assert len(seen) == asked


@pytest.mark.asyncio
async def test_callers_arriving_together_share_one_refresh(fake_cache, monkeypatch):
    monkeypatch.setattr(settings, "ENRICHMENT_MAX_RETRIES", 0)

    async def slow_outage(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.01)
        return httpx.Response(503)

    seen = serve_enrichment(monkeypatch, fake_cache, slow_outage)

    assert await asyncio.gather(_load(), _load(), _load()) == [None] * 3
    assert len(seen) == 1

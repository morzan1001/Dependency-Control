"""The CISA KEV catalog: how it is read, when it counts as unavailable, and how long a pod keeps it."""

import pytest

from app.core.cache import CacheKeys
from app.services.enrichment.service import vulnerability_enrichment_service
from tests.helpers.enrichment import CISA_HOST, Upstreams, serve_enrichment

_LOG4SHELL = "CVE-2021-44228"


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
    await fake_cache.set(CacheKeys.kev_catalog(), {})

    assert await _load() is None
    assert seen == []


@pytest.mark.asyncio
async def test_the_catalog_is_kept_in_process_between_calls(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(kev=(_LOG4SHELL,)))
    first = await _load()
    await fake_cache._client.delete(fake_cache._make_key(CacheKeys.kev_catalog()))

    assert await _load() == first
    assert len(seen) == 1

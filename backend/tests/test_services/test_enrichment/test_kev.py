"""Tests for the CISA KEV catalog loader."""

from typing import Any

import pytest

from app.core.cache import CacheKeys
from app.services.enrichment.kev import KEVProvider

_CATALOG_ENTRY = {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded": "2021-12-10",
    "shortDescription": "JNDI features do not protect against attacker-controlled LDAP.",
    "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
}


class _Response:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _Client:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    async def get(self, _url: str, **_kwargs: Any) -> _Response:
        return _Response(self._payload)


class _FakeCache:
    """Mirrors get_or_fetch_with_lock's own rule: only a non-None fetch is stored for the full TTL."""

    def __init__(self) -> None:
        self.stored: dict[str, Any] = {}

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, **_kwargs: Any) -> Any:
        data = await fetch_fn()
        if data is not None:
            self.stored[key] = data
        return data


@pytest.fixture
def fake_cache(monkeypatch):
    cache = _FakeCache()
    monkeypatch.setattr("app.services.enrichment.kev.cache_service", cache)
    return cache


@pytest.mark.asyncio
async def test_catalog_entries_are_keyed_by_the_cisa_cve_id_field(fake_cache):
    """CISA spells it `cveID`; any other spelling silently empties the whole catalog."""
    catalog = await KEVProvider().load_kev_catalog(_Client({"vulnerabilities": [_CATALOG_ENTRY]}))

    assert list(catalog) == ["CVE-2021-44228"]
    entry = catalog["CVE-2021-44228"]
    assert entry.cve == "CVE-2021-44228"
    assert entry.vendor_project == "Apache"
    assert entry.known_ransomware_use is True


@pytest.mark.asyncio
async def test_a_degraded_catalog_response_is_not_cached(fake_cache):
    """Caching an empty catalog would blind every scan for the whole KEV TTL."""
    catalog = await KEVProvider().load_kev_catalog(_Client({"vulnerabilities": []}))

    assert catalog == {}
    assert CacheKeys.kev_catalog() not in fake_cache.stored

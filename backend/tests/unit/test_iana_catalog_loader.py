"""Unit tests for the IANA TLS cipher-suite catalog loader, patching cache_service to exercise the Redis-miss/fetch/YAML-fallback paths."""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.analyzers.crypto.catalogs.loader import (
    CURRENT_IANA_CATALOG_VERSION,
    CipherSuiteEntry,
    _parse_iana_csv,
    load_iana_catalog,
    reset_iana_cache_for_tests,
)

_REGISTRY_CSV = """Value,Description,DTLS-OK,Recommended,Reference
"0x00,0x9C",TLS_RSA_WITH_AES_128_GCM_SHA256,Y,N,[RFC5288]
"0x00,0x9E",TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,Y,Y,[RFC5288]
"0xC0,0x2F",TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,Y,Y,[RFC5289]
"""


def _by_name(rows):
    return {row["name"]: row for row in rows}


@pytest.fixture(autouse=True)
def _clear_process_cache():
    """Each test starts with a cold in-process cache and patched Redis."""
    reset_iana_cache_for_tests()
    with (
        patch(
            "app.services.analyzers.crypto.catalogs.loader.cache_service.get",
            AsyncMock(return_value=None),
        ),
        patch(
            "app.services.analyzers.crypto.catalogs.loader.cache_service.set",
            AsyncMock(return_value=None),
        ),
        patch(
            "app.services.analyzers.crypto.catalogs.loader._fetch_from_iana",
            AsyncMock(return_value=None),
        ),
    ):
        # Redis miss + fetch miss -> falls back to bundled YAML
        yield
    reset_iana_cache_for_tests()


@pytest.mark.asyncio
async def test_catalog_loads_and_is_nonempty():
    cat = await load_iana_catalog()
    assert isinstance(cat, dict)
    assert len(cat) > 10


@pytest.mark.asyncio
async def test_catalog_has_expected_known_suite():
    cat = await load_iana_catalog()
    entry = cat.get("TLS_RSA_WITH_RC4_128_SHA")
    assert entry is not None
    assert "weak-cipher-rc4" in entry.weaknesses


@pytest.mark.asyncio
async def test_unknown_suite_returns_none():
    cat = await load_iana_catalog()
    assert cat.get("TLS_DEFINITELY_NOT_A_REAL_SUITE") is None


@pytest.mark.asyncio
async def test_catalog_entry_has_shape():
    cat = await load_iana_catalog()
    entry = next(iter(cat.values()))
    # confirm the loader returns the typed class, not a raw dict, so downstream attribute access works.
    assert isinstance(entry, CipherSuiteEntry)


def test_the_mac_is_the_last_segment_and_the_cipher_is_everything_before_it():
    """A cipher name carries its own underscores (AES_128_GCM), so only the final segment is the MAC."""
    suite = _by_name(_parse_iana_csv(_REGISTRY_CSV))["TLS_RSA_WITH_AES_128_GCM_SHA256"]

    assert suite["cipher"] == "AES_128_GCM"
    assert suite["mac"] == "SHA256"
    assert suite["key_exchange"] == "RSA"


def test_an_ephemeral_key_exchange_is_not_reported_as_lacking_forward_secrecy():
    suites = _by_name(_parse_iana_csv(_REGISTRY_CSV))

    assert suites["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]["weaknesses"] == []
    assert suites["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]["weaknesses"] == []
    assert suites["TLS_RSA_WITH_AES_128_GCM_SHA256"]["weaknesses"] == ["no-forward-secrecy"]


def test_current_catalog_version_is_one():
    assert CURRENT_IANA_CATALOG_VERSION == 1


@pytest.mark.asyncio
async def test_catalog_drift_sentinel():
    """Catch accidental catalog wipes."""
    cat = await load_iana_catalog()
    assert len(cat) > 20, f"IANA catalog has only {len(cat)} entries — likely accidental wipe."


@pytest.mark.asyncio
async def test_redis_hit_short_circuits_fetch():
    reset_iana_cache_for_tests()
    cached_suites = [
        {
            "name": "TLS_CACHED_FAKE",
            "value": "0xFF,0xFF",
            "key_exchange": "X",
            "authentication": "Y",
            "cipher": "Z",
            "mac": "W",
            "weaknesses": ["cached-sentinel"],
        }
    ]
    fetch_mock = AsyncMock(return_value=[])
    with (
        patch(
            "app.services.analyzers.crypto.catalogs.loader.cache_service.get",
            AsyncMock(return_value=cached_suites),
        ),
        patch(
            "app.services.analyzers.crypto.catalogs.loader._fetch_from_iana",
            fetch_mock,
        ),
    ):
        cat = await load_iana_catalog()
    assert "TLS_CACHED_FAKE" in cat
    assert "cached-sentinel" in cat["TLS_CACHED_FAKE"].weaknesses
    fetch_mock.assert_not_called()


@pytest.mark.asyncio
async def test_live_fetch_populates_redis():
    reset_iana_cache_for_tests()
    fetched_suites = [
        {
            "name": "TLS_FETCHED_FAKE",
            "value": "0xAA,0xAA",
            "key_exchange": "ECDHE",
            "authentication": "ECDSA",
            "cipher": "AES_128_GCM",
            "mac": "SHA256",
            "weaknesses": [],
        }
    ]
    redis_set = AsyncMock(return_value=None)
    with (
        patch(
            "app.services.analyzers.crypto.catalogs.loader.cache_service.get",
            AsyncMock(return_value=None),
        ),
        patch(
            "app.services.analyzers.crypto.catalogs.loader.cache_service.set",
            redis_set,
        ),
        patch(
            "app.services.analyzers.crypto.catalogs.loader._fetch_from_iana",
            AsyncMock(return_value=fetched_suites),
        ),
    ):
        cat = await load_iana_catalog()
    assert "TLS_FETCHED_FAKE" in cat
    redis_set.assert_awaited_once()
    call_args = redis_set.await_args
    assert call_args is not None
    assert call_args.args[1] == fetched_suites

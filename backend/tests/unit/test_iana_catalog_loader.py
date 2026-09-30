"""Unit tests for the IANA TLS cipher-suite catalog loader: shared-cache read, live fetch and bundled fallback."""

from functools import partial
from unittest.mock import AsyncMock

import httpx
import pytest
import yaml

from app.core.http_utils import InstrumentedAsyncClient
from app.services.analyzers.crypto.catalogs import loader
from app.services.analyzers.crypto.catalogs.loader import (
    WEAKNESS_SEVERITY,
    CipherSuiteEntry,
    _derive_weaknesses,
    _fetch_from_iana,
    _materialize,
    _parse_iana_csv,
    load_iana_catalog,
)

_REGISTRY_CSV = """Value,Description,DTLS-OK,Recommended,Reference
"0x00,0x9C",TLS_RSA_WITH_AES_128_GCM_SHA256,Y,N,[RFC5288]
"0x00,0x9E",TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,Y,Y,[RFC5288]
"0xC0,0x2F",TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,Y,Y,[RFC5289]
"0x00,0x00-FE",Reserved to avoid conflicts with SSLv2,,,[RFC5246]
"""


def _registry_csv_of_the_bundled_snapshot() -> str:
    with loader._CATALOG_FALLBACK_PATH.open() as fh:
        suites = yaml.safe_load(fh)["suites"]
    rows = "\n".join(f'"{s["value"]}",{s["name"]},Y,N,[RFC]' for s in suites)
    return f"Value,Description,DTLS-OK,Recommended,Reference\n{rows}\n"


def _serve_registry(monkeypatch, status: int, body: str) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(status, text=body))
    monkeypatch.setattr(loader, "InstrumentedAsyncClient", partial(InstrumentedAsyncClient, transport=transport))


def _shared_cache_returns(monkeypatch, value) -> AsyncMock:
    helper = AsyncMock(return_value=value)
    monkeypatch.setattr(loader.cache_service, "get_or_fetch_with_lock", helper)
    return helper


def _shared_cache_without_redis(monkeypatch) -> None:
    async def fetch_directly(key, fetch_fn, ttl_seconds):
        return await fetch_fn()

    monkeypatch.setattr(loader.cache_service, "get_or_fetch_with_lock", fetch_directly)


@pytest.fixture(autouse=True)
def _registry_unreachable(monkeypatch):
    _shared_cache_returns(monkeypatch, None)


@pytest.mark.asyncio
async def test_the_bundled_snapshot_serves_a_failed_fetch():
    cat = await load_iana_catalog()

    assert len(cat) == 356
    assert isinstance(cat["TLS_RSA_WITH_RC4_128_SHA"], CipherSuiteEntry)
    assert "weak-cipher-rc4" in cat["TLS_RSA_WITH_RC4_128_SHA"].weaknesses
    assert cat.get("TLS_DEFINITELY_NOT_A_REAL_SUITE") is None


@pytest.mark.asyncio
async def test_the_negative_cache_marker_falls_back_to_the_bundled_snapshot(monkeypatch):
    _shared_cache_returns(monkeypatch, {})

    assert len(await load_iana_catalog()) == 356


@pytest.mark.asyncio
async def test_the_catalog_is_read_through_the_shared_cache_helper(monkeypatch):
    helper = _shared_cache_returns(monkeypatch, [{"name": "TLS_RSA_WITH_RC4_128_SHA", "value": "0x00,0x05"}])

    cat = await load_iana_catalog()

    assert list(cat) == ["TLS_RSA_WITH_RC4_128_SHA"]
    _, fetch_fn, ttl = helper.await_args.args
    assert fetch_fn is loader._fetch_from_iana
    assert ttl == 7 * 24 * 3600


@pytest.mark.asyncio
async def test_a_cached_row_is_graded_by_the_current_rules_not_by_what_was_stored(monkeypatch):
    _shared_cache_returns(
        monkeypatch,
        [{"name": "TLS_RSA_WITH_IDEA_CBC_SHA", "value": "0x00,0x07", "weaknesses": ["stale-tag"]}],
    )

    entry = (await load_iana_catalog())["TLS_RSA_WITH_IDEA_CBC_SHA"]

    assert entry.weaknesses == ["no-forward-secrecy", "weak-cipher-idea", "weak-mac-sha1"]
    assert (entry.key_exchange, entry.cipher, entry.mac) == ("RSA", "IDEA_CBC", "SHA")


@pytest.mark.asyncio
async def test_a_fallback_is_not_pinned_for_the_process(monkeypatch):
    assert len(await load_iana_catalog()) == 356

    _shared_cache_returns(monkeypatch, [{"name": "TLS_RSA_WITH_RC4_128_SHA", "value": "0x00,0x05"}])

    assert list(await load_iana_catalog()) == ["TLS_RSA_WITH_RC4_128_SHA"]


@pytest.mark.asyncio
async def test_a_registry_answer_that_is_not_the_suite_csv_counts_as_a_failed_fetch(monkeypatch):
    _serve_registry(monkeypatch, 200, "<html><body>Access denied by proxy</body></html>")

    assert await _fetch_from_iana() is None


@pytest.mark.asyncio
async def test_a_registry_csv_with_too_few_suites_counts_as_a_failed_fetch(monkeypatch):
    _serve_registry(monkeypatch, 200, _REGISTRY_CSV)

    assert await _fetch_from_iana() is None


@pytest.mark.asyncio
async def test_a_blocked_registry_yields_the_bundled_snapshot_instead_of_an_empty_catalog(monkeypatch):
    _shared_cache_without_redis(monkeypatch)
    _serve_registry(monkeypatch, 200, "<html><body>Access denied by proxy</body></html>")

    assert len(await load_iana_catalog()) == 356


@pytest.mark.asyncio
async def test_a_full_registry_csv_is_fetched_as_raw_rows(monkeypatch):
    _serve_registry(monkeypatch, 200, _registry_csv_of_the_bundled_snapshot())

    rows = await _fetch_from_iana()

    assert len(rows) == 356
    assert rows[0] == {"name": "TLS_NULL_WITH_NULL_NULL", "value": "0x00,0x00"}


@pytest.mark.asyncio
async def test_a_registry_error_status_counts_as_a_failed_fetch(monkeypatch):
    _serve_registry(monkeypatch, 503, "")

    assert await _fetch_from_iana() is None


def test_the_csv_parse_keeps_only_the_registry_columns_of_suite_rows():
    assert _parse_iana_csv(_REGISTRY_CSV) == [
        {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "value": "0x00,0x9C"},
        {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "value": "0x00,0x9E"},
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "value": "0xC0,0x2F"},
    ]


def test_the_mac_is_the_last_segment_and_the_cipher_is_everything_before_it():
    """A cipher name carries its own underscores (AES_128_GCM), so only the final segment is the MAC."""
    suite = _materialize(_parse_iana_csv(_REGISTRY_CSV))["TLS_RSA_WITH_AES_128_GCM_SHA256"]

    assert suite.cipher == "AES_128_GCM"
    assert suite.mac == "SHA256"
    assert suite.key_exchange == "RSA"


def test_an_ephemeral_key_exchange_is_not_reported_as_lacking_forward_secrecy():
    suites = _materialize(_parse_iana_csv(_REGISTRY_CSV))

    assert suites["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"].weaknesses == []
    assert suites["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"].weaknesses == []
    assert suites["TLS_RSA_WITH_AES_128_GCM_SHA256"].weaknesses == ["no-forward-secrecy"]


def test_idea_suites_carry_their_own_cipher_weakness_tag():
    assert "weak-cipher-idea" in _derive_weaknesses("TLS_KRB5_WITH_IDEA_CBC_MD5")
    assert "weak-cipher-des" not in _derive_weaknesses("TLS_RSA_WITH_IDEA_CBC_SHA")


def test_integrity_only_suites_are_graded_as_null_ciphers():
    cat = _materialize([{"name": "TLS_SHA256_SHA256", "value": "0xC0,0xB4"}])

    assert cat["TLS_SHA256_SHA256"].cipher == "NULL"
    assert {"null-cipher", "weak-cipher-null"} <= set(_derive_weaknesses("TLS_SHA384_SHA384"))


@pytest.mark.asyncio
async def test_the_severity_table_covers_exactly_the_tags_the_catalog_emits():
    emitted = {tag for entry in (await load_iana_catalog()).values() for tag in entry.weaknesses}

    assert emitted == set(WEAKNESS_SEVERITY)

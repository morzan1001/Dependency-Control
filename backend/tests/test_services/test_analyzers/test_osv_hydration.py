"""K22: /v1/querybatch answers with {id, modified} only, so the full OSV record must be
fetched per id. Without that, every OSV finding carried a fabricated severity."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.services.aggregation import ResultAggregator
from app.services.analyzers.osv import OSVAnalyzer

_COMPONENTS = [
    {"name": "lodash", "version": "4.17.11", "purl": "pkg:npm/lodash@4.17.11"},
    {"name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
]

_SBOM: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}

# Exactly what production's querybatch returns — no severity, no summary, no affected.
_BATCH_RESULTS = [
    {"vulns": [{"id": "GHSA-lodash", "modified": "2026-01-01T00:00:00Z"}]},
    {"vulns": [{"id": "GHSA-flask", "modified": "2026-02-02T00:00:00Z"}]},
]

_RECORDS = {
    "GHSA-lodash": {
        "id": "GHSA-lodash",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "Prototype pollution in lodash",
        "aliases": ["CVE-2019-10744"],
        "database_specific": {"severity": "LOW"},
        "references": [{"url": "https://github.com/advisories/GHSA-lodash"}],
        "affected": [{"ranges": [{"events": [{"fixed": "4.17.12"}]}]}],
    },
    "GHSA-flask": {
        "id": "GHSA-flask",
        "modified": "2026-02-02T00:00:00Z",
        "summary": "Flask cookie parsing flaw",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "references": [],
        "affected": [],
    },
}


def _batch_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"results": _BATCH_RESULTS}
    return resp


def _record_response(vuln_id: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _RECORDS[vuln_id]
    return resp


def _client_stub(get_side_effect=None) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(return_value=_batch_response())

    async def _get(url: str, *args, **kwargs):
        vuln_id = url.rsplit("/", 1)[-1]
        if get_side_effect is not None:
            return await get_side_effect(vuln_id)
        return _record_response(vuln_id)

    client.get = AsyncMock(side_effect=_get)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


@pytest.fixture
def _cache_spy(monkeypatch):
    """No cache hits; records every mset so the caching contract can be asserted."""
    written: dict[str, Any] = {}

    async def _mget(keys):
        return dict.fromkeys(keys)

    async def _mset(mapping, ttl=None):
        written.update(mapping)
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)
    return written


def _install(monkeypatch, client) -> None:
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)


def _entries(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["component"]: item["vulnerabilities"][0] for item in result["osv_vulnerabilities"]}


@pytest.mark.asyncio
async def test_severity_and_advisory_data_come_from_the_hydrated_record(_cache_spy, monkeypatch):
    client = _client_stub()
    _install(monkeypatch, client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)
    entries = _entries(result)

    assert entries["lodash"]["severity"] == "LOW"
    assert entries["flask"]["severity"] == "CRITICAL"
    assert entries["lodash"]["summary"] == "Prototype pollution in lodash"
    assert entries["lodash"]["aliases"] == ["CVE-2019-10744"]
    assert entries["lodash"]["references"] == ["https://github.com/advisories/GHSA-lodash"]
    assert "partial_vulnerabilities_unhydrated" not in result


@pytest.mark.asyncio
async def test_unrated_record_stays_unknown_instead_of_a_placeholder(_cache_spy, monkeypatch):
    async def _bare(vuln_id: str):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"id": vuln_id, "summary": "no severity anywhere"}
        return resp

    _install(monkeypatch, _client_stub(_bare))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


@pytest.mark.asyncio
async def test_unresolvable_record_is_reported_and_left_unrated(_cache_spy, monkeypatch):
    async def _fail(vuln_id: str):
        if vuln_id == "GHSA-flask":
            raise httpx.TimeoutException("timed out")
        return _record_response(vuln_id)

    _install(monkeypatch, _client_stub(_fail))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)
    entries = _entries(result)

    assert result["partial_vulnerabilities_unhydrated"] == 1
    assert entries["flask"]["severity"] == "UNKNOWN"
    # The vulnerability itself is still reported; only its detail is missing.
    assert entries["flask"]["id"] == "GHSA-flask"
    assert entries["lodash"]["severity"] == "LOW"


@pytest.mark.asyncio
async def test_each_id_is_fetched_once_and_cached_under_its_modified_stamp(_cache_spy, monkeypatch):
    shared = [
        {"name": "a", "version": "1", "purl": "pkg:npm/a@1"},
        {"name": "b", "version": "1", "purl": "pkg:npm/b@1"},
        {"name": "c", "version": "1", "purl": "pkg:npm/c@1"},
    ]
    client = _client_stub()
    client.post = AsyncMock(
        return_value=MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={"results": [{"vulns": [{"id": "GHSA-lodash", "modified": "2026-01-01T00:00:00Z"}]}] * 3}
            ),
        )
    )
    _install(monkeypatch, client)

    await OSVAnalyzer().analyze(_SBOM, parsed_components=shared)

    assert client.get.await_count == 1, "one id shared by three components must be fetched once"
    assert "osvrec:GHSA-lodash:2026-01-01T00:00:00Z" in _cache_spy


@pytest.mark.asyncio
async def test_a_cached_record_costs_no_request(monkeypatch):
    warm = {
        "osvrec:GHSA-lodash:2026-01-01T00:00:00Z": _RECORDS["GHSA-lodash"],
        "osvrec:GHSA-flask:2026-02-02T00:00:00Z": _RECORDS["GHSA-flask"],
    }

    async def _mget(keys):
        # Only the record cache is warm; the per-component cache stays empty.
        return {key: warm.get(key) for key in keys}

    async def _mset(mapping, ttl=None):
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)
    client = _client_stub()
    _install(monkeypatch, client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert client.get.await_count == 0
    assert _entries(result)["lodash"]["severity"] == "LOW"


@pytest.mark.asyncio
async def test_hydrated_severity_survives_into_the_finding(_cache_spy, monkeypatch):
    """End to end: the normalizer must persist the hydrated severity, not UNKNOWN."""
    _install(monkeypatch, _client_stub())

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)
    agg = ResultAggregator()
    agg.aggregate("osv", result)

    severities = {f.component: f.severity for f in agg.get_findings()}
    assert severities["lodash"] == "LOW"
    assert severities["flask"] == "CRITICAL"

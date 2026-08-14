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
        # Real OSV shape: a vector string, never a number.
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
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


# Real RHSA records: a vector string and nothing else. Production census over 242 records
# fetched for real purls: 217 of 217 severity entries are vectors, 232 of them RHSA.
_VECTOR_ONLY_RECORDS = {
    "RHSA-low": {
        "id": "RHSA-low",
        "summary": "libtasn1 flaw",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}],
    },
    "RHSA-critical": {
        "id": "RHSA-critical",
        "summary": "glibc flaw",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    },
}


@pytest.mark.parametrize(
    "record_id,expected",
    [("RHSA-low", "LOW"), ("RHSA-critical", "CRITICAL")],
)
def test_vector_only_records_reach_the_policy_ends(record_id, expected):
    """RHSA and vendor advisories carry only vectors; discarding them lands findings on UNKNOWN."""
    assert OSVAnalyzer()._extract_severity(_VECTOR_ONLY_RECORDS[record_id]) == expected


@pytest.mark.asyncio
async def test_malformed_record_body_costs_one_id_not_the_analyzer(_cache_spy, monkeypatch):
    """A proxy error page answering 200 must not abort hydration for the whole scan."""

    async def _bad_json(vuln_id: str):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
        return resp if vuln_id == "GHSA-flask" else _record_response(vuln_id)

    _install(monkeypatch, _client_stub(_bad_json))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_vulnerabilities_unhydrated"] == 1
    assert _entries(result)["lodash"]["severity"] == "LOW"


@pytest.mark.asyncio
async def test_malformed_batch_body_reports_skipped_components(_cache_spy, monkeypatch):
    client = _client_stub()
    bad = MagicMock()
    bad.status_code = 200
    bad.json.side_effect = ValueError("not json")
    client.post = AsyncMock(return_value=bad)
    _install(monkeypatch, client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 2
    assert result["osv_vulnerabilities"] == []


@pytest.mark.asyncio
async def test_404_leaves_the_record_unresolved(_cache_spy, monkeypatch):
    async def _missing(vuln_id: str):
        resp = MagicMock()
        resp.status_code = 404
        return resp if vuln_id == "GHSA-flask" else _record_response(vuln_id)

    _install(monkeypatch, _client_stub(_missing))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_vulnerabilities_unhydrated"] == 1
    assert _entries(result)["flask"]["severity"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_persistent_429_gives_up_within_the_bounded_retries(_cache_spy, monkeypatch):
    attempts: list[str] = []

    async def _throttled(vuln_id: str):
        attempts.append(vuln_id)
        resp = MagicMock()
        resp.status_code = 429
        return resp

    monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", AsyncMock())
    analyzer = OSVAnalyzer()
    _install(monkeypatch, _client_stub(_throttled))

    result = await analyzer.analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_vulnerabilities_unhydrated"] == 2
    assert len(attempts) == 2 * (1 + analyzer.max_retries)
    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


@pytest.mark.asyncio
async def test_a_failure_run_trips_the_circuit_breaker(_cache_spy, monkeypatch):
    """A dead OSV must not be hammered once per id for the whole scan."""
    many = [{"name": f"p{i}", "version": "1", "purl": f"pkg:npm/p{i}@1"} for i in range(40)]
    calls: list[str] = []

    async def _dead(vuln_id: str):
        calls.append(vuln_id)
        resp = MagicMock()
        resp.status_code = 500
        return resp

    client = _client_stub(_dead)
    client.post = AsyncMock(
        return_value=MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={"results": [{"vulns": [{"id": f"V-{i}", "modified": "m"}]} for i in range(40)]}
            ),
        )
    )
    _install(monkeypatch, client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=many)

    assert len(calls) < 40, "the breaker must stop the run before every id has been tried"
    assert result["partial_vulnerabilities_unhydrated"] == 40


@pytest.mark.asyncio
async def test_entries_holding_unresolved_stubs_are_not_cached(_cache_spy, monkeypatch):
    """Caching them would serve UNKNOWN for six hours with no partial flag on the next scan."""

    async def _one_missing(vuln_id: str):
        resp = MagicMock()
        resp.status_code = 404
        return resp if vuln_id == "GHSA-flask" else _record_response(vuln_id)

    _install(monkeypatch, _client_stub(_one_missing))

    await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    component_keys = [k for k in _cache_spy if k.startswith("osv2:")]
    assert len(component_keys) == 1, "only the fully hydrated component may be cached"


@pytest.mark.asyncio
async def test_budget_deadline_trips_without_any_failure():
    """The wall-clock branch of _HydrationBudget: only the consecutive-failure branch was
    covered, so a broken deadline check would not have shown up."""
    import asyncio

    from app.services.analyzers.osv import _HydrationBudget

    past = _HydrationBudget(deadline=asyncio.get_running_loop().time() - 1)
    assert past.exhausted()
    past.record(success=True)
    assert past.exhausted(), "the deadline cannot be reset by a later success"

    ahead = _HydrationBudget(deadline=asyncio.get_running_loop().time() + 60)
    assert not ahead.exhausted()
    for _ in range(9):
        ahead.record(success=False)
    assert not ahead.exhausted(), "nine failures are below the streak threshold"


@pytest.mark.asyncio
async def test_an_expired_deadline_reports_every_id_as_unhydrated(_cache_spy, monkeypatch):
    """A healthy OSV that is merely slow must leave the ids visible as partial, not silently
    unrated, and must not spend a single request once the budget is gone."""
    calls: list[str] = []

    async def _count(vuln_id: str):
        calls.append(vuln_id)
        return _record_response(vuln_id)

    monkeypatch.setattr("app.services.analyzers.osv._HYDRATION_BUDGET_SECONDS", -1.0)
    _install(monkeypatch, _client_stub(_count))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert calls == [], "no record may be fetched after the budget is exhausted"
    assert result["partial_vulnerabilities_unhydrated"] == 2
    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


@pytest.mark.asyncio
async def test_the_429_ladder_rechecks_the_deadline_between_attempts():
    """The deadline cannot cancel a request in flight, so the ladder must recheck it: without
    that the tail past the budget is 4 x 60s of timeouts plus 35s of backoff, not one request."""
    import asyncio

    from app.services.analyzers.osv import _HydrationBudget

    attempts: list[str] = []

    async def _throttled(vuln_id: str):
        attempts.append(vuln_id)
        resp = MagicMock()
        resp.status_code = 429
        return resp

    analyzer = OSVAnalyzer()
    analyzer.retry_base_delay = 0.0
    client = _client_stub(_throttled)
    expired = _HydrationBudget(deadline=asyncio.get_running_loop().time() - 1)

    assert await analyzer._get_vuln_record(client, "GHSA-lodash", expired) is None
    assert attempts == ["GHSA-lodash"], "the in-flight attempt completes, the ladder does not continue"

    attempts.clear()
    ahead = _HydrationBudget(deadline=asyncio.get_running_loop().time() + 60)
    assert await analyzer._get_vuln_record(client, "GHSA-lodash", ahead) is None
    assert len(attempts) == 1 + analyzer.max_retries, "with budget left the full ladder still runs"

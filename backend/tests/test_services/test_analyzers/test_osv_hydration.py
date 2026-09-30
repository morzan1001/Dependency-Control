"""K22: /v1/querybatch answers with {id, modified} only, so the full OSV record must be
fetched per id. Without that, every OSV finding carried a fabricated severity."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.core.cache import CacheKeys
from app.services.aggregation import ResultAggregator
from app.services.analyzers import osv
from app.services.analyzers.osv import OSVAnalyzer, _HydrationBudget
from tests.helpers.osv import batch_queries, osv_cache, serve_osv, vuln_ids_fetched

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


def _record(vuln_id: str) -> httpx.Response:
    return httpx.Response(200, json=_RECORDS[vuln_id])


def _osv(record_for: Callable[[str], httpx.Response] = _record, batch: list[dict[str, Any]] = _BATCH_RESULTS):
    """querybatch answers ``batch``; /v1/vulns/{id} answers ``record_for(id)``."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"results": batch})
        return record_for(request.url.path.rsplit("/", 1)[-1])

    return handle


@pytest.fixture
def cache(monkeypatch):
    return osv_cache(monkeypatch)


def _entries(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["component"]: item["vulnerabilities"][0] for item in result["osv_vulnerabilities"]}


@pytest.mark.asyncio
async def test_severity_and_advisory_data_come_from_the_hydrated_record(cache, monkeypatch):
    serve_osv(monkeypatch, _osv())

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)
    entries = _entries(result)

    assert entries["lodash"]["severity"] == "LOW"
    assert entries["flask"]["severity"] == "CRITICAL"
    assert entries["lodash"]["summary"] == "Prototype pollution in lodash"
    assert entries["lodash"]["aliases"] == ["CVE-2019-10744"]
    assert entries["lodash"]["references"] == ["https://github.com/advisories/GHSA-lodash"]
    assert "partial_vulnerabilities_unhydrated" not in result


@pytest.mark.asyncio
async def test_unrated_record_stays_unknown_instead_of_a_placeholder(cache, monkeypatch):
    serve_osv(monkeypatch, _osv(lambda vuln_id: httpx.Response(200, json={"id": vuln_id, "summary": "unrated"})))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


def _flask_fails(failure: httpx.Response | Exception) -> Callable[[str], httpx.Response]:
    def record_for(vuln_id: str) -> httpx.Response:
        if vuln_id != "GHSA-flask":
            return _record(vuln_id)
        if isinstance(failure, Exception):
            raise failure
        return failure

    return record_for


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.TimeoutException("timed out"), id="timeout"),
        pytest.param(httpx.Response(404), id="404"),
        # A proxy error page answering 200 must cost one id, not the analyzer.
        pytest.param(httpx.Response(200, text="<html>Bad Gateway</html>"), id="unparseable_body"),
    ],
)
async def test_an_unresolvable_record_is_reported_and_left_unrated(cache, monkeypatch, failure):
    serve_osv(monkeypatch, _osv(_flask_fails(failure)))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)
    entries = _entries(result)

    assert result["partial_vulnerabilities_unhydrated"] == 1
    assert entries["flask"]["severity"] == "UNKNOWN"
    # The vulnerability itself is still reported; only its detail is missing.
    assert entries["flask"]["id"] == "GHSA-flask"
    assert entries["lodash"]["severity"] == "LOW"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.ConnectError("connection reset"), id="transport_error"),
        pytest.param(httpx.Response(503), id="5xx"),
        pytest.param(httpx.Response(429), id="429"),
    ],
)
async def test_a_transient_record_failure_is_retried(cache, monkeypatch, failure):
    failed: list[str] = []

    def record_for(vuln_id: str) -> httpx.Response:
        if vuln_id == "GHSA-flask" and not failed:
            failed.append(vuln_id)
            return _flask_fails(failure)(vuln_id)
        return _record(vuln_id)

    serve_osv(monkeypatch, _osv(record_for))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert "partial_vulnerabilities_unhydrated" not in result
    assert _entries(result)["flask"]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_a_timed_out_record_fetch_is_not_repeated(cache, monkeypatch):
    seen = serve_osv(monkeypatch, _osv(_flask_fails(httpx.ReadTimeout("timed out"))))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert vuln_ids_fetched(seen).count("GHSA-flask") == 1
    assert result["partial_vulnerabilities_unhydrated"] == 1


@pytest.mark.asyncio
async def test_each_id_is_fetched_once_and_cached_under_its_modified_stamp(cache, monkeypatch):
    shared = [{"name": name, "version": "1", "purl": f"pkg:npm/{name}@1"} for name in ("a", "b", "c")]
    seen = serve_osv(monkeypatch, _osv(batch=[_BATCH_RESULTS[0]] * 3))

    await OSVAnalyzer().analyze(_SBOM, parsed_components=shared)

    assert vuln_ids_fetched(seen) == ["GHSA-lodash"], "one id shared by three components must be fetched once"
    assert "osvrec:GHSA-lodash:2026-01-01T00:00:00Z" in cache


@pytest.mark.asyncio
async def test_a_cached_record_costs_no_request(cache, monkeypatch):
    cache["osvrec:GHSA-lodash:2026-01-01T00:00:00Z"] = _RECORDS["GHSA-lodash"]
    cache["osvrec:GHSA-flask:2026-02-02T00:00:00Z"] = _RECORDS["GHSA-flask"]
    seen = serve_osv(monkeypatch, _osv())

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert vuln_ids_fetched(seen) == []
    assert _entries(result)["lodash"]["severity"] == "LOW"


@pytest.mark.asyncio
async def test_hydrated_severity_survives_into_the_finding(cache, monkeypatch):
    """End to end: the normalizer must persist the hydrated severity, not UNKNOWN."""
    serve_osv(monkeypatch, _osv())

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
async def test_malformed_batch_body_reports_skipped_components(cache, monkeypatch):
    serve_osv(monkeypatch, lambda request: httpx.Response(200, text="not json"))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 2
    assert result["osv_vulnerabilities"] == []


@pytest.mark.asyncio
async def test_persistent_429_gives_up_within_the_bounded_retries(cache, monkeypatch):
    seen = serve_osv(monkeypatch, _osv(lambda vuln_id: httpx.Response(429)))
    analyzer = OSVAnalyzer()

    result = await analyzer.analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_vulnerabilities_unhydrated"] == 2
    assert len(vuln_ids_fetched(seen)) == 2 * (1 + analyzer.max_retries)
    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


@pytest.mark.asyncio
async def test_a_failure_run_trips_the_circuit_breaker(cache, monkeypatch):
    """A dead OSV must not be hammered once per id for the whole scan."""
    many = [{"name": f"p{i}", "version": "1", "purl": f"pkg:npm/p{i}@1"} for i in range(40)]
    batch = [{"vulns": [{"id": f"V-{i}", "modified": "m"}]} for i in range(40)]
    seen = serve_osv(monkeypatch, _osv(lambda vuln_id: httpx.Response(500), batch=batch))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=many)

    assert len(set(vuln_ids_fetched(seen))) < 40, "the breaker must stop the run before every id has been tried"
    assert result["partial_vulnerabilities_unhydrated"] == 40


@pytest.mark.asyncio
async def test_the_stubs_are_cached_and_an_unresolved_record_is_fetched_again_next_scan(cache, monkeypatch):
    """The querybatch answer is definitive even when a record fails; the records have their own cache."""
    serve_osv(monkeypatch, _osv(_flask_fails(httpx.Response(404))))
    await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    for component, answer in zip(_COMPONENTS, _BATCH_RESULTS, strict=True):
        assert cache[CacheKeys.osv(component["purl"])] == answer["vulns"]

    seen = serve_osv(monkeypatch, _osv())
    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert batch_queries(seen) == []
    assert vuln_ids_fetched(seen) == ["GHSA-flask"]
    assert "partial_vulnerabilities_unhydrated" not in result
    assert _entries(result)["flask"]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_a_clean_answer_is_cached_and_served_without_a_request(cache, monkeypatch):
    serve_osv(monkeypatch, _osv(batch=[{}, {}]))
    await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    seen = serve_osv(monkeypatch, _osv())
    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert seen == []
    assert result == {"osv_vulnerabilities": []}


@pytest.mark.asyncio
async def test_budget_deadline_trips_without_any_failure():
    """The wall-clock branch of _HydrationBudget: only the consecutive-failure branch was
    covered, so a broken deadline check would not have shown up."""
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
async def test_an_expired_deadline_reports_every_id_as_unhydrated(cache, monkeypatch):
    """A healthy OSV that is merely slow must leave the ids visible as partial, not silently
    unrated, and must not spend a single request once the budget is gone."""
    monkeypatch.setattr("app.services.analyzers.osv._HYDRATION_BUDGET_SECONDS", -1.0)
    seen = serve_osv(monkeypatch, _osv())

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert vuln_ids_fetched(seen) == [], "no record may be fetched after the budget is exhausted"
    assert result["partial_vulnerabilities_unhydrated"] == 2
    assert {e["severity"] for e in _entries(result).values()} == {"UNKNOWN"}


@pytest.mark.asyncio
async def test_the_retry_ladder_stops_at_the_hydration_deadline(monkeypatch):
    """The deadline cannot cancel a request in flight, so no retry may start past it: otherwise
    the tail past the budget is 4 x 60s of timeouts plus 35s of backoff, not one request."""
    seen = serve_osv(monkeypatch, lambda request: httpx.Response(429))
    analyzer = OSVAnalyzer()
    now = asyncio.get_running_loop().time()

    async with osv.InstrumentedAsyncClient("OSV API") as client:
        assert await analyzer._get_vuln_record(client, "GHSA-lodash", now - 1) is None
        assert len(seen) == 1, "the in-flight attempt completes, the ladder does not continue"

        seen.clear()
        assert await analyzer._get_vuln_record(client, "GHSA-lodash", now + 60) is None
        assert len(seen) == 1 + analyzer.max_retries, "with budget left the full ladder still runs"

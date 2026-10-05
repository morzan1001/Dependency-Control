"""W15: OSV must report skipped coverage instead of silently dropping whole batches."""

import json
from typing import Any

import httpx
import pytest

from app.core.cache import CacheKeys
from app.services.analyzers.osv import OSVAnalyzer
from tests.helpers.osv import batch_queries, osv_cache, serve_osv

_COMPONENTS = [{"name": f"pkg-{i}", "version": "1.0.0", "purl": f"pkg:pypi/pkg-{i}@1.0.0"} for i in range(3)]

_SBOM: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}

_CLEAN = httpx.Response(200, json={"results": [{} for _ in _COMPONENTS]})


def _answers(*outcomes: httpx.Response | Exception):
    """Answers each querybatch with the next outcome, repeating the last."""
    sent: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(1)
        outcome = outcomes[min(len(sent), len(outcomes)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return handle


@pytest.fixture(autouse=True)
def _cache(monkeypatch):
    return osv_cache(monkeypatch)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.TimeoutException("timed out"), id="timeout"),
        pytest.param(httpx.Response(500), id="5xx"),
        pytest.param(httpx.Response(429), id="rate_limited"),
        pytest.param(httpx.Response(403), id="refused"),
    ],
)
async def test_a_persistently_failing_batch_reports_skipped_components(monkeypatch, failure):
    serve_osv(monkeypatch, _answers(failure))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 3, "a dropped batch must be reported, not swallowed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.ConnectError("connection reset"), id="transport_error"),
        pytest.param(httpx.Response(503), id="5xx"),
        pytest.param(httpx.Response(429), id="rate_limited"),
    ],
)
async def test_a_transient_batch_failure_is_retried(monkeypatch, failure):
    seen = serve_osv(monkeypatch, _answers(failure, _CLEAN))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert len(seen) == 2
    assert "partial_components_skipped" not in result


@pytest.mark.asyncio
async def test_a_timed_out_batch_is_not_resent(monkeypatch):
    seen = serve_osv(monkeypatch, _answers(httpx.ReadTimeout("timed out"), _CLEAN))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert len(seen) == 1, "a hanging OSV must cost one request timeout per chunk, not one per try"
    assert result["partial_components_skipped"] == 3


@pytest.mark.asyncio
async def test_retries_are_bounded(monkeypatch):
    seen = serve_osv(monkeypatch, _answers(httpx.Response(429)))
    analyzer = OSVAnalyzer()

    await analyzer.analyze(_SBOM, parsed_components=_COMPONENTS)

    assert len(seen) == 1 + analyzer.max_retries


@pytest.mark.asyncio
async def test_response_count_mismatch_reports_truncated_tail(monkeypatch):
    # 3 components sent, 1 result received -> 2 components were never scanned.
    serve_osv(monkeypatch, _answers(httpx.Response(200, json={"results": [{"vulns": []}]})))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 2


@pytest.mark.asyncio
async def test_full_success_has_no_partial_marker(monkeypatch):
    seen = serve_osv(monkeypatch, _answers(_CLEAN))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert len(seen) == 1
    assert "partial_components_skipped" not in result


def _paged(next_page: httpx.Response):
    """querybatch: pkg-0 has a second page behind ``page-2``, answered by ``next_page``; records echo their id."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})
        queries = json.loads(request.content)["queries"]
        if queries[0].get("page_token") == "page-2":
            return next_page
        first_page = {"vulns": [{"id": "OSV-1", "modified": "m"}], "next_page_token": "page-2"}
        return httpx.Response(200, json={"results": [first_page, {"vulns": [{"id": "OSV-2", "modified": "m"}]}, {}]})

    return handle


@pytest.mark.asyncio
async def test_a_paged_result_is_followed_to_its_last_page(monkeypatch, _cache):
    last_page = httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-3", "modified": "m"}]}]})
    seen = serve_osv(monkeypatch, _paged(last_page))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert batch_queries(seen)[3:] == [{"package": {"purl": "pkg:pypi/pkg-0@1.0.0"}, "page_token": "page-2"}]
    ids = {entry["component"]: [v["id"] for v in entry["vulnerabilities"]] for entry in result["osv_vulnerabilities"]}
    assert ids == {"pkg-0": ["OSV-1", "OSV-3"], "pkg-1": ["OSV-2"]}
    assert [stub["id"] for stub in _cache[CacheKeys.osv("pkg:pypi/pkg-0@1.0.0")]] == ["OSV-1", "OSV-3"]
    assert "partial_components_skipped" not in result


@pytest.mark.asyncio
async def test_a_component_whose_next_page_fails_is_skipped_and_not_cached(monkeypatch, _cache):
    serve_osv(monkeypatch, _paged(httpx.Response(500)))

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 1
    assert CacheKeys.osv("pkg:pypi/pkg-0@1.0.0") not in _cache, "a truncated answer must not be cached for hours"
    assert CacheKeys.osv("pkg:pypi/pkg-1@1.0.0") in _cache

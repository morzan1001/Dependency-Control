"""W15: OSV must report skipped coverage instead of silently dropping whole batches."""

from typing import Any

import httpx
import pytest

from app.services.analyzers.osv import OSVAnalyzer
from tests.helpers.osv import osv_cache, serve_osv

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

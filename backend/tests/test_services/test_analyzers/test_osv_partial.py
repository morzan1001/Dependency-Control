"""W15: OSV must report skipped coverage instead of silently dropping whole batches."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.services.analyzers.osv import OSVAnalyzer

_COMPONENTS = [{"name": f"pkg-{i}", "version": "1.0.0", "purl": f"pkg:pypi/pkg-{i}@1.0.0"} for i in range(3)]

_SBOM: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _client_stub(post_side_effect) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(side_effect=post_side_effect)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _response(status_code: int, results: list | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"results": results if results is not None else []}
    return resp


@pytest.fixture
def _no_cache(monkeypatch):
    async def _mget(keys):
        return dict.fromkeys(keys)

    async def _mset(mapping, ttl=None):
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)


@pytest.mark.asyncio
async def test_timeout_reports_skipped_components(_no_cache, monkeypatch):
    client = _client_stub(httpx.TimeoutException("timed out"))
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 3, "a dropped batch must be reported, not swallowed"


@pytest.mark.asyncio
async def test_non_200_reports_skipped_components(_no_cache, monkeypatch):
    client = _client_stub(lambda *a, **k: _response(500))
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 3


@pytest.mark.asyncio
async def test_persistent_rate_limit_reports_skipped_components(_no_cache, monkeypatch):
    client = _client_stub(lambda *a, **k: _response(429))
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)
    analyzer = OSVAnalyzer()
    analyzer.max_retries = 1
    analyzer.retry_base_delay = 0.0

    result = await analyzer.analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 3


@pytest.mark.asyncio
async def test_response_count_mismatch_reports_truncated_tail(_no_cache, monkeypatch):
    # 3 components sent, 1 result received -> 2 components were never scanned.
    client = _client_stub(lambda *a, **k: _response(200, results=[{"vulns": []}]))
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert result["partial_components_skipped"] == 2


@pytest.mark.asyncio
async def test_full_success_has_no_partial_marker(_no_cache, monkeypatch):
    client = _client_stub(lambda *a, **k: _response(200, results=[{"vulns": []}] * 3))
    monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", lambda *a, **k: client)

    result = await OSVAnalyzer().analyze(_SBOM, parsed_components=_COMPONENTS)

    assert "partial_components_skipped" not in result

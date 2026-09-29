"""The scorecard flag threshold is a per-project read of a raw, shared cache entry."""

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from app.services.analyzers.deps_dev import DepsDevAnalyzer

MODULE = "app.services.analyzers.deps_dev"
_COMPONENT = {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}


class _DictCache:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        return {key: self.store.get(key) for key in keys}

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, **_: Any) -> Any:
        if key not in self.store:
            self.store[key] = await fetch_fn()
        return self.store[key]


class _Client:
    def __init__(self, *_: Any, **__: Any) -> None:
        pass

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def get(self, url: str) -> Any:
        response = MagicMock(status_code=200)
        if "/projects/" in url:
            response.json.return_value = {"scorecard": {"overallScore": 6.0, "date": "2026-01-01", "checks": []}}
        elif url.endswith(":dependents"):
            response.json.return_value = {}
        else:
            response.json.return_value = {
                "relatedProjects": [{"projectKey": {"id": "github.com/o/left-pad"}, "relationType": "SOURCE_REPO"}]
            }
        return response


def test_a_project_with_a_higher_threshold_sees_a_package_another_project_fetched_first():
    cache = _DictCache()
    analyzer = DepsDevAnalyzer()

    async def _run(threshold: float) -> list[Any]:
        result = await analyzer.analyze({}, {"scorecard_threshold": threshold}, [_COMPONENT])
        issues: list[Any] = result["scorecard_issues"]
        return issues

    with patch(f"{MODULE}.cache_service", cache), patch(f"{MODULE}.InstrumentedAsyncClient", _Client):
        lenient = asyncio.run(_run(5.0))
        strict = asyncio.run(_run(7.0))

    assert lenient == []
    assert [issue["component"] for issue in strict] == ["left-pad"]

"""Tests for the outdated analyzer: version classification from one cached deps.dev package document."""

import asyncio
from typing import Any

import httpx
import pytest
from typing_extensions import Self

from app.services.analyzers.outdated import OutdatedAnalyzer

_API = "https://api.deps.dev/v3alpha/systems"


def _v(version: str, default: bool = False) -> dict[str, Any]:
    return {
        "versionKey": {"system": "NPM", "name": "pkg", "version": version},
        "publishedAt": "2024-01-01T00:00:00Z",
        "isDefault": default,
    }


def _component(name: str, version: str, ptype: str = "pypi") -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


class _ScriptedClient:
    """deps.dev stand-in: one answer (document, status or raised error) per package name, else 404.

    Records every request and the peak number in flight.
    """

    def __init__(self, answers_by_name: dict[str, Any]) -> None:
        self._answers = answers_by_name
        self.urls: list[str] = []
        self.in_flight = 0
        self.max_in_flight = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> Self:
        return self

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, url: str, **_kwargs: Any) -> httpx.Response:
        self.urls.append(url)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0.01)
        finally:
            self.in_flight -= 1
        answer = next((a for name, a in self._answers.items() if url.endswith(f"/packages/{name}")), 404)
        if isinstance(answer, Exception):
            raise answer
        request = httpx.Request("GET", url)
        if isinstance(answer, int):
            return httpx.Response(answer, request=request)
        return httpx.Response(200, json=answer, request=request)


def _serve(monkeypatch: pytest.MonkeyPatch, cache: Any, answers_by_name: dict[str, Any]) -> _ScriptedClient:
    client = _ScriptedClient(answers_by_name)
    monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)
    monkeypatch.setattr("app.services.analyzers.outdated.InstrumentedAsyncClient", client)
    return client


class TestMultipleVersionsOfSamePackage:
    @pytest.mark.asyncio
    async def test_both_versions_classified_from_shared_latest_warm_cache(self, fake_cache, monkeypatch) -> None:
        # The latest-version cache is a single package-level key; the older copy must still surface a card.
        await fake_cache.set("latest2:npm:lodash", {"default": "4.17.20"})
        client = _serve(monkeypatch, fake_cache, {})

        result = await OutdatedAnalyzer().analyze(
            {}, parsed_components=[_component("lodash", "3.0.0", "npm"), _component("lodash", "4.17.20", "npm")]
        )

        assert client.urls == []
        assert [(o["current_version"], o["latest_version"]) for o in result["outdated_dependencies"]] == [
            ("3.0.0", "4.17.20")
        ]
        assert result["ahead_of_default"] == []

    @pytest.mark.asyncio
    async def test_both_versions_classified_on_cold_cache_single_fetch(self, fake_cache, monkeypatch) -> None:
        client = _serve(monkeypatch, fake_cache, {"lodash": {"versions": [_v("3.0.0"), _v("4.17.20", default=True)]}})

        result = await OutdatedAnalyzer().analyze(
            {}, parsed_components=[_component("lodash", "3.0.0", "npm"), _component("lodash", "4.17.20", "npm")]
        )

        assert [o["current_version"] for o in result["outdated_dependencies"]] == ["3.0.0"]
        assert client.urls == [f"{_API}/npm/packages/lodash"]


class TestDepsDevStatusPolicy:
    @pytest.mark.parametrize("answer", [500, httpx.ConnectError("refused")], ids=["500", "connect-error"])
    @pytest.mark.asyncio
    async def test_a_failed_lookup_marks_the_component_skipped_and_caches_nothing(
        self, fake_cache, monkeypatch, answer
    ) -> None:
        _serve(monkeypatch, fake_cache, {"flaky": answer})

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component("flaky", "1.0.0")])

        assert result == {
            "outdated_dependencies": [],
            "ahead_of_default": [],
            "partial_components_skipped": 1,
            "lookup_failed_components": ["flaky"],
        }
        assert await fake_cache.get("latest2:pypi:flaky") is None

    @pytest.mark.asyncio
    async def test_an_unknown_package_is_negative_cached_briefly(self, fake_cache, monkeypatch) -> None:
        _serve(monkeypatch, fake_cache, {})

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component("typo-pkg", "1.0.0")])

        assert result == {"outdated_dependencies": [], "ahead_of_default": []}
        assert await fake_cache.get("latest2:pypi:typo-pkg") == {}
        assert 0 < await fake_cache._client.ttl(fake_cache._make_key("latest2:pypi:typo-pkg")) <= 3600


class TestDefaultVersionSelection:
    @pytest.mark.asyncio
    async def test_the_flagged_version_wins_over_the_first_one_listed(self, fake_cache, monkeypatch) -> None:
        """deps.dev spells out isDefault: false on every other version, so presence of the key decides nothing."""
        _serve(monkeypatch, fake_cache, {"lodash": {"versions": [_v("1.0.0"), _v("2.0.0", default=True)]}})

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component("lodash", "1.0.0", "npm")])

        assert [o["latest_version"] for o in result["outdated_dependencies"]] == ["2.0.0"]

    @pytest.mark.asyncio
    async def test_a_component_without_a_known_version_is_not_looked_up(self, fake_cache, monkeypatch) -> None:
        client = _serve(monkeypatch, fake_cache, {"lodash": {"versions": [_v("4.17.21", default=True)]}})
        component = {"name": "lodash", "version": "unknown", "purl": "pkg:npm/lodash"}

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[component])

        assert result == {"outdated_dependencies": [], "ahead_of_default": []}
        assert client.urls == []


class TestConcurrentFetch:
    @pytest.mark.asyncio
    async def test_distinct_packages_fetched_concurrently(self, fake_cache, monkeypatch) -> None:
        names = [f"pkg{i}" for i in range(5)]
        client = _serve(monkeypatch, fake_cache, {name: {"versions": [_v("2.0.0", default=True)]} for name in names})

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component(name, "1.0.0") for name in names])

        assert len(client.urls) == 5
        assert client.max_in_flight >= 2  # serial execution would peak at 1
        assert len(result["outdated_dependencies"]) == 5


@pytest.mark.asyncio
async def test_an_ecosystem_deps_dev_does_not_serve_is_neither_requested_nor_cached(fake_cache, monkeypatch) -> None:
    client = _serve(monkeypatch, fake_cache, {})

    result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component("framework", "10.0.0", "composer")])

    assert result == {"outdated_dependencies": [], "ahead_of_default": []}
    assert client.urls == []
    assert await fake_cache._client.keys("*") == []

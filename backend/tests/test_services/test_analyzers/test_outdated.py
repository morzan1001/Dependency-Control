import asyncio
from typing import Any

import httpx
import pytest
from typing_extensions import Self

from app.services.analyzers.outdated import OutdatedAnalyzer

_API = "https://api.deps.dev/v3alpha/systems"


def _v(version: str, default: bool = False, deprecated: bool = False) -> dict[str, Any]:
    return {
        "versionKey": {"system": "NPM", "name": "pkg", "version": version},
        "publishedAt": "2024-01-01T00:00:00Z",
        "isDefault": default,
        "isDeprecated": deprecated,
    }


def _component(name: str, version: str, ptype: str = "pypi") -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


class _ScriptedClient:
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
        await fake_cache.set("latest3:npm:lodash", {"default": "4.17.20", "stable": "4.17.20"})
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
        assert await fake_cache.get("latest3:pypi:flaky") is None

    @pytest.mark.asyncio
    async def test_an_unknown_package_is_negative_cached_briefly(self, fake_cache, monkeypatch) -> None:
        _serve(monkeypatch, fake_cache, {})

        result = await OutdatedAnalyzer().analyze({}, parsed_components=[_component("typo-pkg", "1.0.0")])

        assert result == {"outdated_dependencies": [], "ahead_of_default": []}
        assert await fake_cache.get("latest3:pypi:typo-pkg") == {}
        assert 0 < await fake_cache._client.ttl(fake_cache._make_key("latest3:pypi:typo-pkg")) <= 3600


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

    @pytest.mark.parametrize("purl", ["pkg:npm/", "pkg:maven/org.example/"], ids=["npm", "maven"])
    @pytest.mark.asyncio
    async def test_a_purl_without_a_package_name_is_not_looked_up(self, fake_cache, monkeypatch, purl) -> None:
        client = _serve(monkeypatch, fake_cache, {})

        result = await OutdatedAnalyzer().analyze(
            {}, parsed_components=[{"name": "ghost", "version": "1.0.0", "purl": purl}]
        )

        assert result == {"outdated_dependencies": [], "ahead_of_default": []}
        assert client.urls == []


_SLF4J = [_v("2.0.16"), _v("2.0.17"), _v("2.1.0-alpha0"), _v("2.1.0-alpha1", default=True)]


class TestPrereleaseDefault:
    """deps.dev flags Maven's highest version as default even when it is a pre-release such as 2.1.0-alpha1."""

    @staticmethod
    async def _classify(fake_cache, monkeypatch, versions, installed, ptype="maven") -> dict[str, Any]:
        _serve(monkeypatch, fake_cache, {"lib": {"versions": versions}})
        return await OutdatedAnalyzer().analyze({}, parsed_components=[_component("lib", installed, ptype)])

    @pytest.mark.asyncio
    async def test_a_stable_install_compares_against_the_newest_stable_release(self, fake_cache, monkeypatch) -> None:
        result = await self._classify(fake_cache, monkeypatch, _SLF4J, "2.0.16")

        assert [o["latest_version"] for o in result["outdated_dependencies"]] == ["2.0.17"]

    @pytest.mark.asyncio
    async def test_the_newest_stable_release_is_neither_outdated_nor_ahead(self, fake_cache, monkeypatch) -> None:
        result = await self._classify(fake_cache, monkeypatch, _SLF4J, "2.0.17")

        assert result == {"outdated_dependencies": [], "ahead_of_default": []}

    @pytest.mark.asyncio
    async def test_a_stable_install_ahead_of_the_newest_stable_release_names_that_release(
        self, fake_cache, monkeypatch
    ) -> None:
        result = await self._classify(fake_cache, monkeypatch, _SLF4J, "2.0.18")

        [ahead] = result["ahead_of_default"]
        assert (ahead["default_version"], ahead["latest_version"]) == ("2.1.0-alpha1", "2.0.17")
        assert ahead["message"].startswith("Installed 2.0.18 is newer than the newest stable release 2.0.17")
        assert "registry default" not in ahead["message"]

    @pytest.mark.asyncio
    async def test_an_install_ahead_of_a_stable_default_names_the_registry_default(
        self, fake_cache, monkeypatch
    ) -> None:
        result = await self._classify(fake_cache, monkeypatch, [_v("2.0.17", default=True)], "2.0.18")

        [ahead] = result["ahead_of_default"]
        assert (ahead["default_version"], ahead["latest_version"]) == ("2.0.17", "2.0.17")
        assert ahead["message"].startswith("Installed 2.0.18 is newer than the registry default 2.0.17.")

    @pytest.mark.asyncio
    async def test_a_prerelease_install_compares_against_the_default(self, fake_cache, monkeypatch) -> None:
        result = await self._classify(fake_cache, monkeypatch, _SLF4J, "2.1.0-alpha0")

        assert [o["latest_version"] for o in result["outdated_dependencies"]] == ["2.1.0-alpha1"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "versions",
        [
            [_v("7.1.5.Final"), _v("7.2.0.CR1"), _v("8.0.0.Beta3", default=True)],
            [_v("7.1.5"), _v("7.2.0-M1"), _v("7.2.0-RC1"), _v("7.2.0-SNAPSHOT"), _v("8.0.0.Alpha2", default=True)],
            [_v("7.1.5"), _v("7.1.6", deprecated=True), _v("8.0.0-alpha1", default=True)],
            [_v("7.1.5"), _v("8.0-milestone-1", default=True)],
        ],
        ids=["final-and-cr", "milestone-rc-snapshot", "deprecated", "spelled-out-milestone"],
    )
    async def test_maven_qualifiers_and_deprecations_never_name_the_latest(
        self, fake_cache, monkeypatch, versions
    ) -> None:
        result = await self._classify(fake_cache, monkeypatch, versions, "7.1.4")

        assert [o["latest_version"] for o in result["outdated_dependencies"]] == [versions[0]["versionKey"]["version"]]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("ptype", "stable", "prerelease", "installed"),
        [
            ("npm", "1.2.0", "2.0.0-beta.1", "1.1.0"),
            ("pypi", "1.2.0", "2.0.0b1", "1.1.0"),
            ("golang", "v1.2.0", "v2.0.0-rc.1", "v1.1.0"),
            ("cargo", "1.2.0", "2.0.0-alpha.1", "1.1.0"),
            ("nuget", "1.2.0", "2.0.0-preview.1", "1.1.0"),
            ("gem", "1.2.0", "2.0.0.rc1", "1.1.0"),
        ],
    )
    async def test_every_ecosystem_skips_a_prerelease_default(
        self, fake_cache, monkeypatch, ptype, stable, prerelease, installed
    ) -> None:
        versions = [_v(stable), _v(prerelease, default=True)]

        result = await self._classify(fake_cache, monkeypatch, versions, installed, ptype)

        assert [o["latest_version"] for o in result["outdated_dependencies"]] == [stable]


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

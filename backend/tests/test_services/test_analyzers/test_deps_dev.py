"""deps.dev analyzer: the scorecard threshold, the identity of cached results and the deps.dev status policy."""

import asyncio
from typing import Any

import httpx
import pytest

from app.services.aggregation import ResultAggregator
from app.services.analyzers.deps_dev import DepsDevAnalyzer


class _FakeCache:
    def __init__(self, stored: dict[str, Any], peer_payload: dict[str, Any] | None = None) -> None:
        self.stored = stored
        self.peer_payload = peer_payload
        self.looked_up: list[str] = []

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        self.looked_up.extend(keys)
        return {key: self.stored.get(key) for key in keys}

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, **_kw: Any) -> Any:
        self.looked_up.append(key)
        return self.peer_payload


def _payload(name: str, version: str, purl: str, score: float) -> dict[str, Any]:
    """What another project's scan cached: its own component's spelling in the metadata."""
    return {
        "metadata": {"name": name, "version": version, "system": "npm", "purl": purl, "licenses": ["MIT"]},
        "scorecard_issue": {
            "project_url": "https://github.com/o/r",
            "scorecard": {"overallScore": score, "date": None, "repository": "github.com/o/r", "checks": []},
            "failed_checks": [],
            "critical_issues": [],
        },
    }


class TestIdentityOfCachedResults:
    @pytest.mark.asyncio
    async def test_same_named_packages_keep_their_own_metadata(self, monkeypatch):
        nx, nrwl = "pkg:npm/%40nx/devkit@16.5.0", "pkg:npm/%40nrwl/devkit@16.5.0"
        cache = _FakeCache(
            {
                "deps:npm:@nx/devkit:16.5.0": _payload("devkit", "16.5.0", nx, 9.0),
                "deps:npm:@nrwl/devkit:16.5.0": _payload("devkit", "16.5.0", nrwl, 9.0),
            }
        )
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
        components = [{"name": "devkit", "version": "16.5.0", "purl": purl} for purl in (nx, nrwl)]

        result = await DepsDevAnalyzer().analyze({}, parsed_components=components)

        assert sorted(meta["purl"] for meta in result["package_metadata"].values()) == sorted([nx, nrwl])

    @pytest.mark.asyncio
    async def test_a_cached_payload_is_named_after_the_scanning_component(self, monkeypatch):
        cached = _payload("core", "17.0.0", "pkg:npm/%40angular/core@17.0.0", 3.0)
        monkeypatch.setattr(
            "app.services.analyzers.deps_dev.cache_service", _FakeCache({"deps:npm:@angular/core:17.0.0": cached})
        )
        component = {"name": "@angular/core", "version": "17.0.0", "purl": "pkg:npm/@angular/core@17.0.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        [metadata] = result["package_metadata"].values()
        [issue] = result["scorecard_issues"]
        assert (metadata["name"], metadata["purl"]) == ("@angular/core", "pkg:npm/@angular/core@17.0.0")
        assert (issue["component"], issue["purl"]) == ("@angular/core", "pkg:npm/@angular/core@17.0.0")

    @pytest.mark.asyncio
    async def test_a_payload_a_peer_fetched_is_named_after_the_scanning_component(self, monkeypatch):
        peer = _payload("Django", "4.2.0", "pkg:pypi/Django@4.2.0", 3.0)
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", _FakeCache({}, peer_payload=peer))
        monkeypatch.setattr("app.services.analyzers.deps_dev.InstrumentedAsyncClient", lambda *a, **k: _NoClient())
        component = {"name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        [metadata] = result["package_metadata"].values()
        [issue] = result["scorecard_issues"]
        assert (metadata["name"], issue["component"], issue["purl"]) == ("django", "django", "pkg:pypi/django@4.2.0")

    @pytest.mark.asyncio
    async def test_an_ecosystem_deps_dev_does_not_serve_is_never_looked_up(self, monkeypatch):
        cache = _FakeCache({})
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
        component = {"name": "framework", "version": "10.0.0", "purl": "pkg:composer/laravel/framework@10.0.0"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert cache.looked_up == []

    @pytest.mark.asyncio
    async def test_a_component_without_a_known_version_is_never_looked_up(self, monkeypatch):
        cache = _FakeCache({})
        monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
        component = {"name": "left-pad", "version": "unknown", "purl": "pkg:npm/left-pad"}

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[component])

        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert cache.looked_up == []


class _NoClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a: object) -> None:
        return None


_API = "https://api.deps.dev/v3alpha"
_BABEL = "github.com/babel/babel"
_CORE = {"name": "@babel/core", "version": "7.24.0", "purl": "pkg:npm/%40babel/core@7.24.0"}
_TRAVERSE = {"name": "@babel/traverse", "version": "7.24.0", "purl": "pkg:npm/%40babel/traverse@7.24.0"}
_CORE_KEY = "deps:npm:@babel/core:7.24.0"
_CORE_URL = f"{_API}/systems/npm/packages/%40babel%2Fcore/versions/7.24.0"
_TRAVERSE_URL = f"{_API}/systems/npm/packages/%40babel%2Ftraverse/versions/7.24.0"
_PROJECT_URL = f"{_API}/projects/github.com%2Fbabel%2Fbabel"


def _version_doc(name: str) -> dict[str, Any]:
    return {
        "versionKey": {"system": "NPM", "name": name, "version": "7.24.0"},
        "publishedAt": "2024-02-28T13:25:37Z",
        "isDefault": False,
        "isDeprecated": False,
        "licenses": ["MIT"],
        "advisoryKeys": [],
        "links": [{"label": "SOURCE_REPO", "url": "https://github.com/babel/babel"}],
        "slsaProvenances": [],
        "attestations": [],
        "relatedProjects": [
            {"projectKey": {"id": _BABEL}, "relationProvenance": "UNVERIFIED_METADATA", "relationType": "SOURCE_REPO"}
        ],
    }


def _check(name: str, score: int, reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "documentation": {"shortDescription": f"About {name}.", "url": f"https://scorecard.dev/checks#{name}"},
        "score": score,
        "reason": reason,
        "details": [f"Warn: {reason}"],
    }


_PROJECT_DOC = {
    "projectKey": {"id": _BABEL},
    "openIssuesCount": 812,
    "starsCount": 43000,
    "forksCount": 5700,
    "license": "MIT",
    "description": "Babel is a compiler for writing next generation JavaScript.",
    "homepage": "https://babel.dev",
    "scorecard": {
        "date": "2026-09-22T00:00:00Z",
        "repository": {"name": _BABEL, "commit": "5e2c8b1"},
        "scorecard": {"version": "v5.0.0", "commit": "ea7e27ed"},
        "checks": [
            _check("Maintained", 10, "30 commit(s) and 12 issue activity found in the last 90 days"),
            _check("Code-Review", 2, "Found 3/13 approved changesets"),
            _check("Vulnerabilities", 0, "12 existing vulnerabilities detected"),
            _check("Packaging", -1, "packaging workflow not detected"),
        ],
        "overallScore": 4.2,
        "metadata": [],
    },
}

_DEPENDENTS_DOC = {"dependentCount": 25000, "directDependentCount": 8000, "indirectDependentCount": 17000}


def _babel_routes() -> dict[str, Any]:
    return {
        _CORE_URL: _version_doc("@babel/core"),
        f"{_CORE_URL}:dependents": _DEPENDENTS_DOC,
        _TRAVERSE_URL: _version_doc("@babel/traverse"),
        f"{_TRAVERSE_URL}:dependents": _DEPENDENTS_DOC,
        _PROJECT_URL: _PROJECT_DOC,
    }


class _DepsDev:
    """Answers like api.deps.dev: a JSON body, a status, a raw body or a raised error per URL, else 404."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.requested: list[str] = []
        self.sessions = 0
        self.in_flight = 0
        self.peak_in_flight = 0

    async def __aenter__(self) -> "_DepsDev":
        self.sessions += 1
        return self

    async def __aexit__(self, *_a: object) -> None:
        return None

    async def get(self, url: str, **_kw: Any) -> httpx.Response:
        self.requested.append(url)
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0.01)
        finally:
            self.in_flight -= 1
        answer = self.routes.get(url, 404)
        if isinstance(answer, Exception):
            raise answer
        request = httpx.Request("GET", url)
        if isinstance(answer, int):
            return httpx.Response(answer, request=request)
        if isinstance(answer, str):
            return httpx.Response(200, text=answer, request=request)
        return httpx.Response(200, json=answer, request=request)


def _serve(monkeypatch: pytest.MonkeyPatch, cache: Any, routes: dict[str, Any]) -> _DepsDev:
    api = _DepsDev(routes)
    monkeypatch.setattr("app.services.analyzers.deps_dev.cache_service", cache)
    monkeypatch.setattr("app.services.analyzers.deps_dev.InstrumentedAsyncClient", lambda *a, **k: api)
    return api


class TestDepsDevLookups:
    @pytest.mark.asyncio
    async def test_a_negative_cache_entry_counts_as_a_hit(self, fake_cache, monkeypatch):
        await fake_cache.set(_CORE_KEY, {})
        api = _serve(monkeypatch, fake_cache, _babel_routes())

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE])

        assert api.sessions == 0
        assert result == {"scorecard_issues": [], "package_metadata": {}}

    @pytest.mark.asyncio
    async def test_an_unknown_package_is_negative_cached_as_complete(self, fake_cache, monkeypatch):
        routes = _babel_routes()
        routes[_CORE_URL] = 404
        _serve(monkeypatch, fake_cache, routes)

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE])

        assert result == {"scorecard_issues": [], "package_metadata": {}}
        assert await fake_cache.get(_CORE_KEY) == {}

    @pytest.mark.parametrize(
        ("url", "answer"),
        [
            (_CORE_URL, 500),
            (_CORE_URL, httpx.ReadTimeout("timed out")),
            (_CORE_URL, "<html>upstream error</html>"),
            (_PROJECT_URL, 503),
            (f"{_CORE_URL}:dependents", 500),
        ],
        ids=["version-500", "version-timeout", "version-bad-body", "project-503", "dependents-500"],
    )
    @pytest.mark.asyncio
    async def test_a_failed_lookup_marks_the_component_skipped_and_caches_nothing(
        self, fake_cache, monkeypatch, url, answer
    ):
        routes = _babel_routes()
        routes[url] = answer
        _serve(monkeypatch, fake_cache, routes)

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE])

        assert result["partial_components_skipped"] == 1
        assert result["package_metadata"] == {}
        assert await fake_cache.get(_CORE_KEY) is None

    @pytest.mark.asyncio
    async def test_packages_of_one_project_share_one_project_fetch(self, fake_cache, monkeypatch):
        api = _serve(monkeypatch, fake_cache, _babel_routes())

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE, _TRAVERSE])

        assert api.requested.count(_PROJECT_URL) == 1
        assert [meta["project"]["stars"] for meta in result["package_metadata"].values()] == [43000, 43000]

    @pytest.mark.asyncio
    async def test_project_and_dependents_are_fetched_concurrently(self, fake_cache, monkeypatch):
        api = _serve(monkeypatch, fake_cache, _babel_routes())

        await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE])

        assert api.peak_in_flight == 2

    @pytest.mark.asyncio
    async def test_the_scorecard_issue_carries_only_what_its_readers_use(self, fake_cache, monkeypatch):
        _serve(monkeypatch, fake_cache, _babel_routes())

        result = await DepsDevAnalyzer().analyze({}, parsed_components=[_CORE])

        [issue] = result["scorecard_issues"]
        assert issue == {
            "component": "@babel/core",
            "version": "7.24.0",
            "purl": "pkg:npm/%40babel/core@7.24.0",
            "project_url": "https://github.com/babel/babel",
            "scorecard": {
                "overallScore": 4.2,
                "date": "2026-09-22T00:00:00Z",
                "repository": _BABEL,
                "checks": [
                    {"name": "Maintained", "score": 10},
                    {"name": "Code-Review", "score": 2},
                    {"name": "Vulnerabilities", "score": 0},
                    {"name": "Packaging", "score": -1},
                ],
            },
            "failed_checks": [{"name": "Code-Review", "score": 2}, {"name": "Vulnerabilities", "score": 0}],
            "critical_issues": ["Vulnerabilities"],
        }
        aggregator = ResultAggregator()
        aggregator.aggregate("deps_dev", result)
        [finding] = aggregator.get_findings()
        [quality] = finding.details["quality_issues"]
        details = quality["details"]
        assert (details["overall_score"], details["project_url"], details["critical_issues"]) == (
            4.2,
            "https://github.com/babel/babel",
            ["Vulnerabilities"],
        )
        assert details["checks_summary"] == {"Maintained": 10, "Code-Review": 2, "Vulnerabilities": 0}

    @pytest.mark.asyncio
    async def test_a_project_with_a_higher_threshold_sees_a_package_another_project_fetched_first(
        self, fake_cache, monkeypatch
    ):
        _serve(monkeypatch, fake_cache, _babel_routes())
        analyzer = DepsDevAnalyzer()

        lenient = await analyzer.analyze({}, {"scorecard_threshold": 4.0}, [_CORE])
        strict = await analyzer.analyze({}, {"scorecard_threshold": 7.0}, [_CORE])

        assert lenient["scorecard_issues"] == []
        assert [issue["component"] for issue in strict["scorecard_issues"]] == ["@babel/core"]

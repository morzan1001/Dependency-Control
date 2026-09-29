"""deps.dev analyzer: the validated scorecard threshold and the identity of cached results."""

from typing import Any

import pytest

from app.services.analyzers.deps_dev import DepsDevAnalyzer, _validated_threshold


def test_a_threshold_outside_the_score_range_falls_back_to_the_default():
    assert _validated_threshold({"scorecard_threshold": 11.0}, "scorecard_threshold", 5.0) == 5.0
    assert _validated_threshold({"scorecard_threshold": -1.0}, "scorecard_threshold", 5.0) == 5.0


def test_a_threshold_at_the_edge_of_the_score_range_is_kept():
    assert _validated_threshold({"scorecard_threshold": 0.0}, "scorecard_threshold", 5.0) == 0.0
    assert _validated_threshold({"scorecard_threshold": 10.0}, "scorecard_threshold", 5.0) == 10.0


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
    """What another project's scan cached: its own component's spelling throughout."""
    return {
        "metadata": {"name": name, "version": version, "system": "npm", "purl": purl, "licenses": ["MIT"]},
        "scorecard_issue": {
            "component": name,
            "version": version,
            "purl": purl,
            "scorecard": {"overallScore": score, "checks": []},
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


class _NoClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a: object) -> None:
        return None

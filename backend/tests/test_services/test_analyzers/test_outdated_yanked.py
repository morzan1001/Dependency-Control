"""Tests for the outdated analyzer: version classification and yanked detection.

A version that was published and then withdrawn from the registry is
strictly more dangerous than a merely outdated version — the upstream
authors took action to retract it, often because of a security or
correctness defect. The ``is_version_withdrawn`` helper flags those.

The analyzer fetches each deps.dev package document at most once and derives
the outdated / ahead-of-default / yanked classifications from that single
document, keyed by package (not package+version) so that several installed
versions of the same package are each classified correctly."""

from typing import Any, Dict, List, Optional, Set

import pytest

from app.models.finding import Severity
from app.services.analyzers.outdated import OutdatedAnalyzer, is_version_withdrawn


def _v(version: str, withdrawn: bool = False, default: bool = False) -> dict:
    entry = {"versionKey": {"version": version}}
    if withdrawn:
        entry["isWithdrawn"] = True
    if default:
        entry["isDefault"] = True
    return entry


class TestIsVersionWithdrawn:
    def test_returns_true_when_target_is_withdrawn(self):
        versions = [_v("1.0.0", withdrawn=True), _v("1.0.1", default=True)]
        assert is_version_withdrawn(versions, "1.0.0") is True

    def test_returns_false_when_target_is_active(self):
        versions = [_v("1.0.0"), _v("1.0.1", default=True)]
        assert is_version_withdrawn(versions, "1.0.0") is False

    def test_returns_false_when_target_not_found(self):
        # Conservative default: if we don't have the data, don't claim yanked.
        versions = [_v("1.0.0"), _v("1.0.1")]
        assert is_version_withdrawn(versions, "9.9.9") is False

    def test_handles_empty_versions_list(self):
        assert is_version_withdrawn([], "1.0.0") is False

    def test_only_target_version_matters(self):
        # Other withdrawn entries in the list don't matter — we only care
        # about the version actually installed.
        versions = [
            _v("0.9.0", withdrawn=True),  # old, withdrawn, not what we have
            _v("1.0.0"),
            _v("1.0.1", default=True),
        ]
        assert is_version_withdrawn(versions, "1.0.0") is False

    def test_handles_malformed_entries(self):
        # deps.dev occasionally returns sparse entries; the parser must
        # not crash on them.
        versions = [
            {},  # empty
            {"versionKey": {}},  # no version key
            {"versionKey": {"version": "1.0.0"}, "isWithdrawn": True},
        ]
        assert is_version_withdrawn(versions, "1.0.0") is True

    def test_v_prefix_matches_canonical_form(self):
        # PyPI / npm versions are stored without the "v" prefix in deps.dev.
        # The lookup compares the literal string, but we strip leading "v"
        # from the target to keep parity with how OutdatedAnalyzer normalises.
        versions = [_v("1.0.0", withdrawn=True)]
        assert is_version_withdrawn(versions, "v1.0.0") is True


# --- Test doubles -----------------------------------------------------------


def _component(name: str, version: str, ptype: str = "pypi") -> Dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


class _FakeCache:
    """In-memory replacement for the parts of cache_service the analyzer uses:
    ``mget``, ``get``, ``set`` and ``get_or_fetch_with_lock``."""

    def __init__(self, seed: Optional[Dict[str, Any]] = None) -> None:
        self.store: Dict[str, Any] = dict(seed or {})
        self.mgets: List[List[str]] = []
        self.sets: List[str] = []

    async def mget(self, keys: List[str]) -> Dict[str, Any]:
        self.mgets.append(list(keys))
        return {k: self.store.get(k) for k in keys}

    async def get(self, key: str) -> Optional[Any]:
        return self.store.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 0) -> None:  # noqa: ARG002
        self.sets.append(key)
        self.store[key] = value

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, ttl_seconds: int = 0, **_kw: Any) -> Any:
        existing = self.store.get(key)
        if existing is not None:
            return existing
        data = await fetch_fn()
        # Mirror real cache: negative-cache a None fetch as an empty dict.
        self.store[key] = data if data is not None else {}
        self.sets.append(key)
        return data


class _Response:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int, payload: Dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Dict[str, Any]:
        return self._payload


class _AlwaysFailingClient:
    """Sentinel HTTP client: any .get() call raises so cache-only tests can
    assert the HTTP path was never taken."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None: ...
    async def __aenter__(self) -> "_AlwaysFailingClient":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def get(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("HTTP client should not have been used; cache hit expected")


class _ScriptedClient:
    """HTTP client returning a canned deps.dev document per package URL and
    recording every request, so tests can count round-trips."""

    def __init__(self, docs_by_name: Dict[str, Dict[str, Any]], status: int = 200) -> None:
        self._docs = docs_by_name
        self._status = status
        self.urls: List[str] = []

    def __call__(self, *_args: Any, **_kwargs: Any) -> "_ScriptedClient":
        # Allow being used as the InstrumentedAsyncClient constructor.
        return self

    async def __aenter__(self) -> "_ScriptedClient":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def get(self, url: str, **_kwargs: Any) -> Any:
        self.urls.append(url)
        if self._status != 200:
            return _Response(self._status, {})
        for name, doc in self._docs.items():
            if name in url:
                return _Response(200, doc)
        return _Response(404, {})


def _seed_key(system: str, name: str) -> str:
    return f"latest:{system}:{name}"


# --- Finding 1: multiple versions of one package must each be classified -----


class TestMultipleVersionsOfSamePackage:
    @pytest.mark.asyncio
    async def test_both_versions_classified_from_shared_latest_warm_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # lodash@3.0.0 (outdated) and lodash@4.17.20 (up to date) both present.
        # The latest-version cache is a single package-level key; the older copy
        # must still surface an "Update available" finding.
        cache = _FakeCache({_seed_key("npm", "lodash"): {"default": "4.17.20", "withdrawn": []}})
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)
        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient",
            _AlwaysFailingClient,
        )

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze(
            {},
            parsed_components=[
                _component("lodash", "3.0.0", "npm"),
                _component("lodash", "4.17.20", "npm"),
            ],
        )

        outdated = result["outdated_dependencies"]
        assert len(outdated) == 1
        assert outdated[0]["current_version"] == "3.0.0"
        assert outdated[0]["latest_version"] == "4.17.20"
        # 4.17.20 equals the default, so it is neither outdated nor ahead.
        assert result["ahead_of_default"] == []

    @pytest.mark.asyncio
    async def test_both_versions_classified_on_cold_cache_single_fetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cache = _FakeCache()
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        client = _ScriptedClient({"lodash": {"versions": [_v("3.0.0"), _v("4.17.20", default=True)]}})
        monkeypatch.setattr("app.services.analyzers.outdated.InstrumentedAsyncClient", client)

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze(
            {},
            parsed_components=[
                _component("lodash", "3.0.0", "npm"),
                _component("lodash", "4.17.20", "npm"),
            ],
        )

        outdated = result["outdated_dependencies"]
        assert [o["current_version"] for o in outdated] == ["3.0.0"]
        # The package document is fetched exactly once for both installed versions.
        assert len(client.urls) == 1


# --- Finding 2: one fetch feeds both outdated and yanked classifications -----


class TestSingleFetchFeedsOutdatedAndYanked:
    @pytest.mark.asyncio
    async def test_cold_cache_single_http_call_yields_outdated_and_yanked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = _FakeCache()
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        # 1.0.0 is both withdrawn and behind the 1.0.1 default.
        client = _ScriptedClient({"retract-me": {"versions": [_v("1.0.0", withdrawn=True), _v("1.0.1", default=True)]}})
        monkeypatch.setattr("app.services.analyzers.outdated.InstrumentedAsyncClient", client)

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze({}, parsed_components=[_component("retract-me", "1.0.0")])

        # Both classifications derive from a single HTTP round-trip.
        assert len(client.urls) == 1
        assert len(result["yanked_versions"]) == 1
        assert result["yanked_versions"][0]["severity"] == Severity.HIGH.value
        assert result["yanked_versions"][0]["component"] == "retract-me"
        assert [o["current_version"] for o in result["outdated_dependencies"]] == ["1.0.0"]

    @pytest.mark.asyncio
    async def test_warm_cache_emits_yanked_without_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cache = _FakeCache({_seed_key("pypi", "retract-me"): {"default": "1.0.1", "withdrawn": ["1.0.0"]}})
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)
        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient",
            _AlwaysFailingClient,
        )

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze({}, parsed_components=[_component("retract-me", "1.0.0")])

        assert len(result["yanked_versions"]) == 1
        assert result["yanked_versions"][0]["component"] == "retract-me"

    @pytest.mark.asyncio
    async def test_active_version_emits_no_yanked_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cache = _FakeCache({_seed_key("pypi", "still-good"): {"default": "1.0.1", "withdrawn": ["0.9.0"]}})
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)
        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient",
            _AlwaysFailingClient,
        )

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze({}, parsed_components=[_component("still-good", "1.0.0")])

        assert result["yanked_versions"] == []

    @pytest.mark.asyncio
    async def test_http_failure_skips_findings_rather_than_false_positive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = _FakeCache()
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        client = _ScriptedClient({}, status=500)
        monkeypatch.setattr("app.services.analyzers.outdated.InstrumentedAsyncClient", client)

        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze({}, parsed_components=[_component("flaky", "1.0.0")])

        assert result["yanked_versions"] == []
        assert result["outdated_dependencies"] == []
        assert result["ahead_of_default"] == []


# --- Finding 2b: distinct packages are fetched concurrently, not serially ----


class _ConcurrencyTrackingClient:
    """Records the peak number of simultaneously in-flight GETs to prove the
    fetch path uses concurrency (asyncio.gather) rather than a serial loop."""

    def __init__(self) -> None:
        self.in_flight = 0
        self.max_in_flight = 0
        self.urls: List[str] = []

    def __call__(self, *_args: Any, **_kwargs: Any) -> "_ConcurrencyTrackingClient":
        return self

    async def __aenter__(self) -> "_ConcurrencyTrackingClient":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def get(self, url: str, **_kwargs: Any) -> Any:
        import asyncio as _asyncio

        self.urls.append(url)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await _asyncio.sleep(0.02)
        finally:
            self.in_flight -= 1
        return _Response(200, {"versions": [_v("2.0.0", default=True)]})


class TestConcurrentFetch:
    @pytest.mark.asyncio
    async def test_distinct_packages_fetched_concurrently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cache = _FakeCache()
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        client = _ConcurrencyTrackingClient()
        monkeypatch.setattr("app.services.analyzers.outdated.InstrumentedAsyncClient", client)

        components = [_component(f"pkg{i}", "1.0.0") for i in range(5)]
        analyzer = OutdatedAnalyzer()
        result = await analyzer.analyze({}, parsed_components=components)

        assert len(client.urls) == 5
        assert client.max_in_flight >= 2  # serial execution would peak at 1
        assert len(result["outdated_dependencies"]) == 5


def _suppress_unused(_set: Set[str]) -> None:
    """Hint to linters that Set is intentionally imported for type hints."""
    return None

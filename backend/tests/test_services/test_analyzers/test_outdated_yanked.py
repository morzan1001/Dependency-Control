"""Tests for yanked-version detection (A8) inside the outdated analyzer.

A version that was published and then withdrawn from the registry is
strictly more dangerous than a merely outdated version — the upstream
authors took action to retract it, often because of a security or
correctness defect. Our scans were treating those as legitimate
installations. The detection helper here flags them so the SBOM
report can surface a finding."""

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


# --- Integration tests for _check_yanked: cache + HTTP path ---


def _component(name: str, version: str, ptype: str = "pypi") -> Dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "type": ptype,
        "purl": f"pkg:{ptype}/{name}@{version}",
    }


class _FakeCache:
    """In-memory replacement for cache_service.get / cache_service.set."""

    def __init__(self, seed: Optional[Dict[str, Any]] = None) -> None:
        self.store: Dict[str, Any] = dict(seed or {})
        self.gets: List[str] = []
        self.sets: List[str] = []

    async def get(self, key: str) -> Optional[Any]:
        self.gets.append(key)
        return self.store.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 0) -> None:  # noqa: ARG002
        self.sets.append(key)
        self.store[key] = value


class TestCheckYankedIntegration:
    """The pure helper above is well-covered. These tests exercise the
    cache hot-path and the HTTP miss-path of ``_check_yanked``, since
    both branches affect whether a yanked finding actually surfaces."""

    @pytest.mark.asyncio
    async def test_cache_hit_emits_finding_without_http(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pre-seed the cache with a withdrawn version list. The analyzer
        # should never call the HTTP layer in this path.
        seeded_key = "yanked:pypi:retract-me"
        cache = _FakeCache({seeded_key: ["1.0.0"]})
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        analyzer = OutdatedAnalyzer()
        # InstrumentedAsyncClient is constructed inside _check_yanked; replace
        # it with one whose `.get` raises so any accidental HTTP call fails loud.
        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient",
            _AlwaysFailingClient,
        )

        findings = await analyzer._check_yanked([_component("retract-me", "1.0.0")])
        assert len(findings) == 1
        assert findings[0]["severity"] == Severity.HIGH.value
        assert findings[0]["component"] == "retract-me"
        assert seeded_key in cache.gets

    @pytest.mark.asyncio
    async def test_cache_hit_with_active_version_emits_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Cache holds the withdrawn list, but our installed version isn't in it.
        cache = _FakeCache({"yanked:pypi:still-good": ["0.9.0"]})  # 1.0.0 not yanked
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)
        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient",
            _AlwaysFailingClient,
        )

        analyzer = OutdatedAnalyzer()
        findings = await analyzer._check_yanked([_component("still-good", "1.0.0")])
        assert findings == []

    @pytest.mark.asyncio
    async def test_cache_miss_falls_through_to_http_and_caches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = _FakeCache()  # cold
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        captured_urls: List[str] = []

        class _ScriptedClient:
            def __init__(self, *_a: Any, **_k: Any) -> None: ...
            async def __aenter__(self) -> "_ScriptedClient": return self
            async def __aexit__(self, *_a: Any) -> None: return None

            async def get(self, url: str, **_kwargs: Any) -> Any:
                captured_urls.append(url)
                # deps.dev shape: each version has versionKey.version + isWithdrawn
                return _Response(
                    200,
                    {
                        "versions": [
                            {"versionKey": {"version": "1.0.0"}, "isWithdrawn": True},
                            {"versionKey": {"version": "1.0.1"}, "isDefault": True},
                        ]
                    },
                )

        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient", _ScriptedClient
        )

        analyzer = OutdatedAnalyzer()
        findings = await analyzer._check_yanked([_component("withdrawn-pkg", "1.0.0")])

        # Finding emitted
        assert len(findings) == 1
        assert findings[0]["component"] == "withdrawn-pkg"
        assert findings[0]["severity"] == Severity.HIGH.value
        # HTTP was hit exactly once
        assert len(captured_urls) == 1
        # And the result was cached for the next scan
        assert "yanked:pypi:withdrawn-pkg" in cache.sets

    @pytest.mark.asyncio
    async def test_http_failure_skips_finding_rather_than_false_positive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # If we can't reach deps.dev we must not invent yanked findings —
        # the conservative behaviour is "no signal".
        cache = _FakeCache()
        monkeypatch.setattr("app.services.analyzers.outdated.cache_service", cache)

        class _ErrorClient:
            def __init__(self, *_a: Any, **_k: Any) -> None: ...
            async def __aenter__(self) -> "_ErrorClient": return self
            async def __aexit__(self, *_a: Any) -> None: return None

            async def get(self, *_a: Any, **_kw: Any) -> Any:
                return _Response(500, {})

        monkeypatch.setattr(
            "app.services.analyzers.outdated.InstrumentedAsyncClient", _ErrorClient
        )

        analyzer = OutdatedAnalyzer()
        findings = await analyzer._check_yanked([_component("flaky", "1.0.0")])
        assert findings == []


class _Response:
    """Minimal stand-in for httpx.Response used inside _get_withdrawn_versions."""

    def __init__(self, status_code: int, payload: Dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Dict[str, Any]:
        return self._payload


class _AlwaysFailingClient:
    """Sentinel HTTP client: any .get() call raises so cache-only tests can
    assert the HTTP path was never taken."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None: ...
    async def __aenter__(self) -> "_AlwaysFailingClient": return self
    async def __aexit__(self, *_args: Any) -> None: return None

    async def get(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("HTTP client should not have been used; cache hit expected")


def _suppress_unused(_set: Set[str]) -> None:
    """Hint to linters that Set is intentionally imported for type hints."""
    return None

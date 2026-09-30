"""Tests for the TyposquattingAnalyzer - detects potential typosquatting attacks."""

import logging
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import AsyncMock, patch

import pytest

from app.core.cache import CacheKeys, CacheTTL
from app.core.constants import ANALYZER_TIMEOUTS, TYPOSQUATTING_POPULAR_PACKAGE_RANKS
from app.services.analyzers import typosquatting
from app.services.analyzers.typosquatting import _STATIC_NPM_PACKAGES, _STATIC_PYPI_FALLBACK, TyposquattingAnalyzer
from tests.helpers.analyzers import analyze_cyclonedx


class TestIsSuspicious:
    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    def test_prefix_relationship_not_suspicious(self):
        assert self.analyzer._is_suspicious("react-dom", "react") is False

    def test_reverse_prefix_not_suspicious(self):
        assert self.analyzer._is_suspicious("react", "react-native") is False

    def test_true_typo_is_suspicious(self):
        assert self.analyzer._is_suspicious("reqeusts", "requests") is True

    def test_similar_but_not_prefix(self):
        assert self.analyzer._is_suspicious("expresz", "express") is True

    def test_suffix_addition_not_suspicious(self):
        assert self.analyzer._is_suspicious("flask", "flask-cors") is False

    def test_single_char_swap_suspicious(self):
        assert self.analyzer._is_suspicious("djagno", "django") is True

    def test_hyphen_vs_underscore_normalized_away(self):
        """PEP 503 treats -, _ and . as equivalent, so python_dateutil must not be flagged."""
        from app.services.analyzers.typosquatting import _normalize_pkg_name

        assert _normalize_pkg_name("python_dateutil") == _normalize_pkg_name("python-dateutil")
        assert _normalize_pkg_name("Python.DateUtil") == _normalize_pkg_name("python-dateutil")

    def test_completely_different_names(self):
        assert self.analyzer._is_suspicious("zxcvbn", "abcdef") is True

    def test_name_starts_with_popular(self):
        assert self.analyzer._is_suspicious("express-validator", "express") is False

    def test_suffix_addition_without_separator_is_suspicious(self):
        """A prefix match is legitimate only when a separator follows it, so 'expresss' is suspicious."""
        assert self.analyzer._is_suspicious("expresss", "express") is True
        assert self.analyzer._is_suspicious("requestss", "requests") is True
        assert self.analyzer._is_suspicious("lodashh", "lodash") is True

    def test_legitimate_subpackage_with_separator_still_safe(self):
        # Real sub-packages with a separator must still be allowed.
        assert self.analyzer._is_suspicious("react-dom", "react") is False
        assert self.analyzer._is_suspicious("flask-cors", "flask") is False
        assert self.analyzer._is_suspicious("requests-oauthlib", "requests") is False
        assert self.analyzer._is_suspicious("typing-extensions", "typing") is False
        assert self.analyzer._is_suspicious("django-extensions", "django") is False


class TestNormalizePkgName:
    """Separators in package names are interchangeable per PEP 503; normalisation prevents false positives."""

    def test_collapses_separators(self):
        from app.services.analyzers.typosquatting import _normalize_pkg_name

        assert _normalize_pkg_name("python_dateutil") == "python-dateutil"
        assert _normalize_pkg_name("python.dateutil") == "python-dateutil"
        assert _normalize_pkg_name("python--dateutil") == "python-dateutil"
        assert _normalize_pkg_name("python__dateutil") == "python-dateutil"

    def test_lowercases(self):
        from app.services.analyzers.typosquatting import _normalize_pkg_name

        assert _normalize_pkg_name("Requests") == "requests"
        assert _normalize_pkg_name("PYTHON-DATEUTIL") == "python-dateutil"

    def test_npm_scope_stripped(self):
        # @scope/name -> name: the imitated target is the unscoped popular name.
        from app.services.analyzers.typosquatting import _normalize_pkg_name

        assert _normalize_pkg_name("@babel/core") == "core"
        assert _normalize_pkg_name("@types/node") == "node"

    def test_empty_input(self):
        from app.services.analyzers.typosquatting import _normalize_pkg_name

        assert _normalize_pkg_name("") == ""
        assert _normalize_pkg_name(None) == ""


@pytest.mark.parametrize("name", ["requests", "flask", "django", "numpy", "pydantic", "fastapi"])
def test_the_built_in_pypi_names_cover_the_most_imitated_packages(name):
    assert name in _STATIC_PYPI_FALLBACK


@pytest.mark.parametrize("name", ["react", "lodash", "express", "typescript", "webpack", "vue"])
def test_the_npm_corpus_covers_the_most_imitated_packages(name):
    assert name in _STATIC_NPM_PACKAGES


class TestSeverityThresholds:
    """Severity calculation based on similarity ratio in analyze()."""

    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    CRITICAL_AT = 0.95
    HIGH_AT = 0.90

    def _make_issue(self, ratio):
        """Compute severity via the real production _severity_for_ratio function."""
        from app.services.analyzers.typosquatting import _severity_for_ratio

        return _severity_for_ratio(ratio, self.CRITICAL_AT, self.HIGH_AT)

    def test_ratio_above_095_is_critical(self):
        assert self._make_issue(0.96) == "CRITICAL"

    def test_ratio_above_090_is_high(self):
        assert self._make_issue(0.92) == "HIGH"

    def test_ratio_exactly_091_is_high(self):
        assert self._make_issue(0.91) == "HIGH"

    def test_ratio_below_090_is_medium(self):
        assert self._make_issue(0.85) == "MEDIUM"

    def test_ratio_at_boundary_090_is_medium(self):
        # 0.90 is not > 0.90, so it is MEDIUM.
        assert self._make_issue(0.90) == "MEDIUM"

    def test_ratio_at_boundary_095_is_high(self):
        # 0.95 is not > 0.95, so it is HIGH.
        assert self._make_issue(0.95) == "HIGH"


class TestCorpusMembershipDecidesWhoIsScanned:
    """The corpus names the packages being imitated; a component in it is the real thing."""

    _CORPUS: ClassVar[dict[str, set[str]]] = {"npm": {"express", "react", "lodash"}}

    async def _issues(self, *names):
        analyzer = TyposquattingAnalyzer()
        components = [{"name": name, "version": "1.0.0", "purl": f"pkg:npm/{name}@1.0.0"} for name in names]
        with patch.object(analyzer, "_ensure_popular_packages", new=AsyncMock(return_value=self._CORPUS)):
            result = await analyzer.analyze({}, parsed_components=components)
        return result["typosquatting_issues"]

    @pytest.mark.asyncio
    async def test_the_imitation_is_flagged_and_the_package_it_imitates_is_not(self):
        issues = await self._issues("express", "expresss")

        assert [issue["component"] for issue in issues] == ["expresss"]
        assert issues[0]["imitated_package"] == "express"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["lodashh", "lodashhh"])
    async def test_a_name_within_two_characters_of_a_popular_one_is_still_compared(self, name):
        """The length gate is a shortcut past hopeless pairs, not a filter on same-length names."""
        issues = await self._issues(name)

        assert [issue["imitated_package"] for issue in issues] == ["lodash"]


def _serve_corpus(client_cls, status_code: int, payload) -> None:
    client_cls.return_value.__aenter__.return_value.get = AsyncMock(
        return_value=SimpleNamespace(status_code=status_code, json=lambda: payload)
    )


class TestCorpusDepthIsDeclaredAndReported:
    """One declared depth drives the fetch, and the result says what the comparison covered."""

    @pytest.mark.asyncio
    async def test_the_fetch_cuts_at_the_declared_rank_depth(self):
        served_ranks = TYPOSQUATTING_POPULAR_PACKAGE_RANKS * 3
        payload = {"rows": [{"project": f"pkg-{index}"} for index in range(served_ranks)]}

        with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
            _serve_corpus(ClientCls, 200, payload)
            packages = await TyposquattingAnalyzer()._fetch_pypi_packages()

        assert len(packages) == TYPOSQUATTING_POPULAR_PACKAGE_RANKS

    @pytest.mark.asyncio
    async def test_the_result_names_the_corpus_each_ecosystem_was_compared_against(self):
        analyzer = TyposquattingAnalyzer()
        corpus = {"pypi": {"requests", "flask"}, "npm": {"react"}}

        with patch.object(analyzer, "_ensure_popular_packages", new=AsyncMock(return_value=corpus)):
            result = await analyzer.analyze({"components": []})

        assert result["popular_packages_compared"] == {"npm": 1, "pypi": 2}

    @pytest.mark.asyncio
    async def test_the_fetch_follows_the_corpus_when_it_moves_host(self):
        """A 301 that is not followed leaves the detector on the built-in handful of names."""
        with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
            _serve_corpus(ClientCls, 200, {"rows": []})
            await TyposquattingAnalyzer()._fetch_pypi_packages()

        assert ClientCls.call_args.kwargs["follow_redirects"] is True


class _CorpusCache:
    """Mirrors cache_service.get_or_fetch_with_lock and records every write with its TTL and lock timing."""

    def __init__(self, entries: dict[str, Any] | None = None):
        self.entries = dict(entries or {})
        self.writes: list[tuple[str, Any, int | None]] = []
        self.lock_timing: tuple[int, float] | None = None

    async def get_or_fetch_with_lock(
        self,
        key: str,
        fetch_fn,
        ttl_seconds: int | None = None,
        lock_ttl_seconds: int = 30,
        max_wait_seconds: float = 5.0,
    ) -> Any:
        self.lock_timing = (lock_ttl_seconds, max_wait_seconds)
        if self.entries.get(key) is not None:
            return self.entries[key]
        value = await fetch_fn()
        if value is None:
            self.writes.append((key, {}, CacheTTL.NEGATIVE_RESULT))
        else:
            self.writes.append((key, value, ttl_seconds))
        return value


_PYPI_KEY = CacheKeys.popular_packages("pypi")


class TestOnlyThePypiCorpusIsCached:
    """The npm list is a constant; only the fetched PyPI ranking goes through the locked cache helper."""

    async def _corpus(self, monkeypatch, cache: _CorpusCache, status_code: int = 200, payload=None):
        monkeypatch.setattr(typosquatting, "cache_service", cache)
        with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
            _serve_corpus(ClientCls, status_code, payload)
            corpus = await TyposquattingAnalyzer()._ensure_popular_packages()
        return corpus, ClientCls

    @pytest.mark.asyncio
    async def test_a_fetched_ranking_is_cached_and_the_npm_list_is_not(self, monkeypatch):
        cache = _CorpusCache()

        corpus, _ = await self._corpus(monkeypatch, cache, payload={"rows": [{"project": "Requests"}]})

        assert corpus == {"pypi": {"requests"}, "npm": set(_STATIC_NPM_PACKAGES)}
        assert cache.writes == [(_PYPI_KEY, ["requests"], CacheTTL.POPULAR_PACKAGES)]

    @pytest.mark.asyncio
    async def test_peers_wait_out_the_holders_fetch_instead_of_downloading_again(self, monkeypatch):
        cache = _CorpusCache()

        await self._corpus(monkeypatch, cache, payload={"rows": [{"project": "requests"}]})

        lock_ttl, max_wait = cache.lock_timing
        assert ANALYZER_TIMEOUTS["typosquatting"] < max_wait < lock_ttl

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("status_code", "payload", "reason"),
        [
            pytest.param(301, {}, "HTTP 301", id="unfollowed_redirect"),
            pytest.param(200, {"rows": []}, "empty corpus", id="empty_ranking"),
            pytest.param(200, {"rows": [{"name": "requests"}]}, "KeyError", id="rows_without_project"),
            pytest.param(200, ["requests"], "AttributeError", id="not_an_object"),
        ],
    )
    async def test_an_unusable_ranking_is_negative_cached_and_the_run_uses_the_built_in_names(
        self, monkeypatch, caplog, status_code, payload, reason
    ):
        cache = _CorpusCache()

        with caplog.at_level(logging.WARNING, logger="app.services.analyzers.typosquatting"):
            corpus, _ = await self._corpus(monkeypatch, cache, status_code, payload)

        assert corpus["pypi"] == set(_STATIC_PYPI_FALLBACK)
        assert cache.writes == [(_PYPI_KEY, {}, CacheTTL.NEGATIVE_RESULT)]
        assert reason in caplog.text

    @pytest.mark.asyncio
    async def test_a_cached_negative_entry_uses_the_built_in_names_without_a_fetch(self, monkeypatch):
        cache = _CorpusCache({_PYPI_KEY: {}})

        corpus, client_cls = await self._corpus(monkeypatch, cache)

        assert corpus["pypi"] == set(_STATIC_PYPI_FALLBACK)
        assert client_cls.call_count == 0
        assert cache.writes == []


class TestTheEcosystemComesFromThePurl:
    """The purl's registry is the ecosystem rule every analyzer shares, so a generic purl names none."""

    _CORPUS: ClassVar[dict[str, set[str]]] = {"pypi": {"requests"}}

    async def _issues(self, component):
        analyzer = TyposquattingAnalyzer()
        with patch.object(analyzer, "_ensure_popular_packages", new=AsyncMock(return_value=self._CORPUS)):
            result = await analyze_cyclonedx(analyzer, [component])
        return result["typosquatting_issues"]

    @pytest.mark.asyncio
    async def test_a_pypi_purl_is_compared_against_the_pypi_corpus(self):
        component = {"type": "library", "name": "reqests", "version": "1.0", "purl": "pkg:pypi/reqests@1.0"}

        assert [issue["imitated_package"] for issue in await self._issues(component)] == ["requests"]

    @pytest.mark.asyncio
    async def test_a_syft_binary_type_without_a_purl_is_not_compared(self):
        component = {
            "type": "library",
            "name": "reqests",
            "version": "1.0",
            "properties": [{"name": "syft:package:type", "value": "binary"}],
        }

        assert await self._issues(component) == []

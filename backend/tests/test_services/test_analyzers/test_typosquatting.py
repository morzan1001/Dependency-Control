"""Tests for the TyposquattingAnalyzer - detects potential typosquatting attacks."""

import asyncio
import difflib
import json
import logging
import random
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import AsyncMock, patch

import pytest

from app.core.cache import CacheKeys, CacheTTL
from app.core.constants import (
    ANALYZER_TIMEOUTS,
    TYPOSQUATTING_CRITICAL_SIMILARITY,
    TYPOSQUATTING_HIGH_SIMILARITY,
    TYPOSQUATTING_POPULAR_PACKAGE_RANKS,
    TYPOSQUATTING_SIMILARITY_THRESHOLD,
)
from app.services.analyzers import typosquatting
from app.services.analyzers.typosquatting import (
    _STATIC_PYPI_FALLBACK,
    TyposquattingAnalyzer,
    _severity_for_ratio,
)
from app.services.sbom_parser import parse_sbom
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

    _CORPUS: ClassVar[dict[str, list[str]]] = {"npm": ["express", "lodash", "react"]}

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
    """The fetch keeps the whole ranking, and the result reports the depth the comparison covered."""

    @pytest.mark.asyncio
    async def test_the_fetch_keeps_every_served_rank_in_rank_order(self):
        served = [f"pkg-{index}" for index in reversed(range(TYPOSQUATTING_POPULAR_PACKAGE_RANKS * 3))]

        with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
            _serve_corpus(ClientCls, 200, {"rows": [{"project": name} for name in served]})
            packages = await TyposquattingAnalyzer()._fetch_pypi_packages()

        assert packages == served

    @pytest.mark.asyncio
    async def test_the_result_names_the_depth_each_ecosystem_was_compared_against(self):
        analyzer = TyposquattingAnalyzer()
        deep_ranking = [f"pkg-{index}" for index in range(TYPOSQUATTING_POPULAR_PACKAGE_RANKS + 10)]
        corpus = {"pypi": deep_ranking, "npm": ["react"]}

        with patch.object(analyzer, "_ensure_popular_packages", new=AsyncMock(return_value=corpus)):
            result = await analyzer.analyze({"components": []})

        assert result["popular_packages_compared"] == {"npm": 1, "pypi": TYPOSQUATTING_POPULAR_PACKAGE_RANKS}

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

        assert corpus["pypi"] == ["requests"]
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

        assert corpus["pypi"] == sorted(_STATIC_PYPI_FALLBACK)
        assert cache.writes == [(_PYPI_KEY, {}, CacheTTL.NEGATIVE_RESULT)]
        assert reason in caplog.text

    @pytest.mark.asyncio
    async def test_a_cached_negative_entry_uses_the_built_in_names_without_a_fetch(self, monkeypatch):
        cache = _CorpusCache({_PYPI_KEY: {}})

        corpus, client_cls = await self._corpus(monkeypatch, cache)

        assert corpus["pypi"] == sorted(_STATIC_PYPI_FALLBACK)
        assert client_cls.call_count == 0
        assert cache.writes == []


def _pypi(name: str) -> dict[str, str]:
    return {"type": "library", "name": name, "version": "1.0", "purl": f"pkg:pypi/{name}@1.0"}


def _npm(name: str) -> dict[str, str]:
    return {"type": "library", "name": name, "version": "1.0.0", "purl": f"pkg:npm/{name}@1.0.0"}


async def _issues_against_the_real_corpus(monkeypatch, cache: _CorpusCache, components, payload=None):
    monkeypatch.setattr(typosquatting, "cache_service", cache)
    with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
        _serve_corpus(ClientCls, 200, payload)
        result = await analyze_cyclonedx(TyposquattingAnalyzer(), components)
    return {issue["component"]: issue["imitated_package"] for issue in result["typosquatting_issues"]}


class TestTheWholePypiRankingIsKnownAndOnlyItsTopIsImitated:
    """Every served rank is a real package; only the top ranks are names worth imitating."""

    @pytest.mark.asyncio
    async def test_a_package_ranked_past_the_depth_is_known_and_a_typo_of_the_top_is_flagged(self, monkeypatch):
        top = ["elasticsearch"] + [f"pkg-{index}" for index in range(TYPOSQUATTING_POPULAR_PACKAGE_RANKS - 1)]
        payload = {"rows": [{"project": name} for name in [*top, "elasticsearch8", "zxcvbnmasdf"]]}
        components = [_pypi("elasticsearch8"), _pypi("elasticsaerch"), _pypi("zxcvbnmasdfg")]

        issues = await _issues_against_the_real_corpus(monkeypatch, _CorpusCache(), components, payload)

        assert issues == {"elasticsaerch": "elasticsearch"}


class TestTheShippedNpmRanking:
    """npm components are compared against the shipped download ranking of npm packages."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["react", "lodash", "express", "typescript", "webpack", "vue"])
    async def test_the_most_imitated_packages_are_in_the_compared_top(self, monkeypatch, name):
        monkeypatch.setattr(typosquatting, "cache_service", _CorpusCache({_PYPI_KEY: {}}))

        corpus = await TyposquattingAnalyzer()._ensure_popular_packages()

        assert name in corpus["npm"][:TYPOSQUATTING_POPULAR_PACKAGE_RANKS]

    @pytest.mark.asyncio
    async def test_a_squat_of_a_popular_package_is_flagged_and_popular_lookalikes_are_not(self, monkeypatch):
        """crossenv is the 2017 squat of cross-env; gaxios and @npmcli/redact are popular packages close to axios and react."""
        components = [_npm("crossenv"), _npm("gaxios"), _npm("@npmcli/redact")]

        issues = await _issues_against_the_real_corpus(monkeypatch, _CorpusCache({_PYPI_KEY: {}}), components)

        assert issues == {"crossenv": "cross-env"}

    @pytest.mark.asyncio
    async def test_the_compared_top_counts_unscoped_names_only(self, monkeypatch):
        ranking = [f"@scope/pkg-{index}" for index in range(10)]
        ranking += [f"pkg-{index}" for index in range(TYPOSQUATTING_POPULAR_PACKAGE_RANKS - 1)]
        monkeypatch.setattr(typosquatting, "_NPM_RANKING", [*ranking, "elasticsearch", "zxcvbnmasdf"])
        components = [_npm("elasticsaerch"), _npm("zxcvbnmasdfg")]

        issues = await _issues_against_the_real_corpus(monkeypatch, _CorpusCache({_PYPI_KEY: {}}), components)

        assert issues == {"elasticsaerch": "elasticsearch"}

    @pytest.mark.asyncio
    async def test_a_squat_of_a_rank_behind_scoped_names_is_flagged_and_ranked_lookalikes_are_not(self, monkeypatch):
        """react-intl makes the top only once scoped names are skipped; coffee-script and rambda are ranked packages."""
        components = [_npm("react-intll"), _npm("coffee-script"), _npm("rambda")]

        issues = await _issues_against_the_real_corpus(monkeypatch, _CorpusCache({_PYPI_KEY: {}}), components)

        assert issues == {"react-intll": "react-intl"}

    @pytest.mark.asyncio
    async def test_only_the_full_ranked_name_or_a_ranked_unscoped_name_is_known(self, monkeypatch):
        """Only scoped packages like @sentry/browser are ranked, so an unscoped browser is still compared."""
        components = [_npm("browser"), _npm("@sentry/browser"), _npm("@myorg/axios")]

        issues = await _issues_against_the_real_corpus(monkeypatch, _CorpusCache({_PYPI_KEY: {}}), components)

        assert issues == {"browser": "bowser"}


class TestTheEcosystemComesFromThePurl:
    """The purl's registry is the ecosystem rule every analyzer shares, so a generic purl names none."""

    _CORPUS: ClassVar[dict[str, list[str]]] = {"pypi": ["requests"]}

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


class TestSeveralPassingPopularNames:
    """Several popular names can pass; the closest is reported, and a tie goes to the higher-ranked name."""

    _RANKING: ClassVar[list[str]] = [
        "tomlkit",
        "typing-extensions",
        "pymysql",
        "botocore",
        "flake8",
        "mypy-extensions",
        "tomli",
        "pymssql",
        "aiobotocore",
        "blake3",
    ]

    @pytest.mark.asyncio
    async def test_the_closest_popular_name_is_reported_and_a_tie_goes_to_the_higher_ranked_name(self, monkeypatch):
        monkeypatch.setattr(typosquatting, "cache_service", _CorpusCache({_PYPI_KEY: self._RANKING}))
        components = [
            {"type": "library", "name": name, "version": "1.0", "purl": f"pkg:pypi/{name}@1.0"}
            for name in ("abotocore", "tomlki", "typin-extensions", "mypyi-extensions", "pmyssql", "flake3")
        ]

        result = await analyze_cyclonedx(TyposquattingAnalyzer(), components)

        assert [
            (issue["component"], issue["imitated_package"], issue["similarity"], issue["severity"])
            for issue in result["typosquatting_issues"]
        ] == [
            ("abotocore", "botocore", 0.94, "HIGH"),
            ("tomlki", "tomlkit", 0.92, "HIGH"),
            ("typin-extensions", "typing-extensions", 0.97, "CRITICAL"),
            ("mypyi-extensions", "mypy-extensions", 0.97, "CRITICAL"),
            ("pmyssql", "pymysql", 0.86, "MEDIUM"),
            ("flake3", "flake8", 0.83, "MEDIUM"),
        ]


_UV_SBOM = Path(__file__).parents[2] / "fixtures" / "sbom" / "uvdev.syft.cdx.json"
_SCANNED_COMPONENTS = 1000
_PLANTED = 20
_HEARTBEAT_SECONDS = 0.01
_MAX_LOOP_GAP_SECONDS = 0.5


def _names(rng: random.Random, letters: str, count: int) -> list[str]:
    names: set[str] = set()
    while len(names) < count:
        names.add("".join(rng.choice(letters) for _ in range(rng.randint(5, 14))))
    return sorted(names)


def _cyclonedx_of(names: list[str]) -> dict[str, Any]:
    """The uv fixture with its first component's syft record repeated under each name."""
    sbom = json.loads(_UV_SBOM.read_text())
    template = json.dumps(sbom["components"][0])
    sbom["components"] = [json.loads(template.replace("anyio", name)) for name in names]
    sbom["dependencies"] = []
    return sbom


async def _with_largest_loop_gap(awaitable):
    """Await ``awaitable`` while a heartbeat measures the longest the event loop went unserved."""
    gaps: list[float] = []
    done = False

    async def beat():
        while not done:
            started = time.perf_counter()
            await asyncio.sleep(_HEARTBEAT_SECONDS)
            gaps.append(time.perf_counter() - started)

    beating = asyncio.create_task(beat())
    await asyncio.sleep(0)
    result = await awaitable
    done = True
    await beating
    return result, max(gaps)


class TestALargeSbomDoesNotStallTheLoop:
    """The pairwise comparison runs in a thread, and only pairs that can pass get a full ratio."""

    @pytest.mark.asyncio
    async def test_1000_components_leave_the_loop_served_and_report_the_plain_ratios(self, monkeypatch):
        rng = random.Random(20260930)
        popular = _names(rng, "abcdefghijklm", TYPOSQUATTING_POPULAR_PACKAGE_RANKS)
        swapped = (name[:2] + name[3] + name[2] + name[4:] for name in popular[::50] if len(name) >= 8)
        planted = [name for name in swapped if name not in popular][:_PLANTED]
        clean = _names(rng, "nopqrstuvwxyz", _SCANNED_COMPONENTS - _PLANTED)
        parsed = [dep.model_dump() for dep in parse_sbom(_cyclonedx_of(clean + planted)).dependencies]
        analyzer = TyposquattingAnalyzer()
        ranking = popular[::-1]
        payload = {"rows": [{"project": name} for name in ranking]}
        monkeypatch.setattr(typosquatting, "cache_service", _CorpusCache())

        with patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls:
            _serve_corpus(ClientCls, 200, payload)
            result, gap = await _with_largest_loop_gap(analyzer.analyze({}, parsed_components=parsed))

        assert len(parsed) == _SCANNED_COMPONENTS
        assert gap < _MAX_LOOP_GAP_SECONDS
        assert {
            issue["component"]: (issue["imitated_package"], issue["similarity"], issue["severity"])
            for issue in result["typosquatting_issues"]
        } == {name: _ungated_verdict(analyzer, name, ranking) for name in planted}


def _ungated_verdict(analyzer: TyposquattingAnalyzer, name: str, ranking: list[str]) -> tuple[str, float, str]:
    """The passing popular name with the highest plain ratio (the higher-ranked on a tie), ungated."""
    passing = [
        (ratio, candidate)
        for candidate in ranking
        if abs(len(name) - len(candidate)) <= 2 and analyzer._is_suspicious(name, candidate)
        for ratio in [difflib.SequenceMatcher(None, name, candidate).ratio()]
        if ratio > TYPOSQUATTING_SIMILARITY_THRESHOLD
    ]
    if not passing:
        raise AssertionError(f"{name} imitates no popular name")
    ratio, candidate = max(passing, key=lambda pair: pair[0])
    severity = _severity_for_ratio(ratio, TYPOSQUATTING_CRITICAL_SIMILARITY, TYPOSQUATTING_HIGH_SIMILARITY)
    return candidate, round(ratio, 2), severity

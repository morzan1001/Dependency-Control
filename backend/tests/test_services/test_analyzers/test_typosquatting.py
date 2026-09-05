"""Tests for the TyposquattingAnalyzer - detects potential typosquatting attacks."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.cache import cache_service
from app.core.constants import TYPOSQUATTING_POPULAR_PACKAGE_RANKS
from app.services.analyzers.typosquatting import TyposquattingAnalyzer


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

    def test_identical_names_not_suspicious(self):
        assert self.analyzer._is_suspicious("lodash", "lodash") is False

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
        """A prefix match is legitimate only when followed by a separator (-, _, .), so 'expresss' is suspicious."""
        assert self.analyzer._is_suspicious("expresss", "express") is True
        assert self.analyzer._is_suspicious("requestss", "requests") is True
        assert self.analyzer._is_suspicious("lodashh", "lodash") is True

    def test_legitimate_subpackage_with_separator_still_safe(self):
        # Real sub-packages with a separator must still be allowed.
        assert self.analyzer._is_suspicious("react-dom", "react") is False
        assert self.analyzer._is_suspicious("flask-cors", "flask") is False
        assert self.analyzer._is_suspicious("requests-oauthlib", "requests") is False
        assert self.analyzer._is_suspicious("typing.extensions", "typing") is False
        assert self.analyzer._is_suspicious("django_extensions", "django") is False


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


class TestGetStaticPypi:
    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    def test_returns_non_empty_set(self):
        result = self.analyzer._get_static_pypi()
        assert isinstance(result, set)
        assert len(result) > 0

    def test_contains_requests(self):
        assert "requests" in self.analyzer._get_static_pypi()

    def test_contains_flask(self):
        assert "flask" in self.analyzer._get_static_pypi()

    def test_contains_django(self):
        assert "django" in self.analyzer._get_static_pypi()

    def test_contains_numpy(self):
        assert "numpy" in self.analyzer._get_static_pypi()

    def test_contains_pydantic(self):
        assert "pydantic" in self.analyzer._get_static_pypi()

    def test_contains_fastapi(self):
        assert "fastapi" in self.analyzer._get_static_pypi()


class TestGetStaticNpm:
    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    def test_returns_non_empty_set(self):
        result = self.analyzer._get_static_npm()
        assert isinstance(result, set)
        assert len(result) > 0

    def test_contains_react(self):
        assert "react" in self.analyzer._get_static_npm()

    def test_contains_lodash(self):
        assert "lodash" in self.analyzer._get_static_npm()

    def test_contains_express(self):
        assert "express" in self.analyzer._get_static_npm()

    def test_contains_typescript(self):
        assert "typescript" in self.analyzer._get_static_npm()

    def test_contains_webpack(self):
        assert "webpack" in self.analyzer._get_static_npm()

    def test_contains_vue(self):
        assert "vue" in self.analyzer._get_static_npm()


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


class TestCorpusDepthIsDeclaredAndReported:
    """One declared depth drives the fetch, and the result says what the comparison covered."""

    @pytest.mark.asyncio
    async def test_the_fetch_cuts_at_the_declared_rank_depth(self):
        served_ranks = TYPOSQUATTING_POPULAR_PACKAGE_RANKS * 3
        payload = {"rows": [{"project": f"pkg-{index}"} for index in range(served_ranks)]}

        with (
            patch.object(cache_service, "set", new=AsyncMock()),
            patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls,
        ):
            ClientCls.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=SimpleNamespace(status_code=200, json=lambda: payload)
            )
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
        with (
            patch.object(cache_service, "set", new=AsyncMock()),
            patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls,
        ):
            ClientCls.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=SimpleNamespace(status_code=200, json=lambda: {"rows": []})
            )
            await TyposquattingAnalyzer()._fetch_pypi_packages()

        assert ClientCls.call_args.kwargs["follow_redirects"] is True

    @pytest.mark.asyncio
    async def test_falling_back_to_the_built_in_names_is_reported(self, caplog):
        with (
            patch.object(cache_service, "set", new=AsyncMock()),
            patch("app.services.analyzers.typosquatting.InstrumentedAsyncClient") as ClientCls,
            caplog.at_level(logging.WARNING, logger="app.services.analyzers.typosquatting"),
        ):
            ClientCls.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=SimpleNamespace(status_code=301, json=lambda: {})
            )
            packages = await TyposquattingAnalyzer()._fetch_pypi_packages()

        assert len(packages) < TYPOSQUATTING_POPULAR_PACKAGE_RANKS
        assert "HTTP 301" in caplog.text

"""Tests for the TyposquattingAnalyzer - detects potential typosquatting attacks."""

from app.services.analyzers.typosquatting import TyposquattingAnalyzer


class TestIsSuspicious:
    """Tests for _is_suspicious - determines if a package name is a suspicious near-match."""

    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    def test_prefix_relationship_not_suspicious(self):
        """'react-dom' starts with 'react', so it is not suspicious."""
        assert self.analyzer._is_suspicious("react-dom", "react") is False

    def test_reverse_prefix_not_suspicious(self):
        """'react' starts 'react-native', so it is not suspicious."""
        assert self.analyzer._is_suspicious("react", "react-native") is False

    def test_true_typo_is_suspicious(self):
        """'reqeusts' is a typo of 'requests' (no prefix relationship)."""
        assert self.analyzer._is_suspicious("reqeusts", "requests") is True

    def test_similar_but_not_prefix(self):
        """'expresz' does not start with 'express' nor vice versa."""
        assert self.analyzer._is_suspicious("expresz", "express") is True

    def test_identical_names_not_suspicious(self):
        """Identical names: one starts with the other, so returns False."""
        assert self.analyzer._is_suspicious("lodash", "lodash") is False

    def test_suffix_addition_not_suspicious(self):
        """'flask' starts with 'flask' prefix of 'flask-cors'."""
        assert self.analyzer._is_suspicious("flask", "flask-cors") is False

    def test_single_char_swap_suspicious(self):
        """'djagno' is a typo of 'django' (no prefix relationship)."""
        assert self.analyzer._is_suspicious("djagno", "django") is True

    def test_hyphen_vs_underscore_suspicious(self):
        """Names differing by separator are suspicious if no prefix match."""
        # "python_dateutil" does not start with "python-dateutil" nor vice versa
        assert self.analyzer._is_suspicious("python_dateutil", "python-dateutil") is True

    def test_completely_different_names(self):
        """Completely unrelated names with no prefix relationship."""
        assert self.analyzer._is_suspicious("zxcvbn", "abcdef") is True

    def test_name_starts_with_popular(self):
        """If name starts with popular, it's not suspicious (legitimate extension)."""
        assert self.analyzer._is_suspicious("express-validator", "express") is False


class TestGetStaticPypi:
    """Tests for _get_static_pypi - returns a static set of popular PyPI packages."""

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
    """Tests for _get_static_npm - returns a static set of popular npm packages."""

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
    """Tests for severity calculation based on similarity ratio in analyze()."""

    def setup_method(self):
        self.analyzer = TyposquattingAnalyzer()

    def _make_issue(self, ratio):
        """Build a severity string using the same thresholds as analyze()."""
        from app.models.finding import Severity

        if ratio > 0.95:
            return Severity.CRITICAL.value
        elif ratio > 0.90:
            return Severity.HIGH.value
        else:
            return Severity.MEDIUM.value

    def test_ratio_above_095_is_critical(self):
        assert self._make_issue(0.96) == "CRITICAL"

    def test_ratio_exactly_096_is_critical(self):
        assert self._make_issue(0.96) == "CRITICAL"

    def test_ratio_above_090_is_high(self):
        assert self._make_issue(0.92) == "HIGH"

    def test_ratio_exactly_091_is_high(self):
        assert self._make_issue(0.91) == "HIGH"

    def test_ratio_below_090_is_medium(self):
        assert self._make_issue(0.85) == "MEDIUM"

    def test_ratio_at_boundary_090_is_medium(self):
        """Ratio of exactly 0.90 is not > 0.90, so it is MEDIUM."""
        assert self._make_issue(0.90) == "MEDIUM"

    def test_ratio_at_boundary_095_is_high(self):
        """Ratio of exactly 0.95 is not > 0.95, so it is HIGH."""
        assert self._make_issue(0.95) == "HIGH"

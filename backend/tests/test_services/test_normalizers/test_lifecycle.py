"""Tests for lifecycle normalizers (outdated packages, end-of-life)."""

from app.services.aggregator import ResultAggregator


class TestNormalizeOutdated:
    """Tests for normalize_outdated - outdated package normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_outdated(self):
        result = {
            "outdated_dependencies": [
                {
                    "component": "lodash",
                    "current_version": "4.17.0",
                    "latest_version": "4.17.21",
                    "severity": "INFO",
                    "message": "lodash is outdated (4.17.0 -> 4.17.21)",
                }
            ]
        }
        self.agg.aggregate("outdated_packages", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "outdated"
        assert f.component == "lodash"
        assert f.version == "4.17.0"
        assert f.details["fixed_version"] == "4.17.21"
        assert "outdated_packages" in f.scanners

    def test_default_severity_info(self):
        """Outdated findings should default to INFO severity."""
        result = {
            "outdated_dependencies": [
                {"component": "pkg", "current_version": "1.0"}
            ]
        }
        self.agg.aggregate("outdated_packages", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "INFO"

    def test_custom_severity(self):
        result = {
            "outdated_dependencies": [
                {"component": "pkg", "current_version": "1.0", "severity": "MEDIUM"}
            ]
        }
        self.agg.aggregate("outdated_packages", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "MEDIUM"

    def test_default_description(self):
        """Without message, should generate default description."""
        result = {
            "outdated_dependencies": [
                {"component": "lodash", "current_version": "1.0"}
            ]
        }
        self.agg.aggregate("outdated_packages", result)
        f = list(self.agg.findings.values())[0]
        assert "lodash" in f.description

    def test_empty_dependencies(self):
        self.agg.aggregate("outdated_packages", {"outdated_dependencies": []})
        assert len(self.agg.findings) == 0

    def test_multiple_outdated(self):
        result = {
            "outdated_dependencies": [
                {"component": "pkg-a", "current_version": "1.0", "latest_version": "2.0"},
                {"component": "pkg-b", "current_version": "3.0", "latest_version": "4.0"},
            ]
        }
        self.agg.aggregate("outdated_packages", result)
        assert len(self.agg.findings) == 2


class TestNormalizeEol:
    """Tests for normalize_eol - end-of-life normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_eol(self):
        result = {
            "eol_issues": [
                {
                    "component": "nodejs",
                    "version": "14.0.0",
                    "eol_info": {
                        "eol": "2023-04-30",
                        "cycle": "14",
                        "latest": "20.10.0",
                    },
                }
            ]
        }
        self.agg.aggregate("end_of_life", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "eol"
        assert f.severity == "HIGH"  # EOL is always HIGH
        assert f.component == "nodejs"
        assert "end_of_life" in f.scanners

    def test_description_contains_eol_date(self):
        result = {
            "eol_issues": [
                {
                    "component": "python",
                    "version": "3.7.0",
                    "eol_info": {
                        "eol": "2023-06-27",
                        "cycle": "3.7",
                        "latest": "3.12.0",
                    },
                }
            ]
        }
        self.agg.aggregate("end_of_life", result)
        f = list(self.agg.findings.values())[0]
        assert "2023-06-27" in f.description
        assert "3.7" in f.description

    def test_fixed_version_is_latest(self):
        result = {
            "eol_issues": [
                {
                    "component": "ruby",
                    "version": "2.7.0",
                    "eol_info": {
                        "eol": "2023-03-31",
                        "cycle": "2.7",
                        "latest": "3.3.0",
                    },
                }
            ]
        }
        self.agg.aggregate("end_of_life", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["fixed_version"] == "3.3.0"

    def test_eol_details(self):
        result = {
            "eol_issues": [
                {
                    "component": "django",
                    "version": "3.2.0",
                    "eol_info": {
                        "eol": "2024-04-01",
                        "cycle": "3.2",
                        "latest": "5.0.0",
                        "lts": True,
                        "link": "https://endoflife.date/django",
                    },
                }
            ]
        }
        self.agg.aggregate("end_of_life", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["eol_date"] == "2024-04-01"
        assert f.details["cycle"] == "3.2"
        assert f.details["lts"] is True
        assert f.details["link"] == "https://endoflife.date/django"

    def test_empty_issues(self):
        self.agg.aggregate("end_of_life", {"eol_issues": []})
        assert len(self.agg.findings) == 0

    def test_missing_eol_info(self):
        """Gracefully handle missing eol_info."""
        result = {"eol_issues": [{"component": "pkg", "version": "1.0"}]}
        self.agg.aggregate("end_of_life", result)
        f = list(self.agg.findings.values())[0]
        assert f.type == "eol"
        assert f.component == "pkg"

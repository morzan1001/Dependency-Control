"""Tests for license normalizer."""

from app.services.aggregator import ResultAggregator


class TestNormalizeLicense:
    """Tests for normalize_license - license compliance normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_license_issue(self):
        result = {
            "license_issues": [
                {
                    "component": "left-pad",
                    "version": "1.3.0",
                    "license": "GPL-3.0",
                    "severity": "HIGH",
                    "category": "copyleft",
                    "message": "GPL-3.0 is copyleft and may require source disclosure",
                }
            ]
        }
        self.agg.aggregate("license_compliance", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "license"
        assert f.component == "left-pad"
        assert f.severity == "HIGH"
        assert "license_compliance" in f.scanners

    def test_license_details(self):
        result = {
            "license_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "license": "AGPL-3.0",
                    "category": "copyleft",
                    "explanation": "Strong copyleft license",
                    "recommendation": "Consider alternative",
                    "obligations": ["disclose source"],
                    "risks": ["viral licensing"],
                }
            ]
        }
        self.agg.aggregate("license_compliance", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["license"] == "AGPL-3.0"
        assert f.details["category"] == "copyleft"
        assert f.details["explanation"] == "Strong copyleft license"
        assert f.details["obligations"] == ["disclose source"]
        assert f.details["risks"] == ["viral licensing"]

    def test_default_severity_medium(self):
        """License issues should default to MEDIUM severity."""
        result = {"license_issues": [{"component": "pkg", "version": "1.0", "license": "MIT"}]}
        self.agg.aggregate("license_compliance", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "MEDIUM"

    def test_default_description(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0", "license": "GPL-2.0"}]}
        self.agg.aggregate("license_compliance", result)
        f = list(self.agg.findings.values())[0]
        assert "GPL-2.0" in f.description

    def test_enrichment_called(self):
        """License scanner should enrich dependency data."""
        result = {
            "license_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "license": "MIT",
                    "category": "permissive",
                }
            ]
        }
        self.agg.aggregate("license_compliance", result)
        license_data = self.agg.get_license_data()
        assert "pkg@1.0" in license_data

    def test_empty_issues(self):
        self.agg.aggregate("license_compliance", {"license_issues": []})
        assert len(self.agg.findings) == 0

    def test_unknown_license(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0"}]}
        self.agg.aggregate("license_compliance", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["license"] == "UNKNOWN"

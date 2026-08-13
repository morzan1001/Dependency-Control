"""Tests for license normalizer."""

from app.services.aggregation import ResultAggregator


class TestNormalizeLicense:
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
        f = next(iter(self.agg.findings.values()))
        assert f.details["license"] == "AGPL-3.0"
        assert f.details["category"] == "copyleft"
        assert f.details["explanation"] == "Strong copyleft license"
        assert f.details["obligations"] == ["disclose source"]
        assert f.details["risks"] == ["viral licensing"]

    def test_default_severity_medium(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0", "license": "MIT"}]}
        self.agg.aggregate("license_compliance", result)
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "MEDIUM"

    def test_default_description(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0", "license": "GPL-2.0"}]}
        self.agg.aggregate("license_compliance", result)
        f = next(iter(self.agg.findings.values()))
        assert "GPL-2.0" in f.description

    def test_component_licenses_feed_enrichment(self):
        result = {
            "license_issues": [],
            "component_licenses": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "purl": "pkg:npm/pkg@1.0",
                    "license": "MIT",
                    "category": "permissive",
                    "obligations": [],
                    "risks": [],
                    "explanation": "Permissive license",
                }
            ],
        }
        self.agg.aggregate("license_compliance", result)
        payload = self.agg.get_dependency_enrichments()["pkg@1.0"]
        assert payload["license"] == "MIT"
        assert payload["license_category"] == "permissive"

    def test_issues_alone_do_not_feed_enrichment(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0", "license": "GPL-3.0-only"}]}
        self.agg.aggregate("license_compliance", result)
        assert self.agg.get_dependency_enrichments() == {}

    def test_empty_issues(self):
        self.agg.aggregate("license_compliance", {"license_issues": []})
        assert len(self.agg.findings) == 0

    def test_unknown_license(self):
        result = {"license_issues": [{"component": "pkg", "version": "1.0"}]}
        self.agg.aggregate("license_compliance", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["license"] == "UNKNOWN"

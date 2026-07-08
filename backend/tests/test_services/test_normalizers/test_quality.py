"""Tests for quality normalizers (Scorecard, Typosquatting, Maintainer Risk)."""

from app.services.aggregation import ResultAggregator


class TestNormalizeScorecard:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_scorecard(self):
        result = {
            "scorecard_issues": [
                {
                    "component": "lodash",
                    "version": "4.17.0",
                    "scorecard": {"overallScore": 3.5, "checks": []},
                    "failed_checks": [
                        {"name": "Maintained", "score": 0},
                        {"name": "Vulnerabilities", "score": 0},
                    ],
                    "critical_issues": ["Maintained", "Vulnerabilities"],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "quality"
        assert f.component == "lodash"
        assert "deps_dev" in f.scanners

    def test_severity_high_for_low_score(self):
        """Score < 3.0 should be HIGH severity."""
        result = {
            "scorecard_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "scorecard": {"overallScore": 2.5, "checks": []},
                    "failed_checks": [],
                    "critical_issues": [],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "HIGH"

    def test_severity_high_for_maintained_critical(self):
        """'Maintained' in critical_issues should be HIGH regardless of score."""
        result = {
            "scorecard_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "scorecard": {"overallScore": 4.0, "checks": []},
                    "failed_checks": [],
                    "critical_issues": ["Maintained"],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "HIGH"

    def test_severity_medium_for_moderate_score(self):
        """Score >= 3.0 but < 5.0 should be MEDIUM severity."""
        result = {
            "scorecard_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "scorecard": {"overallScore": 4.5, "checks": []},
                    "failed_checks": [{"name": "Fuzzing", "score": 0}],
                    "critical_issues": ["Fuzzing"],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "MEDIUM"

    def test_severity_low_for_good_score(self):
        """Score >= 5.0 with no critical issues should be LOW."""
        result = {
            "scorecard_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "scorecard": {"overallScore": 7.0, "checks": []},
                    "failed_checks": [{"name": "Fuzzing", "score": 0}],
                    "critical_issues": [],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "LOW"

    def test_description_contains_score(self):
        result = {
            "scorecard_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "scorecard": {"overallScore": 3.5, "checks": []},
                    "failed_checks": [],
                    "critical_issues": [],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        f = list(self.agg.findings.values())[0]
        assert "3.5" in f.description

    def test_record_scorecard_public_method(self):
        assert hasattr(ResultAggregator, "record_scorecard")
        self.agg.record_scorecard("pkg@2.0", {"overall_score": 4.2})
        assert self.agg._scorecard_cache["pkg@2.0"] == {"overall_score": 4.2}

    def test_scorecard_recorded_end_to_end(self):
        """Recorded scorecard payload is complete and keyed by component@version."""
        result = {
            "scorecard_issues": [
                {
                    "component": "requests",
                    "version": "2.31.0",
                    "project_url": "https://github.com/psf/requests",
                    "scorecard": {
                        "overallScore": 2.5,
                        "checks": [{"name": "Fuzzing", "score": 0}],
                    },
                    "failed_checks": [{"name": "Fuzzing", "score": 0}],
                    "critical_issues": ["Maintained"],
                }
            ]
        }
        self.agg.aggregate("deps_dev", result)
        cached = self.agg._scorecard_cache.get("requests@2.31.0")
        assert cached is not None, "scorecard data was silently dropped"
        assert cached["overall_score"] == 2.5
        assert cached["project_url"] == "https://github.com/psf/requests"
        assert cached["critical_issues"] == ["Maintained"]
        assert cached["failed_checks"] == [{"name": "Fuzzing", "score": 0}]
        assert cached["checks"] == [{"name": "Fuzzing", "score": 0}]

    def test_empty_scorecard_issues(self):
        self.agg.aggregate("deps_dev", {"scorecard_issues": []})
        assert len(self.agg.findings) == 0

    def test_package_metadata_enrichment(self):
        result = {
            "package_metadata": {
                "lodash@4.17.21": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "project": {"stars": 58000, "forks": 7000},
                }
            },
            "scorecard_issues": [],
        }
        self.agg.aggregate("deps_dev", result)
        enrichments = self.agg.get_dependency_enrichments()
        assert "lodash@4.17.21" in enrichments


class TestNormalizeTyposquatting:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_typosquat(self):
        result = {
            "typosquatting_issues": [
                {
                    "component": "lodassh",
                    "version": "1.0.0",
                    "imitated_package": "lodash",
                    "similarity": 0.9,
                }
            ]
        }
        self.agg.aggregate("typosquatting", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "malware"
        assert f.severity == "CRITICAL"
        assert "lodassh" in f.description
        assert "lodash" in f.description

    def test_similarity_in_description(self):
        result = {
            "typosquatting_issues": [
                {
                    "component": "reacct",
                    "imitated_package": "react",
                    "similarity": 0.85,
                }
            ]
        }
        self.agg.aggregate("typosquatting", result)
        f = list(self.agg.findings.values())[0]
        assert "85.0%" in f.description

    def test_details_contain_imitated_package(self):
        result = {
            "typosquatting_issues": [
                {
                    "component": "reacct",
                    "imitated_package": "react",
                    "similarity": 0.9,
                }
            ]
        }
        self.agg.aggregate("typosquatting", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["imitated_package"] == "react"
        assert f.details["similarity"] == 0.9

    def test_empty_issues(self):
        self.agg.aggregate("typosquatting", {"typosquatting_issues": []})
        assert len(self.agg.findings) == 0


class TestNormalizeMaintainerRisk:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_maintainer_risk(self):
        result = {
            "maintainer_issues": [
                {
                    "component": "old-package",
                    "version": "1.0.0",
                    "severity": "MEDIUM",
                    "risks": [{"type": "stale_package", "message": "No releases in 2+ years"}],
                }
            ]
        }
        self.agg.aggregate("maintainer_risk", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "quality"
        assert f.severity == "MEDIUM"
        assert "maintainer_risk" in f.scanners

    def test_multiple_risks_combined(self):
        result = {
            "maintainer_issues": [
                {
                    "component": "pkg",
                    "version": "1.0",
                    "risks": [
                        {"type": "stale_package", "message": "Stale"},
                        {"type": "single_maintainer", "message": "Single maintainer"},
                    ],
                }
            ]
        }
        self.agg.aggregate("maintainer_risk", result)
        f = list(self.agg.findings.values())[0]
        assert "Stale" in f.description
        assert "Single maintainer" in f.description

    def test_default_severity_medium(self):
        result = {
            "maintainer_issues": [
                {
                    "component": "pkg",
                    "risks": [{"type": "test", "message": "test"}],
                }
            ]
        }
        self.agg.aggregate("maintainer_risk", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "MEDIUM"

    def test_empty_issues(self):
        self.agg.aggregate("maintainer_risk", {"maintainer_issues": []})
        assert len(self.agg.findings) == 0

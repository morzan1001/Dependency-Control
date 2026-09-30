"""Tests for quality normalizers (Scorecard, Typosquatting, Maintainer Risk)."""

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analyzers.typosquatting import TyposquattingAnalyzer
from tests.helpers.analyzers import analyze_cyclonedx


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
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
        assert "3.5" in f.description

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
        assert [(e["name"], e["version"]) for e in enrichments] == [("lodash", "4.17.21")]


async def _typosquatting_result(name: str, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    analyzer = TyposquattingAnalyzer()
    component = {"type": "library", "name": name, "version": "1.0.0", "purl": f"pkg:npm/{name}@1.0.0"}
    corpus = {"npm": {"lodash", "react", "typescript"}}
    with patch.object(analyzer, "_ensure_popular_packages", new=AsyncMock(return_value=corpus)):
        return await analyze_cyclonedx(analyzer, [component], settings)


class TestNormalizeTyposquatting:
    def setup_method(self):
        self.agg = ResultAggregator()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("name", "severity"),
        [
            pytest.param("lodahs", "MEDIUM", id="similarity_0.83"),
            pytest.param("reacct", "HIGH", id="similarity_0.91"),
            pytest.param("typescriptt", "CRITICAL", id="similarity_0.95"),
        ],
    )
    async def test_the_finding_keeps_the_severity_the_analyzer_graded(self, name, severity):
        self.agg.aggregate("typosquatting", await _typosquatting_result(name))

        [finding] = self.agg.get_findings()
        assert finding.type == "malware"
        assert finding.severity == severity

    @pytest.mark.asyncio
    async def test_the_project_similarity_settings_move_the_severity(self):
        self.agg.aggregate("typosquatting", await _typosquatting_result("lodahs", {"high_similarity": 0.8}))

        assert [finding.severity for finding in self.agg.get_findings()] == ["HIGH"]

    @pytest.mark.asyncio
    async def test_the_description_is_the_analyzer_message(self):
        result = await _typosquatting_result("reacct")
        self.agg.aggregate("typosquatting", result)

        [finding] = self.agg.get_findings()
        assert finding.description == result["typosquatting_issues"][0]["message"]
        assert finding.description == (
            "Possible typosquatting detected! 'reacct' is 91.0% similar to popular package 'react'"
        )

    @pytest.mark.asyncio
    async def test_details_contain_imitated_package(self):
        self.agg.aggregate("typosquatting", await _typosquatting_result("reacct"))

        [finding] = self.agg.get_findings()
        assert finding.details["imitated_package"] == "react"
        assert finding.details["similarity"] == 0.91

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
        f = next(iter(self.agg.findings.values()))
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
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "MEDIUM"

    def test_empty_issues(self):
        self.agg.aggregate("maintainer_risk", {"maintainer_issues": []})
        assert len(self.agg.findings) == 0


class TestQualityIssueTypeFollowsTheNormalizerPrefix:
    def test_scorecard_and_maintainer_findings_land_in_their_buckets(self):
        agg = ResultAggregator()
        agg.aggregate(
            "deps_dev",
            {
                "scorecard_issues": [
                    {
                        "component": "lodash",
                        "version": "4.17.0",
                        "scorecard": {"overallScore": 3.5, "checks": []},
                        "failed_checks": [],
                        "critical_issues": [],
                    }
                ]
            },
        )
        agg.aggregate(
            "maintainer_risk",
            {
                "maintainer_issues": [
                    {
                        "component": "lodash",
                        "version": "4.17.0",
                        "severity": "MEDIUM",
                        "risks": [{"type": "stale_package", "message": "No releases in 2+ years"}],
                    }
                ]
            },
        )

        [quality] = agg.get_findings()

        assert sorted(issue["type"] for issue in quality.details["quality_issues"]) == ["maintainer_risk", "scorecard"]

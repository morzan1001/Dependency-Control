"""Tests for app.services.recommendation.sast."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.sast import process_sast


def _sast(
    severity="HIGH",
    component="app.py",
    category="sql-injection",
    finding_id="sast1",
    rule_id="rule-1",
):
    """Merged-SAST shape: category and rule ids live in details.sast_findings[]."""
    entry = {
        "id": rule_id,
        "scanner": "opengrep",
        "severity": severity,
        "title": category,
        "description": "",
        "details": {"rule_id": rule_id, "category": category},
    }
    return {
        "type": "sast",
        "severity": severity,
        "component": component,
        "details": {"sast_findings": [entry], "file": component, "line": 1},
        "id": finding_id,
    }


def _sast_findings(severity, count):
    return [_sast(severity=severity, finding_id=f"s{i}", category="sql-injection") for i in range(count)]


class TestProcessSastEmpty:
    def test_empty_list_returns_empty(self):
        assert process_sast([]) == []


class TestProcessSastInjection:
    @pytest.mark.parametrize("category", ["sql-injection", "sqli", "command-inject"])
    def test_category_normalized_to_injection(self, category):
        rec = process_sast([_sast(category=category)])[0]
        assert "Injection" in rec.title

    def test_type_is_fix_code_security(self):
        rec = process_sast([_sast(category="sql-injection")])[0]
        assert rec.type == RecommendationType.FIX_CODE_SECURITY


class TestProcessSastXSS:
    @pytest.mark.parametrize("category", ["xss-reflected", "cross-site-scripting"])
    def test_category_normalized_to_xss(self, category):
        rec = process_sast([_sast(category=category)])[0]
        assert "XSS" in rec.title


class TestProcessSastCryptography:
    @pytest.mark.parametrize("category", ["weak-crypto", "insecure-cipher"])
    def test_category_normalized_to_cryptography(self, category):
        rec = process_sast([_sast(category=category)])[0]
        assert "Cryptography" in rec.title


class TestProcessSastAuthentication:
    def test_auth_keyword(self):
        rec = process_sast([_sast(category="broken-auth")])[0]
        assert "Authentication" in rec.title


class TestProcessSastPathTraversal:
    @pytest.mark.parametrize("category", ["path-traversal", "directory-traversal"])
    def test_category_normalized_to_path_traversal(self, category):
        rec = process_sast([_sast(category=category)])[0]
        assert "Path Traversal" in rec.title


class TestProcessSastBelowThreshold:
    """No critical/high severity and fewer than three findings -> skip."""

    @pytest.mark.parametrize(
        ("severity", "count"),
        [
            pytest.param("LOW", 1, id="one-low"),
            pytest.param("LOW", 2, id="two-low"),
            pytest.param("MEDIUM", 1, id="one-medium"),
            pytest.param("MEDIUM", 2, id="two-medium"),
        ],
    )
    def test_no_recommendation(self, severity, count):
        assert process_sast(_sast_findings(severity, count)) == []


class TestProcessSastAboveThreshold:
    @pytest.mark.parametrize(
        ("severity", "count"),
        [
            pytest.param("LOW", 3, id="three-low"),
            pytest.param("HIGH", 1, id="single-high"),
            pytest.param("CRITICAL", 1, id="single-critical"),
        ],
    )
    def test_generates_recommendation(self, severity, count):
        assert len(process_sast(_sast_findings(severity, count))) == 1

    def test_three_low_findings_priority_low(self):
        rec = process_sast(_sast_findings("LOW", 3))[0]
        assert rec.priority == Priority.LOW


class TestProcessSastPriority:
    @pytest.mark.parametrize(
        ("severity", "count", "expected"),
        [
            pytest.param("CRITICAL", 1, Priority.CRITICAL, id="critical"),
            pytest.param("HIGH", 1, Priority.HIGH, id="high"),
            pytest.param("MEDIUM", 3, Priority.MEDIUM, id="medium-needs-three-to-pass-threshold"),
        ],
    )
    def test_priority_follows_severity(self, severity, count, expected):
        rec = process_sast(_sast_findings(severity, count))[0]
        assert rec.priority == expected


class TestProcessSastMixedCategories:
    @pytest.mark.parametrize(
        "categories",
        [
            pytest.param(["sql-injection", "xss-reflected"], id="two-categories"),
            pytest.param(["sql-injection", "xss-reflected", "broken-auth"], id="three-categories"),
        ],
    )
    def test_one_recommendation_per_category(self, categories):
        findings = [_sast(category=category, finding_id=f"s{i}") for i, category in enumerate(categories)]
        result = process_sast(findings)
        assert len(result) == len(categories)

    def test_separate_categories_have_correct_titles(self):
        findings = [
            _sast(category="sql-injection", finding_id="s1"),
            _sast(category="xss-reflected", finding_id="s2"),
        ]
        result = process_sast(findings)
        titles = {r.title for r in result}
        assert "Fix Injection Issues" in titles
        assert "Fix XSS Issues" in titles


class TestProcessSastEffort:
    """Effort is 'medium' for <10 findings, 'high' for >=10."""

    @pytest.mark.parametrize(
        ("count", "expected"),
        [
            pytest.param(5, "medium", id="below-ten"),
            pytest.param(10, "high", id="at-ten"),
            pytest.param(15, "high", id="above-ten"),
        ],
    )
    def test_effort_scales_with_finding_count(self, count, expected):
        rec = process_sast(_sast_findings("HIGH", count))[0]
        assert rec.effort == expected


class TestProcessSastImpactAndAction:
    def test_impact_severity_counts(self):
        findings = [
            _sast(severity="CRITICAL", finding_id="s1", category="sql-injection"),
            _sast(severity="HIGH", finding_id="s2", category="sql-injection"),
            _sast(severity="MEDIUM", finding_id="s3", category="sql-injection"),
        ]
        rec = process_sast(findings)[0]
        assert rec.impact["critical"] == 1
        assert rec.impact["high"] == 1
        assert rec.impact["medium"] == 1
        assert rec.impact["total"] == 3

    def test_action_category_set(self):
        rec = process_sast([_sast(category="sql-injection")])[0]
        assert rec.action["category"] == "Injection"

    def test_action_contains_files(self):
        rec = process_sast([_sast(component="app.py")])[0]
        assert "app.py" in rec.action["files"]

    def test_rule_ids_extracted(self):
        findings = [
            _sast(category="sql-injection", rule_id="S3649", finding_id="s1"),
            _sast(category="sql-injection", rule_id="S3649", finding_id="s2"),
        ]
        rec = process_sast(findings)[0]
        assert "S3649" in rec.action["rules"]

    def test_affected_components_limited_to_twenty(self):
        findings = [
            _sast(
                severity="HIGH",
                component=f"file{i}.py",
                category="sql-injection",
                finding_id=f"s{i}",
            )
            for i in range(25)
        ]
        rec = process_sast(findings)[0]
        assert len(rec.affected_components) <= 20

    def test_description_mentions_severity_counts(self):
        findings = [
            _sast(severity="CRITICAL", finding_id="s1", category="sql-injection"),
            _sast(severity="HIGH", finding_id="s2", category="sql-injection"),
        ]
        rec = process_sast(findings)[0]
        assert "1 critical" in rec.description
        assert "1 high" in rec.description


class TestProcessSastCategoryFallback:
    """Category falls back to the entry rule id, then to 'security'."""

    @pytest.mark.parametrize(
        ("details", "expected_in_title"),
        [
            pytest.param(
                {"sast_findings": [{"id": "custom-rule", "details": {}}]},
                "custom-rule",
                id="entry-id-when-no-category",
            ),
            pytest.param(
                {
                    "sast_findings": [
                        {"id": "rule-a", "details": {}},
                        {"id": "rule-b", "details": {"category": "sqli"}},
                    ]
                },
                "Injection",
                id="category-from-later-entry",
            ),
            pytest.param({}, "security", id="default-security"),
        ],
    )
    def test_title_uses_category_fallback(self, details, expected_in_title):
        finding = {
            "type": "sast",
            "severity": "HIGH",
            "component": "app.py",
            "details": details,
            "id": "s1",
        }
        rec = process_sast([finding])[0]
        assert expected_in_title in rec.title

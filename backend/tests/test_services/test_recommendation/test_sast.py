"""Tests for app.services.recommendation.sast."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.sast import process_sast


def _sast(
    severity="HIGH",
    component="app.py",
    category="sql-injection",
    finding_id="sast1",
    rule_id=None,
):
    details = {"category": category}
    if rule_id is not None:
        details["rule_id"] = rule_id
    return {
        "type": "sast",
        "severity": severity,
        "component": component,
        "details": details,
        "id": finding_id,
    }


class TestProcessSastEmpty:
    """Edge case: no findings."""

    def test_empty_list_returns_empty(self):
        assert process_sast([]) == []

    def test_empty_iterable(self):
        assert process_sast(list()) == []


class TestProcessSastInjection:
    """Injection category normalization and recommendation."""

    def test_sql_injection_normalized_to_injection(self):
        rec = process_sast([_sast(category="sql-injection")])[0]
        assert "Injection" in rec.title

    def test_sqli_normalized_to_injection(self):
        rec = process_sast([_sast(category="sqli")])[0]
        assert "Injection" in rec.title

    def test_command_injection_normalized(self):
        rec = process_sast([_sast(category="command-inject")])[0]
        assert "Injection" in rec.title

    def test_type_is_fix_code_security(self):
        rec = process_sast([_sast(category="sql-injection")])[0]
        assert rec.type == RecommendationType.FIX_CODE_SECURITY


class TestProcessSastXSS:
    """XSS category normalization."""

    def test_xss_keyword(self):
        rec = process_sast([_sast(category="xss-reflected")])[0]
        assert "XSS" in rec.title

    def test_cross_site_keyword(self):
        rec = process_sast([_sast(category="cross-site-scripting")])[0]
        assert "XSS" in rec.title


class TestProcessSastCryptography:
    """Cryptography category normalization."""

    def test_crypto_keyword(self):
        rec = process_sast([_sast(category="weak-crypto")])[0]
        assert "Cryptography" in rec.title

    def test_cipher_keyword(self):
        rec = process_sast([_sast(category="insecure-cipher")])[0]
        assert "Cryptography" in rec.title


class TestProcessSastAuthentication:
    """Authentication category normalization."""

    def test_auth_keyword(self):
        rec = process_sast([_sast(category="broken-auth")])[0]
        assert "Authentication" in rec.title


class TestProcessSastPathTraversal:
    """Path Traversal category normalization."""

    def test_path_keyword(self):
        rec = process_sast([_sast(category="path-traversal")])[0]
        assert "Path Traversal" in rec.title

    def test_traversal_keyword(self):
        rec = process_sast([_sast(category="directory-traversal")])[0]
        assert "Path Traversal" in rec.title


class TestProcessSastBelowThreshold:
    """Findings that do not meet the significance threshold are skipped."""

    def test_single_low_no_recommendation(self):
        """One LOW finding: no critical/high AND <3 total -> skip."""
        result = process_sast([_sast(severity="LOW")])
        assert result == []

    def test_two_low_no_recommendation(self):
        """Two LOW findings: still <3 total and no critical/high."""
        findings = [
            _sast(severity="LOW", finding_id="s1"),
            _sast(severity="LOW", finding_id="s2"),
        ]
        result = process_sast(findings)
        assert result == []

    def test_single_medium_no_recommendation(self):
        """One MEDIUM finding, no critical/high, <3 total -> skip."""
        result = process_sast([_sast(severity="MEDIUM")])
        assert result == []

    def test_two_medium_no_recommendation(self):
        findings = [
            _sast(severity="MEDIUM", finding_id="s1"),
            _sast(severity="MEDIUM", finding_id="s2"),
        ]
        result = process_sast(findings)
        assert result == []


class TestProcessSastAboveThreshold:
    """Findings that DO meet the significance threshold."""

    def test_three_low_findings_generates_recommendation(self):
        findings = [
            _sast(severity="LOW", finding_id=f"s{i}", category="sql-injection")
            for i in range(3)
        ]
        result = process_sast(findings)
        assert len(result) == 1

    def test_three_low_findings_priority_low(self):
        findings = [
            _sast(severity="LOW", finding_id=f"s{i}", category="sql-injection")
            for i in range(3)
        ]
        rec = process_sast(findings)[0]
        assert rec.priority == Priority.LOW

    def test_single_high_generates_recommendation(self):
        result = process_sast([_sast(severity="HIGH")])
        assert len(result) == 1

    def test_single_critical_generates_recommendation(self):
        result = process_sast([_sast(severity="CRITICAL")])
        assert len(result) == 1


class TestProcessSastPriority:
    """Priority determination for SAST recommendations."""

    def test_critical_severity_gives_critical_priority(self):
        rec = process_sast([_sast(severity="CRITICAL")])[0]
        assert rec.priority == Priority.CRITICAL

    def test_high_severity_gives_high_priority(self):
        rec = process_sast([_sast(severity="HIGH")])[0]
        assert rec.priority == Priority.HIGH

    def test_medium_severity_only_gives_medium_priority(self):
        """Three MEDIUM findings pass threshold; priority should be MEDIUM."""
        findings = [
            _sast(severity="MEDIUM", finding_id=f"s{i}", category="sql-injection")
            for i in range(3)
        ]
        rec = process_sast(findings)[0]
        assert rec.priority == Priority.MEDIUM


class TestProcessSastMixedCategories:
    """Different categories produce separate recommendations."""

    def test_two_categories_produce_two_recommendations(self):
        findings = [
            _sast(category="sql-injection", finding_id="s1"),
            _sast(category="xss-reflected", finding_id="s2"),
        ]
        result = process_sast(findings)
        assert len(result) == 2

    def test_separate_categories_have_correct_titles(self):
        findings = [
            _sast(category="sql-injection", finding_id="s1"),
            _sast(category="xss-reflected", finding_id="s2"),
        ]
        result = process_sast(findings)
        titles = {r.title for r in result}
        assert "Fix Injection Issues" in titles
        assert "Fix XSS Issues" in titles

    def test_three_categories_produce_three_recommendations(self):
        findings = [
            _sast(category="sql-injection", finding_id="s1"),
            _sast(category="xss-reflected", finding_id="s2"),
            _sast(category="broken-auth", finding_id="s3"),
        ]
        result = process_sast(findings)
        assert len(result) == 3


class TestProcessSastEffort:
    """Effort is 'medium' for <10 findings, 'high' for >=10."""

    def test_effort_medium_below_ten(self):
        findings = [
            _sast(severity="HIGH", finding_id=f"s{i}", category="sql-injection")
            for i in range(5)
        ]
        rec = process_sast(findings)[0]
        assert rec.effort == "medium"

    def test_effort_high_at_ten(self):
        findings = [
            _sast(severity="HIGH", finding_id=f"s{i}", category="sql-injection")
            for i in range(10)
        ]
        rec = process_sast(findings)[0]
        assert rec.effort == "high"

    def test_effort_high_above_ten(self):
        findings = [
            _sast(severity="HIGH", finding_id=f"s{i}", category="sql-injection")
            for i in range(15)
        ]
        rec = process_sast(findings)[0]
        assert rec.effort == "high"


class TestProcessSastImpactAndAction:
    """Verify impact dict and action content."""

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
    """Category fallback through rule_id, check_id, then default 'security'."""

    def test_rule_id_fallback_when_no_category(self):
        finding = {
            "type": "sast",
            "severity": "HIGH",
            "component": "app.py",
            "details": {"rule_id": "custom-rule"},
            "id": "s1",
        }
        rec = process_sast([finding])[0]
        assert "custom-rule" in rec.title

    def test_check_id_fallback(self):
        finding = {
            "type": "sast",
            "severity": "HIGH",
            "component": "app.py",
            "details": {"check_id": "CKV_123"},
            "id": "s1",
        }
        rec = process_sast([finding])[0]
        assert "CKV_123" in rec.title

    def test_default_security_category(self):
        finding = {
            "type": "sast",
            "severity": "HIGH",
            "component": "app.py",
            "details": {},
            "id": "s1",
        }
        rec = process_sast([finding])[0]
        assert "security" in rec.title

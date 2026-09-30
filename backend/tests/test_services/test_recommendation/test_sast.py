"""Tests for app.services.recommendation.sast."""

import json
from pathlib import Path

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.recommendation.sast import process_sast

# bearer 2.1.1 over a file hashing a password with MD5 (CWE-326) and logging an email (CWE-532).
_BEARER_FIXTURE = Path(__file__).parents[2] / "fixtures/sast/bearer_2.1.1_findings.json"

_SQL_INJECTION = {
    "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
    "vulnerability_class": ["SQL Injection"],
}
_XSS = {
    "check_id": "javascript.browser.security.insecure-document-method.insecure-document-method",
    "cwe": ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
    "vulnerability_class": ["Cross-Site-Scripting (XSS)"],
}
_HARDCODED_SECRET = {
    "check_id": "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret",
    "cwe": ["CWE-798: Use of Hard-coded Credentials"],
    "vulnerability_class": ["Hard-coded Secrets"],
}
_PATH_TRAVERSAL = {
    "check_id": "python.django.security.injection.path-traversal.path-traversal-open.path-traversal-open",
    "cwe": ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"],
    "vulnerability_class": ["Path Traversal"],
}
_DEBUG_ENABLED = {
    "check_id": "python.flask.security.audit.debug-enabled.debug-enabled",
    "cwe": ["CWE-489: Active Debug Code"],
    "vulnerability_class": ["Active Debug Code"],
}
_NOSQL_INJECTION = {
    "check_id": "javascript.express.security.audit.express-mongo-nosql-injection",
    "cwe": ["CWE-943: Improper Neutralization of Special Elements in Data Query Logic"],
    "vulnerability_class": ["NoSQL Injection"],
}


def _opengrep_item(rule, *, severity="ERROR", path="app/db.py", line=1, category="security"):
    """An OpenGrep --config=auto result: registry rules carry category 'security' plus cwe and vulnerability_class."""
    metadata = {
        "category": category,
        "cwe": rule.get("cwe", []),
        "vulnerability_class": rule.get("vulnerability_class", []),
    }
    return {
        "check_id": rule["check_id"],
        "path": path,
        "start": {"line": line, "col": 5},
        "end": {"line": line, "col": 40},
        "extra": {"severity": severity, "message": "Detected a risky call.", "metadata": metadata},
    }


def _normalized(scanner, result):
    aggregator = ResultAggregator()
    aggregator.aggregate(scanner, result)
    return [f.model_dump() for f in aggregator.get_findings()]


def _opengrep(*items):
    return _normalized("opengrep", {"results": list(items)})


def _sql_injections(severity, count):
    return _opengrep(*(_opengrep_item(_SQL_INJECTION, severity=severity, line=i) for i in range(1, count + 1)))


class TestProcessSastEmpty:
    def test_empty_list_returns_empty(self):
        assert process_sast([]) == []


class TestProcessSastClassification:
    @pytest.mark.parametrize(
        ("rule", "expected_title"),
        [
            pytest.param(_SQL_INJECTION, "Fix Injection Issues", id="cwe-89"),
            pytest.param(_XSS, "Fix XSS Issues", id="cwe-79"),
            pytest.param(_HARDCODED_SECRET, "Fix Authentication Issues", id="cwe-798"),
            pytest.param(_PATH_TRAVERSAL, "Fix Path Traversal Issues", id="cwe-22"),
            pytest.param(_NOSQL_INJECTION, "Fix Injection Issues", id="vulnerability-class-keyword"),
            pytest.param(_DEBUG_ENABLED, "Fix Active Debug Code Issues", id="vulnerability-class-verbatim"),
        ],
    )
    def test_registry_rule_is_classified_beyond_its_security_category(self, rule, expected_title):
        rec = process_sast(_opengrep(_opengrep_item(rule)))[0]
        assert rec.title == expected_title
        assert rec.type == RecommendationType.FIX_CODE_SECURITY

    def test_specific_category_names_the_card_when_nothing_else_does(self):
        rule = {"check_id": "rules.custom.unsafe-yaml-load"}
        rec = process_sast(_opengrep(_opengrep_item(rule, category="deserialization")))[0]
        assert rec.title == "Fix deserialization Issues"

    def test_rule_id_names_the_card_as_the_last_resort(self):
        rule = {"check_id": "rules.custom.no-eval"}
        rec = process_sast(_opengrep(_opengrep_item(rule)))[0]
        assert rec.title == "Fix rules.custom.no-eval Issues"

    def test_bearer_findings_are_named_by_cwe_then_title(self):
        output = json.loads(_BEARER_FIXTURE.read_text())
        # Both ranked high so the single medium logger finding passes the card gate too.
        findings = _normalized("bearer", {"findings": {"high": output["high"] + output["medium"]}})
        titles = {rec.title for rec in process_sast(findings)}
        assert titles == {"Fix Cryptography Issues", "Fix Leakage of sensitive information in logger message Issues"}

    def test_one_card_per_category(self):
        findings = _opengrep(
            _opengrep_item(_SQL_INJECTION, line=1),
            _opengrep_item(_XSS, line=2),
            _opengrep_item(_HARDCODED_SECRET, line=3),
        )
        titles = {r.title for r in process_sast(findings)}
        assert titles == {"Fix Injection Issues", "Fix XSS Issues", "Fix Authentication Issues"}


class TestProcessSastBelowThreshold:
    """No critical/high severity and fewer than three findings -> skip."""

    @pytest.mark.parametrize(
        ("severity", "count"),
        [
            pytest.param("INFO", 1, id="one-low"),
            pytest.param("INFO", 2, id="two-low"),
            pytest.param("WARNING", 1, id="one-medium"),
            pytest.param("WARNING", 2, id="two-medium"),
        ],
    )
    def test_no_recommendation(self, severity, count):
        assert process_sast(_sql_injections(severity, count)) == []


class TestProcessSastPriority:
    @pytest.mark.parametrize(
        ("severity", "count", "expected"),
        [
            pytest.param("CRITICAL", 1, Priority.CRITICAL, id="critical"),
            pytest.param("ERROR", 1, Priority.HIGH, id="high"),
            pytest.param("WARNING", 3, Priority.MEDIUM, id="medium-needs-three-to-pass-threshold"),
            pytest.param("INFO", 3, Priority.LOW, id="low-needs-three-to-pass-threshold"),
        ],
    )
    def test_priority_follows_severity(self, severity, count, expected):
        rec = process_sast(_sql_injections(severity, count))[0]
        assert rec.priority == expected


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
        rec = process_sast(_sql_injections("ERROR", count))[0]
        assert rec.effort == expected


class TestProcessSastImpactAndAction:
    def test_impact_counts_each_severity(self):
        findings = _opengrep(
            _opengrep_item(_SQL_INJECTION, severity="CRITICAL", line=1),
            _opengrep_item(_SQL_INJECTION, severity="ERROR", line=2),
            _opengrep_item(_SQL_INJECTION, severity="WARNING", line=3),
            _opengrep_item(_SQL_INJECTION, severity="INFO", line=4),
        )
        rec = process_sast(findings)[0]
        assert rec.impact == {"critical": 1, "high": 1, "medium": 1, "low": 1, "total": 4}
        assert "1 critical" in rec.description
        assert "1 high" in rec.description

    def test_action_names_category_files_and_rules(self):
        findings = _opengrep(
            _opengrep_item(_SQL_INJECTION, path="app/db.py", line=1),
            _opengrep_item(_NOSQL_INJECTION, path="app/db.py", line=2),
            _opengrep_item(_SQL_INJECTION, path="app/api.py", line=3),
        )
        action = process_sast(findings)[0].action
        assert action["category"] == "Injection"
        assert action["files"] == ["app/api.py", "app/db.py"]
        assert action["rules"] == sorted([_NOSQL_INJECTION["check_id"], _SQL_INJECTION["check_id"]])
        assert action["rules_total"] == 2

    def test_affected_components_limited_to_twenty(self):
        findings = _opengrep(*(_opengrep_item(_SQL_INJECTION, path=f"file{i}.py") for i in range(25)))
        rec = process_sast(findings)[0]
        assert len(rec.affected_components) == 20
        assert rec.affected_components_total == 25

"""Tests for Finding model and enums."""

import pytest
from pydantic import ValidationError

from app.models.finding import Severity, FindingType, Finding


class TestSeverityEnum:
    def test_all_values(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN"}
        actual = {s.value for s in Severity}
        assert actual == expected

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            Severity("BANANA")


class TestFindingTypeEnum:
    def test_all_types(self):
        expected = {
            "vulnerability", "license", "secret", "malware", "eol",
            "iac", "sast", "system_warning", "outdated", "quality", "other",
        }
        actual = {t.value for t in FindingType}
        assert actual == expected


class TestFindingModel:
    def test_minimal_valid_finding(self):
        finding = Finding(
            id="CVE-2023-1234",
            type=FindingType.VULNERABILITY,
            severity=Severity.HIGH,
            component="requests",
            description="Test vulnerability",
            scanners=["trivy"],
        )
        assert finding.id == "CVE-2023-1234"
        assert finding.component == "requests"

    def test_defaults_populated(self):
        finding = Finding(
            id="test",
            type=FindingType.VULNERABILITY,
            severity=Severity.LOW,
            component="test-pkg",
            description="Test",
            scanners=["grype"],
        )
        assert finding.details == {}
        assert finding.found_in == []
        assert finding.aliases == []
        assert finding.related_findings == []
        assert finding.waived is False
        assert finding.waiver_reason is None

    def test_use_enum_values(self):
        finding = Finding(
            id="test",
            type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            component="pkg",
            description="Test",
            scanners=["osv"],
        )
        # use_enum_values=True stores the string value
        assert finding.type == "vulnerability"
        assert finding.severity == "CRITICAL"

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="test",
                type=FindingType.VULNERABILITY,
                # missing severity, component, description, scanners
            )


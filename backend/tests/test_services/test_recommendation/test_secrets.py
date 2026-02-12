"""Tests for app.services.recommendation.secrets."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.secrets import process_secrets


def _secret(
    severity="HIGH",
    component="src/config.py",
    detector_type="AWS Key",
    finding_id="s1",
):
    return {
        "type": "secret",
        "severity": severity,
        "component": component,
        "details": {"detector_type": detector_type},
        "id": finding_id,
    }


class TestProcessSecretsEmpty:
    """Edge case: no findings at all."""

    def test_empty_list_returns_empty(self):
        assert process_secrets([]) == []

    def test_none_equivalent_empty(self):
        """An empty iterable should also be safe."""
        assert process_secrets(list()) == []


class TestProcessSecretsSingleFinding:
    """A single secret finding should produce exactly one recommendation."""

    def test_returns_one_recommendation(self):
        result = process_secrets([_secret()])
        assert len(result) == 1

    def test_type_is_rotate_secrets(self):
        rec = process_secrets([_secret()])[0]
        assert rec.type == RecommendationType.ROTATE_SECRETS

    def test_priority_critical_for_high_severity(self):
        rec = process_secrets([_secret(severity="HIGH")])[0]
        assert rec.priority == Priority.CRITICAL

    def test_priority_critical_for_critical_severity(self):
        rec = process_secrets([_secret(severity="CRITICAL")])[0]
        assert rec.priority == Priority.CRITICAL

    def test_title_contains_rotate(self):
        rec = process_secrets([_secret()])[0]
        assert "Rotate" in rec.title

    def test_description_contains_count(self):
        rec = process_secrets([_secret()])[0]
        assert "1 exposed secrets" in rec.description

    def test_description_contains_file_count(self):
        rec = process_secrets([_secret()])[0]
        assert "1 files" in rec.description

    def test_affected_components_contains_file(self):
        rec = process_secrets([_secret(component="src/config.py")])[0]
        assert "src/config.py" in rec.affected_components

    def test_impact_total(self):
        rec = process_secrets([_secret()])[0]
        assert rec.impact["total"] == 1

    def test_action_type(self):
        rec = process_secrets([_secret()])[0]
        assert rec.action["type"] == "rotate_secrets"


class TestProcessSecretsMultipleGroupedByDetector:
    """Multiple secrets should be grouped by detector type."""

    def test_multiple_same_detector_grouped(self):
        findings = [
            _secret(detector_type="AWS Key", finding_id="s1"),
            _secret(detector_type="AWS Key", finding_id="s2"),
        ]
        result = process_secrets(findings)
        # Still one recommendation for all secrets
        assert len(result) == 1
        assert result[0].impact["total"] == 2

    def test_different_detectors_listed_in_description(self):
        findings = [
            _secret(detector_type="AWS Key", finding_id="s1"),
            _secret(detector_type="GitHub Token", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert "AWS Key" in rec.description
        assert "GitHub Token" in rec.description

    def test_secret_types_in_action(self):
        findings = [
            _secret(detector_type="AWS Key", finding_id="s1"),
            _secret(detector_type="GitHub Token", finding_id="s2"),
            _secret(detector_type="Slack Webhook", finding_id="s3"),
        ]
        rec = process_secrets(findings)[0]
        secret_types = rec.action["secret_types"]
        assert "AWS Key" in secret_types
        assert "GitHub Token" in secret_types
        assert "Slack Webhook" in secret_types

    def test_secret_types_limited_to_five(self):
        findings = [
            _secret(detector_type=f"Detector{i}", finding_id=f"s{i}")
            for i in range(8)
        ]
        rec = process_secrets(findings)[0]
        assert len(rec.action["secret_types"]) <= 5


class TestProcessSecretsFilesAffected:
    """Files affected should be tracked correctly."""

    def test_unique_files_counted(self):
        findings = [
            _secret(component="src/a.py", finding_id="s1"),
            _secret(component="src/a.py", finding_id="s2"),
            _secret(component="src/b.py", finding_id="s3"),
        ]
        rec = process_secrets(findings)[0]
        assert "2 files" in rec.description

    def test_affected_components_deduplicated(self):
        findings = [
            _secret(component="src/a.py", finding_id="s1"),
            _secret(component="src/a.py", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert len(rec.affected_components) == 1

    def test_affected_components_limited_to_twenty(self):
        findings = [
            _secret(component=f"src/file{i}.py", finding_id=f"s{i}")
            for i in range(25)
        ]
        rec = process_secrets(findings)[0]
        assert len(rec.affected_components) <= 20

    def test_action_files_limited_to_ten(self):
        findings = [
            _secret(component=f"src/file{i}.py", finding_id=f"s{i}")
            for i in range(15)
        ]
        rec = process_secrets(findings)[0]
        assert len(rec.action["files"]) <= 10

    def test_empty_component_not_tracked(self):
        findings = [_secret(component="")]
        rec = process_secrets(findings)[0]
        assert len(rec.affected_components) == 0


class TestProcessSecretsPriority:
    """Priority determination based on severity mix."""

    def test_only_medium_severity_gives_high_priority(self):
        findings = [
            _secret(severity="MEDIUM", finding_id="s1"),
            _secret(severity="MEDIUM", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert rec.priority == Priority.HIGH

    def test_only_low_severity_gives_high_priority(self):
        findings = [_secret(severity="LOW")]
        rec = process_secrets(findings)[0]
        assert rec.priority == Priority.HIGH

    def test_mix_of_medium_and_high_gives_critical(self):
        findings = [
            _secret(severity="MEDIUM", finding_id="s1"),
            _secret(severity="HIGH", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert rec.priority == Priority.CRITICAL

    def test_single_critical_among_lows_gives_critical(self):
        findings = [
            _secret(severity="LOW", finding_id="s1"),
            _secret(severity="LOW", finding_id="s2"),
            _secret(severity="CRITICAL", finding_id="s3"),
        ]
        rec = process_secrets(findings)[0]
        assert rec.priority == Priority.CRITICAL


class TestProcessSecretsSeverityCounts:
    """Impact dict should have correct severity counts."""

    def test_severity_counts_correct(self):
        findings = [
            _secret(severity="CRITICAL", finding_id="s1"),
            _secret(severity="HIGH", finding_id="s2"),
            _secret(severity="HIGH", finding_id="s3"),
            _secret(severity="MEDIUM", finding_id="s4"),
        ]
        rec = process_secrets(findings)[0]
        assert rec.impact["critical"] == 1
        assert rec.impact["high"] == 2
        assert rec.impact["medium"] == 1
        assert rec.impact["low"] == 0
        assert rec.impact["total"] == 4


class TestProcessSecretsDetectorFallbacks:
    """Detector type extraction falls back through rule_id then 'generic'."""

    def test_rule_id_fallback(self):
        finding = {
            "type": "secret",
            "severity": "HIGH",
            "component": "src/x.py",
            "details": {"rule_id": "secret-rule-42"},
            "id": "s1",
        }
        rec = process_secrets([finding])[0]
        assert "secret-rule-42" in rec.description

    def test_generic_fallback(self):
        finding = {
            "type": "secret",
            "severity": "HIGH",
            "component": "src/x.py",
            "details": {},
            "id": "s1",
        }
        rec = process_secrets([finding])[0]
        assert "generic" in rec.description

    def test_effort_is_high(self):
        rec = process_secrets([_secret()])[0]
        assert rec.effort == "high"

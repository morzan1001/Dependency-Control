"""Tests for app.services.recommendation.secrets."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.recommendation.common import AFFECTED_COMPONENTS_SHOWN
from app.services.recommendation.secrets import _SECRET_TYPES_NAMED, process_secrets
from tests.test_services.test_normalizers.test_secret import _GIT_FINDING


def _secret(
    severity="HIGH",
    component="src/config.py",
    detector="2",
    detector_name="AWS",
    finding_id="s1",
):
    # Mirrors a stored secret finding: TruffleHog's DetectorType ordinal and, when sent, its DetectorName.
    details = {"detector": detector, "verified": True}
    if detector_name:
        details["detector_name"] = detector_name
    return {
        "type": "secret",
        "severity": severity,
        "component": component,
        "details": details,
        "id": finding_id,
    }


class TestProcessSecretsEmpty:
    def test_empty_list_returns_empty(self):
        assert process_secrets([]) == []


class TestProcessSecretsSingleFinding:
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
    def test_multiple_same_detector_grouped(self):
        findings = [
            _secret(detector="2", finding_id="s1"),
            _secret(detector="2", finding_id="s2"),
        ]
        result = process_secrets(findings)
        assert len(result) == 1
        assert result[0].impact["total"] == 2

    def test_different_detectors_listed_in_description(self):
        findings = [
            _secret(detector="2", finding_id="s1"),
            _secret(detector="8", detector_name="Github", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert "AWS" in rec.description
        assert "Github" in rec.description

    def test_secret_types_in_action(self):
        findings = [
            _secret(detector="2", finding_id="s1"),
            _secret(detector="8", detector_name="Github", finding_id="s2"),
            _secret(detector="30", detector_name="SlackWebhook", finding_id="s3"),
        ]
        rec = process_secrets(findings)[0]
        secret_types = rec.action["secret_types"]
        assert "AWS" in secret_types
        assert "Github" in secret_types
        assert "SlackWebhook" in secret_types

    def test_a_detector_trufflehog_does_not_name_keeps_its_stored_label(self):
        rec = process_secrets([_secret(detector="Generic Secret", detector_name=None)])[0]
        assert rec.action["secret_types"] == ["Generic Secret"]

    def test_the_action_carries_every_detector_and_the_prose_counts_the_rest(self):
        found = 8
        findings = [_secret(detector=str(i), detector_name=f"Detector{i}", finding_id=f"s{i}") for i in range(found)]

        rec = process_secrets(findings)[0]

        assert len(rec.action["secret_types"]) == found
        assert f"and {found - _SECRET_TYPES_NAMED} more" in rec.description


class TestProcessSecretsFilesAffected:
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
        findings = [_secret(component=f"src/file{i}.py", finding_id=f"s{i}") for i in range(25)]
        rec = process_secrets(findings)[0]
        assert len(rec.affected_components) <= 20

    def test_the_files_the_action_lists_are_counted_before_they_are_cut(self):
        found = AFFECTED_COMPONENTS_SHOWN + 15
        findings = [_secret(component=f"src/file{i:03d}.py", finding_id=f"s{i}") for i in range(found)]

        rec = process_secrets(findings)[0]

        assert len(rec.action["files"]) == AFFECTED_COMPONENTS_SHOWN
        assert rec.action["files_total"] == found
        assert rec.affected_components_total == found

    def test_empty_component_not_tracked(self):
        findings = [_secret(component="")]
        rec = process_secrets(findings)[0]
        assert len(rec.affected_components) == 0


def _trufflehog(*entries):
    aggregator = ResultAggregator()
    aggregator.aggregate("trufflehog", {"findings": list(entries)})
    return [f.model_dump() for f in aggregator.get_findings()]


def _git_leak(file, raw, *, in_current_tree, verified=False):
    git = {**_GIT_FINDING["SourceMetadata"]["Data"]["Git"], "file": file}
    return {
        **_GIT_FINDING,
        "SourceMetadata": {"Data": {"Git": git}},
        "Raw": raw,
        "RawV2": raw,
        "Verified": verified,
        "DcInCurrentTree": in_current_tree,
    }


class TestProcessSecretsSplitsLiveFromDeprioritized:
    def test_secrets_only_left_in_history_and_unverified_rank_low(self):
        [rec] = process_secrets(_trufflehog(_git_leak("old.py", "AKIAOLD0000000000001", in_current_tree=False)))

        assert rec.priority == Priority.LOW
        assert rec.impact == {"critical": 0, "high": 0, "medium": 0, "low": 1, "total": 1}
        assert not any("Remove secrets from code" in step for step in rec.action["steps"])

    def test_a_verified_secret_in_history_is_still_live(self):
        leak = _git_leak("old.py", "AKIAOLD0000000000001", in_current_tree=False, verified=True)

        [rec] = process_secrets(_trufflehog(leak))

        assert rec.priority == Priority.CRITICAL

    def test_live_and_historical_secrets_get_their_own_cards(self):
        historical = [
            _git_leak(f"a{i:02d}.py", f"AKIAOLD{i:013d}", in_current_tree=False)
            for i in range(AFFECTED_COMPONENTS_SHOWN)
        ]
        live = _git_leak("z_app.py", "AKIALIVE000000000001", in_current_tree=True)

        live_card, historical_card = process_secrets(_trufflehog(*historical, live))

        assert (live_card.priority, live_card.affected_components, live_card.impact["total"]) == (
            Priority.CRITICAL,
            ["z_app.py"],
            1,
        )
        assert (historical_card.priority, historical_card.affected_components_total) == (
            Priority.LOW,
            AFFECTED_COMPONENTS_SHOWN,
        )
        assert live_card.title != historical_card.title


class TestProcessSecretsDetectorFallbacks:
    """Credential type is details.detector_name, falling back to the stored details.detector."""

    def test_detector_named_in_description(self):
        rec = process_secrets([_secret(detector="8", detector_name="Github")])[0]
        assert "Github" in rec.description
        assert rec.action["secret_types"] == ["Github"]

    def test_a_detector_newer_than_this_release_is_named(self):
        findings = [
            _secret(detector="17", detector_name="URI", finding_id="s1"),
            _secret(detector="1070", detector_name="FutureCloudToken", finding_id="s2"),
        ]
        rec = process_secrets(findings)[0]
        assert "These include: FutureCloudToken, URI" in rec.description

    def test_a_finding_stored_without_a_name_shows_its_ordinal(self):
        rec = process_secrets([_secret(detector="17", detector_name=None)])[0]
        assert rec.action["secret_types"] == ["17"]

    def test_effort_is_high(self):
        rec = process_secrets([_secret()])[0]
        assert rec.effort == "high"

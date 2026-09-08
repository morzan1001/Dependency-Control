"""The three predicates the stats fold, the recommendation schema and the secret normalizer share."""

import pytest

from app.core.risk_scoring import (
    is_actionable_vulnerability,
    is_deprioritized_secret,
    is_deprioritized_vulnerability,
)
from app.models.finding import Severity
from app.schemas.recommendation import VulnerabilityInfo
from app.services.enrichment.scoring import calculate_secret_severity


def _vuln(**kwargs) -> VulnerabilityInfo:
    base = {
        "finding_id": "test-id",
        "cve_id": "CVE-2024-0001",
        "severity": "HIGH",
        "package_name": "pkg",
        "current_version": "1.0.0",
        "fixed_version": None,
    }
    base.update(kwargs)
    return VulnerabilityInfo(**base)


class TestActionable:
    def test_kev_with_unknown_reachability_is_actionable(self):
        assert is_actionable_vulnerability(epss_score=None, is_kev=True, reachable=None) is True

    def test_high_epss_reachable_is_actionable(self):
        assert is_actionable_vulnerability(epss_score=0.1, is_kev=False, reachable=True) is True

    def test_epss_just_below_the_threshold_is_not_actionable(self):
        assert is_actionable_vulnerability(epss_score=0.09, is_kev=False, reachable=True) is False

    def test_unreachable_kev_is_not_actionable(self):
        assert is_actionable_vulnerability(epss_score=0.9, is_kev=True, reachable=False) is False

    def test_no_signal_is_not_actionable(self):
        assert is_actionable_vulnerability(epss_score=None, is_kev=False, reachable=True) is False


class TestDeprioritized:
    def test_unreachable_kev_is_still_deprioritized(self):
        # Surprising but load-bearing: unreachability outranks KEV in this predicate.
        assert is_deprioritized_vulnerability(epss_score=0.9, is_kev=True, reachable=False) is True

    def test_missing_epss_is_not_evidence_of_low_likelihood(self):
        assert is_deprioritized_vulnerability(epss_score=None, is_kev=False, reachable=None) is False

    def test_measured_low_epss_without_kev_is_deprioritized(self):
        assert is_deprioritized_vulnerability(epss_score=0.001, is_kev=False, reachable=None) is True

    def test_epss_on_the_medium_threshold_is_not_deprioritized(self):
        assert is_deprioritized_vulnerability(epss_score=0.01, is_kev=False, reachable=None) is False

    def test_kev_with_no_epss_is_not_deprioritized(self):
        assert is_deprioritized_vulnerability(epss_score=None, is_kev=True, reachable=None) is False


class TestSecret:
    def test_unverified_and_gone_from_tree_is_deprioritized(self):
        assert is_deprioritized_secret(False, False) is True

    def test_unknown_verification_and_gone_from_tree_is_deprioritized(self):
        assert is_deprioritized_secret(None, False) is True

    def test_verified_survives_a_deleted_file(self):
        assert is_deprioritized_secret(True, False) is False

    def test_unknown_tree_is_not_deprioritized(self):
        assert is_deprioritized_secret(False, None) is False


class TestConsumersDelegate:
    """The three call sites must answer identically to the shared predicates."""

    @pytest.mark.parametrize(
        ("epss", "kev", "reachable"),
        [
            (None, False, None),
            (None, True, None),
            (0.005, False, True),
            (0.5, False, False),
            (0.9, True, True),
        ],
    )
    def test_vulnerability_info_matches(self, epss, kev, reachable):
        v = _vuln(epss_score=epss, is_kev=kev, is_reachable=reachable)
        assert v.is_actionable == is_actionable_vulnerability(epss_score=epss, is_kev=kev, reachable=reachable)
        assert v.is_deprioritized == is_deprioritized_vulnerability(epss_score=epss, is_kev=kev, reachable=reachable)

    @pytest.mark.parametrize(
        ("verified", "in_tree"),
        [(True, True), (True, False), (False, True), (False, False), (None, None), (None, False)],
    )
    def test_secret_severity_matches(self, verified, in_tree):
        expected = Severity.LOW if is_deprioritized_secret(verified, in_tree) else Severity.CRITICAL
        assert calculate_secret_severity(verified, in_tree) == expected

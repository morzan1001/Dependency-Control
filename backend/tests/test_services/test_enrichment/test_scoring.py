"""Tests for risk scoring and exploit maturity calculation."""

import pytest

from app.core.risk_scoring import calculate_exploit_maturity
from app.models.finding import Severity
from app.services.enrichment.scoring import (
    calculate_adjusted_risk_score,
    calculate_risk_score,
    calculate_secret_risk_score,
    calculate_secret_severity,
)


class TestCalculateExploitMaturity:
    @pytest.mark.parametrize(
        ("kev", "ransomware", "epss", "expected"),
        [
            pytest.param(True, True, 0.5, "weaponized", id="weaponized_when_kev_ransomware"),
            pytest.param(True, False, 0.5, "active", id="active_when_kev_only"),
            pytest.param(False, False, 0.15, "high", id="high_when_epss_above_high_threshold"),
            pytest.param(False, False, 0.05, "medium", id="medium_when_epss_between_thresholds"),
            pytest.param(False, False, 0.005, "low", id="low_when_epss_below_medium_threshold"),
            pytest.param(False, False, None, "unknown", id="unknown_when_no_epss"),
            pytest.param(True, True, 0.95, "weaponized", id="kev_ransomware_takes_precedence_over_epss"),
            pytest.param(True, False, 0.95, "active", id="kev_takes_precedence_over_high_epss"),
            pytest.param(False, False, 0.1, "high", id="boundary_epss_at_exactly_high_threshold"),
            pytest.param(False, False, 0.01, "medium", id="boundary_epss_at_exactly_medium_threshold"),
            pytest.param(False, False, 0.009, "low", id="epss_just_below_medium_threshold"),
            pytest.param(False, False, 0.0, "low", id="epss_zero"),
        ],
    )
    def test_maturity_for_kev_and_epss_combination(self, kev, ransomware, epss, expected):
        assert calculate_exploit_maturity(kev, ransomware, epss) == expected


class TestCalculateRiskScore:
    @pytest.mark.parametrize(
        ("cvss", "epss", "kev", "ransomware", "expected"),
        [
            pytest.param(None, None, False, False, 20.0, id="all_none_returns_baseline"),  # default CVSS contribution
            pytest.param(10.0, None, False, False, 40.0, id="max_cvss_contribution"),  # (10/10) * 40
            pytest.param(0.0, None, False, False, 0.0, id="zero_cvss"),
            pytest.param(5.0, None, False, False, 20.0, id="medium_cvss"),  # (5/10) * 40
            pytest.param(None, None, True, False, 40.0, id="kev_adds_20_points"),  # 20 (default CVSS) + 20 (KEV)
        ],
    )
    def test_score_for_cvss_and_kev_inputs(self, cvss, epss, kev, ransomware, expected):
        assert calculate_risk_score(cvss, epss, kev, ransomware) == expected

    def test_ransomware_adds_5_on_top_of_kev(self):
        score_kev = calculate_risk_score(None, None, True, False)
        score_kev_ransomware = calculate_risk_score(None, None, True, True)
        assert score_kev_ransomware - score_kev == 5.0

    def test_epss_high_contribution(self):
        score = calculate_risk_score(None, 0.5, False, False)
        assert score > 40.0  # 20 (default CVSS) + high EPSS

    def test_epss_contribution_capped_at_25(self):
        score = calculate_risk_score(None, 1.0, False, False)
        assert score <= 45.0  # 20 (default CVSS) + max 25 (EPSS)

    @pytest.mark.parametrize(
        ("epss_below", "epss_above"),
        [
            pytest.param(0.0099, 0.0101, id="medium_boundary"),
            pytest.param(0.099, 0.101, id="high_boundary"),
        ],
    )
    def test_epss_contribution_continuous_at_boundary(self, epss_below, epss_above):
        # EPSS contribution must be continuous across the bucket boundaries (no cliff).
        below = calculate_risk_score(None, epss_below, False, False)
        above = calculate_risk_score(None, epss_above, False, False)
        assert abs(above - below) < 0.5

    def test_epss_contribution_monotonic(self):
        # Higher EPSS must always yield a >= contribution across the full range.
        epss_grid = [0.0, 0.005, 0.0099, 0.01, 0.05, 0.099, 0.1, 0.3, 0.7, 1.0]
        scores = [calculate_risk_score(None, e, False, False) for e in epss_grid]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-9, (
                f"Non-monotonic at epss={epss_grid[i]}: {scores[i]} < {scores[i - 1]}"
            )

    def test_score_capped_at_100(self):
        assert calculate_risk_score(30.0, None, False, False) == 100.0


class TestCalculateAdjustedRiskScore:
    @pytest.mark.parametrize(
        ("base", "is_reachable", "analysis_level", "expected"),
        [
            pytest.param(50.0, None, None, 50.0, id="unanalysed_returns_base"),
            pytest.param(50.0, False, "import", 20.0, id="unreachable_returns_40_percent"),
            pytest.param(50.0, True, "symbol", 55.0, id="confirmed_boosts"),
            pytest.param(95.0, True, "symbol", 100.0, id="confirmed_cap_at_100"),
            pytest.param(50.0, True, "import", 50.0, id="likely_returns_base"),
            pytest.param(50.0, True, None, 50.0, id="untiered_reachable_returns_base"),
        ],
    )
    def test_adjusted_score_for_reachability(self, base, is_reachable, analysis_level, expected):
        assert calculate_adjusted_risk_score(base, is_reachable, analysis_level) == pytest.approx(expected)


class TestCalculateSecretRiskScore:
    @pytest.mark.parametrize(
        "in_current_tree",
        [
            pytest.param(False, id="historical_only"),
            pytest.param(True, id="in_current_tree"),
        ],
    )
    def test_verified_secret_gets_boosted_regardless_of_tree(self, in_current_tree):
        risk, adjusted = calculate_secret_risk_score(verified=True, in_current_tree=in_current_tree)
        assert risk == 40.0
        assert abs(adjusted - 44.0) < 0.01

    @pytest.mark.parametrize(
        ("verified", "in_current_tree", "expected_adjusted"),
        [
            pytest.param(False, True, 40.0, id="unverified_in_current_tree_is_baseline"),
            pytest.param(False, False, 16.0, id="unverified_historical_only_is_deprioritized"),
            pytest.param(None, None, 40.0, id="unknown_verified_and_unknown_tree_is_baseline"),
            pytest.param(None, False, 16.0, id="unknown_verified_historical_only_is_deprioritized"),
        ],
    )
    def test_unboosted_secret_adjusted_score(self, verified, in_current_tree, expected_adjusted):
        risk, adjusted = calculate_secret_risk_score(verified=verified, in_current_tree=in_current_tree)
        assert risk == 40.0
        assert adjusted == expected_adjusted

    def test_adjusted_score_capped_at_100(self):
        _, adjusted = calculate_secret_risk_score(verified=True, in_current_tree=True)
        assert adjusted <= 100.0


class TestCalculateSecretSeverity:
    """Only unverified secrets that are gone from the current tree drop to LOW; this must
    match the secret_deprioritized_count predicate (type=secret AND verified!=True AND
    in_current_tree=False) so the downgraded findings are exactly the deprioritized bucket."""

    @pytest.mark.parametrize(
        ("verified", "in_current_tree", "expected"),
        [
            pytest.param(False, False, Severity.LOW, id="unverified_historical_only_drops_to_low"),
            # secret_deprioritized_count uses $ne verified True, so unknown-verified counts as not-verified.
            pytest.param(None, False, Severity.LOW, id="unknown_verified_historical_only_drops_to_low"),
            # A verified credential is a live leak until rotated, even after the file is gone.
            pytest.param(True, False, Severity.CRITICAL, id="verified_historical_only_stays_critical"),
            pytest.param(False, True, Severity.CRITICAL, id="unverified_in_current_tree_stays_critical"),
            pytest.param(None, None, Severity.CRITICAL, id="unknown_tree_stays_critical"),
            pytest.param(True, True, Severity.CRITICAL, id="verified_in_current_tree_stays_critical"),
        ],
    )
    def test_severity_for_verification_and_tree_state(self, verified, in_current_tree, expected):
        assert calculate_secret_severity(verified=verified, in_current_tree=in_current_tree) == expected

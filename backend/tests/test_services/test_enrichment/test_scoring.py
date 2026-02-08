"""Tests for risk scoring and exploit maturity calculation."""

from app.services.enrichment.scoring import (
    calculate_exploit_maturity,
    calculate_risk_score,
    calculate_adjusted_risk_score,
)


class TestCalculateExploitMaturity:
    def test_weaponized_when_kev_ransomware(self):
        assert calculate_exploit_maturity(True, True, 0.5) == "weaponized"

    def test_active_when_kev_only(self):
        assert calculate_exploit_maturity(True, False, 0.5) == "active"

    def test_high_when_epss_above_high_threshold(self):
        assert calculate_exploit_maturity(False, False, 0.15) == "high"

    def test_medium_when_epss_between_thresholds(self):
        assert calculate_exploit_maturity(False, False, 0.05) == "medium"

    def test_low_when_epss_below_medium_threshold(self):
        assert calculate_exploit_maturity(False, False, 0.005) == "low"

    def test_unknown_when_no_epss(self):
        assert calculate_exploit_maturity(False, False, None) == "unknown"

    def test_kev_ransomware_takes_precedence_over_epss(self):
        assert calculate_exploit_maturity(True, True, 0.95) == "weaponized"

    def test_kev_takes_precedence_over_high_epss(self):
        assert calculate_exploit_maturity(True, False, 0.95) == "active"

    def test_boundary_epss_at_exactly_high_threshold(self):
        assert calculate_exploit_maturity(False, False, 0.1) == "high"

    def test_boundary_epss_at_exactly_medium_threshold(self):
        assert calculate_exploit_maturity(False, False, 0.01) == "medium"

    def test_epss_just_below_medium_threshold(self):
        assert calculate_exploit_maturity(False, False, 0.009) == "low"

    def test_epss_zero(self):
        assert calculate_exploit_maturity(False, False, 0.0) == "low"


class TestCalculateRiskScore:
    def test_all_none_returns_baseline(self):
        score = calculate_risk_score(None, None, False, False)
        assert score == 20.0  # Default CVSS contribution

    def test_max_cvss_contribution(self):
        score = calculate_risk_score(10.0, None, False, False)
        assert score == 40.0  # (10/10) * 40

    def test_zero_cvss(self):
        score = calculate_risk_score(0.0, None, False, False)
        assert score == 0.0

    def test_medium_cvss(self):
        score = calculate_risk_score(5.0, None, False, False)
        assert score == 20.0  # (5/10) * 40

    def test_kev_adds_20_points(self):
        score = calculate_risk_score(None, None, True, False)
        assert score == 40.0  # 20 (default CVSS) + 20 (KEV)

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

    def test_unreachable_reduces_score(self):
        base = calculate_risk_score(10.0, None, False, False)
        reduced = calculate_risk_score(10.0, None, False, False, is_reachable=False)
        assert reduced == base * 0.4

    def test_unreachable_via_level_string(self):
        base = calculate_risk_score(10.0, None, False, False)
        reduced = calculate_risk_score(10.0, None, False, False, reachability_level="unreachable")
        assert reduced == base * 0.4

    def test_confirmed_reachable_boosts(self):
        base = calculate_risk_score(10.0, None, False, False)
        boosted = calculate_risk_score(10.0, None, False, False, reachability_level="confirmed")
        assert boosted == base * 1.1

    def test_likely_reachable_no_modifier(self):
        base = calculate_risk_score(10.0, None, False, False)
        same = calculate_risk_score(10.0, None, False, False, reachability_level="likely")
        assert same == base

    def test_score_capped_at_100(self):
        score = calculate_risk_score(10.0, 0.95, True, True, reachability_level="confirmed")
        assert score <= 100.0

    def test_full_score_worst_case(self):
        score = calculate_risk_score(10.0, 0.95, True, True, reachability_level="confirmed")
        assert score >= 80.0  # Should be very high


class TestCalculateAdjustedRiskScore:
    def test_no_reachability_returns_base(self):
        assert calculate_adjusted_risk_score(50.0) == 50.0

    def test_unreachable_returns_40_percent(self):
        assert calculate_adjusted_risk_score(50.0, is_reachable=False) == 20.0

    def test_unreachable_via_level(self):
        assert calculate_adjusted_risk_score(50.0, reachability_level="unreachable") == 20.0

    def test_confirmed_returns_boosted(self):
        result = calculate_adjusted_risk_score(50.0, reachability_level="confirmed")
        assert abs(result - 55.0) < 0.01

    def test_confirmed_cap_at_100(self):
        assert calculate_adjusted_risk_score(95.0, reachability_level="confirmed") == 100.0

    def test_likely_returns_base(self):
        assert calculate_adjusted_risk_score(50.0, reachability_level="likely") == 50.0

    def test_unknown_level_returns_base(self):
        assert calculate_adjusted_risk_score(50.0, reachability_level="unknown") == 50.0

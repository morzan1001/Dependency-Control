"""Tests for risk scoring and exploit maturity calculation."""

from app.services.enrichment.scoring import (
    calculate_exploit_maturity,
    calculate_risk_score,
    calculate_adjusted_risk_score,
    map_reachability_level_to_modifier,
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

    def test_epss_contribution_continuous_at_medium_boundary(self):
        # B1: no jump at the 0.01 boundary. Difference between just-below and
        # just-above must be tiny (no >1-point cliff).
        below = calculate_risk_score(None, 0.0099, False, False)
        above = calculate_risk_score(None, 0.0101, False, False)
        assert abs(above - below) < 0.5

    def test_epss_contribution_continuous_at_high_boundary(self):
        # B1: no jump at the 0.1 boundary either.
        below = calculate_risk_score(None, 0.099, False, False)
        above = calculate_risk_score(None, 0.101, False, False)
        assert abs(above - below) < 0.5

    def test_epss_contribution_monotonic(self):
        # Higher EPSS must always yield >= contribution. Spot-check across
        # the full range, including both former cliffs.
        epss_grid = [0.0, 0.005, 0.0099, 0.01, 0.05, 0.099, 0.1, 0.3, 0.7, 1.0]
        scores = [calculate_risk_score(None, e, False, False) for e in epss_grid]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-9, (
                f"Non-monotonic at epss={epss_grid[i]}: {scores[i]} < {scores[i - 1]}"
            )

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
        # Worst-case inputs produce a very high score that is still capped at 100.
        assert 80.0 <= score <= 100.0


class TestMapReachabilityLevelToModifier:
    """The reachability enrichment vocabulary (none/import/symbol + is_reachable)
    must map onto the modifier vocabulary (unreachable/confirmed/None) that the
    scoring functions expect. Only an unambiguous high-confidence reachable hit
    becomes 'confirmed'; a definitively-not-reachable verdict becomes
    'unreachable'; everything else stays identity (None)."""

    def test_not_reachable_maps_to_unreachable(self):
        assert map_reachability_level_to_modifier("import", is_reachable=False) == "unreachable"

    def test_symbol_level_reachable_maps_to_confirmed(self):
        assert map_reachability_level_to_modifier("symbol", is_reachable=True) == "confirmed"

    def test_import_only_reachable_is_identity(self):
        # Import-only is a weaker signal; must NOT boost as if confirmed.
        assert map_reachability_level_to_modifier("import", is_reachable=True) is None

    def test_none_level_reachable_is_identity(self):
        assert map_reachability_level_to_modifier("none", is_reachable=True) is None

    def test_unknown_is_identity(self):
        assert map_reachability_level_to_modifier("unknown", is_reachable=None) is None

    def test_confirmed_passthrough(self):
        # If callers already speak the modifier vocabulary it is preserved.
        assert map_reachability_level_to_modifier("confirmed", is_reachable=True) == "confirmed"

    def test_unreachable_passthrough(self):
        assert map_reachability_level_to_modifier("unreachable", is_reachable=False) == "unreachable"


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

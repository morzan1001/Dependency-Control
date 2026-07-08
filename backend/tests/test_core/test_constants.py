"""Tests for constants utility functions."""

from app.core.constants import (
    EFFORT_BONUSES,
    RECOMMENDATION_TYPE_BONUSES,
    get_severity_value,
    sort_by_severity,
)


class TestGetSeverityValue:
    def test_critical(self):
        assert get_severity_value("CRITICAL") == 5

    def test_high(self):
        assert get_severity_value("HIGH") == 4

    def test_medium(self):
        assert get_severity_value("MEDIUM") == 3

    def test_low(self):
        assert get_severity_value("LOW") == 2

    def test_info(self):
        assert get_severity_value("INFO") == 0

    def test_unknown(self):
        assert get_severity_value("UNKNOWN") == 0

    def test_case_insensitive(self):
        assert get_severity_value("critical") == 5
        assert get_severity_value("High") == 4

    def test_none_returns_zero(self):
        assert get_severity_value(None) == 0

    def test_empty_string_returns_zero(self):
        assert get_severity_value("") == 0

    def test_invalid_returns_zero(self):
        assert get_severity_value("INVALID") == 0


class TestSortBySeverity:
    def test_descending_by_default(self):
        items = [
            {"name": "a", "severity": "LOW"},
            {"name": "b", "severity": "CRITICAL"},
            {"name": "c", "severity": "MEDIUM"},
        ]
        result = sort_by_severity(items)
        assert result[0]["name"] == "b"
        assert result[1]["name"] == "c"
        assert result[2]["name"] == "a"

    def test_ascending(self):
        items = [
            {"severity": "CRITICAL"},
            {"severity": "LOW"},
        ]
        result = sort_by_severity(items, reverse=False)
        assert result[0]["severity"] == "LOW"
        assert result[1]["severity"] == "CRITICAL"

    def test_custom_key(self):
        items = [{"level": "LOW"}, {"level": "HIGH"}]
        result = sort_by_severity(items, key="level")
        assert result[0]["level"] == "HIGH"
        assert result[1]["level"] == "LOW"

    def test_empty_list(self):
        assert sort_by_severity([]) == []

    def test_with_objects(self):
        class Item:
            def __init__(self, severity):
                self.severity = severity

        items = [Item("LOW"), Item("CRITICAL"), Item("HIGH")]
        result = sort_by_severity(items)
        assert result[0].severity == "CRITICAL"
        assert result[1].severity == "HIGH"
        assert result[2].severity == "LOW"

    def test_stable_sort_same_severity(self):
        items = [
            {"name": "first", "severity": "HIGH"},
            {"name": "second", "severity": "HIGH"},
        ]
        result = sort_by_severity(items)
        assert result[0]["name"] == "first"
        assert result[1]["name"] == "second"


class TestRecommendationTypeBonusesOrdering:
    """Only the relative ordering of the type bonuses is a real invariant; pin it, not the raw numbers."""

    def _bonus(self, key: str) -> int:
        return RECOMMENDATION_TYPE_BONUSES[key]

    def test_security_threats_outrank_impact_updates(self):
        # The "critical security" tier must beat the "high impact updates" tier.
        critical_security_min = min(
            self._bonus(k)
            for k in (
                "malware_detected",
                "ransomware_risk",
                "known_exploit",
                "actively_exploited",
                "critical_hotspot",
                "rotate_secrets",
                "typosquat_detected",
                "critical_risk",
            )
        )
        impact_max = max(
            self._bonus(k)
            for k in (
                "base_image_update",
                "single_update_multi_fix",
                "quick_win",
                "toxic_dependency",
                "shared_vulnerability",
            )
        )
        assert critical_security_min > impact_max

    def test_malware_outranks_ransomware_outranks_active_exploit(self):
        # This stack ranking is intentional and load-bearing for which recommendation surfaces first.
        assert self._bonus("malware_detected") > self._bonus("ransomware_risk")
        assert self._bonus("ransomware_risk") > self._bonus("known_exploit")
        assert self._bonus("known_exploit") > self._bonus("actively_exploited")
        assert self._bonus("actively_exploited") > self._bonus("critical_hotspot")

    def test_regression_tier_below_impact_tier(self):
        regression_max = max(self._bonus(k) for k in ("regression_detected", "recurring_vulnerability"))
        impact_min = min(
            self._bonus(k)
            for k in (
                "base_image_update",
                "single_update_multi_fix",
                "quick_win",
                "toxic_dependency",
                "shared_vulnerability",
            )
        )
        assert regression_max < impact_min

    def test_hygiene_tier_is_lowest(self):
        hygiene_max = max(
            self._bonus(k)
            for k in (
                "version_fragmentation",
                "deep_dependency_chain",
                "duplicate_functionality",
                "dev_in_production",
            )
        )
        assert hygiene_max < self._bonus("outdated_dependency")
        assert hygiene_max < self._bonus("license_compliance")

    def test_all_bonuses_are_positive(self):
        # A zero/negative bonus would silently demote a category; guard against a typo.
        for key, value in RECOMMENDATION_TYPE_BONUSES.items():
            assert value > 0, f"{key} has non-positive bonus {value}"


class TestEffortBonusesOrdering:
    def test_lower_effort_yields_higher_bonus(self):
        assert EFFORT_BONUSES["low"] > EFFORT_BONUSES["medium"]
        assert EFFORT_BONUSES["medium"] >= EFFORT_BONUSES["high"]

    def test_high_effort_has_no_bonus(self):
        assert EFFORT_BONUSES["high"] == 0

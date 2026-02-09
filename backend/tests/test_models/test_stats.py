"""Tests for Stats models."""

from app.models.stats import (
    Stats,
    ThreatIntelligenceStats,
    ReachabilityStats,
    PrioritizedCounts,
)


class TestStatsModel:
    def test_defaults_all_zero(self):
        stats = Stats()
        assert stats.critical == 0
        assert stats.high == 0
        assert stats.medium == 0
        assert stats.low == 0
        assert stats.info == 0
        assert stats.unknown == 0
        assert stats.risk_score == 0.0
        assert stats.adjusted_risk_score == 0.0

    def test_optional_fields_default_none(self):
        stats = Stats()
        assert stats.threat_intel is None
        assert stats.reachability is None
        assert stats.prioritized is None


class TestThreatIntelligenceStats:
    def test_defaults(self):
        ti = ThreatIntelligenceStats()
        assert ti.kev_count == 0
        assert ti.kev_ransomware_count == 0
        assert ti.avg_epss_score is None
        assert ti.max_epss_score is None
        assert ti.weaponized_count == 0


class TestReachabilityStats:
    def test_defaults(self):
        reach = ReachabilityStats()
        assert reach.analyzed_count == 0
        assert reach.reachable_count == 0
        assert reach.unreachable_count == 0
        assert reach.unknown_count == 0
        assert reach.reachable_critical == 0
        assert reach.reachable_high == 0


class TestPrioritizedCounts:
    def test_defaults(self):
        prio = PrioritizedCounts()
        assert prio.total == 0
        assert prio.actionable_total == 0
        assert prio.deprioritized_count == 0

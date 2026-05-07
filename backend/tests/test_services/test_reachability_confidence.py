"""Tests for the high-confidence reachability gate (B9).

The raw ``is_reachable: bool`` flag mixes two very different signals:
solid evidence that a vulnerable function is actually called (high
confidence) vs. "the package is imported, the rest is heuristic" (low
confidence). Headline counts that don't distinguish the two prioritise
noise. ``is_high_confidence_reachable`` is the gate that lets call-sites
opt into the conservative reading without losing the raw boolean.
"""

from app.core.constants import REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
from app.services.reachability_enrichment import is_high_confidence_reachable


class TestIsHighConfidenceReachable:
    def test_reachable_with_high_confidence_returns_true(self):
        data = {"is_reachable": True, "confidence_score": 0.9}
        assert is_high_confidence_reachable(data) is True

    def test_reachable_at_threshold_returns_true(self):
        # Inclusive boundary — a finding sitting exactly on the threshold
        # is considered high-confidence.
        data = {"is_reachable": True, "confidence_score": REACHABILITY_HIGH_CONFIDENCE_THRESHOLD}
        assert is_high_confidence_reachable(data) is True

    def test_reachable_below_threshold_returns_false(self):
        # Imported-but-no-symbol-info matches sit at 0.5; they should
        # not feed headline reachable counts.
        data = {"is_reachable": True, "confidence_score": 0.5}
        assert is_high_confidence_reachable(data) is False

    def test_unreachable_returns_false_regardless_of_confidence(self):
        data = {"is_reachable": False, "confidence_score": 0.99}
        assert is_high_confidence_reachable(data) is False

    def test_missing_is_reachable_returns_false(self):
        data = {"confidence_score": 0.9}
        assert is_high_confidence_reachable(data) is False

    def test_missing_confidence_returns_false(self):
        # Without a confidence number we can't assert "high confidence".
        data = {"is_reachable": True}
        assert is_high_confidence_reachable(data) is False

    def test_empty_dict_returns_false(self):
        assert is_high_confidence_reachable({}) is False

    def test_none_returns_false(self):
        assert is_high_confidence_reachable(None) is False

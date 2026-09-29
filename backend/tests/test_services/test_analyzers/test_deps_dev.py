"""The scorecard flag threshold falls back to the default when a project stores one outside the score range."""

from app.services.analyzers.deps_dev import _validated_threshold


def test_a_threshold_outside_the_score_range_falls_back_to_the_default():
    assert _validated_threshold({"scorecard_threshold": 11.0}, "scorecard_threshold", 5.0) == 5.0
    assert _validated_threshold({"scorecard_threshold": -1.0}, "scorecard_threshold", 5.0) == 5.0


def test_a_threshold_at_the_edge_of_the_score_range_is_kept():
    assert _validated_threshold({"scorecard_threshold": 0.0}, "scorecard_threshold", 5.0) == 0.0
    assert _validated_threshold({"scorecard_threshold": 10.0}, "scorecard_threshold", 5.0) == 10.0

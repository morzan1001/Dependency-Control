"""Tests for the shared EPSS bucketing function bucket_epss."""

from app.core.epss import bucket_epss


class TestBucketEpss:
    def test_zero_is_low(self):
        assert bucket_epss(0.0) == "low"

    def test_just_below_medium_is_low(self):
        assert bucket_epss(0.0099) == "low"

    def test_at_medium_threshold_is_medium(self):
        # Inclusive: 0.01 lands in "medium".
        assert bucket_epss(0.01) == "medium"

    def test_just_above_medium_is_medium(self):
        assert bucket_epss(0.05) == "medium"

    def test_just_below_high_is_medium(self):
        assert bucket_epss(0.099) == "medium"

    def test_at_high_threshold_is_high(self):
        # Inclusive: 0.1 lands in "high".
        assert bucket_epss(0.1) == "high"

    def test_above_high_is_high(self):
        assert bucket_epss(0.5) == "high"

    def test_max_is_high(self):
        assert bucket_epss(1.0) == "high"

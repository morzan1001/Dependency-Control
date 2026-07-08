"""Unit tests for the update-frequency endpoint helpers, focused on the ``window_days`` -> cutoff conversion (the full HTTP path is covered by integration tests)."""

from datetime import datetime, timedelta, timezone

from app.api.v1.endpoints.analytics.update_frequency import _resolve_since


class TestResolveSince:
    def test_none_window_returns_none(self):
        # No window_days -> orchestrator falls back to max_scans behaviour.
        assert _resolve_since(None) is None

    def test_window_days_translates_to_cutoff_in_past(self):
        before = datetime.now(tz=timezone.utc)
        result = _resolve_since(30)
        after = datetime.now(tz=timezone.utc)

        assert result is not None
        expected_low = before - timedelta(days=30)
        expected_high = after - timedelta(days=30)
        assert expected_low <= result <= expected_high

    def test_result_is_timezone_aware(self):
        # must be UTC-aware or Mongo date comparison (Mongo stores UTC) compares wrong
        result = _resolve_since(365)
        assert result is not None
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(0)

    def test_one_day_window(self):
        result = _resolve_since(1)
        assert result is not None
        assert (datetime.now(tz=timezone.utc) - result).days <= 1

    def test_long_window_does_not_overflow(self):
        # the endpoint allows up to 3650 days (10 years)
        result = _resolve_since(3650)
        assert result is not None
        assert result.year < datetime.now(tz=timezone.utc).year

"""Unit tests for the small helpers that back the update-frequency endpoints.

The full HTTP path is exercised by integration tests against real Mongo
+ Redis. Those carry significant fixture cost; for the calendar-window
translation (the new ``window_days`` query parameter) a focused unit
test is the right fit — it covers the actual conversion logic without
spinning up databases."""

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
        # Result should fall within (before - 30d, after - 30d).
        expected_low = before - timedelta(days=30)
        expected_high = after - timedelta(days=30)
        assert expected_low <= result <= expected_high

    def test_result_is_timezone_aware(self):
        # Must be UTC-aware so MongoDB date comparison works (Mongo stores
        # datetimes as UTC). A naive datetime would silently compare wrong.
        result = _resolve_since(365)
        assert result is not None
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(0)

    def test_one_day_window(self):
        # Sanity-check the small end of the allowed range.
        result = _resolve_since(1)
        assert result is not None
        assert (datetime.now(tz=timezone.utc) - result).days <= 1

    def test_long_window_does_not_overflow(self):
        # The endpoint allows up to 3650 days (10 years). The helper
        # should produce a valid datetime, not blow up.
        result = _resolve_since(3650)
        assert result is not None
        assert result.year < datetime.now(tz=timezone.utc).year

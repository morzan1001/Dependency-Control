"""Unit tests for the update-frequency endpoint helpers, focused on the ``window_days`` -> cutoff conversion (the full HTTP path is covered by integration tests)."""

from datetime import datetime, timedelta, timezone

from app.api.v1.endpoints.analytics.update_frequency import (
    _comparison_cache_key,
    _project_cache_key,
    _resolve_since,
)


class TestProjectCacheKey:
    def test_key_versions_on_latest_scan(self):
        # A new scan changes the scan id -> a new key -> no stale cache after a scan.
        base = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, latest_scan_id="scanA")
        after_scan = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, latest_scan_id="scanB")
        assert base != after_scan

    def test_key_distinguishes_branch_and_params(self):
        auto = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, latest_scan_id="s")
        main = _project_cache_key("proj-1", max_scans=20, window_days=None, branch="main", latest_scan_id="s")
        windowed = _project_cache_key("proj-1", max_scans=20, window_days=90, branch=None, latest_scan_id="s")
        assert len({auto, main, windowed}) == 3

    def test_key_stable_for_same_inputs(self):
        a = _project_cache_key("proj-1", max_scans=20, window_days=90, branch="main", latest_scan_id="s")
        b = _project_cache_key("proj-1", max_scans=20, window_days=90, branch="main", latest_scan_id="s")
        assert a == b


class TestComparisonCacheKey:
    def test_key_versions_on_newest_scan_timestamp(self):
        older = _comparison_cache_key("user-1", "all", max_scans=20, window_days=None, newest_scan_at="2026-01-01")
        newer = _comparison_cache_key("user-1", "all", max_scans=20, window_days=None, newest_scan_at="2026-02-01")
        assert older != newer

    def test_key_scoped_per_user_and_team(self):
        u1 = _comparison_cache_key("user-1", "all", max_scans=20, window_days=None, newest_scan_at="t")
        u2 = _comparison_cache_key("user-2", "all", max_scans=20, window_days=None, newest_scan_at="t")
        team = _comparison_cache_key("user-1", "team-x", max_scans=20, window_days=None, newest_scan_at="t")
        assert len({u1, u2, team}) == 3


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

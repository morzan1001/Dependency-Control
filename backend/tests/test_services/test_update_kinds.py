"""Every update total counts the same kinds: a rollback, or anything outside the vocabulary, is not update activity."""

from datetime import datetime, timezone

from app.schemas.analytics import DependencyUpdateEvent
from app.services.update_frequency import _build_timeline_entry

_SCAN_DATE = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _event(kind: str) -> DependencyUpdateEvent:
    return DependencyUpdateEvent(
        package_name="requests",
        package_type="pypi",
        old_version="1.0",
        new_version="2.0",
        update_type=kind,
        scan_date=_SCAN_DATE.isoformat(),
        previous_scan_date=_SCAN_DATE.isoformat(),
        days_between_scans=1,
        was_outdated=False,
    )


def test_a_timeline_bar_counts_only_the_counted_kinds():
    events = [_event("minor"), _event("patch"), _event("downgrade"), _event("none")]

    entry = _build_timeline_entry("scan-1", _SCAN_DATE, events, None)

    assert entry.updates_count == 2

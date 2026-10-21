"""Every update total counts the same kinds: a rollback, or anything outside the vocabulary, is not update activity."""

from collections import Counter
from datetime import datetime, timezone

from app.services.update_frequency import _build_timeline_entry

_SCAN_DATE = datetime(2026, 1, 2, tzinfo=timezone.utc)


def test_a_timeline_bar_counts_only_the_counted_kinds():
    kinds = Counter(["minor", "patch", "downgrade", "none"])

    entry = _build_timeline_entry("scan-1", _SCAN_DATE, kinds, None)

    assert entry.updates_count == 2

"""Tests asserting analysis engine paths use Primary-pinned reads.

Background: with MONGODB_READ_PREFERENCE=secondaryPreferred, reads that
follow a write in the same coroutine can race against replication and
return stale state. Worker pickup → engine load → race-check is the
hottest read-after-write path; it must hit the Mongo Primary.
"""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services.analysis.engine import _check_race_condition


class TestCheckRaceCondition:
    def test_uses_strong_read(self):
        scan_repo = SimpleNamespace(
            get_by_id_strong=AsyncMock(return_value=None),
            get_by_id=AsyncMock(side_effect=AssertionError("must use get_by_id_strong, not get_by_id")),
        )

        result = asyncio.run(
            _check_race_condition("scan-1", datetime.now(timezone.utc), scan_repo),  # type: ignore[arg-type]
        )

        scan_repo.get_by_id_strong.assert_awaited_once_with("scan-1")
        scan_repo.get_by_id.assert_not_awaited()
        assert result is False

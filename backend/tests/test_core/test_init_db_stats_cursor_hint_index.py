"""create_indexes must keep building the index the stats cursor hints; without it every stats read errors."""

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from app.services.analysis.stats import _STATS_CURSOR_HINT
from tests.mocks.fake_mongo import FakeDatabase

FINDINGS_COLLECTION = "findings"


def test_findings_indexes_include_the_stats_cursor_hint_key_pattern():
    db = FakeDatabase()
    findings = db[FINDINGS_COLLECTION]
    findings.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    issued = [call.args[0] for call in findings.create_index.await_args_list]
    assert _STATS_CURSOR_HINT in issued, (
        "calculate_comprehensive_stats passes this key pattern as a hint; MongoDB errors on an "
        "unsatisfiable hint instead of falling back, so dropping this index fails every stats read"
    )

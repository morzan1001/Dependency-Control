"""A read past its time limit stops on the server, so an abandoned chat search does not keep a mongod thread busy."""

import pytest
from pymongo.errors import ExecutionTimeout

from app.repositories.base import find_window

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_ROWS = 40
_LIMIT_MS = 300
# Server-side JavaScript that stalls each document it examines, so the read's length is the number of rows it reads.
_SLOW = {"$expr": {"$function": {"body": "function() { sleep(20); return true; }", "args": [], "lang": "js"}}}


async def _seed(db) -> None:
    await db.rows.insert_many([{"_id": i} for i in range(_ROWS)])


async def test_the_page_read_stops_at_the_time_limit(db):
    await _seed(db)

    with pytest.raises(ExecutionTimeout):
        await find_window(db.rows, _SLOW, _ROWS, max_time_ms=_LIMIT_MS)


async def test_the_total_count_after_a_full_page_stops_at_the_time_limit(db):
    await _seed(db)

    with pytest.raises(ExecutionTimeout):
        await find_window(db.rows, _SLOW, 1, max_time_ms=_LIMIT_MS)

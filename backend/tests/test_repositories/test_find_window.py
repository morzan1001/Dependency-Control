"""Read up to a limit and count only when the read saturated: the count is what tells a small
result from a truncated one, and a result that exactly fills the limit is not truncated."""

import pytest

from app.repositories.base import find_window
from app.services.chat.tools._helpers import begin_limit_ledger, bounded_read, bounded_read_note
from tests.mocks.fake_mongo import FakeDatabase

_LIMIT = 3


async def _seeded(count: int) -> FakeDatabase:
    db = FakeDatabase()
    for index in range(count):
        await db.webhooks.insert_one({"_id": f"w{index}", "project_id": "p1"})
    return db


@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "shown", "total"), [(2, 2, 2), (3, 3, 3), (5, 3, 5)])
async def test_the_window_carries_the_rows_and_the_total(stored, shown, total):
    db = await _seeded(stored)

    rows, counted = await find_window(db.webhooks, {"project_id": "p1"}, _LIMIT)

    assert (len(rows), counted) == (shown, total)


@pytest.mark.asyncio
async def test_a_read_that_exactly_fills_its_limit_carries_no_caveat():
    db = await _seeded(_LIMIT)
    begin_limit_ledger()

    await bounded_read(db.webhooks, {"project_id": "p1"}, subject="webhooks", limit=_LIMIT)

    assert bounded_read_note() is None


@pytest.mark.asyncio
async def test_a_truncated_read_still_says_so():
    db = await _seeded(_LIMIT + 2)
    begin_limit_ledger()

    await bounded_read(db.webhooks, {"project_id": "p1"}, subject="webhooks", limit=_LIMIT)

    assert "3 of 5 webhooks" in (bounded_read_note() or "")

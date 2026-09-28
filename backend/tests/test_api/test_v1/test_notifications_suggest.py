"""The advisory package typeahead keeps its cap, reads head scans only and says when the query has to narrow."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from pymongo.errors import ExecutionTimeout

from app.api.v1.endpoints.notifications import _PACKAGE_SUGGESTION_LIMIT, suggest_packages
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.notifications"
_HEAD_SCAN = "head"


def _user() -> User:
    return User(id="broadcaster-1", username="broadcaster", email="broadcaster@test.com", permissions=[])


def _suggest(db: Any, q: str = "lib") -> Any:
    with patch(f"{MODULE}.resolve_scan_ids", AsyncMock(return_value={"p": _HEAD_SCAN})):
        return asyncio.run(suggest_packages(db=db, current_user=_user(), q=q))


def _db_with(names: list[str], scan_id: str = _HEAD_SCAN) -> FakeDatabase:
    db = FakeDatabase()

    async def _seed():
        for index, name in enumerate(names):
            await db.dependencies.insert_one({"_id": f"{scan_id}-{index}", "scan_id": scan_id, "name": name})

    asyncio.run(_seed())
    return db


def test_a_query_matching_more_than_the_cap_says_the_list_is_not_the_answer():
    suggestions = _suggest(_db_with([f"lib{index:03d}" for index in range(_PACKAGE_SUGGESTION_LIMIT + 5)]))

    assert len(suggestions.names) == _PACKAGE_SUGGESTION_LIMIT
    assert suggestions.more is True


def test_a_query_the_cap_answers_whole_claims_nothing_more():
    suggestions = _suggest(_db_with([f"lib{index:03d}" for index in range(_PACKAGE_SUGGESTION_LIMIT)]))

    assert len(suggestions.names) == _PACKAGE_SUGGESTION_LIMIT
    assert suggestions.more is False


def test_the_cap_keeps_the_alphabetically_first_matches_in_order():
    """An over-full query is cut from the front, so the tail of the alphabet is what the user narrows away."""
    # Inserted back to front so the ordering cannot come from insertion order.
    names = [f"lib{index:03d}" for index in reversed(range(_PACKAGE_SUGGESTION_LIMIT + 2))]

    suggestions = _suggest(_db_with(names))

    assert suggestions.names == [f"lib{index:03d}" for index in range(_PACKAGE_SUGGESTION_LIMIT)]
    assert suggestions.more is True


def test_a_name_only_a_superseded_scan_carries_is_not_suggested():
    suggestions = _suggest(_db_with(["libold"], scan_id="superseded"))

    assert suggestions.names == []


def test_a_query_that_outruns_the_time_limit_asks_to_narrow():
    db = MagicMock()
    cursor = db.__getitem__.return_value.aggregate.return_value
    cursor.to_list = AsyncMock(side_effect=ExecutionTimeout("operation exceeded time limit"))

    suggestions = _suggest(db)

    assert (suggestions.names, suggestions.more) == ([], True)

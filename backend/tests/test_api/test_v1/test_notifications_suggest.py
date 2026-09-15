"""The advisory package typeahead keeps its cap and says when the query has to narrow."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.v1.endpoints.notifications import _PACKAGE_SUGGESTION_LIMIT, suggest_packages
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.notifications"


def _user() -> User:
    return User(id="broadcaster-1", username="broadcaster", email="broadcaster@test.com", permissions=[])


def _run(matches: int) -> Any:
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(
        side_effect=lambda pipeline, limit=None: [{"name": f"lib{index:03d}"} for index in range(matches)][:limit]
    )
    with patch(f"{MODULE}.DependencyRepository", return_value=dep_repo):
        return asyncio.run(suggest_packages(db=MagicMock(), current_user=_user(), q="lib"))


def test_a_query_matching_more_than_the_cap_says_the_list_is_not_the_answer():
    suggestions = _run(_PACKAGE_SUGGESTION_LIMIT + 5)

    assert len(suggestions.names) == _PACKAGE_SUGGESTION_LIMIT
    assert suggestions.more is True


def test_a_query_the_cap_answers_whole_claims_nothing_more():
    suggestions = _run(_PACKAGE_SUGGESTION_LIMIT)

    assert len(suggestions.names) == _PACKAGE_SUGGESTION_LIMIT
    assert suggestions.more is False


def test_the_cap_keeps_the_alphabetically_first_matches_in_order():
    """An over-full query is cut from the front, so the tail of the alphabet is what the user narrows away."""

    async def _suggest_over_a_real_collection():
        db = FakeDatabase()
        # Inserted back to front so the ordering cannot come from insertion order.
        for index in reversed(range(_PACKAGE_SUGGESTION_LIMIT + 2)):
            await db.dependencies.insert_one({"_id": f"d{index:03d}", "name": f"lib{index:03d}"})
        return await suggest_packages(db=db, current_user=_user(), q="lib")

    suggestions = asyncio.run(_suggest_over_a_real_collection())

    assert suggestions.names == [f"lib{index:03d}" for index in range(_PACKAGE_SUGGESTION_LIMIT)]
    assert suggestions.more is True

"""MCP API keys: the listing states what its page left out."""

import pytest

from app.repositories.mcp_api_keys import LIST_LIMIT, MCPApiKeyRepository
from tests.mocks.fake_mongo import FakeDatabase

_OWNER = "user-1"
_KEY_NAME = "client"
_EXPIRY_DAYS = 30
_OVER_THE_PAGE = 3


@pytest.mark.asyncio
async def test_list_for_user_reports_the_population_behind_a_saturated_page():
    """An MCP key reaches every tool the owner can, so one they cannot see is one they
    cannot revoke."""
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert len(keys) == LIST_LIMIT
    assert total == LIST_LIMIT + _OVER_THE_PAGE


@pytest.mark.asyncio
async def test_a_complete_listing_costs_no_count_round_trip():
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert total == len(keys)

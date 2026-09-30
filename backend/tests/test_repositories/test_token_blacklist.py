"""The blacklist insert is the atomic step of refresh rotation, so only a duplicate may read as "already listed"."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from pymongo.errors import AutoReconnect

from app.repositories.token_blacklist import TokenBlacklistRepository
from tests.mocks.fake_mongo import FakeDatabase

_JTI = "jti-1"
_EXPIRES_AT = datetime.now(timezone.utc) + timedelta(days=7)


@pytest.mark.asyncio
async def test_listing_a_token_twice_reports_the_second_attempt():
    repo = TokenBlacklistRepository(FakeDatabase())

    assert await repo.blacklist_token(_JTI, _EXPIRES_AT, "logout") is True
    assert await repo.blacklist_token(_JTI, _EXPIRES_AT, "logout") is False


@pytest.mark.asyncio
async def test_a_failed_write_is_raised_rather_than_read_as_already_listed():
    repo = TokenBlacklistRepository(FakeDatabase())
    repo.collection.insert_one = AsyncMock(side_effect=AutoReconnect("primary stepped down"))

    with pytest.raises(AutoReconnect):
        await repo.blacklist_token(_JTI, _EXPIRES_AT, "logout")

"""Unit tests for UserRepository lookup/existence helpers.

These pin the behavior of ``exists_by_*`` and ``get_raw_by_*`` after they were
reduced to delegations onto ``BaseRepository.exists``/``find_one_raw``.
"""

import pytest
import pytest_asyncio

from app.repositories.users import UserRepository
from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def repo():
    db = FakeDatabase()
    r = UserRepository(db)
    await r.create_raw(
        {"_id": "u1", "username": "alice", "email": "alice@corp.com", "permissions": []}
    )
    return r


@pytest.mark.asyncio
async def test_exists_by_username(repo):
    assert await repo.exists_by_username("alice") is True
    assert await repo.exists_by_username("bob") is False


@pytest.mark.asyncio
async def test_exists_by_email(repo):
    assert await repo.exists_by_email("alice@corp.com") is True
    assert await repo.exists_by_email("nobody@corp.com") is False


@pytest.mark.asyncio
async def test_get_raw_by_username(repo):
    doc = await repo.get_raw_by_username("alice")
    assert doc is not None
    assert doc["_id"] == "u1"
    assert doc["email"] == "alice@corp.com"
    assert await repo.get_raw_by_username("bob") is None


@pytest.mark.asyncio
async def test_get_raw_by_email(repo):
    doc = await repo.get_raw_by_email("alice@corp.com")
    assert doc is not None
    assert doc["_id"] == "u1"
    assert doc["username"] == "alice"
    assert await repo.get_raw_by_email("nobody@corp.com") is None

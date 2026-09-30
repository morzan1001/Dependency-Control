"""Unit tests for UserRepository lookup/existence helpers."""

import pytest
import pytest_asyncio

from app.repositories.users import UserRepository
from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def repo():
    db = FakeDatabase()
    r = UserRepository(db)
    await r.create_raw({"_id": "u1", "username": "alice", "email": "alice@corp.com", "permissions": []})
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


@pytest.mark.asyncio
async def test_email_lookups_ignore_case(repo):
    assert (await repo.get_raw_by_email("Alice@CORP.com"))["_id"] == "u1"
    assert await repo.exists_by_email("ALICE@corp.com") is True


@pytest.mark.asyncio
async def test_email_lookups_match_the_whole_address_literally(repo):
    assert await repo.get_raw_by_email("a.ice@corp.com") is None
    assert await repo.exists_by_email("lice@corp.com") is False


@pytest.mark.asyncio
async def test_the_verified_email_lookup_skips_an_account_that_has_not_proven_the_address(repo):
    assert await repo.get_raw_by_verified_email("alice@corp.com") is None

    await repo.update("u1", {"is_verified": True})

    assert (await repo.get_raw_by_verified_email("ALICE@corp.com"))["_id"] == "u1"


@pytest.mark.asyncio
async def test_the_batched_verified_email_lookup_matches_as_the_single_one_does(repo):
    await repo.update("u1", {"is_verified": True})
    await repo.create_raw({"_id": "u2", "username": "bob", "email": "bob@corp.com", "permissions": []})
    await repo.create_raw({"_id": "u3", "username": "carl", "email": "carl@corp.com", "is_verified": True})

    found = await repo.find_raw_by_verified_emails(["ALICE@corp.com", "bob@corp.com", "c.rl@corp.com"])

    assert [user["_id"] for user in found] == ["u1"]

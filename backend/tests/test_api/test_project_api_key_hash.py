"""A project key is a 256-bit random secret, so a SHA-256 digest guards it as well as argon2 at a fraction of the cost."""

import pytest
from fastapi import HTTPException

from app.api import deps
from app.api.v1.helpers.projects import generate_project_api_key
from app.core import security
from app.repositories.api_keys import hash_token
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "proj-1"
_SECRET = "the-secret"
_ARGON2_HASH = security.get_password_hash(_SECRET)


async def _db(api_key_hash: str) -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one({"_id": _PROJECT, "name": "p", "api_key_hash": api_key_hash})
    return db


async def _authenticate(db: FakeDatabase, secret: str = _SECRET):
    return await deps.get_project_for_ingest(x_api_key=f"{_PROJECT}.{secret}", oidc_token=None, db=db)


def _stored_hash(db: FakeDatabase) -> str:
    return db.projects._docs[_PROJECT]["api_key_hash"]


def test_a_new_key_is_stored_as_the_sha256_of_its_secret():
    api_key, api_key_hash = generate_project_api_key(_PROJECT)

    project_id, secret = api_key.split(".", 1)
    assert (project_id, api_key_hash) == (_PROJECT, hash_token(secret))


@pytest.mark.asyncio
async def test_a_sha256_key_authenticates_without_argon2(monkeypatch):
    db = await _db(hash_token(_SECRET))
    monkeypatch.setattr(security, "verify_password", None)

    assert (await _authenticate(db)).id == _PROJECT


@pytest.mark.asyncio
@pytest.mark.parametrize("stored", [hash_token(_SECRET), _ARGON2_HASH], ids=["sha256", "argon2"])
async def test_a_wrong_secret_is_refused_and_changes_nothing(stored):
    db = await _db(stored)

    with pytest.raises(HTTPException) as exc_info:
        await _authenticate(db, secret="not-the-secret")

    assert exc_info.value.status_code == 403
    assert _stored_hash(db) == stored


@pytest.mark.asyncio
async def test_an_argon2_key_is_verified_once_and_rewritten_as_sha256(monkeypatch):
    db = await _db(_ARGON2_HASH)

    assert (await _authenticate(db)).id == _PROJECT
    assert _stored_hash(db) == hash_token(_SECRET)

    monkeypatch.setattr(security, "verify_password", None)
    assert (await _authenticate(db)).id == _PROJECT


@pytest.mark.asyncio
async def test_a_rotation_during_the_argon2_check_is_not_undone(monkeypatch):
    db = await _db(_ARGON2_HASH)
    rotated = hash_token("rotated-secret")
    verify = security.verify_password

    def verify_while_rotating(secret, hashed):
        db.projects._docs[_PROJECT]["api_key_hash"] = rotated
        return verify(secret, hashed)

    monkeypatch.setattr(security, "verify_password", verify_while_rotating)

    await _authenticate(db)

    assert _stored_hash(db) == rotated

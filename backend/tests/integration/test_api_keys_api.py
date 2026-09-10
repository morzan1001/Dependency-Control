"""CRUD for unified API keys."""

from datetime import datetime, timedelta

import pytest
from jose import jwt

from app.api.deps import SURFACE_PERMISSIONS
from app.core.config import settings
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP, API_KEY_SURFACES
from app.core.permissions import Permissions
from app.repositories.api_keys import LIST_LIMIT, ApiKeyRepository

_BASE = "/api/v1/api-keys"
_COLLECTION = "api_keys"

_OWNER = "key-owner"
_OTHER_OWNER = "another-owner"
_KEY_NAME = "ci"
_EXPIRY_DAYS = 30
_TOKEN_PREFIX = "dck_"
_PREFIX_LENGTH = 12

_OK = 200
_CREATED = 201
_UNAUTHORIZED = 401
_FORBIDDEN = 403
_NOT_FOUND = 404

_TIMESTAMP_FIELDS = ("created_at", "expires_at", "revoked_at", "last_used_at")
# BSON dates are int64 milliseconds, so a stored timestamp loses the digits below that and no more.
_BSON_RESOLUTION = timedelta(milliseconds=1)

_BOTH_SURFACES = [API_KEY_SURFACE_MCP, API_KEY_SURFACE_ADHOC]
_BOTH_PERMISSIONS = [Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC]

_NO_KEYS = 0
_ONE_KEY = 1
_OVER_THE_PAGE = 3


def _headers(permissions, subject=_OWNER):
    token = jwt.encode(
        {"sub": subject, "permissions": list(permissions)},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return {"Authorization": f"Bearer {token}"}


async def _key_count(db):
    return await db[_COLLECTION].count_documents({})


async def _stored(db, key_id):
    return await db[_COLLECTION].find_one({"_id": key_id})


@pytest.mark.asyncio
async def test_create_returns_the_plaintext_once_and_the_listing_never_shows_it(client, db):
    headers = _headers(_BOTH_PERMISSIONS)

    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": _BOTH_SURFACES, "expires_in_days": _EXPIRY_DAYS},
        headers=headers,
    )

    assert created.status_code == _CREATED, created.text
    body = created.json()
    assert body["token"].startswith(_TOKEN_PREFIX)
    assert body["prefix"] == body["token"][:_PREFIX_LENGTH]

    listed = await client.get(f"{_BASE}/", headers=headers)
    assert listed.status_code == _OK, listed.text
    keys = listed.json()["keys"]
    assert len(keys) == _ONE_KEY
    assert "token" not in keys[0]
    assert keys[0]["prefix"] == body["prefix"]


@pytest.mark.asyncio
async def test_create_records_the_requested_surfaces_and_the_listing_reports_them(client, db):
    headers = _headers(_BOTH_PERMISSIONS)

    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": [API_KEY_SURFACE_ADHOC]},
        headers=headers,
    )

    assert created.status_code == _CREATED, created.text
    assert created.json()["surfaces"] == [API_KEY_SURFACE_ADHOC]
    assert (await _stored(db, created.json()["id"]))["surfaces"] == [API_KEY_SURFACE_ADHOC]

    listed = await client.get(f"{_BASE}/", headers=headers)
    assert listed.json()["keys"][0]["surfaces"] == [API_KEY_SURFACE_ADHOC]


def test_every_surface_a_key_can_name_has_a_permission():
    """Minting indexes the dependency's table with whatever the schema admitted, so a surface
    added to the literal without a permission beside it would 500 the mint rather than refuse it."""
    assert set(SURFACE_PERMISSIONS) == API_KEY_SURFACES


@pytest.mark.parametrize(
    ("held_permission", "refused_surface", "granted_surface"),
    [
        (Permissions.ANALYZE_ADHOC, API_KEY_SURFACE_MCP, API_KEY_SURFACE_ADHOC),
        (Permissions.MCP_ACCESS, API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP),
    ],
    ids=["lacks-mcp", "lacks-adhoc"],
)
@pytest.mark.asyncio
async def test_create_is_refused_naming_the_surface_the_caller_lacks(
    client, db, held_permission, refused_surface, granted_surface
):
    resp = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": _BOTH_SURFACES},
        headers=_headers([held_permission]),
    )

    assert resp.status_code == _FORBIDDEN, resp.text
    detail = resp.json()["detail"]
    assert refused_surface in detail
    assert granted_surface not in detail
    assert await _key_count(db) == _NO_KEYS


@pytest.mark.parametrize(
    ("permission", "surface"),
    [
        (Permissions.ANALYZE_ADHOC, API_KEY_SURFACE_ADHOC),
        (Permissions.MCP_ACCESS, API_KEY_SURFACE_MCP),
    ],
    ids=[API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP],
)
@pytest.mark.asyncio
async def test_create_succeeds_for_the_surfaces_the_caller_does_hold(client, db, permission, surface):
    resp = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": [surface]},
        headers=_headers([permission, Permissions.PROJECT_READ]),
    )

    assert resp.status_code == _CREATED, resp.text
    assert resp.json()["surfaces"] == [surface]
    assert await _key_count(db) == _ONE_KEY


@pytest.mark.asyncio
async def test_the_listing_is_scoped_to_the_owner(client, db):
    repo = ApiKeyRepository(db)
    await repo.create(_OTHER_OWNER, "stranger-key", _BOTH_SURFACES, _EXPIRY_DAYS)
    await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=_headers(_BOTH_PERMISSIONS))

    assert listed.status_code == _OK, listed.text
    assert [key["name"] for key in listed.json()["keys"]] == [_KEY_NAME]


@pytest.mark.asyncio
async def test_the_listing_works_for_a_caller_who_holds_neither_surface_permission(client, db):
    # Divergence from the per-surface systems, and the point of the unified one: withdrawing the
    # permission that minted a key must not hide it from its owner, or it could never be revoked.
    await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=_headers([Permissions.PROJECT_READ]))

    assert listed.status_code == _OK, listed.text
    assert [key["name"] for key in listed.json()["keys"]] == [_KEY_NAME]


@pytest.mark.asyncio
async def test_revoking_works_for_a_caller_who_holds_neither_surface_permission(client, db):
    # The same divergence: revocation belongs to the owner, not to the permission, so a credential
    # stays killable after the permission behind it is gone.
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    revoked = await client.delete(f"{_BASE}/{doc['_id']}", headers=_headers([Permissions.PROJECT_READ]))

    assert revoked.status_code == _OK, revoked.text
    assert (await _stored(db, doc["_id"]))["revoked_at"] is not None


@pytest.mark.asyncio
async def test_revoke_is_idempotent_and_404s_the_second_time(client, db):
    headers = _headers(_BOTH_PERMISSIONS)
    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": _BOTH_SURFACES},
        headers=headers,
    )
    key_id = created.json()["id"]

    first = await client.delete(f"{_BASE}/{key_id}", headers=headers)
    second = await client.delete(f"{_BASE}/{key_id}", headers=headers)

    assert first.status_code == _OK, first.text
    assert second.status_code == _NOT_FOUND


@pytest.mark.asyncio
async def test_revoke_is_refused_for_another_users_key(client, db):
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    stranger = await client.delete(
        f"{_BASE}/{doc['_id']}",
        headers=_headers(_BOTH_PERMISSIONS, subject=_OTHER_OWNER),
    )

    assert stranger.status_code == _NOT_FOUND
    assert (await _stored(db, doc["_id"]))["revoked_at"] is None
    # The owner's revoke separates "the route refused this caller" from "there is no such route".
    owner = await client.delete(f"{_BASE}/{doc['_id']}", headers=_headers(_BOTH_PERMISSIONS))
    assert owner.status_code == _OK, owner.text


@pytest.mark.asyncio
async def test_a_saturated_listing_names_the_keys_it_did_not_show(client, db):
    repo = ApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _BOTH_SURFACES, _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=_headers(_BOTH_PERMISSIONS))

    assert listed.status_code == _OK, listed.text
    body = listed.json()
    assert len(body["keys"]) == LIST_LIMIT
    assert body["truncated"] == {
        "limit": LIST_LIMIT,
        "returned": LIST_LIMIT,
        "total": LIST_LIMIT + _OVER_THE_PAGE,
    }


@pytest.mark.asyncio
async def test_a_complete_listing_declares_no_truncation(client, db):
    await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=_headers(_BOTH_PERMISSIONS))

    assert listed.json()["truncated"] is None


@pytest.mark.asyncio
async def test_every_listed_timestamp_carries_a_utc_offset(client, db):
    # Mongo returns naive UTC. Serialised without an offset, a client parses the value as local
    # time, which moves the active/expired boundary by the server's offset.
    repo = ApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    await repo.touch_last_used(doc["_id"])
    await repo.revoke(doc["_id"], _OWNER)

    listed = await client.get(f"{_BASE}/", headers=_headers(_BOTH_PERMISSIONS))

    assert listed.status_code == _OK, listed.text
    key = listed.json()["keys"][0]
    for field in _TIMESTAMP_FIELDS:
        assert datetime.fromisoformat(key[field]).tzinfo is not None, f"{field}: {key[field]}"


@pytest.mark.asyncio
async def test_the_mint_and_the_listing_report_the_same_expiry(client, db):
    # The mint answers from the in-memory document and the listing from Mongo; the two must not
    # describe the same key's expiry differently.
    headers = _headers(_BOTH_PERMISSIONS)
    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "surfaces": _BOTH_SURFACES, "expires_in_days": _EXPIRY_DAYS},
        headers=headers,
    )
    listed = await client.get(f"{_BASE}/", headers=headers)

    assert created.status_code == _CREATED, created.text
    minted, relisted = created.json(), listed.json()["keys"][0]
    for field in ("created_at", "expires_at"):
        at_mint, at_listing = datetime.fromisoformat(minted[field]), datetime.fromisoformat(relisted[field])
        where = f"{field}: {minted[field]} vs {relisted[field]}"
        assert at_mint.utcoffset() == at_listing.utcoffset(), where
        assert abs(at_mint - at_listing) < _BSON_RESOLUTION, where


@pytest.mark.asyncio
async def test_an_api_key_can_neither_mint_nor_list_api_keys(client, db):
    # The surface takes a session token alone: a key able to mint keys would outlive its revocation.
    _, plaintext = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    headers = {"Authorization": f"Bearer {plaintext}"}

    minted = await client.post(f"{_BASE}/", json={"name": _KEY_NAME, "surfaces": _BOTH_SURFACES}, headers=headers)
    listed = await client.get(f"{_BASE}/", headers=headers)

    assert minted.status_code == _UNAUTHORIZED, minted.text
    assert listed.status_code == _UNAUTHORIZED, listed.text
    assert await _key_count(db) == _ONE_KEY


@pytest.mark.asyncio
async def test_the_listing_carries_last_used_at_non_null_after_a_stamp(client, db):
    repo = ApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    headers = _headers(_BOTH_PERMISSIONS)

    before = await client.get(f"{_BASE}/", headers=headers)
    await repo.touch_last_used(doc["_id"])
    after = await client.get(f"{_BASE}/", headers=headers)

    assert "last_used_at" in before.json()["keys"][0]
    assert before.json()["keys"][0]["last_used_at"] is None
    assert after.json()["keys"][0]["last_used_at"] is not None

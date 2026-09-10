"""The unified key dependency admits a caller only when the key names the surface and the owner
still holds that surface's permission."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.deps import require_api_key
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.api_keys import hash_token
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_COL = "api_keys"
_TOKEN_BODY_CHARS = 64
_TOKEN = "dck_" + "a" * _TOKEN_BODY_CHARS
_PREFIX_LENGTH = 12
_KEY_ID = "key-1"
_OWNER = "user-1"
_KEY_NAME = "claude-desktop"
_UNAUTHORIZED = 401
_FORBIDDEN = 403

_BOTH_SURFACES = [API_KEY_SURFACE_MCP, API_KEY_SURFACE_ADHOC]

# The permission each surface gates on, and the sibling surface's permission, which is the one an
# escalation would accept in its place.
_SURFACE_PERMISSION = {
    API_KEY_SURFACE_MCP: Permissions.MCP_ACCESS,
    API_KEY_SURFACE_ADHOC: Permissions.ANALYZE_ADHOC,
}
_SIBLING_PERMISSION = {
    API_KEY_SURFACE_MCP: Permissions.ANALYZE_ADHOC,
    API_KEY_SURFACE_ADHOC: Permissions.MCP_ACCESS,
}

_MSG_MISSING_BEARER = "Missing Bearer token"
# Unknown, revoked and expired share one message: distinguishing them would confirm to a caller
# holding a rejected token that the token once existed.
_MSG_OPAQUE_KEY = "Invalid, revoked, or expired API key"

# Asserting on the key collection alone leaves a usage or audit collection free to be read.
_USERS_COL = "users"
_REACHABLE_COLLECTIONS = frozenset({_COL, _USERS_COL})

# Every write create_mock_collection stubs. find_one_and_update is the idiomatic way to write a
# touch-on-read, so leaving it unchecked would let the write the default must not do slip in.
_WRITE_METHODS = (
    "insert_one",
    "find_one_and_update",
    "update_one",
    "update_many",
    "delete_one",
    "bulk_write",
    "create_index",
)


_ABSENT = object()
_SIBLING = object()

# Everything a "surfaces" field can hold that names no surface. A bare membership test admits the
# strings and the dict — `"mcp" in "xxmcpxx"` is a substring hit, `"mcp" in {"mcp": 1}` a key hit —
# and raises TypeError on the null and the number.
_NAMES_NO_SURFACE = {
    "the-sibling-surface": _SIBLING,
    "no-surfaces-field": _ABSENT,
    "null": None,
    "a-number": 123,
    "the-bare-surface-string": API_KEY_SURFACE_MCP,
    "a-string-containing-the-surface": f"xx{API_KEY_SURFACE_MCP}xx",
    "a-dict-keyed-by-the-surface": {API_KEY_SURFACE_MCP: 1},
}


def _key_doc(surfaces=_ABSENT):
    doc = {
        "_id": _KEY_ID,
        "user_id": _OWNER,
        "name": _KEY_NAME,
        "prefix": _TOKEN[:_PREFIX_LENGTH],
        "token_hash": hash_token(_TOKEN),
        "revoked_at": None,
    }
    if surfaces is not _ABSENT:
        doc["surfaces"] = surfaces
    return doc


def _db_with_key(doc):
    keys = create_mock_collection(find_one=doc)
    # get_by_plaintext reads through with_options(read_preference=PRIMARY); create_mock_collection
    # does not stub it, so the strong-read alias has to point back at the same mock.
    keys.with_options = MagicMock(return_value=keys)
    return create_mock_db({_COL: keys}), keys


def _patch_user(monkeypatch, user):
    # Resolves the owner's id alone, so a key document naming nobody resolves to nobody.
    monkeypatch.setattr(
        "app.repositories.users.UserRepository.get_by_id",
        AsyncMock(side_effect=lambda user_id: user if user_id == _OWNER else None),
    )


def _patch_touch_last_used(monkeypatch):
    touch = AsyncMock()
    monkeypatch.setattr("app.repositories.api_keys.ApiKeyRepository.touch_last_used", touch)
    return touch


def _active_user(permissions):
    return User(id=_OWNER, username="u", email="u@example.com", permissions=permissions, is_active=True)


async def _authenticate(surface, db, *, touch=False, authorization=f"Bearer {_TOKEN}"):
    return await require_api_key(surface, touch=touch)(authorization=authorization, db=db)


# RFC 7235 makes the auth scheme case-insensitive, and clients do spell it "bearer".
@pytest.mark.parametrize("scheme", ["Bearer", "bearer"])
@pytest.mark.asyncio
async def test_a_valid_key_for_the_surface_returns_the_owner_and_the_key_document(monkeypatch, scheme):
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))

    user, key_doc = await _authenticate(API_KEY_SURFACE_MCP, db, authorization=f"{scheme} {_TOKEN}")

    assert user.id == _OWNER
    assert key_doc["_id"] == _KEY_ID


@pytest.mark.asyncio
async def test_a_missing_header_is_401():
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(API_KEY_SURFACE_MCP, db, authorization="")

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _MSG_MISSING_BEARER


@pytest.mark.asyncio
async def test_a_non_bearer_header_is_401():
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(API_KEY_SURFACE_MCP, db, authorization=_TOKEN)

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _MSG_MISSING_BEARER


@pytest.mark.asyncio
async def test_an_unresolvable_token_is_401_with_one_shared_message():
    # The repository filters revoked and expired keys inside the query, so unknown, revoked and
    # expired all arrive here as the same miss and must leave with the same answer.
    db, _ = _db_with_key(None)

    with pytest.raises(HTTPException) as exc:
        await _authenticate(API_KEY_SURFACE_MCP, db)

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _MSG_OPAQUE_KEY
    # A distinguishing signal outside the body would be just as much of an oracle.
    assert exc.value.headers is None


@pytest.mark.asyncio
async def test_an_inactive_owner_is_401(monkeypatch):
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))
    inactive = User(
        id=_OWNER,
        username="u",
        email="u@example.com",
        permissions=[Permissions.MCP_ACCESS],
        is_active=False,
    )
    _patch_user(monkeypatch, inactive)

    with pytest.raises(HTTPException) as exc:
        await _authenticate(API_KEY_SURFACE_MCP, db)

    assert exc.value.status_code == _UNAUTHORIZED


# The sibling case is the escalation this design guards against: a gate widened to accept either
# permission would hand every ad-hoc key owner the MCP tool surface, and no unrelated permission
# would show that.
@pytest.mark.parametrize("surface", _BOTH_SURFACES)
@pytest.mark.parametrize("held", ["unrelated", "sibling"])
@pytest.mark.asyncio
async def test_an_owner_without_the_surface_permission_is_403(monkeypatch, surface, held):
    permission = Permissions.PROJECT_READ if held == "unrelated" else _SIBLING_PERMISSION[surface]
    db, _ = _db_with_key(_key_doc(_BOTH_SURFACES))
    _patch_user(monkeypatch, _active_user([permission]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(surface, db)

    assert exc.value.status_code == _FORBIDDEN
    assert exc.value.detail == f"Token owner no longer has {surface} access"


# A malformed surfaces field is reachable: anything writing the collection outside
# ApiKeyRepository.create — a migration, an operator — writes one, and it must name no surface.
@pytest.mark.parametrize("surface", _BOTH_SURFACES)
@pytest.mark.parametrize("stored", _NAMES_NO_SURFACE.values(), ids=list(_NAMES_NO_SURFACE))
@pytest.mark.asyncio
async def test_a_key_that_does_not_name_the_surface_is_403(monkeypatch, surface, stored):
    if stored is _SIBLING:
        stored = [API_KEY_SURFACE_ADHOC if surface == API_KEY_SURFACE_MCP else API_KEY_SURFACE_MCP]
    db, _ = _db_with_key(_key_doc(stored))
    # The owner holds the permission, so only the key's surface list can turn this caller away.
    _patch_user(monkeypatch, _active_user([_SURFACE_PERMISSION[surface]]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(surface, db)

    assert exc.value.status_code == _FORBIDDEN
    assert exc.value.detail == f"API key does not grant the {surface} surface"
    assert exc.value.detail != f"Token owner no longer has {surface} access"


@pytest.mark.parametrize("surface", _BOTH_SURFACES)
@pytest.mark.asyncio
async def test_the_surface_is_answered_before_the_permission(monkeypatch, surface):
    # Checking the permission first tells the holder of a key that never named the surface whether
    # its owner still holds that surface's permission, which is not theirs to learn.
    other = API_KEY_SURFACE_ADHOC if surface == API_KEY_SURFACE_MCP else API_KEY_SURFACE_MCP
    db, _ = _db_with_key(_key_doc([other]))
    _patch_user(monkeypatch, _active_user([Permissions.PROJECT_READ]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(surface, db)

    assert exc.value.detail == f"API key does not grant the {surface} surface"


# Same provenance as a malformed surfaces field: a write that did not come from the repository.
@pytest.mark.asyncio
async def test_a_key_document_naming_no_owner_is_401(monkeypatch):
    doc = _key_doc([API_KEY_SURFACE_MCP])
    del doc["user_id"]
    db, _ = _db_with_key(doc)
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))

    with pytest.raises(HTTPException) as exc:
        await _authenticate(API_KEY_SURFACE_MCP, db)

    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_a_key_document_carrying_no_id_still_authenticates(monkeypatch):
    doc = _key_doc([API_KEY_SURFACE_MCP])
    del doc["_id"]
    db, _ = _db_with_key(doc)
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))
    touch = _patch_touch_last_used(monkeypatch)

    user, _ = await _authenticate(API_KEY_SURFACE_MCP, db, touch=True)

    assert user.id == _OWNER
    # The stamp has nothing to address and matches no document; the credential is still good.
    touch.assert_awaited_once_with("")


@pytest.mark.parametrize("surface", _BOTH_SURFACES)
@pytest.mark.asyncio
async def test_a_key_naming_both_surfaces_satisfies_either_request(monkeypatch, surface):
    db, _ = _db_with_key(_key_doc(_BOTH_SURFACES))
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC]))

    user, key_doc = await _authenticate(surface, db)

    assert user.id == _OWNER
    assert key_doc["_id"] == _KEY_ID


@pytest.mark.asyncio
async def test_the_default_writes_nothing(monkeypatch):
    db, keys = _db_with_key(_key_doc([API_KEY_SURFACE_ADHOC]))
    _patch_user(monkeypatch, _active_user([Permissions.ANALYZE_ADHOC]))

    # Built without touch=, because omitting it is the call shape a surface that persists nothing
    # uses, and the promise belongs to the default rather than to a caller who passes False.
    await require_api_key(API_KEY_SURFACE_ADHOC)(authorization=f"Bearer {_TOKEN}", db=db)

    for method_name in _WRITE_METHODS:
        method = getattr(keys, method_name)
        # A name this collection does not stub would fail the call below with unittest.mock's
        # "not a valid assertion" AttributeError; asserting first names the offending method.
        assert isinstance(method, AsyncMock), method_name
        method.assert_not_awaited()


@pytest.mark.asyncio
async def test_touch_stamps_last_used_once_with_the_key_id(monkeypatch):
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))
    touch = _patch_touch_last_used(monkeypatch)

    await _authenticate(API_KEY_SURFACE_MCP, db, touch=True)

    touch.assert_awaited_once_with(_KEY_ID)


@pytest.mark.asyncio
async def test_authentication_reaches_no_collection_beyond_keys_and_users(monkeypatch):
    db, _ = _db_with_key(_key_doc([API_KEY_SURFACE_MCP]))
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))

    await _authenticate(API_KEY_SURFACE_MCP, db, touch=True)

    by_item = {call.args[0] for call in db.__getitem__.call_args_list}
    assert by_item == _REACHABLE_COLLECTIONS
    # db.some_collection.insert_one(...) never touches __getitem__, but does land in mock_calls.
    by_attribute = {name.split(".")[0] for name, _, _ in db.mock_calls} - {"__getitem__"}
    assert by_attribute <= _REACHABLE_COLLECTIONS


@pytest.mark.parametrize(
    ("surfaces", "permissions"),
    [
        (_BOTH_SURFACES, [Permissions.PROJECT_READ]),
        ([API_KEY_SURFACE_ADHOC], [Permissions.MCP_ACCESS]),
    ],
    ids=["owner-lost-permission", "key-lacks-surface"],
)
@pytest.mark.asyncio
async def test_a_rejected_caller_is_never_stamped(monkeypatch, surfaces, permissions):
    db, keys = _db_with_key(_key_doc(surfaces))
    _patch_user(monkeypatch, _active_user(permissions))
    touch = _patch_touch_last_used(monkeypatch)

    with pytest.raises(HTTPException):
        await _authenticate(API_KEY_SURFACE_MCP, db, touch=True)

    touch.assert_not_awaited()
    keys.update_one.assert_not_awaited()

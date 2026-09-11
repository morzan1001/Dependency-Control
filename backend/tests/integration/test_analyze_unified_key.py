"""POST /api/v1/analyze: a unified key gets in, and its budget is the owner's rather than the key's."""

import fakeredis
import fakeredis.aioredis
import pytest
import redis.asyncio as redis

from app.core.constants import API_KEY_SURFACE_ADHOC
from app.core.permissions import Permissions
from app.repositories.api_keys import ApiKeyRepository

_ANALYZE = "/api/v1/analyze"
_OWNER = "analyze-user"
_OTHER_OWNER = "another-analyze-user"
_EXPIRY_DAYS = 30
_LICENSE_COMPLIANCE = "license_compliance"
_ONE_REQUEST_A_MINUTE = 1

_OK = 200
_UNAUTHORIZED = 401
_TOO_MANY_REQUESTS = 429

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
        }
    ],
}
_BODY = {"sboms": [_SBOM], "analyzers": [_LICENSE_COMPLIANCE], "apply_global_waivers": False}


@pytest.fixture(autouse=True)
def _shared_window(monkeypatch):
    """The real limiter over one in-process Redis: every request of a test spends the same window."""
    server = fakeredis.FakeServer()
    monkeypatch.setattr(redis, "from_url", lambda *_a, **_k: fakeredis.aioredis.FakeRedis(server=server))


async def _issue_key(db, name="ci", owner=_OWNER, permissions=(Permissions.ANALYZE_ADHOC,)):
    _doc, plaintext = await ApiKeyRepository(db).create(owner, name, [API_KEY_SURFACE_ADHOC], _EXPIRY_DAYS)
    await db.users.update_one(
        {"_id": owner},
        {
            "$set": {
                "username": owner,
                "email": f"{owner}@example.com",
                "permissions": list(permissions),
                "is_active": True,
                "hashed_password": "x",
            }
        },
        upsert=True,
    )
    return plaintext


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_unified_key_produces_a_normal_analysis_result(client, db):
    token = await _issue_key(db)

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    body = resp.json()
    assert body["analyzers"]["ran"], "the request must actually be analysed, or this proves nothing"
    assert body["findings"]


@pytest.mark.asyncio
async def test_the_budget_belongs_to_the_owner_and_to_no_one_else(client, db, monkeypatch):
    """Minting is uncapped, so a budget keyed on the key would be one budget per key. The second
    request comes from a different key of the same owner, and the first has spent the minute; the
    third comes from another owner, whose own minute nobody has touched — a budget collapsed to a
    constant would refuse that one too."""
    monkeypatch.setattr("app.api.v1.endpoints.analyze.ADHOC_RATE_LIMIT_PER_MINUTE", _ONE_REQUEST_A_MINUTE)
    first = await _issue_key(db)
    second = await _issue_key(db, name="ci-2")
    other_owner = await _issue_key(db, name="ci-3", owner=_OTHER_OWNER)

    accepted = await client.post(_ANALYZE, json=_BODY, headers=_bearer(first))
    refused = await client.post(_ANALYZE, json=_BODY, headers=_bearer(second))
    unaffected = await client.post(_ANALYZE, json=_BODY, headers=_bearer(other_owner))

    assert accepted.status_code == _OK, accepted.text
    assert refused.status_code == _TOO_MANY_REQUESTS, refused.text
    assert unaffected.status_code == _OK, unaffected.text


@pytest.mark.asyncio
async def test_a_request_without_an_authorization_header_is_401_with_a_challenge(client, db):
    await _issue_key(db)

    resp = await client.post(_ANALYZE, json=_BODY)

    assert resp.status_code == _UNAUTHORIZED, resp.text
    # Without the challenge a client has nothing to tell it what kind of credential to send.
    assert resp.headers["WWW-Authenticate"] == f'Bearer realm="{API_KEY_SURFACE_ADHOC}"'

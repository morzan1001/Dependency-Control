"""POST /api/v1/analyze: a unified key gets in."""

import pytest

from app.core.constants import API_KEY_SURFACE_ADHOC
from app.core.permissions import Permissions
from app.repositories.api_keys import ApiKeyRepository

_ANALYZE = "/api/v1/analyze"
_OWNER = "analyze-user"
_EXPIRY_DAYS = 30
_LICENSE_COMPLIANCE = "license_compliance"

_ACCEPTED = 202
_OK = 200
_UNAUTHORIZED = 401

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


async def _issue_key(db):
    _doc, plaintext = await ApiKeyRepository(db).create(_OWNER, "ci", [API_KEY_SURFACE_ADHOC], _EXPIRY_DAYS)
    await db.users.insert_one(
        {
            "_id": _OWNER,
            "username": _OWNER,
            "email": f"{_OWNER}@example.com",
            "permissions": [Permissions.ANALYZE_ADHOC],
            "is_active": True,
            "hashed_password": "x",
        }
    )
    return plaintext


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_unified_key_produces_a_normal_analysis_result(client, db, running_worker):
    token = await _issue_key(db)

    posted = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))
    assert posted.status_code == _ACCEPTED, posted.text
    await running_worker.queue.join()
    resp = await client.get(f"{_ANALYZE}/{posted.json()['job_id']}", headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    body = resp.json()
    assert body["analyzers"]["ran"], "the request must actually be analysed, or this proves nothing"
    assert body["findings"]


@pytest.mark.asyncio
async def test_a_request_without_an_authorization_header_is_401_with_a_challenge(client, db):
    await _issue_key(db)

    resp = await client.post(_ANALYZE, json=_BODY)

    assert resp.status_code == _UNAUTHORIZED, resp.text
    # Without the challenge a client has nothing to tell it what kind of credential to send.
    assert resp.headers["WWW-Authenticate"] == f'Bearer realm="{API_KEY_SURFACE_ADHOC}"'

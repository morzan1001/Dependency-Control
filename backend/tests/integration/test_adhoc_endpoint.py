"""HTTP behaviour of POST /api/v1/analyze."""

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.constants import API_KEY_SURFACE_ADHOC
from app.core.permissions import Permissions
from app.repositories.api_keys import ApiKeyRepository
from app.schemas.adhoc import AdhocAnalyzeResponse
from app.services.analysis import adhoc

_ANALYZE = "/api/v1/analyze"
_ENVELOPE = {
    "findings",
    "stats",
    "dependencies",
    "epss_kev_summary",
    "reachability_summary",
    "recommendations",
    "analyzers",
    "waivers_applied",
    "waived_count",
    "truncated",
}
_ENRICHMENT = "epss_kev"
_LICENSE_COMPLIANCE = "license_compliance"
_SECRET_MARKER = "swordfish"
# Long enough that a second request landing inside it would overlap observably.
_OVERLAP_WINDOW = 0.05
_CONCURRENT_REQUESTS = 2
_TIGHT_DEADLINE = 0.01
_CHUNK_BYTES = 512
_CHUNKS = 4
_SMALL_BODY_LIMIT = 1024

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

_TWO_COMPONENT_SBOM = {
    **_SBOM,
    "components": [
        *_SBOM["components"],
        {
            "type": "library",
            "bom-ref": "pkg:npm/express@4.18.2",
            "name": "express",
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
        },
    ],
}


async def _issue_key(db, permissions=(Permissions.ANALYZE_ADHOC,)):
    doc, plaintext = await ApiKeyRepository(db).create("adhoc-user", "ci", [API_KEY_SURFACE_ADHOC], 30)
    await db.users.insert_one(
        {
            "_id": "adhoc-user",
            "username": "adhoc-user",
            "email": "adhoc@example.com",
            "permissions": list(permissions),
            "is_active": True,
            "hashed_password": "x",
        }
    )
    return doc, plaintext


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _rate_limit_allows(monkeypatch):
    """The window has its own file and its own Redis; here it must not depend on a listening port."""

    async def _allow(_token_prefix):
        return None

    monkeypatch.setattr("app.api.v1.endpoints.analyze._enforce_rate_limit", _allow)


@pytest.mark.asyncio
async def test_analyze_returns_the_full_envelope(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        json={"sboms": [_SBOM], "analyzers": [_LICENSE_COMPLIANCE], "apply_global_waivers": False},
        headers=_bearer(token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == _ENVELOPE
    assert body["analyzers"]["ran"]
    assert body["waivers_applied"] == "none"


@pytest.mark.asyncio
async def test_the_response_names_the_stages_that_left_the_process(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        json={"sboms": [_SBOM], "analyzers": [_LICENSE_COMPLIANCE], "apply_global_waivers": False},
        headers=_bearer(token),
    )

    assert resp.status_code == 200, resp.text
    assert set(resp.json()["analyzers"]["notes"]) == {_ENRICHMENT}


@pytest.mark.asyncio
async def test_html_format_returns_a_document(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        json={
            "sboms": [_SBOM],
            "analyzers": [_LICENSE_COMPLIANCE],
            "apply_global_waivers": False,
            "format": "html",
        },
        headers=_bearer(token),
    )

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.text.startswith("<!DOCTYPE html>")
    assert "requests" in resp.text


@pytest.mark.asyncio
async def test_the_default_format_is_still_json(client, db):
    """The two branches share one route; an html default would break every existing caller."""
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        json={"sboms": [_SBOM], "analyzers": [_LICENSE_COMPLIANCE], "apply_global_waivers": False},
        headers=_bearer(token),
    )

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/json")


@pytest.mark.asyncio
async def test_unauthenticated_request_is_rejected(db):
    from app.db.mongodb import get_database
    from app.main import app

    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    async def _fake_get_database():
        return db

    app.dependency_overrides[get_database] = _fake_get_database
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(_ANALYZE, json={"sboms": [_SBOM]})
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)

    assert resp.status_code in (401, 403), resp.text


@pytest.mark.asyncio
async def test_revoked_key_is_rejected(client, db):
    doc, token = await _issue_key(db)
    await ApiKeyRepository(db).revoke(doc["_id"], "adhoc-user")

    resp = await client.post(_ANALYZE, json={"sboms": [_SBOM]}, headers=_bearer(token))

    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_a_key_without_the_permission_is_rejected(client, db):
    _, token = await _issue_key(db, permissions=())

    resp = await client.post(_ANALYZE, json={"sboms": [_SBOM]}, headers=_bearer(token))

    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_oversized_streamed_body_is_413(client, db, monkeypatch):
    """Chunked upload: no Content-Length, so only the streaming guard can stop it."""
    _, token = await _issue_key(db)
    monkeypatch.setattr("app.api.v1.endpoints.analyze.MAX_ADHOC_BODY_BYTES", _SMALL_BODY_LIMIT)

    async def _chunks():
        yield b'{"sboms": [{"bomFormat": "CycloneDX", "pad": "'
        for _ in range(_CHUNKS):
            yield b"x" * _CHUNK_BYTES
        yield b'"}]}'

    resp = await client.post(
        _ANALYZE,
        content=_chunks(),
        headers={**_bearer(token), "Content-Type": "application/json"},
    )

    assert resp.status_code == 413, resp.text


@pytest.mark.asyncio
async def test_an_input_shape_the_pipeline_cannot_afford_is_413(client, db, monkeypatch):
    """Small on the wire, expensive to parse: the body ceiling cannot see this one."""
    _, token = await _issue_key(db)
    monkeypatch.setattr(adhoc, "ADHOC_MAX_SBOM_COMPONENTS", 1)

    resp = await client.post(
        _ANALYZE,
        json={"sboms": [_TWO_COMPONENT_SBOM], "analyzers": [], "apply_global_waivers": False},
        headers=_bearer(token),
    )

    assert resp.status_code == 413, resp.text
    assert "2 components" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_malformed_body_is_422_without_echoing_the_payload(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(
        _ANALYZE,
        content=b'{"sboms": "not-a-list", "secret_marker": "' + _SECRET_MARKER.encode() + b'"}',
        headers={**_bearer(token), "Content-Type": "application/json"},
    )

    assert resp.status_code == 422, resp.text
    assert _SECRET_MARKER not in resp.text


@pytest.mark.asyncio
async def test_only_one_analysis_runs_at_a_time(client, db, monkeypatch):
    """The two in-process analysis workers share this pod; a second caller waits for the slot."""
    _, token = await _issue_key(db)
    live = 0
    peak = 0

    async def _slow_analysis(_payload, _db):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(_OVERLAP_WINDOW)
        live -= 1
        return AdhocAnalyzeResponse()

    monkeypatch.setattr("app.api.v1.endpoints.analyze.run_adhoc_analysis", _slow_analysis)

    responses = await asyncio.gather(
        *(
            client.post(_ANALYZE, json={"sboms": [_SBOM], "analyzers": []}, headers=_bearer(token))
            for _ in range(_CONCURRENT_REQUESTS)
        )
    )

    assert [resp.status_code for resp in responses] == [200] * _CONCURRENT_REQUESTS
    assert peak == 1


@pytest.mark.asyncio
async def test_an_analysis_past_the_deadline_is_504(client, db, monkeypatch):
    """A backstop for the awaiting stages: the synchronous ones are bounded by the input ceiling."""
    _, token = await _issue_key(db)
    monkeypatch.setattr("app.api.v1.endpoints.analyze.ADHOC_DEADLINE_SECONDS", _TIGHT_DEADLINE)

    async def _never_finishes(_payload, _db):
        await asyncio.sleep(_OVERLAP_WINDOW * 100)
        return AdhocAnalyzeResponse()

    monkeypatch.setattr("app.api.v1.endpoints.analyze.run_adhoc_analysis", _never_finishes)

    resp = await client.post(_ANALYZE, json={"sboms": [_SBOM], "analyzers": []}, headers=_bearer(token))

    assert resp.status_code == 504, resp.text
    # The slot has to come back, or one slow request takes the pod down with it.
    assert not adhoc.ADHOC_SLOTS.locked()

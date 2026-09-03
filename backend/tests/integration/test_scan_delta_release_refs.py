"""from=release&to=head resolves the pair server-side; explicit scan ids keep working."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import (
    DEFAULT_RELEASE_ENVIRONMENT,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_PENDING,
)
from app.models.release import Release
from app.repositories.releases import ReleaseRepository

BASE = "/api/v1/analytics/scan-delta"

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_TEN_DAYS = timedelta(days=10)
_ONE_DAY = timedelta(days=1)

_PROJECT = "test-project-id"
_BRANCH = "main"
_HEAD_SCAN = "head-scan"
_RELEASED_SCAN = "released-scan"
_RESCAN = "rescan-of-released"
_CANARY_SCAN = "canary-scan"
_PENDING_SCAN = "pending-scan"

_CANARY = "canary"
_EMPTY_ENVIRONMENT = "nowhere"
_INVALID_ENVIRONMENT = "Prod.EU"

_RELEASE_REF = "release"
_HEAD_REF = "head"
_UNKNOWN_REF = "trunk"
_FINDINGS = "findings"


async def _seed_scan(db, scan_id: str, *, created_at: datetime, status: str = SCAN_STATUS_COMPLETED, **extra) -> None:
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "status": status,
        "created_at": created_at,
    }
    doc.update(extra)
    await db.scans.insert_one(doc)


async def _seed_release(db, scan_id: str, *, released_at: datetime, environment: str = DEFAULT_RELEASE_ENVIRONMENT):
    await ReleaseRepository(db).record(
        Release(project_id=_PROJECT, environment=environment, scan_id=scan_id, released_at=released_at)
    )
    # is_release denormalises "this scan has a release record" for the partial index; the mark
    # endpoint sets it, so a seeded release without it would be a state production cannot reach.
    await db.scans.update_one({"_id": scan_id}, {"$set": {"is_release": True}})


async def _seed(db) -> None:
    """A production release ten days back, plus a fresher branch tip."""
    await _seed_scan(db, _HEAD_SCAN, created_at=_NOW)
    await _seed_scan(db, _RELEASED_SCAN, created_at=_NOW - _TEN_DAYS)
    await _seed_release(db, _RELEASED_SCAN, released_at=_NOW - _TEN_DAYS)


async def _delta(client, headers, **params):
    return await client.get(BASE, params={"project_id": _PROJECT, "category": _FINDINGS, **params}, headers=headers)


@pytest.mark.asyncio
async def test_release_to_head_resolves_both_sides(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, **{"from": _RELEASE_REF, "to": _HEAD_REF})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["from_scan_id"] == _RELEASED_SCAN
    assert body["to_scan_id"] == _HEAD_SCAN


@pytest.mark.asyncio
async def test_a_named_environment_is_honoured(client, db, member_auth_headers):
    await _seed(db)
    await _seed_scan(db, _CANARY_SCAN, created_at=_NOW - _ONE_DAY)
    await _seed_release(db, _CANARY_SCAN, released_at=_NOW - _ONE_DAY, environment=_CANARY)

    resp = await _delta(client, member_auth_headers, environment=_CANARY, **{"from": _RELEASE_REF, "to": _HEAD_REF})

    assert resp.status_code == 200, resp.text
    assert resp.json()["from_scan_id"] == _CANARY_SCAN


@pytest.mark.asyncio
async def test_the_release_side_follows_the_rescan_chain(client, db, member_auth_headers):
    """A delta compares what we know now, so a released scan that was rescanned reports the rescan."""
    await _seed(db)
    await db.scans.update_one({"_id": _RELEASED_SCAN}, {"$set": {"latest_rescan_id": _RESCAN}})
    await _seed_scan(db, _RESCAN, created_at=_NOW - _ONE_DAY, is_rescan=True, original_scan_id=_RELEASED_SCAN)

    resp = await _delta(client, member_auth_headers, **{"from": _RELEASE_REF, "to": _HEAD_REF})

    assert resp.status_code == 200, resp.text
    assert resp.json()["from_scan_id"] == _RESCAN


@pytest.mark.asyncio
async def test_no_release_in_that_environment_is_a_404(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(
        client, member_auth_headers, environment=_EMPTY_ENVIRONMENT, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 404, resp.text
    assert _EMPTY_ENVIRONMENT in resp.json()["detail"]


@pytest.mark.asyncio
async def test_a_head_with_no_usable_scan_is_a_404(client, db, member_auth_headers):
    await _seed_scan(db, _PENDING_SCAN, created_at=_NOW, status=SCAN_STATUS_PENDING)

    resp = await _delta(client, member_auth_headers, from_scan_id=_PENDING_SCAN, to=_HEAD_REF)

    assert resp.status_code == 404, resp.text
    assert _HEAD_REF in resp.json()["detail"]


@pytest.mark.asyncio
async def test_explicit_scan_ids_still_work(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, from_scan_id=_RELEASED_SCAN, to_scan_id=_HEAD_SCAN)

    assert resp.status_code == 200, resp.text
    assert resp.json()["from_scan_id"] == _RELEASED_SCAN


@pytest.mark.asyncio
async def test_one_side_may_be_explicit_while_the_other_is_a_reference(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, from_scan_id=_RELEASED_SCAN, to=_HEAD_REF)

    assert resp.status_code == 200, resp.text
    assert resp.json()["to_scan_id"] == _HEAD_SCAN


@pytest.mark.asyncio
async def test_a_request_with_neither_pair_is_a_400(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers)

    assert resp.status_code == 400, resp.text
    assert "from_scan_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_a_scan_id_and_a_reference_for_one_side_is_a_400(client, db, member_auth_headers):
    """Naming both would make one of them silently ineffective."""
    await _seed(db)

    resp = await _delta(
        client, member_auth_headers, from_scan_id=_RELEASED_SCAN, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 400, resp.text
    assert "from_scan_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_unknown_reference_is_a_400(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, **{"from": _UNKNOWN_REF, "to": _HEAD_REF})

    assert resp.status_code == 400, resp.text
    assert _UNKNOWN_REF in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_invalid_environment_slug_is_rejected(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(
        client, member_auth_headers, environment=_INVALID_ENVIRONMENT, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 422, resp.text

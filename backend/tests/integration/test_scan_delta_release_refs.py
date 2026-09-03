"""from=release&to=head resolves the pair server-side; explicit scan ids keep working."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import (
    DEFAULT_RELEASE_ENVIRONMENT,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_PENDING,
)
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.models.release import Release
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.releases import ReleaseRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

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
_ONLY_SCAN = "only-scan"
_RETIRED_SCAN = "retention-deleted-scan"

_CANARY = "canary"
_EMPTY_ENVIRONMENT = "nowhere"
_INVALID_ENVIRONMENT = "Prod.EU"
_ENVIRONMENT_PARAM = "release_environment"
_UNRESOLVED_RELEASE_DETAIL = "resolves to no analysed scan"

_RELEASE_REF = "release"
_HEAD_REF = "head"
_UNKNOWN_REF = "trunk"
_FINDINGS = "findings"
_COMPONENTS = "components"
_CRYPTO = "crypto"

_NOTHING = 0
_ONE_SEEDED = 1
_NO_ITEMS: list[dict] = []

_SEEDED_FINDING = "seeded-finding"
_SEEDED_DEPENDENCY = "seeded-dependency"
_SEEDED_CVE = "CVE-2026-0001"
_SEEDED_COMPONENT = "left-pad"
_SEEDED_VERSION = "1.0.0"
_SEEDED_PURL = "pkg:npm/left-pad@1.0.0"
_SEEDED_LICENSE = "MIT"
_SEEDED_PACKAGE_TYPE = "npm"
_SEEDED_ALGORITHM = "MD5"
_SEEDED_BOM_REF = "seeded-crypto-asset"


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


async def _seed_one_scan_that_is_head_and_release(db) -> None:
    """The healthiest state: the only scan is both the branch tip and what production runs.
    Seeded with one row per category so an empty delta is provably "all unchanged", not "both sides empty"."""
    await _seed_scan(db, _ONLY_SCAN, created_at=_NOW)
    await _seed_release(db, _ONLY_SCAN, released_at=_NOW)
    await db.findings.insert_one(
        {
            "_id": _SEEDED_FINDING,
            "project_id": _PROJECT,
            "scan_id": _ONLY_SCAN,
            "finding_id": _SEEDED_FINDING,
            "type": FindingType.VULNERABILITY.value,
            "severity": Severity.CRITICAL.value,
            "component": _SEEDED_COMPONENT,
            "version": _SEEDED_VERSION,
            "description": _SEEDED_CVE,
            "details": {"vulnerabilities": [{"id": _SEEDED_CVE}]},
        }
    )
    await db.dependencies.insert_one(
        {
            "_id": _SEEDED_DEPENDENCY,
            "project_id": _PROJECT,
            "scan_id": _ONLY_SCAN,
            "name": _SEEDED_COMPONENT,
            "version": _SEEDED_VERSION,
            "purl": _SEEDED_PURL,
            "license": _SEEDED_LICENSE,
            "type": _SEEDED_PACKAGE_TYPE,
        }
    )
    await CryptoAssetRepository(db).bulk_upsert(
        _PROJECT,
        _ONLY_SCAN,
        [
            CryptoAsset(
                project_id=_PROJECT,
                scan_id=_ONLY_SCAN,
                bom_ref=_SEEDED_BOM_REF,
                name=_SEEDED_ALGORITHM,
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            )
        ],
    )


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
@pytest.mark.parametrize("category", [_FINDINGS, _COMPONENTS, _CRYPTO])
async def test_a_release_that_is_also_head_reports_an_empty_delta(client, db, member_auth_headers, category):
    """Nothing shipped since the last deploy is an answer, not a bad request."""
    await _seed_one_scan_that_is_head_and_release(db)

    resp = await _delta(client, member_auth_headers, category=category, **{"from": _RELEASE_REF, "to": _HEAD_REF})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["from_scan_id"] == _ONLY_SCAN
    assert body["to_scan_id"] == _ONLY_SCAN
    assert body["totals"]["added"] == _NOTHING
    assert body["totals"]["removed"] == _NOTHING
    assert body["totals"]["changed"] == _NOTHING
    assert body["totals"]["unchanged"] == _ONE_SEEDED
    assert body["items"] == _NO_ITEMS


@pytest.mark.asyncio
async def test_head_against_head_reports_an_empty_delta(client, db, member_auth_headers):
    await _seed_one_scan_that_is_head_and_release(db)

    resp = await _delta(client, member_auth_headers, **{"from": _HEAD_REF, "to": _HEAD_REF})

    assert resp.status_code == 200, resp.text
    assert resp.json()["totals"]["unchanged"] == _ONE_SEEDED


@pytest.mark.asyncio
async def test_a_named_environment_is_honoured(client, db, member_auth_headers):
    await _seed(db)
    await _seed_scan(db, _CANARY_SCAN, created_at=_NOW - _ONE_DAY)
    await _seed_release(db, _CANARY_SCAN, released_at=_NOW - _ONE_DAY, environment=_CANARY)

    resp = await _delta(
        client, member_auth_headers, release_environment=_CANARY, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

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
        client, member_auth_headers, release_environment=_EMPTY_ENVIRONMENT, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 404, resp.text
    assert _EMPTY_ENVIRONMENT in resp.json()["detail"]


@pytest.mark.asyncio
async def test_a_release_that_resolves_to_nothing_reads_apart_from_an_absent_release(client, db, member_auth_headers):
    """Retention or an unusable rescan chain is an operational condition an operator can act on."""
    await _seed(db)
    await _seed_release(db, _RETIRED_SCAN, released_at=_NOW, environment=_CANARY)

    resp = await _delta(
        client, member_auth_headers, release_environment=_CANARY, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 404, resp.text
    assert _UNRESOLVED_RELEASE_DETAIL in resp.json()["detail"]


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
async def test_a_reference_from_side_pairs_with_an_explicit_to_side(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, to_scan_id=_HEAD_SCAN, **{"from": _RELEASE_REF})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["from_scan_id"] == _RELEASED_SCAN
    assert body["to_scan_id"] == _HEAD_SCAN


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
async def test_a_scan_id_and_a_reference_for_the_to_side_is_a_400(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(client, member_auth_headers, from_scan_id=_RELEASED_SCAN, to_scan_id=_HEAD_SCAN, to=_HEAD_REF)

    assert resp.status_code == 400, resp.text
    assert "to_scan_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_unknown_reference_is_a_422(client, db, member_auth_headers):
    """The legal refs are in the schema, so a generated client sees them before it sends."""
    await _seed(db)

    resp = await _delta(client, member_auth_headers, **{"from": _UNKNOWN_REF, "to": _HEAD_REF})

    assert resp.status_code == 422, resp.text
    assert _UNKNOWN_REF in resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pair",
    [
        {"from_scan_id": _RELEASED_SCAN, "to_scan_id": _HEAD_SCAN},
        {"from": _HEAD_REF, "to": _HEAD_REF},
    ],
)
async def test_an_environment_without_a_release_side_is_a_400(client, db, member_auth_headers, pair):
    """A caller who names an environment believes it scopes the comparison; nothing here would read it."""
    await _seed(db)

    resp = await _delta(client, member_auth_headers, release_environment=_CANARY, **pair)

    assert resp.status_code == 400, resp.text
    assert _ENVIRONMENT_PARAM in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_invalid_environment_slug_is_rejected(client, db, member_auth_headers):
    await _seed(db)

    resp = await _delta(
        client, member_auth_headers, release_environment=_INVALID_ENVIRONMENT, **{"from": _RELEASE_REF, "to": _HEAD_REF}
    )

    assert resp.status_code == 422, resp.text

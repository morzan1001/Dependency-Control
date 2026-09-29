"""The Pipelines table filters on the release mark, the table and the detail page both read where a
scan runs, and a rescan repeats the source's analyzer selection without inheriting its release
identity."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from tests.helpers.auth import bearer_headers

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_AN_HOUR = timedelta(hours=1)
_A_DAY = timedelta(days=1)
_PROJECT = "test-project-id"

_RELEASE_SCAN = "rel"
_UNMARKED_SCAN = "unmarked"
_PLAIN_SCAN = "plain"
_STRAY_KEY_SCAN = "stray"
_DELETED_BRANCH_SCAN = "rel-on-deleted-branch"

_BRANCH = "main"
_DELETED_BRANCH = "release/1.0"
_PRODUCTION = "production"
_STAGING = "staging"
_STAGING_VERSION = "v1.3.0-rc1"
_PRODUCTION_RELEASE_ID = "rel-prod"
_STAGING_RELEASE_ID = "rel-staging"
_COMMIT_HASH = "a" * 40
_GRIDFS_ID = "g1"
_SCAN_STATUS = "completed"
_CBOM_SCAN_TYPE = "cbom"
_PIPELINE_ID = 99
_PIPELINE_IID = 7
_PIPELINE_USER = "ci-bot"
_FINDINGS_COUNT = 12

_MSG_NO_SBOMS = "Cannot re-scan: No SBOMs found in the source scan."

_EDITOR_USERNAME = "editoruser"
_EDITOR_ROLE = "editor"

# The module-level worker_manager owns an asyncio.Queue bound to the import-time loop.
_WORKER_MANAGER = "app.api.v1.endpoints.projects.worker_manager"


@pytest_asyncio.fixture
async def editor_headers(client, db):
    """trigger_rescan needs role=editor; member_auth_headers only grants viewer."""
    from app.core.permissions import Permissions
    from app.models.project import ProjectMember

    # _fake_get_current_user derives current_user.id from the JWT "sub", so membership
    # must key off the username.
    member = ProjectMember(user_id=_EDITOR_USERNAME, role=_EDITOR_ROLE)
    await db.projects.update_one(
        {"_id": _PROJECT},
        {"$set": {"members": [member.model_dump(by_alias=True)]}},
        upsert=True,
    )

    return bearer_headers(_EDITOR_USERNAME, [Permissions.PROJECT_READ])


async def _seed(db) -> None:
    await db.scans.insert_one(
        {
            "_id": _RELEASE_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "commit_hash": _COMMIT_HASH,
            "status": _SCAN_STATUS,
            "created_at": _NOW,
            "sbom_refs": [{"gridfs_id": _GRIDFS_ID}],
            "scan_type": _CBOM_SCAN_TYPE,
            "is_release": True,
            "last_rescanned_at": _NOW,
            "pipeline_id": _PIPELINE_ID,
            "pipeline_iid": _PIPELINE_IID,
            "pipeline_user": _PIPELINE_USER,
        }
    )
    await db.scans.insert_one(
        {
            "_id": _UNMARKED_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "status": _SCAN_STATUS,
            "created_at": _NOW - _AN_HOUR,
            "is_release": False,
        }
    )
    # Tri-state: a scan predating the mark carries no is_release field at all.
    await db.scans.insert_one(
        {
            "_id": _PLAIN_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "status": _SCAN_STATUS,
            "created_at": _NOW - _A_DAY,
        }
    )


async def _seed_releases(db) -> None:
    """The release scan runs in two environments at once, the older one without a recorded version."""
    await db.releases.insert_many(
        [
            {
                "_id": _PRODUCTION_RELEASE_ID,
                "project_id": _PROJECT,
                "environment": _PRODUCTION,
                "version": None,
                "scan_id": _RELEASE_SCAN,
                "released_at": _NOW - _AN_HOUR,
            },
            {
                "_id": _STAGING_RELEASE_ID,
                "project_id": _PROJECT,
                "environment": _STAGING,
                "version": _STAGING_VERSION,
                "scan_id": _RELEASE_SCAN,
                "released_at": _NOW,
            },
        ]
    )


async def _seed_stray_key_scan(db) -> None:
    await db.scans.insert_one(
        {
            "_id": _STRAY_KEY_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "status": _SCAN_STATUS,
            "created_at": _NOW,
            "releases": [{"environment": _STAGING, "version": _STAGING_VERSION, "released_at": _NOW}],
        }
    )


async def _rescan(client, headers, scan_id: str = _RELEASE_SCAN):
    with patch(_WORKER_MANAGER, new=AsyncMock()):
        return await client.post(f"/api/v1/projects/{_PROJECT}/scans/{scan_id}/rescan", headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"is_release": True}, [_RELEASE_SCAN]),
        ({"is_release": False}, [_UNMARKED_SCAN, _PLAIN_SCAN]),
        ({}, [_RELEASE_SCAN, _UNMARKED_SCAN, _PLAIN_SCAN]),
    ],
)
async def test_the_scan_list_filters_on_the_release_mark(client, db, member_auth_headers, params, expected):
    await _seed(db)

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", params=params, headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert [s["id"] for s in resp.json()] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"is_release": True}, [_DELETED_BRANCH_SCAN, _RELEASE_SCAN]),
        ({"is_release": True, "exclude_deleted_branches": True}, [_RELEASE_SCAN]),
    ],
)
async def test_the_release_filter_reaches_a_release_whose_branch_is_gone(
    client, db, member_auth_headers, params, expected
):
    """A branch deleted after its release is what the mark is for, so the Pipelines table drops the
    deleted-branch exclusion while the filter is on — keeping both would hide the release again."""
    await _seed(db)
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"deleted_branches": [_DELETED_BRANCH]}})
    await db.scans.insert_one(
        {
            "_id": _DELETED_BRANCH_SCAN,
            "project_id": _PROJECT,
            "branch": _DELETED_BRANCH,
            "status": _SCAN_STATUS,
            "created_at": _NOW + _AN_HOUR,
            "is_release": True,
        }
    )

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", params=params, headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert [s["id"] for s in resp.json()] == expected


@pytest.mark.asyncio
async def test_the_scan_list_exposes_the_release_mark(client, db, member_auth_headers):
    await _seed(db)

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = {s["id"]: s for s in resp.json()}
    assert body[_RELEASE_SCAN]["is_release"] is True
    assert body[_PLAIN_SCAN]["is_release"] is False


@pytest.mark.asyncio
async def test_the_scan_list_names_every_environment_a_scan_runs_in(client, db, member_auth_headers):
    """The badge needs the environment and the version, which the scan document does not hold."""
    await _seed(db)
    await _seed_releases(db)

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = {s["id"]: s for s in resp.json()}
    assert [(r["environment"], r["version"]) for r in body[_RELEASE_SCAN]["releases"]] == [
        (_STAGING, _STAGING_VERSION),
        (_PRODUCTION, None),
    ]
    assert body[_PLAIN_SCAN]["releases"] == []


@pytest.mark.asyncio
async def test_a_scan_document_holding_a_releases_key_still_lists(client, db, member_auth_headers):
    """The environments come from the releases collection, whatever key the document happens to carry."""
    await _seed_stray_key_scan(db)

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = {s["id"]: s for s in resp.json()}
    assert body[_STRAY_KEY_SCAN]["releases"] == []


@pytest.mark.asyncio
async def test_one_scan_names_every_environment_it_runs_in(client, db, member_auth_headers):
    """The detail page offers a per-environment withdrawal, which needs the scan's own release rows
    rather than the project's paged release list."""
    await _seed(db)
    await _seed_releases(db)

    resp = await client.get(f"/api/v1/projects/scans/{_RELEASE_SCAN}", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert [(r["environment"], r["version"]) for r in resp.json()["releases"]] == [
        (_STAGING, _STAGING_VERSION),
        (_PRODUCTION, None),
    ]


@pytest.mark.asyncio
async def test_one_unreleased_scan_names_no_environment(client, db, member_auth_headers):
    await _seed(db)
    await _seed_releases(db)

    resp = await client.get(f"/api/v1/projects/scans/{_PLAIN_SCAN}", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["releases"] == []


@pytest.mark.asyncio
async def test_a_scan_document_holding_a_releases_key_reports_none_of_it(client, db, member_auth_headers):
    await _seed_stray_key_scan(db)

    resp = await client.get(f"/api/v1/projects/scans/{_STRAY_KEY_SCAN}", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["releases"] == []


@pytest.mark.asyncio
async def test_a_manual_rescan_of_a_cbom_scan_stays_a_cbom_scan(client, db, editor_headers):
    """The engine gates the crypto analyzers on this field, so dropping it changes the analysis."""
    await _seed(db)

    resp = await _rescan(client, editor_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_rescan"] is True
    assert body["original_scan_id"] == _RELEASE_SCAN
    assert body["scan_type"] == _CBOM_SCAN_TYPE
    assert body["pipeline_iid"] == _PIPELINE_IID


@pytest.mark.asyncio
async def test_a_manual_rescan_carries_neither_the_release_identity_nor_the_clock(client, db, editor_headers):
    """A rescan of a release is a new analysis, not a new release."""
    await _seed(db)

    resp = await _rescan(client, editor_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_release"] is False
    assert body["last_rescanned_at"] is None
    assert body["pipeline_id"] is None
    assert body["pipeline_user"] is None


@pytest.mark.asyncio
async def test_a_manual_rescan_resets_the_rescan_clock_of_the_lineage(client, db, editor_headers):
    """Otherwise the scheduler queues another rescan of the same commit as soon as its old clock runs out."""
    await _seed(db)

    resp = await _rescan(client, editor_headers)

    assert resp.status_code == 200, resp.text
    source = await db.scans.find_one({"_id": _RELEASE_SCAN})
    assert source["last_rescanned_at"] > _NOW
    assert source["latest_run"]["scan_id"] == resp.json()["id"]


@pytest.mark.asyncio
async def test_a_second_rescan_while_the_first_is_under_way_is_refused(client, db, editor_headers):
    await _seed(db)
    first = await _rescan(client, editor_headers)

    second = await _rescan(client, editor_headers, scan_id=first.json()["id"])

    assert second.status_code == 409, second.text
    assert await db.scans.count_documents({"is_rescan": True}) == 1


@pytest.mark.asyncio
async def test_a_scan_still_being_analysed_is_not_rescanned(client, db, editor_headers):
    """Its scanner results may still be arriving, and a rescan would copy the incomplete set."""
    await _seed(db)
    await db.scans.update_one({"_id": _RELEASE_SCAN}, {"$set": {"status": "processing"}})

    resp = await _rescan(client, editor_headers)

    assert resp.status_code == 409, resp.text
    assert await db.scans.count_documents({"is_rescan": True}) == 0


@pytest.mark.asyncio
async def test_a_rescan_of_a_source_without_sboms_is_refused(client, db, editor_headers):
    """The endpoint re-analyses the source's SBOMs, so a source with none has nothing to re-analyse."""
    await _seed(db)

    resp = await _rescan(client, editor_headers, scan_id=_PLAIN_SCAN)

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"] == _MSG_NO_SBOMS

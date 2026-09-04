"""The Pipelines table filters on the release mark and reads where each scan runs, and a rescan
repeats the source's analyzer selection without inheriting its release identity."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from app.models.project import Scan

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_AN_HOUR = timedelta(hours=1)
_A_DAY = timedelta(days=1)
_PROJECT = "test-project-id"

_RELEASE_SCAN = "rel"
_UNMARKED_SCAN = "unmarked"
_PLAIN_SCAN = "plain"
_SATURATED_SCAN = "saturated"
_STRAY_KEY_SCAN = "stray"

_BRANCH = "main"
_PRODUCTION = "production"
_STAGING = "staging"
_STAGING_VERSION = "v1.3.0-rc1"
_PRODUCTION_RELEASE_ID = "rel-prod"
_STAGING_RELEASE_ID = "rel-staging"
_COMMIT_HASH = "a" * 40
_COMMIT_MESSAGE = "bump the parser"
_COMMIT_TAG = "v1.0.0"
_GRIDFS_ID = "g1"
_SCAN_STATUS = "completed"
_CBOM_SCAN_TYPE = "cbom"
_PIPELINE_ID = 99
_PIPELINE_IID = 7
_PIPELINE_USER = "ci-bot"
_PROJECT_URL = "https://example.invalid/group/proj"
_PIPELINE_URL = f"{_PROJECT_URL}/-/pipelines/{_PIPELINE_ID}"
_JOB_ID = 5
_JOB_STARTED_AT = "2026-09-01T00:00:00Z"
_PROJECT_NAME = "group/proj"
_PREVIOUS_RESCAN_ID = "prev-rescan"
_RETRY_COUNT = 3
_WORKER_ID = "worker-1"
_SCAN_ERROR = "analyzer crashed"
_FAILED_ANALYZER = "trivy"
_ENRICHMENT_FAILURE = "epss"
_FINDINGS_COUNT = 12
_FINDINGS_SUMMARY = [{"severity": "high"}]
_STATS = {"total": _FINDINGS_COUNT}
_LATEST_RUN = {"scan_id": _PREVIOUS_RESCAN_ID}
_RECEIVED_RESULTS = ["sbom"]

_MSG_NO_SBOMS = "Cannot re-scan: No SBOMs found in the source scan."

# The scheduled path pins the same set in tests/test_core/test_housekeeping_rescan.py; the two
# builders are separate code and drift apart silently.
_CARRIED_FROM_SOURCE = frozenset(
    {
        "project_id",
        "branch",
        "commit_hash",
        "pipeline_iid",
        "project_url",
        "pipeline_url",
        "job_id",
        "job_started_at",
        "project_name",
        "commit_message",
        "commit_tag",
        "sbom_refs",
        "scan_type",
    }
)

_EDITOR_USERNAME = "editoruser"
_EDITOR_ROLE = "editor"

# The module-level worker_manager owns an asyncio.Queue bound to the import-time loop.
_WORKER_MANAGER = "app.api.v1.endpoints.projects.worker_manager"


@pytest_asyncio.fixture
async def editor_headers(client, db):
    """trigger_rescan needs role=editor; member_auth_headers only grants viewer."""
    from jose import jwt

    from app.core.config import settings
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

    payload = {"sub": _EDITOR_USERNAME, "permissions": [Permissions.PROJECT_READ]}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


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


def _saturated_scan_doc() -> dict[str, Any]:
    """A source holding every Scan field at a value a freshly built rescan does not hold, so a field
    whose value survives into the rescan is exactly a field the endpoint copied."""
    return {
        "_id": _SATURATED_SCAN,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "commit_hash": _COMMIT_HASH,
        "commit_message": _COMMIT_MESSAGE,
        "commit_tag": _COMMIT_TAG,
        "status": _SCAN_STATUS,
        "created_at": _NOW - _A_DAY,
        "sbom_refs": [{"gridfs_id": _GRIDFS_ID}],
        "scan_type": _CBOM_SCAN_TYPE,
        "pipeline_id": _PIPELINE_ID,
        "pipeline_iid": _PIPELINE_IID,
        "pipeline_user": _PIPELINE_USER,
        "project_url": _PROJECT_URL,
        "pipeline_url": _PIPELINE_URL,
        "job_id": _JOB_ID,
        "job_started_at": _JOB_STARTED_AT,
        "project_name": _PROJECT_NAME,
        "retry_count": _RETRY_COUNT,
        "worker_id": _WORKER_ID,
        "analysis_started_at": _NOW - _A_DAY,
        "error": _SCAN_ERROR,
        "failed_analyzers": [_FAILED_ANALYZER],
        "enrichment_failures": [_ENRICHMENT_FAILURE],
        "findings_summary": _FINDINGS_SUMMARY,
        "findings_count": _FINDINGS_COUNT,
        "stats": _STATS,
        "completed_at": _NOW - _AN_HOUR,
        "reachability_pending": True,
        "reachability_pending_since": _NOW - _AN_HOUR,
        "pinned": True,
        "is_release": True,
        "is_rescan": False,
        "original_scan_id": None,
        "latest_rescan_id": _PREVIOUS_RESCAN_ID,
        "last_rescanned_at": _NOW - _AN_HOUR,
        "latest_run": _LATEST_RUN,
        "last_result_at": _NOW - _AN_HOUR,
        "received_results": _RECEIVED_RESULTS,
    }


def _carried_fields(source: dict[str, Any], rescan: Scan) -> set[str]:
    return {name for name in Scan.model_fields if getattr(rescan, name) == source.get(name)}


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

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/scans", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = {s["id"]: s for s in resp.json()}
    assert body[_STRAY_KEY_SCAN]["releases"] == []


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
async def test_a_manual_rescan_carries_exactly_the_pinned_fields_and_nothing_else(client, db, editor_headers):
    source = _saturated_scan_doc()
    await db.scans.insert_one(source)

    resp = await _rescan(client, editor_headers, scan_id=_SATURATED_SCAN)

    assert resp.status_code == 200, resp.text
    stored = await db.scans.find_one({"_id": resp.json()["id"]})
    assert _carried_fields(source, Scan(**stored)) == _CARRIED_FROM_SOURCE


@pytest.mark.asyncio
async def test_a_rescan_of_a_source_without_sboms_is_refused(client, db, editor_headers):
    """The endpoint re-analyses the source's SBOMs, so a source with none has nothing to re-analyse."""
    await _seed(db)

    resp = await _rescan(client, editor_headers, scan_id=_PLAIN_SCAN)

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"] == _MSG_NO_SBOMS

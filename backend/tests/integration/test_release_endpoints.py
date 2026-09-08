"""Mark, unmark and list releases: commit resolution, per-environment records, idempotency and hybrid auth.

The hybrid dependency calls get_project_for_ingest and get_current_user as plain functions, so the
client fixture's overrides for them do not apply here and every request carries a real credential.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from jose import jwt

from app.core.config import settings
from app.core.constants import (
    DEFAULT_RELEASE_ENVIRONMENT,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
)
from app.core.permissions import Permissions
from app.core.security import get_password_hash
from app.models.project import Project, ProjectMember
from app.models.release import Release
from app.models.user import User
from app.repositories.releases import ReleaseRepository
from app.services.releases import latest_release_scan

_NOW = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
_PROJECT = "test-project-id"
_OTHER_PROJECT = "other-project-id"
_API_SECRET = "dummy-secret"
# Argon2 is deliberately slow; one hash serves every test in this module.
_API_KEY_HASH = get_password_hash(_API_SECRET)

_COMMIT = "c" * 40
_OTHER_COMMIT = "d" * 40
_MISSING_COMMIT = "e" * 40
_STAGING = "staging"
_CANARY = "canary"
_VERSION = "v2.1.0"
_OTHER_VERSION = "v3.0.0"
_BLANK_TAG = ""
_BRANCH = "main"
_INVALID_ENVIRONMENT = "Prod.EU"
# Two marks of one instant; the row inserted first is the one insertion order alone would list first.
_TIED_LOW_ROW_ID = "row-a"
_TIED_HIGH_ROW_ID = "row-z"

_PAST = _NOW - timedelta(days=1)
# BSON has no offsets, so an aware datetime reads back as naive UTC.
_PAST_NAIVE = _PAST.replace(tzinfo=None)

_NO_RECORDS = 0
_ONE_RECORD = 1
_TWO_RECORDS = 2
_THREE_RECORDS = 3
_FIRST_PAGE = 1
_SECOND_PAGE = 2
_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100


@pytest_asyncio.fixture(autouse=True)
async def _ci_key(client, db):
    """The client fixture's get_project_for_ingest override does not reach this dependency, so the
    seeded project needs a hash the real API-key check can verify."""
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"api_key_hash": _API_KEY_HASH}}, upsert=True)


@pytest.fixture
def other_project_api_key_headers():
    return {"X-API-Key": f"{_OTHER_PROJECT}.{_API_SECRET}"}


@pytest_asyncio.fixture
async def other_project(db):
    doc = Project(id=_OTHER_PROJECT, name="other-project").model_dump(by_alias=True)
    doc["api_key_hash"] = _API_KEY_HASH
    await db.projects.update_one({"_id": _OTHER_PROJECT}, {"$setOnInsert": doc}, upsert=True)


async def _role_headers(db, role: str) -> dict[str, str]:
    """A real user document plus project membership, because the hybrid dependency runs the real
    get_current_user rather than the client fixture's stub."""
    username = f"release-{role}"
    user = User(
        id=username,
        username=username,
        email=f"{username}@example.com",
        permissions=[Permissions.PROJECT_READ],
        is_active=True,
    )
    await db.users.update_one({"_id": username}, {"$setOnInsert": user.model_dump(by_alias=True)}, upsert=True)
    member = ProjectMember(user_id=username, role=role)
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"members": [member.model_dump(by_alias=True)]}})
    token = jwt.encode(
        {"sub": username, "permissions": user.permissions}, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def editor_auth_headers(db):
    return await _role_headers(db, PROJECT_ROLE_EDITOR)


@pytest_asyncio.fixture
async def viewer_auth_headers(db):
    return await _role_headers(db, PROJECT_ROLE_VIEWER)


async def _seed_scan(db, scan_id, *, commit=_COMMIT, created_delta=0, status=SCAN_STATUS_COMPLETED, **extra):
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "commit_hash": commit,
        "status": status,
        "created_at": _NOW + timedelta(hours=created_delta),
    }
    doc.update(extra)
    await db.scans.insert_one(doc)


async def _mark(client, headers, **payload):
    return await client.post(f"/api/v1/projects/{_PROJECT}/releases", json=payload, headers=headers)


async def _unmark(client, headers, scan_id, environment=None):
    url = f"/api/v1/projects/{_PROJECT}/scans/{scan_id}/release"
    params = {"environment": environment} if environment else None
    return await client.delete(url, headers=headers, params=params)


@pytest.mark.asyncio
async def test_mark_resolves_the_commit_to_its_newest_build_scan(client, db, api_key_headers):
    await _seed_scan(db, "older", created_delta=-2, commit_tag=_VERSION)
    await _seed_scan(db, "newest", created_delta=0, commit_tag=_VERSION)

    resp = await _mark(client, api_key_headers, commit_hash=_COMMIT)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_id"] == "newest"
    assert body["environment"] == DEFAULT_RELEASE_ENVIRONMENT
    assert body["version"] == _VERSION
    assert body["commit_hash"] == _COMMIT
    assert body["branch"] == _BRANCH
    assert body["scan_status"] == SCAN_STATUS_COMPLETED
    assert body["analysis_scan_id"] == "newest"

    scan = await db.scans.find_one({"_id": "newest"})
    assert scan["is_release"] is True
    assert await latest_release_scan(db, _PROJECT, DEFAULT_RELEASE_ENVIRONMENT) == "newest"


@pytest.mark.asyncio
async def test_mark_of_a_branch_build_records_no_version_rather_than_a_blank_one(client, db, api_key_headers):
    """Every scanner sends an unset tag as "", so a branch build's mark must name no version at all."""
    await _seed_scan(db, "branch-build", commit_tag=_BLANK_TAG)

    resp = await _mark(client, api_key_headers, commit_hash=_COMMIT)

    assert resp.status_code == 201, resp.text
    assert resp.json()["version"] is None
    row = await db.releases.find_one({"scan_id": "branch-build"})
    assert row.get("version") is None


@pytest.mark.asyncio
async def test_mark_of_an_unknown_commit_is_404_naming_it(client, db, api_key_headers):
    resp = await _mark(client, api_key_headers, commit_hash=_MISSING_COMMIT)

    assert resp.status_code == 404
    assert _MISSING_COMMIT in resp.json()["detail"]


@pytest.mark.asyncio
async def test_mark_accepts_a_scan_that_has_not_finished_analysing(client, db, api_key_headers):
    """A deploy can precede the analysis; the mark states where the artefact runs, not what we know."""
    await _seed_scan(db, "analysed", created_delta=-1)
    await _seed_scan(db, "deploying", status=SCAN_STATUS_PENDING)

    resp = await _mark(client, api_key_headers, commit_hash=_COMMIT)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_id"] == "deploying"
    assert body["scan_status"] == SCAN_STATUS_PENDING
    assert body["analysis_scan_id"] is None
    # The resolver still refuses to report a number for it, which is the point of the split.
    assert await latest_release_scan(db, _PROJECT, DEFAULT_RELEASE_ENVIRONMENT) is None


@pytest.mark.asyncio
async def test_re_marking_an_already_rescanned_commit_keeps_one_record(client, db, api_key_headers):
    """A re-scan copies the commit with a fresh created_at, so without excluding re-scans a CD retry
    would resolve to a different scan and open a second record for the same deployment."""
    await _seed_scan(db, "build-1")
    assert (await _mark(client, api_key_headers, commit_hash=_COMMIT)).status_code == 201

    await _seed_scan(db, "rescan-1", created_delta=1, is_rescan=True, original_scan_id="build-1")
    await db.scans.update_one({"_id": "build-1"}, {"$set": {"latest_rescan_id": "rescan-1"}})

    redeploy = await _mark(client, api_key_headers, commit_hash=_COMMIT)

    assert redeploy.status_code == 201, redeploy.text
    assert redeploy.json()["scan_id"] == "build-1"
    records = await db.releases.find({"project_id": _PROJECT}).to_list(None)
    assert len(records) == _ONE_RECORD
    assert records[0]["scan_id"] == "build-1"
    rescan = await db.scans.find_one({"_id": "rescan-1"})
    assert rescan.get("is_release", False) is False
    # Naming the build scan keeps the chain walkable: latest_rescan_id lives on build-1, not rescan-1.
    assert redeploy.json()["analysis_scan_id"] == "rescan-1"


@pytest.mark.asyncio
async def test_marking_the_same_scan_twice_refreshes_one_record(client, db, api_key_headers):
    await _seed_scan(db, "rel")

    first = await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_VERSION)
    assert first.status_code == 201, first.text
    first_released_at = (await db.releases.find_one({"scan_id": "rel"}))["released_at"]

    second = await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_VERSION)
    assert second.status_code == 201, second.text

    records = await db.releases.find({"scan_id": "rel"}).to_list(None)
    assert len(records) == _ONE_RECORD
    assert records[0]["released_at"] > first_released_at
    assert records[0]["version"] == _VERSION


@pytest.mark.asyncio
async def test_a_record_withdrawn_before_the_read_back_is_a_conflict(client, db, api_key_headers):
    await _seed_scan(db, "rel")

    with patch.object(ReleaseRepository, "record", new=AsyncMock(return_value=None)):
        resp = await _mark(client, api_key_headers, commit_hash=_COMMIT)

    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_marking_a_second_environment_leaves_the_first_intact(client, db, api_key_headers):
    await _seed_scan(db, "rel")

    assert (await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_VERSION)).status_code == 201
    second = await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING, version=_OTHER_VERSION)
    assert second.status_code == 201, second.text

    records = await db.releases.find({"scan_id": "rel"}).to_list(None)
    assert len(records) == _TWO_RECORDS
    assert {r["environment"] for r in records} == {DEFAULT_RELEASE_ENVIRONMENT, _STAGING}
    assert {r["version"] for r in records} == {_VERSION, _OTHER_VERSION}
    for environment in (DEFAULT_RELEASE_ENVIRONMENT, _STAGING):
        assert await latest_release_scan(db, _PROJECT, environment) == "rel"


@pytest.mark.asyncio
async def test_re_marking_an_older_scan_rolls_the_environment_back(client, db, api_key_headers):
    await _seed_scan(db, "first", commit=_COMMIT)
    await _seed_scan(db, "second", commit=_OTHER_COMMIT, created_delta=1)

    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)
    await _mark(client, api_key_headers, commit_hash=_OTHER_COMMIT, environment=_STAGING)
    assert await latest_release_scan(db, _PROJECT, _STAGING) == "second"

    rollback = await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)
    assert rollback.status_code == 201, rollback.text
    assert await latest_release_scan(db, _PROJECT, _STAGING) == "first"
    assert await db.releases.count_documents({"environment": _STAGING}) == _TWO_RECORDS


@pytest.mark.asyncio
async def test_a_supplied_released_at_drives_the_ordering(client, db, api_key_headers):
    """A CD job may report its own deploy time; released_at is what rollback ordering reads."""
    await _seed_scan(db, "current", commit=_COMMIT)
    await _seed_scan(db, "backfilled", commit=_OTHER_COMMIT, created_delta=1)

    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)
    late = await _mark(
        client,
        api_key_headers,
        commit_hash=_OTHER_COMMIT,
        environment=_STAGING,
        released_at=_PAST.isoformat(),
    )

    assert late.status_code == 201, late.text
    row = await db.releases.find_one({"scan_id": "backfilled"})
    assert row["released_at"] == _PAST_NAIVE
    # Recorded in the past, so it does not take the environment over from the live release.
    assert await latest_release_scan(db, _PROJECT, _STAGING) == "current"


@pytest.mark.asyncio
async def test_an_invalid_environment_slug_is_rejected(client, db, api_key_headers):
    await _seed_scan(db, "rel")

    resp = await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_INVALID_ENVIRONMENT)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_an_invalid_environment_slug_is_rejected_on_every_route(client, db, api_key_headers, member_auth_headers):
    await _seed_scan(db, "rel")
    params = {"environment": _INVALID_ENVIRONMENT}

    assert (await _unmark(client, api_key_headers, "rel", environment=_INVALID_ENVIRONMENT)).status_code == 422
    listed = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers, params=params)
    assert listed.status_code == 422


@pytest.mark.asyncio
async def test_unmark_of_the_last_environment_clears_the_flag(client, db, api_key_headers):
    await _seed_scan(db, "rel")
    assert (await _mark(client, api_key_headers, commit_hash=_COMMIT)).status_code == 201

    resp = await _unmark(client, api_key_headers, "rel")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "scan_id": "rel",
        "environment": DEFAULT_RELEASE_ENVIRONMENT,
        "is_release": False,
        "remaining_environments": [],
        "environment_release": None,
    }
    assert await db.releases.count_documents({"scan_id": "rel"}) == _NO_RECORDS
    scan = await db.scans.find_one({"_id": "rel"})
    assert scan["is_release"] is False


@pytest.mark.asyncio
async def test_unmark_of_one_environment_keeps_the_flag_while_another_holds_it(client, db, api_key_headers):
    await _seed_scan(db, "rel")
    await _mark(client, api_key_headers, commit_hash=_COMMIT)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)

    resp = await _unmark(client, api_key_headers, "rel", environment=_STAGING)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_release"] is True
    assert body["remaining_environments"] == [DEFAULT_RELEASE_ENVIRONMENT]
    scan = await db.scans.find_one({"_id": "rel"})
    assert scan["is_release"] is True
    assert await latest_release_scan(db, _PROJECT, DEFAULT_RELEASE_ENVIRONMENT) == "rel"
    assert await latest_release_scan(db, _PROJECT, _STAGING) is None


@pytest.mark.asyncio
async def test_unmark_names_the_release_it_uncovers(client, db, api_key_headers):
    """Marks are history, so withdrawing the newest makes the one below it live again. An operator
    withdrawing the only thing they believe is deployed must not be told only that the scan is
    no longer a release."""
    await _seed_scan(db, "old", commit=_OTHER_COMMIT, created_delta=-2)
    await _seed_scan(db, "new", commit=_COMMIT, created_delta=0)
    await _mark(client, api_key_headers, commit_hash=_OTHER_COMMIT, version=_VERSION)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_OTHER_VERSION)

    resp = await _unmark(client, api_key_headers, "new")

    assert resp.status_code == 200, resp.text
    uncovered = resp.json()["environment_release"]
    assert uncovered["scan_id"] == "old"
    assert uncovered["version"] == _VERSION
    assert uncovered["environment"] == DEFAULT_RELEASE_ENVIRONMENT
    assert await latest_release_scan(db, _PROJECT, DEFAULT_RELEASE_ENVIRONMENT) == uncovered["scan_id"]


@pytest.mark.asyncio
async def test_unmark_of_one_environment_reports_the_other_environment_as_untouched(client, db, api_key_headers):
    """The uncovered record belongs to the environment withdrawn from, not to whichever environment
    the scan still holds."""
    await _seed_scan(db, "rel")
    await _mark(client, api_key_headers, commit_hash=_COMMIT)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)

    resp = await _unmark(client, api_key_headers, "rel", environment=_STAGING)

    assert resp.json()["environment_release"] is None


@pytest.mark.asyncio
async def test_unmark_leaves_the_other_environments_records_alone(client, db, api_key_headers):
    await _seed_scan(db, "rel")
    await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_VERSION)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_CANARY, version=_OTHER_VERSION)

    await _unmark(client, api_key_headers, "rel", environment=_CANARY)

    records = await db.releases.find({"scan_id": "rel"}).to_list(None)
    assert len(records) == _ONE_RECORD
    assert records[0]["environment"] == DEFAULT_RELEASE_ENVIRONMENT
    assert records[0]["version"] == _VERSION


@pytest.mark.asyncio
async def test_unmark_of_a_scan_that_is_not_released_is_404(client, db, api_key_headers):
    await _seed_scan(db, "rel")

    resp = await _unmark(client, api_key_headers, "rel")

    assert resp.status_code == 404
    assert DEFAULT_RELEASE_ENVIRONMENT in resp.json()["detail"]


@pytest.mark.asyncio
async def test_unmark_does_not_reach_across_projects(client, db, api_key_headers):
    await _seed_scan(db, "rel")
    await _mark(client, api_key_headers, commit_hash=_COMMIT)
    await ReleaseRepository(db).record(
        Release(project_id=_OTHER_PROJECT, environment=DEFAULT_RELEASE_ENVIRONMENT, scan_id="rel", released_at=_NOW)
    )

    resp = await _unmark(client, api_key_headers, "rel")

    assert resp.status_code == 200, resp.text
    # The flag denormalises this project's records only, so the foreign one must not keep it alive.
    assert resp.json()["remaining_environments"] == []
    assert await db.releases.count_documents({"project_id": _OTHER_PROJECT}) == _ONE_RECORD


@pytest.mark.asyncio
async def test_list_returns_every_environment_newest_first(client, db, member_auth_headers, api_key_headers):
    await _seed_scan(db, "first", commit=_COMMIT)
    await _seed_scan(db, "second", commit=_OTHER_COMMIT, created_delta=1)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, version=_VERSION)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING, version=_VERSION)
    await _mark(client, api_key_headers, commit_hash=_OTHER_COMMIT, environment=_CANARY, version=_OTHER_VERSION)

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == _THREE_RECORDS
    assert [item["environment"] for item in body["items"]] == [
        _CANARY,
        _STAGING,
        DEFAULT_RELEASE_ENVIRONMENT,
    ]
    assert body["items"][0]["scan_id"] == "second"
    assert body["items"][0]["version"] == _OTHER_VERSION
    assert body["page"] == _FIRST_PAGE


@pytest.mark.asyncio
async def test_list_orders_releases_marked_at_the_same_instant_deterministically(client, db, member_auth_headers):
    """A CD job that marks two environments with one explicit released_at ties the sort key, and
    among equal keys Mongo's order is unspecified — so "the latest release" could flip per request."""
    await _seed_scan(db, "rel")
    for row_id, environment in ((_TIED_HIGH_ROW_ID, _CANARY), (_TIED_LOW_ROW_ID, _STAGING)):
        await ReleaseRepository(db).record(
            Release(id=row_id, project_id=_PROJECT, environment=environment, scan_id="rel", released_at=_NOW)
        )

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert [item["environment"] for item in resp.json()["items"]] == [_STAGING, _CANARY]


@pytest.mark.asyncio
async def test_list_filters_by_environment(client, db, member_auth_headers, api_key_headers):
    await _seed_scan(db, "rel")
    await _mark(client, api_key_headers, commit_hash=_COMMIT)
    await _mark(client, api_key_headers, commit_hash=_COMMIT, environment=_STAGING)

    resp = await client.get(
        f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers, params={"environment": _STAGING}
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == _ONE_RECORD
    assert body["items"][0]["environment"] == _STAGING


@pytest.mark.asyncio
async def test_a_release_still_being_analysed_is_listed_and_named(client, db, member_auth_headers):
    await _seed_scan(db, "deploying", status=SCAN_STATUS_PROCESSING)
    await ReleaseRepository(db).record(
        Release(
            project_id=_PROJECT,
            environment=DEFAULT_RELEASE_ENVIRONMENT,
            version=_VERSION,
            scan_id="deploying",
            released_at=_NOW,
        )
    )

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    item = resp.json()["items"][0]
    assert item["version"] == _VERSION
    assert item["scan_id"] == "deploying"
    assert item["scan_status"] == SCAN_STATUS_PROCESSING
    # The resolver omits this project entirely; the list is what tells a caller a deploy is in flight.
    assert item["analysis_scan_id"] is None
    assert await latest_release_scan(db, _PROJECT, DEFAULT_RELEASE_ENVIRONMENT) is None


@pytest.mark.asyncio
async def test_a_release_whose_scan_was_pruned_still_lists(client, db, member_auth_headers):
    """Retention deletes scans without cascading to releases, so an orphan row is a steady state."""
    await ReleaseRepository(db).record(
        Release(
            project_id=_PROJECT,
            environment=DEFAULT_RELEASE_ENVIRONMENT,
            version=_VERSION,
            scan_id="pruned",
            released_at=_NOW,
        )
    )

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    item = resp.json()["items"][0]
    assert item["scan_id"] == "pruned"
    assert item["version"] == _VERSION
    # A null scan_status is what separates "scan pruned" from "still analysing".
    assert item["scan_status"] is None
    assert item["commit_hash"] is None
    assert item["branch"] is None
    assert item["analysis_scan_id"] is None


@pytest.mark.asyncio
async def test_list_pages_through_the_records(client, db, member_auth_headers, api_key_headers):
    await _seed_scan(db, "rel")
    for hours, environment in enumerate((DEFAULT_RELEASE_ENVIRONMENT, _STAGING, _CANARY)):
        await _mark(
            client,
            api_key_headers,
            commit_hash=_COMMIT,
            environment=environment,
            released_at=(_NOW + timedelta(hours=hours)).isoformat(),
        )

    resp = await client.get(
        f"/api/v1/projects/{_PROJECT}/releases",
        headers=member_auth_headers,
        params={"skip": _ONE_RECORD, "limit": _ONE_RECORD},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == _THREE_RECORDS
    assert len(body["items"]) == _ONE_RECORD
    assert body["page"] == _SECOND_PAGE
    assert body["size"] == _ONE_RECORD
    # skip lands on the second-newest, which is the staging mark.
    assert body["items"][0]["environment"] == _STAGING


@pytest.mark.asyncio
async def test_list_rejects_out_of_range_pagination(client, db, member_auth_headers):
    async def _get(params):
        return await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers, params=params)

    assert (await _get({"limit": _MAX_PAGE_SIZE + 1})).status_code == 422
    assert (await _get({"limit": 0})).status_code == 422
    assert (await _get({"skip": -1})).status_code == 422
    assert (await _get({"limit": _MAX_PAGE_SIZE})).status_code == 200


@pytest.mark.asyncio
async def test_list_of_a_project_without_releases_is_empty(client, db, member_auth_headers):
    await _seed_scan(db, "plain")

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "items": [],
        "total": _NO_RECORDS,
        "page": _FIRST_PAGE,
        "size": _DEFAULT_PAGE_SIZE,
    }


@pytest.mark.asyncio
async def test_a_rescan_of_the_released_scan_becomes_its_analysis(client, db, member_auth_headers, api_key_headers):
    await _seed_scan(db, "released", latest_rescan_id="rescan")
    await _seed_scan(db, "rescan", created_delta=5, is_rescan=True, original_scan_id="released")

    assert (await _mark(client, api_key_headers, commit_hash=_COMMIT)).status_code == 201

    resp = await client.get(f"/api/v1/projects/{_PROJECT}/releases", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    item = resp.json()["items"][0]
    assert item["scan_id"] == "released"
    assert item["analysis_scan_id"] == "rescan"


@pytest.mark.asyncio
async def test_a_project_editor_may_mark_without_ci_credentials(client, db, editor_auth_headers):
    await _seed_scan(db, "rel")

    resp = await _mark(client, editor_auth_headers, commit_hash=_COMMIT, version=_VERSION)

    assert resp.status_code == 201, resp.text
    assert resp.json()["scan_id"] == "rel"


@pytest.mark.asyncio
async def test_a_project_viewer_may_not_mark(client, db, viewer_auth_headers):
    await _seed_scan(db, "rel")

    resp = await _mark(client, viewer_auth_headers, commit_hash=_COMMIT)

    assert resp.status_code == 403
    assert await db.releases.count_documents({}) == _NO_RECORDS


@pytest.mark.asyncio
async def test_ci_credentials_of_another_project_are_rejected(client, db, other_project, other_project_api_key_headers):
    await _seed_scan(db, "rel")

    resp = await _mark(client, other_project_api_key_headers, commit_hash=_COMMIT)

    assert resp.status_code == 403
    assert await db.releases.count_documents({}) == _NO_RECORDS


@pytest.mark.asyncio
async def test_an_unknown_api_secret_is_rejected(client, db):
    await _seed_scan(db, "rel")

    resp = await _mark(client, {"X-API-Key": f"{_PROJECT}.wrong-secret"}, commit_hash=_COMMIT)

    assert resp.status_code == 403
    assert await db.releases.count_documents({}) == _NO_RECORDS


@pytest.mark.asyncio
async def test_mark_and_unmark_reject_unauthenticated_callers(client, db):
    await _seed_scan(db, "rel")

    assert (await _mark(client, {}, commit_hash=_COMMIT)).status_code == 401
    assert (await _unmark(client, {}, "rel")).status_code == 401

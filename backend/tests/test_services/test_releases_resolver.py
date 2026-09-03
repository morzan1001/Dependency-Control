"""The one place that answers 'which scan counts for this project'."""

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.services.releases import latest_release_scan, release_environments, resolve_scan_ids
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_PRODUCTION = "production"
_STAGING = "staging"
_CANARY = "canary"
_ANOTHER_PROJECTS_ENVIRONMENT = "elsewhere"
_PROJECT_A = "pa"
_PROJECT_B = "pb"
_OTHER_PROJECT = "pz"
_COMPLETED = "completed"
_FAILED = "failed"
_MAIN = "main"
_GONE_BRANCH = "gone"
_NO_SCANS: dict[str, str] = {}
_ONE_PROJECT = 1
_MANY_PROJECTS = 50
_COUNTED_COLLECTIONS = ("projects", "scans", "releases")
_COUNTED_OPERATIONS = ("find", "find_one", "aggregate", "distinct")
_HEAD_QUERIES = {"projects.find": 1, "scans.aggregate": 1}
_HEAD_QUERIES_POINTERS_ONLY = {"projects.find": 1}
_RELEASE_QUERIES = {"releases.aggregate": 1, "scans.find": 1}
_NO_QUERIES: dict[str, int] = {}


@pytest.fixture
def db():
    return FakeDatabase()


def _scan(scan_id: str, project_id: str, *, created_delta: int = 0, status: str = _COMPLETED, **extra) -> dict:
    return {
        "_id": scan_id,
        "project_id": project_id,
        "branch": _MAIN,
        "status": status,
        "created_at": _NOW + timedelta(hours=created_delta),
        **extra,
    }


def _release(project_id: str, environment: str, scan_id: str, *, released_delta: int = 0) -> dict:
    return {
        "_id": f"row-{project_id}-{environment}-{scan_id}",
        "project_id": project_id,
        "environment": environment,
        "scan_id": scan_id,
        "released_at": _NOW + timedelta(hours=released_delta),
    }


async def _seed_one_scan_each(db: FakeDatabase, project_count: int) -> list[str]:
    """Pointer-less projects, so the head path takes its scan read rather than short-circuiting."""
    project_ids = [f"p{index}" for index in range(project_count)]
    for index, project_id in enumerate(project_ids):
        await db.projects.insert_one({"_id": project_id, "name": project_id})
        await db.scans.insert_one(_scan(f"scan-{index}", project_id))
        await db.releases.insert_one(_release(project_id, _PRODUCTION, f"scan-{index}"))
    return project_ids


def _count_queries(db: FakeDatabase) -> Counter:
    """Wraps every read the resolver can reach so a per-project query shows up as a rising count."""
    counts: Counter = Counter()
    for collection_name in _COUNTED_COLLECTIONS:
        collection = db[collection_name]
        for operation in _COUNTED_OPERATIONS:
            original = getattr(collection, operation)

            def counted(*args, _key=f"{collection_name}.{operation}", _original=original, **kwargs):
                counts[_key] += 1
                return _original(*args, **kwargs)

            setattr(collection, operation, counted)
    return counts


@pytest.mark.asyncio
async def test_latest_release_scan_orders_by_released_at(db):
    await db.scans.insert_one(_scan("new-build", _PROJECT_A, created_delta=5))
    await db.scans.insert_one(_scan("rolled-back-to", _PROJECT_A, created_delta=-50))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "new-build"))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "rolled-back-to", released_delta=1))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rolled-back-to"


@pytest.mark.asyncio
async def test_latest_release_scan_is_scoped_to_one_environment_of_one_project(db):
    await db.scans.insert_one(_scan("staged", _PROJECT_A))
    await db.scans.insert_one(_scan("other-project-prod", _OTHER_PROJECT))
    await db.releases.insert_one(_release(_PROJECT_A, _STAGING, "staged"))
    await db.releases.insert_one(_release(_OTHER_PROJECT, _PRODUCTION, "other-project-prod"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) is None


@pytest.mark.asyncio
async def test_latest_release_scan_follows_the_rescan(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rescan"


@pytest.mark.asyncio
async def test_latest_release_scan_of_a_deleted_scan_is_none(db):
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "retained-nowhere"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) is None


@pytest.mark.asyncio
async def test_release_environments_are_sorted_and_deduplicated(db):
    for index, environment in enumerate([_STAGING, _PRODUCTION, _STAGING, _CANARY]):
        await db.releases.insert_one(_release(_PROJECT_A, environment, f"scan-{index}"))
    await db.releases.insert_one(_release(_OTHER_PROJECT, _ANOTHER_PROJECTS_ENVIRONMENT, "scan-elsewhere"))

    assert await release_environments(db, _PROJECT_A) == [_CANARY, _PRODUCTION, _STAGING]


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_uses_the_project_pointer(db):
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))

    assert await resolve_scan_ids(db, [_PROJECT_A]) == {_PROJECT_A: "head-a"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_matches_the_repository(db):
    """The head path must stay the repository's answer, or the dashboards move when callers switch."""
    await db.projects.insert_one({"_id": "with-pointer", "name": "one", "latest_scan_id": "pointed-at"})
    await db.projects.insert_one({"_id": "no-pointer", "name": "two"})
    await db.projects.insert_one(
        {
            "_id": "deleted-branch",
            "name": "three",
            "latest_scan_id": "on-a-dead-branch",
            "deleted_branches": [_GONE_BRANCH],
        }
    )
    await db.projects.insert_one({"_id": "no-scans", "name": "four"})
    await db.scans.insert_one(_scan("pointed-at", "with-pointer"))
    await db.scans.insert_one(_scan("older", "no-pointer", created_delta=-1))
    await db.scans.insert_one(_scan("newest", "no-pointer", created_delta=1))
    await db.scans.insert_one(_scan("failed", "no-pointer", created_delta=2, status=_FAILED))
    await db.scans.insert_one({**_scan("on-a-dead-branch", "deleted-branch", created_delta=3), "branch": _GONE_BRANCH})
    await db.scans.insert_one(_scan("still-alive", "deleted-branch"))

    project_ids = ["with-pointer", "no-pointer", "deleted-branch", "no-scans"]
    projects = await ProjectRepository(db).find_many_with_scan_id(
        {"_id": {"$in": project_ids}}, limit=ANALYTICS_MAX_QUERY_LIMIT
    )
    expected = await ScanRepository(db).get_latest_active_scan_ids(projects)

    assert expected == {"with-pointer": "pointed-at", "no-pointer": "newest", "deleted-branch": "still-alive"}
    assert await resolve_scan_ids(db, project_ids) == expected


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_omits_a_project_without_a_release(db):
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.projects.insert_one({"_id": _PROJECT_B, "name": _PROJECT_B, "latest_scan_id": "head-b"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A, created_delta=9))
    await db.scans.insert_one(_scan("released-a", _PROJECT_A))
    await db.scans.insert_one(_scan("head-b", _PROJECT_B, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))

    assert await resolve_scan_ids(db, [_PROJECT_A, _PROJECT_B], release_environment=_PRODUCTION) == {
        _PROJECT_A: "released-a"
    }


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_follows_the_rescan(db):
    await db.scans.insert_one(_scan("released-a", _PROJECT_A, latest_rescan_id="rescan-a"))
    await db.scans.insert_one(_scan("rescan-a", _PROJECT_A, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))

    assert await resolve_scan_ids(db, [_PROJECT_A], release_environment=_PRODUCTION) == {_PROJECT_A: "rescan-a"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_omits_a_deleted_scan(db):
    await db.scans.insert_one(_scan("released-b", _PROJECT_B))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "retained-nowhere"))
    await db.releases.insert_one(_release(_PROJECT_B, _PRODUCTION, "released-b"))

    assert await resolve_scan_ids(db, [_PROJECT_A, _PROJECT_B], release_environment=_PRODUCTION) == {
        _PROJECT_B: "released-b"
    }


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_without_a_project_filter(db):
    await db.scans.insert_one(_scan("released-a", _PROJECT_A))
    await db.scans.insert_one(_scan("released-b", _PROJECT_B))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))
    await db.releases.insert_one(_release(_PROJECT_B, _PRODUCTION, "released-b"))
    await db.releases.insert_one(_release(_OTHER_PROJECT, _STAGING, "released-a"))

    resolved = await resolve_scan_ids(db, None, release_environment=_PRODUCTION)

    assert resolved == {_PROJECT_A: "released-a", _PROJECT_B: "released-b"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_empty_scope_reads_nothing(db):
    counts = _count_queries(db)

    assert await resolve_scan_ids(db, []) == _NO_SCANS
    assert await resolve_scan_ids(db, [], release_environment=_PRODUCTION) == _NO_SCANS
    assert dict(counts) == _NO_QUERIES


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_head_query_count_does_not_grow_with_the_scope(db, project_count):
    project_ids = await _seed_one_scan_each(db, project_count)
    counts = _count_queries(db)

    await resolve_scan_ids(db, project_ids)

    assert dict(counts) == _HEAD_QUERIES


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_release_query_count_does_not_grow_with_the_scope(db, project_count):
    project_ids = await _seed_one_scan_each(db, project_count)
    counts = _count_queries(db)

    await resolve_scan_ids(db, project_ids, release_environment=_PRODUCTION)

    assert dict(counts) == _RELEASE_QUERIES


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_skips_the_scan_read_when_every_pointer_is_set(db):
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))
    counts = _count_queries(db)

    await resolve_scan_ids(db, [_PROJECT_A])

    assert dict(counts) == _HEAD_QUERIES_POINTERS_ONLY

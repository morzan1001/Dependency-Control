"""The one place that answers 'which scan counts for this project'."""

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.services.releases import (
    _MAX_RESCAN_HOPS,
    latest_release_scan,
    released_scan_ids,
    resolve_scan_ids,
)
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
_COMPLETED_WITH_ERRORS = "completed_with_errors"
_FAILED = "failed"
_PENDING = "pending"
_PROCESSING = "processing"
_UNUSABLE_STATUSES = [_PENDING, _FAILED]
_MAIN = "main"
_GONE_BRANCH = "gone"
_NO_SCANS: dict[str, str] = {}
_ONE_PROJECT = 1
_MANY_PROJECTS = 50
_COUNTED_COLLECTIONS = ("projects", "scans", "releases")
_COUNTED_OPERATIONS = ("find", "find_one", "aggregate", "distinct")
_HEAD_QUERIES = {"projects.find": 1, "scans.aggregate": 1}
_HEAD_QUERIES_POINTERS_ONLY = {"projects.find": 1, "scans.distinct": 1}
_HEAD_QUERIES_WITH_A_DANGLING_POINTER = {"projects.find": 1, "scans.distinct": 1, "scans.aggregate": 1}
_RELEASE_QUERIES = {"releases.aggregate": 1, "scans.find": 1}
_RELEASE_QUERIES_WITH_RESCANS = {"releases.aggregate": 1, "scans.find": 2}
_RELEASE_QUERIES_WITH_A_CHAIN = {"releases.aggregate": 1, "scans.find": 4}
_CHAIN_DEPTH = 3
_CHAIN_BEYOND_THE_BOUND = _MAX_RESCAN_HOPS + 5
_NO_RELEASES: dict[str, str] = {}
_CYCLE_QUERIES = {"releases.find_one": 1, "scans.find": 2}
_NO_QUERIES: dict[str, int] = {}
_NAMES_AND_HEAD_QUERIES = {"projects.find": 1, "scans.distinct": 1}
_NAMES_AND_RELEASE_QUERIES = {"projects.find": 1, "releases.aggregate": 1, "scans.find": 1}
_RETENTION_DELETED = "head-deleted-by-retention"
_EXEMPTED_RELEASE = "exempted-release"
_SURVIVOR_AGE_HOURS = -100
_CRITICALS_ON_THE_SURVIVOR = 7
_CURRENT_PROJECT = "pc"


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


async def _seed_one_pointed_scan_each(db: FakeDatabase, project_count: int) -> list[str]:
    """Every pointer set and readable, so the head path can answer from the projects read alone."""
    project_ids = await _seed_one_scan_each(db, project_count)
    for index, project_id in enumerate(project_ids):
        await db.projects.update_one({"_id": project_id}, {"$set": {"latest_scan_id": f"scan-{index}"}})
    return project_ids


async def _seed_rescan_chain(db: FakeDatabase, project_id: str, released: str, statuses: list[str]) -> list[str]:
    """released -> rescan-1 -> ... : housekeeping rescans the project's newest usable scan, so each
    rescan carries the next pointer and the released scan's own pointer never advances past the first."""
    chain = [f"{released}-rescan-{depth}" for depth in range(1, len(statuses) + 1)]
    for depth, (scan_id, status) in enumerate(zip(chain, statuses, strict=True), start=1):
        await db.scans.insert_one(_scan(scan_id, project_id, created_delta=depth, status=status))
    for source, target in zip([released, *chain], chain, strict=False):
        await db.scans.update_one({"_id": source}, {"$set": {"latest_rescan_id": target}})
    return chain


async def _seed_a_dangling_pointer(db: FakeDatabase) -> None:
    """Retention deletes the scan document without clearing latest_scan_id, and exempts release
    scans, so the pointer names nothing while an older usable scan is still there to be found."""
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": _RETENTION_DELETED})
    await db.scans.insert_one(
        _scan(
            _EXEMPTED_RELEASE,
            _PROJECT_A,
            created_delta=_SURVIVOR_AGE_HOURS,
            is_release=True,
            stats={"critical": _CRITICALS_ON_THE_SURVIVOR},
        )
    )


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


@pytest.mark.parametrize("rescan_status", _UNUSABLE_STATUSES)
@pytest.mark.asyncio
async def test_latest_release_scan_keeps_the_original_while_the_rescan_is_unusable(db, rescan_status):
    """latest_rescan_id is written when the rescan is created, so it points at an empty scan for as
    long as the rescan runs; the released artefact's own analysis is the honest answer meanwhile."""
    await db.scans.insert_one(_scan("released", _PROJECT_A, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9, status=rescan_status))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "released"


@pytest.mark.asyncio
async def test_latest_release_scan_takes_a_partially_failed_rescan(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9, status=_COMPLETED_WITH_ERRORS))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rescan"


@pytest.mark.asyncio
async def test_latest_release_scan_takes_the_rescan_that_repaired_a_failed_original(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, status=_FAILED, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rescan"


@pytest.mark.asyncio
async def test_latest_release_scan_without_any_usable_analysis_is_none(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, status=_FAILED, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9, status=_PENDING))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) is None


@pytest.mark.asyncio
async def test_latest_release_scan_of_an_unanalysed_release_is_none(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, status=_PENDING))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) is None


@pytest.mark.asyncio
async def test_latest_release_scan_walks_the_whole_rescan_chain(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A))
    chain = await _seed_rescan_chain(db, _PROJECT_A, "released", [_COMPLETED] * _CHAIN_DEPTH)
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == chain[-1]


@pytest.mark.asyncio
async def test_latest_release_scan_walks_through_a_failed_link_of_the_chain(db):
    """Stopping at the first unusable hop would answer with the released scan and ignore a fresher
    analysis of the same artefact that is sitting one link further along."""
    await db.scans.insert_one(_scan("released", _PROJECT_A))
    chain = await _seed_rescan_chain(db, _PROJECT_A, "released", [_FAILED, _COMPLETED])
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == chain[-1]


@pytest.mark.asyncio
async def test_latest_release_scan_keeps_the_freshest_usable_when_the_chain_ends_unusable(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A))
    chain = await _seed_rescan_chain(db, _PROJECT_A, "released", [_COMPLETED, _PENDING, _FAILED])
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == chain[0]


@pytest.mark.asyncio
async def test_a_chain_longer_than_the_bound_stops_at_the_bound(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A))
    chain = await _seed_rescan_chain(db, _PROJECT_A, "released", [_COMPLETED] * _CHAIN_BEYOND_THE_BOUND)
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    resolved = await latest_release_scan(db, _PROJECT_A, _PRODUCTION)

    assert resolved == chain[_MAX_RESCAN_HOPS - 1], "the walk stops at the bound instead of running the chain out"


@pytest.mark.asyncio
async def test_a_cyclic_rescan_pointer_is_walked_once(db):
    await db.scans.insert_one(_scan("released", _PROJECT_A, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=1, latest_rescan_id="released"))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))
    counts = _count_queries(db)

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rescan"
    assert dict(counts) == _CYCLE_QUERIES, "a scan already walked is not read again, so the cycle ends itself"


@pytest.mark.asyncio
async def test_latest_release_scan_of_a_deleted_scan_is_none(db):
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "retained-nowhere"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) is None


@pytest.mark.asyncio
async def test_released_scan_ids_hold_one_sorted_entry_per_environment(db):
    for index, environment in enumerate([_STAGING, _PRODUCTION, _CANARY]):
        await db.releases.insert_one(_release(_PROJECT_A, environment, f"scan-{index}"))
    await db.releases.insert_one(_release(_OTHER_PROJECT, _ANOTHER_PROJECTS_ENVIRONMENT, "scan-elsewhere"))

    released = await released_scan_ids(db, _PROJECT_A)

    assert released == {_STAGING: "scan-0", _PRODUCTION: "scan-1", _CANARY: "scan-2"}
    assert list(released) == [_CANARY, _PRODUCTION, _STAGING], "sorted, so callers rescan in a fixed order"


@pytest.mark.asyncio
async def test_released_scan_ids_take_the_newest_release_of_an_environment(db):
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "new-build"))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "rolled-back-to", released_delta=1))

    assert await released_scan_ids(db, _PROJECT_A) == {_PRODUCTION: "rolled-back-to"}


@pytest.mark.asyncio
async def test_released_scan_ids_of_a_project_without_releases_is_empty(db):
    await db.releases.insert_one(_release(_OTHER_PROJECT, _PRODUCTION, "someone-elses"))

    assert await released_scan_ids(db, _PROJECT_A) == _NO_RELEASES


@pytest.mark.asyncio
async def test_released_scan_ids_list_an_environment_that_resolves_to_nothing(db):
    """Intended asymmetry: the environment was released to, so it stays selectable even while its
    release has no readable analysis. Hiding it would need a deliberate change here."""
    await db.scans.insert_one(_scan("unanalysed", _PROJECT_A, status=_PENDING))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "unanalysed"))

    assert await released_scan_ids(db, _PROJECT_A) == {_PRODUCTION: "unanalysed"}
    assert await resolve_scan_ids(db, [_PROJECT_A], release_environment=_PRODUCTION) == _NO_SCANS


@pytest.mark.asyncio
async def test_released_scan_ids_stay_on_the_marked_scan_rather_than_its_rescan(db):
    """The marked scan is what a rescan must be created from: rescanning its rescan instead would
    lengthen the chain by one link per interval until it outruns the bound the walk stops at."""
    await db.scans.insert_one(_scan("released", _PROJECT_A, latest_rescan_id="rescan"))
    await db.scans.insert_one(_scan("rescan", _PROJECT_A, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released"))

    assert await latest_release_scan(db, _PROJECT_A, _PRODUCTION) == "rescan"
    assert await released_scan_ids(db, _PROJECT_A) == {_PRODUCTION: "released"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_uses_the_project_pointer(db):
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))

    assert await resolve_scan_ids(db, [_PROJECT_A]) == {_PROJECT_A: "head-a"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_without_a_project_filter(db):
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.projects.insert_one({"_id": _PROJECT_B, "name": _PROJECT_B, "latest_scan_id": "head-b"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))
    await db.scans.insert_one(_scan("head-b", _PROJECT_B))

    assert await resolve_scan_ids(db, None) == {_PROJECT_A: "head-a", _PROJECT_B: "head-b"}


@pytest.mark.asyncio
async def test_resolve_scan_ids_head_matches_the_repository(db):
    """The head path must stay the repository's answer, or the dashboards move when callers switch.
    A completed rescan becomes the project's own pointer, so the head path never hops to one itself."""
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
    await db.scans.insert_one(_scan("pointed-at", "with-pointer", latest_rescan_id="a-usable-rescan"))
    await db.scans.insert_one(_scan("a-usable-rescan", "with-pointer", created_delta=4))
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


@pytest.mark.parametrize("rescan_status", _UNUSABLE_STATUSES)
@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_keeps_the_original_while_the_rescan_is_unusable(db, rescan_status):
    await db.scans.insert_one(_scan("released-a", _PROJECT_A, latest_rescan_id="rescan-a"))
    await db.scans.insert_one(_scan("rescan-a", _PROJECT_A, created_delta=9, status=rescan_status))
    await db.scans.insert_one(_scan("released-b", _PROJECT_B, latest_rescan_id="rescan-b"))
    await db.scans.insert_one(_scan("rescan-b", _PROJECT_B, created_delta=9))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))
    await db.releases.insert_one(_release(_PROJECT_B, _PRODUCTION, "released-b"))

    assert await resolve_scan_ids(db, [_PROJECT_A, _PROJECT_B], release_environment=_PRODUCTION) == {
        _PROJECT_A: "released-a",
        _PROJECT_B: "rescan-b",
    }


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_omits_a_release_without_usable_analysis(db):
    await db.scans.insert_one(_scan("released-a", _PROJECT_A, status=_PENDING))
    await db.scans.insert_one(_scan("released-b", _PROJECT_B))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))
    await db.releases.insert_one(_release(_PROJECT_B, _PRODUCTION, "released-b"))

    assert await resolve_scan_ids(db, [_PROJECT_A, _PROJECT_B], release_environment=_PRODUCTION) == {
        _PROJECT_B: "released-b"
    }


@pytest.mark.asyncio
async def test_resolve_scan_ids_release_mode_walks_the_chain_per_project(db):
    await db.scans.insert_one(_scan("released-a", _PROJECT_A))
    await db.scans.insert_one(_scan("released-b", _PROJECT_B))
    chain_a = await _seed_rescan_chain(db, _PROJECT_A, "released-a", [_FAILED, _COMPLETED])
    chain_b = await _seed_rescan_chain(db, _PROJECT_B, "released-b", [_COMPLETED] * _CHAIN_DEPTH)
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))
    await db.releases.insert_one(_release(_PROJECT_B, _PRODUCTION, "released-b"))

    assert await resolve_scan_ids(db, [_PROJECT_A, _PROJECT_B], release_environment=_PRODUCTION) == {
        _PROJECT_A: chain_a[-1],
        _PROJECT_B: chain_b[-1],
    }


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


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_release_query_count_with_rescans_does_not_grow_with_the_scope(db, project_count):
    """Checking the rescans' status costs one more read for the whole scope, never one per project."""
    project_ids = await _seed_one_scan_each(db, project_count)
    for index, project_id in enumerate(project_ids):
        await db.scans.update_one({"_id": f"scan-{index}"}, {"$set": {"latest_rescan_id": f"rescan-{index}"}})
        await db.scans.insert_one(_scan(f"rescan-{index}", project_id, created_delta=9))
    counts = _count_queries(db)

    await resolve_scan_ids(db, project_ids, release_environment=_PRODUCTION)

    assert dict(counts) == _RELEASE_QUERIES_WITH_RESCANS


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_release_query_count_with_a_chain_does_not_grow_with_the_scope(db, project_count):
    """One read per depth of the deepest chain, shared by the whole scope — never one per project."""
    project_ids = await _seed_one_scan_each(db, project_count)
    for index, project_id in enumerate(project_ids):
        await _seed_rescan_chain(db, project_id, f"scan-{index}", [_COMPLETED] * _CHAIN_DEPTH)
    counts = _count_queries(db)

    await resolve_scan_ids(db, project_ids, release_environment=_PRODUCTION)

    assert dict(counts) == _RELEASE_QUERIES_WITH_A_CHAIN


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_resolve_scan_ids_head_skips_the_scan_read_when_every_pointer_is_set(db, project_count):
    """One distinct validates every pointer in the scope, never one read per pointer."""
    project_ids = await _seed_one_pointed_scan_each(db, project_count)
    counts = _count_queries(db)

    await resolve_scan_ids(db, project_ids)

    assert dict(counts) == _HEAD_QUERIES_POINTERS_ONLY


@pytest.mark.asyncio
async def test_crypto_hotspots_pick_scan_ids_uses_the_resolver(db):
    from app.services.analytics.crypto_hotspots import CryptoHotspotService
    from app.services.analytics.scopes import ResolvedScope

    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))
    await db.scans.insert_one(_scan("on-dead-branch", _PROJECT_A, branch=_GONE_BRANCH, created_delta=5))

    scope = ResolvedScope(scope="user", scope_id=None, project_ids=[_PROJECT_A])
    picked = await CryptoHotspotService(db)._pick_scan_ids(scope, None)

    assert picked == ["head-a"]


@pytest.mark.asyncio
async def test_crypto_hotspots_override_still_short_circuits(db):
    from app.services.analytics.crypto_hotspots import CryptoHotspotService
    from app.services.analytics.scopes import ResolvedScope

    scope = ResolvedScope(scope="user", scope_id=None, project_ids=[_PROJECT_A])
    assert await CryptoHotspotService(db)._pick_scan_ids(scope, "explicit") == ["explicit"]


@pytest.mark.asyncio
async def test_compliance_pick_scan_ids_returns_project_scan_pairs(db):
    from app.services.analytics.scopes import ResolvedScope
    from app.services.compliance.engine import ComplianceReportEngine

    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))

    scope = ResolvedScope(scope="user", scope_id=None, project_ids=[_PROJECT_A])
    pairs = await ComplianceReportEngine()._pick_scan_ids(db, scope)

    assert pairs == [(_PROJECT_A, "head-a")]


@pytest.mark.asyncio
async def test_chat_registry_skips_unusable_scans(db):
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": None})
    await db.scans.insert_one(_scan("running", _PROJECT_A, status=_PROCESSING, created_delta=5))
    await db.scans.insert_one(_scan("done", _PROJECT_A))

    resolved = await ChatToolRegistry()._latest_scan_ids_for_user({"_id": {"$in": [_PROJECT_A]}}, None, db)

    assert resolved == {_PROJECT_A: "done"}


@pytest.mark.asyncio
async def test_chat_registry_resolves_nothing_for_a_project_outside_the_user_scope(db):
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))

    resolved = await ChatToolRegistry()._latest_scan_ids_for_user({"_id": {"$in": [_OTHER_PROJECT]}}, _PROJECT_A, db)

    assert resolved == _NO_SCANS


@pytest.mark.asyncio
async def test_every_consumer_falls_back_when_the_pointer_names_a_deleted_scan(db):
    """A dangling pointer answers with a scan that holds no assets and no findings, so the framework
    would read a project as clean; every consumer must land on the scan that outlived the head."""
    from app.api.v1.helpers.analytics import get_latest_scan_ids
    from app.services.analytics.crypto_hotspots import CryptoHotspotService
    from app.services.analytics.scopes import ResolvedScope
    from app.services.chat.tools.registry import ChatToolRegistry
    from app.services.compliance.engine import ComplianceReportEngine

    await _seed_a_dangling_pointer(db)
    scope = ResolvedScope(scope="user", scope_id=None, project_ids=[_PROJECT_A])

    assert await resolve_scan_ids(db, [_PROJECT_A]) == {_PROJECT_A: _EXEMPTED_RELEASE}
    assert await get_latest_scan_ids([_PROJECT_A], db) == [_EXEMPTED_RELEASE]
    assert await CryptoHotspotService(db)._pick_scan_ids(scope, None) == [_EXEMPTED_RELEASE]
    assert await ComplianceReportEngine()._pick_scan_ids(db, scope) == [(_PROJECT_A, _EXEMPTED_RELEASE)]
    assert await ChatToolRegistry()._latest_scan_ids_for_user({"_id": {"$in": [_PROJECT_A]}}, None, db) == {
        _PROJECT_A: _EXEMPTED_RELEASE
    }
    assert await ChatToolRegistry()._latest_scan_ids_for_user({}, _PROJECT_A, db) == {_PROJECT_A: _EXEMPTED_RELEASE}


@pytest.mark.asyncio
async def test_cross_project_data_falls_back_when_the_pointer_names_a_deleted_scan(db):
    """gather_cross_project_data reads the repository rather than the resolver, so the fallback has
    to live in the repository; the survivor's stats are what proves the scan it landed on."""
    from app.api.v1.helpers.analytics import gather_cross_project_data

    await _seed_a_dangling_pointer(db)
    await db.projects.insert_one({"_id": _CURRENT_PROJECT, "name": _CURRENT_PROJECT})

    data = await gather_cross_project_data([_PROJECT_A, _CURRENT_PROJECT], _CURRENT_PROJECT, db)

    assert data is not None
    assert [(row["project_id"], row["total_critical"]) for row in data["projects"]] == [
        (_PROJECT_A, _CRITICALS_ON_THE_SURVIVOR)
    ]


@pytest.mark.parametrize("pointer_status", _UNUSABLE_STATUSES)
@pytest.mark.asyncio
async def test_a_pointer_at_an_unreadable_scan_falls_back_to_the_last_usable_one(db, pointer_status):
    """The pointer is only as good as the analysis behind it: a scan that carries no results is the
    same dead end as one retention removed."""
    await db.projects.insert_one({"_id": _PROJECT_A, "name": _PROJECT_A, "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A, created_delta=5, status=pointer_status))
    await db.scans.insert_one(_scan("last-good", _PROJECT_A))

    assert await resolve_scan_ids(db, [_PROJECT_A]) == {_PROJECT_A: "last-good"}


@pytest.mark.asyncio
async def test_a_dangling_pointer_costs_one_extra_read_for_the_whole_scope(db):
    await _seed_a_dangling_pointer(db)
    counts = _count_queries(db)

    await resolve_scan_ids(db, [_PROJECT_A])

    assert dict(counts) == _HEAD_QUERIES_WITH_A_DANGLING_POINTER


@pytest.mark.asyncio
async def test_analytics_get_latest_scan_ids_uses_the_resolver(db):
    from app.api.v1.helpers.analytics import get_latest_scan_ids

    await db.projects.insert_one(
        {
            "_id": _PROJECT_A,
            "name": _PROJECT_A,
            "latest_scan_id": "on-a-dead-branch",
            "deleted_branches": [_GONE_BRANCH],
        }
    )
    await db.scans.insert_one({**_scan("on-a-dead-branch", _PROJECT_A, created_delta=5), "branch": _GONE_BRANCH})
    await db.scans.insert_one(_scan("still-alive", _PROJECT_A))

    assert await get_latest_scan_ids([_PROJECT_A], db) == ["still-alive"]


@pytest.mark.asyncio
async def test_analytics_get_projects_with_scans_names_every_project_in_scope(db):
    """The name map covers the scope; the scan list only the projects that resolved to one."""
    from app.api.v1.helpers.analytics import get_projects_with_scans

    await db.projects.insert_one({"_id": _PROJECT_A, "name": "alpha", "latest_scan_id": "head-a"})
    await db.projects.insert_one({"_id": _PROJECT_B, "name": "beta"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A))

    names, scan_ids = await get_projects_with_scans([_PROJECT_A, _PROJECT_B], db)

    assert names == {_PROJECT_A: "alpha", _PROJECT_B: "beta"}
    assert scan_ids == ["head-a"]


@pytest.mark.asyncio
async def test_analytics_helpers_select_the_release_when_asked(db):
    from app.api.v1.helpers.analytics import get_latest_scan_ids, get_projects_with_scans

    await db.projects.insert_one({"_id": _PROJECT_A, "name": "alpha", "latest_scan_id": "head-a"})
    await db.scans.insert_one(_scan("head-a", _PROJECT_A, created_delta=9))
    await db.scans.insert_one(_scan("released-a", _PROJECT_A))
    await db.releases.insert_one(_release(_PROJECT_A, _PRODUCTION, "released-a"))

    assert await get_latest_scan_ids([_PROJECT_A], db, release_environment=_PRODUCTION) == ["released-a"]
    _, scan_ids = await get_projects_with_scans([_PROJECT_A], db, release_environment=_PRODUCTION)
    assert scan_ids == ["released-a"]


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_get_projects_with_scans_reads_the_projects_once(db, project_count):
    """The name map and the resolver's scope are the same read, not one each."""
    from app.api.v1.helpers.analytics import get_projects_with_scans

    project_ids = await _seed_one_pointed_scan_each(db, project_count)
    counts = _count_queries(db)

    await get_projects_with_scans(project_ids, db)

    assert dict(counts) == _NAMES_AND_HEAD_QUERIES


@pytest.mark.parametrize("project_count", [_ONE_PROJECT, _MANY_PROJECTS])
@pytest.mark.asyncio
async def test_get_projects_with_scans_release_mode_reads_the_projects_once(db, project_count):
    from app.api.v1.helpers.analytics import get_projects_with_scans

    project_ids = await _seed_one_scan_each(db, project_count)
    counts = _count_queries(db)

    await get_projects_with_scans(project_ids, db, release_environment=_PRODUCTION)

    assert dict(counts) == _NAMES_AND_RELEASE_QUERIES


def test_scope_resolution_counts_reports_the_projects_that_never_resolved():
    from app.api.v1.helpers.analytics import scope_resolution_counts

    assert scope_resolution_counts([_PROJECT_A, _PROJECT_B, _OTHER_PROJECT], ["head-a"]) == (1, 2)

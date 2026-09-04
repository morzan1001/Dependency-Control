"""The scheduler and the latest-scan guard driven together over consecutive intervals: targets stay
originals and only the branch-tip lineage keeps the project slot."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.housekeeping import _build_rescan, _rescan_targets
from app.models.project import Project
from app.models.release import Release
from app.repositories import ProjectRepository, ScanRepository
from app.services.analysis.engine import _should_update_project_latest_scan
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p1"
_PROJECT_NAME = "proj"
_HEAD_SCAN_ID = "head"
_RELEASED_SCAN_ID = "released"
_MAIN_BRANCH = "main"
_PRODUCTION_ENVIRONMENT = "production"
_RELEASE_ROW_ID = "release:production"
_GRIDFS_ID = "gridfs-1"

_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_RELEASE_AGE = timedelta(days=30)
_INTERVAL = timedelta(hours=24)
_WITHIN_PASS_SPACING = timedelta(minutes=1)
_INTERVAL_COUNT = 3


@dataclass(frozen=True)
class _Pass:
    target_ids: tuple[str, ...]
    outcomes: tuple[tuple[str | None, bool], ...]


def _project() -> Project:
    return Project(id=_PROJECT_ID, name=_PROJECT_NAME, last_scan_at=_T0)


async def _seed_original(db: FakeDatabase, scan_id: str, created_at: datetime) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": _PROJECT_ID,
            "branch": _MAIN_BRANCH,
            "status": SCAN_STATUS_COMPLETED,
            "created_at": created_at,
            "sbom_refs": [{"gridfs_id": _GRIDFS_ID}],
        }
    )


async def _seed_project_with_head(db: FakeDatabase) -> None:
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": _HEAD_SCAN_ID})
    await _seed_original(db, _HEAD_SCAN_ID, _T0)


async def _seed_release(db: FakeDatabase) -> None:
    await _seed_original(db, _RELEASED_SCAN_ID, _T0 - _RELEASE_AGE)
    release = Release(
        id=_RELEASE_ROW_ID,
        project_id=_PROJECT_ID,
        environment=_PRODUCTION_ENVIRONMENT,
        scan_id=_RELEASED_SCAN_ID,
        released_at=_T0,
    )
    await db.releases.insert_one(release.model_dump(by_alias=True))


async def _latest_scan_id(db: FakeDatabase) -> str | None:
    project: dict[str, Any] = await db.projects.find_one({"_id": _PROJECT_ID})
    latest_scan_id: str | None = project.get("latest_scan_id")
    return latest_scan_id


async def _rescan_pass(db: FakeDatabase, clock: datetime) -> _Pass:
    """One scheduler pass: every due target is rescanned, and every rescan is offered the slot."""
    project = _project()
    targets = await _rescan_targets(project, db)
    outcomes: list[tuple[str | None, bool]] = []

    for position, source in enumerate(targets):
        rescan = _build_rescan(project, source)
        rescan.created_at = clock + position * _WITHIN_PASS_SPACING
        await db.scans.insert_one(rescan.model_dump(by_alias=True))
        await db.scans.update_one(
            {"_id": source["_id"]},
            {"$set": {"latest_rescan_id": rescan.id, "last_rescanned_at": rescan.created_at}},
        )

        won = await _should_update_project_latest_scan(
            rescan.id, rescan, _PROJECT_ID, ScanRepository(db), ProjectRepository(db)
        )
        if won:
            await db.projects.update_one({"_id": _PROJECT_ID}, {"$set": {"latest_scan_id": rescan.id}})

        # The rescan finishes before the next pass; a pending one could never be a source at all.
        await db.scans.update_one({"_id": rescan.id}, {"$set": {"status": SCAN_STATUS_COMPLETED}})
        outcomes.append((rescan.original_scan_id, won))

    return _Pass(tuple(str(t["_id"]) for t in targets), tuple(outcomes))


async def _run_intervals(db: FakeDatabase) -> list[_Pass]:
    return [await _rescan_pass(db, _T0 + (interval + 1) * _INTERVAL) for interval in range(_INTERVAL_COUNT)]


@pytest.fixture
def db() -> FakeDatabase:
    return FakeDatabase()


class TestProjectWithARelease:
    @pytest.mark.asyncio
    async def test_the_tip_lineage_is_targeted_and_wins_the_slot_on_every_interval(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)
        await _seed_release(db)

        passes = await _run_intervals(db)

        assert (
            passes
            == [
                _Pass(
                    target_ids=(_HEAD_SCAN_ID, _RELEASED_SCAN_ID),
                    outcomes=((_HEAD_SCAN_ID, True), (_RELEASED_SCAN_ID, False)),
                )
            ]
            * _INTERVAL_COUNT
        )

    @pytest.mark.asyncio
    async def test_every_rescan_hangs_directly_off_an_original(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)
        await _seed_release(db)

        await _run_intervals(db)

        rescans = await db.scans.find({"is_rescan": True}).to_list(None)
        assert len(rescans) == 2 * _INTERVAL_COUNT
        assert {r["original_scan_id"] for r in rescans} == {_HEAD_SCAN_ID, _RELEASED_SCAN_ID}

    @pytest.mark.asyncio
    async def test_the_project_ends_on_the_newest_rescan_of_the_tip(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)
        await _seed_release(db)

        await _run_intervals(db)

        head = await db.scans.find_one({"_id": _HEAD_SCAN_ID})
        assert await _latest_scan_id(db) == head["latest_rescan_id"]

    @pytest.mark.asyncio
    async def test_no_rescan_of_the_release_ever_holds_the_slot(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)
        await _seed_release(db)

        await _run_intervals(db)

        release_lineage = await db.scans.find({"original_scan_id": _RELEASED_SCAN_ID}).to_list(None)
        assert release_lineage
        assert await _latest_scan_id(db) not in {r["_id"] for r in release_lineage}


class TestProjectWithoutARelease:
    @pytest.mark.asyncio
    async def test_the_tip_lineage_is_targeted_and_wins_the_slot_on_every_interval(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)

        passes = await _run_intervals(db)

        assert passes == [_Pass(target_ids=(_HEAD_SCAN_ID,), outcomes=((_HEAD_SCAN_ID, True),))] * _INTERVAL_COUNT

    @pytest.mark.asyncio
    async def test_the_chain_never_grows_past_one_link(self, db: FakeDatabase) -> None:
        await _seed_project_with_head(db)

        await _run_intervals(db)

        rescans = await db.scans.find({"is_rescan": True}).to_list(None)
        assert len(rescans) == _INTERVAL_COUNT
        assert {r["original_scan_id"] for r in rescans} == {_HEAD_SCAN_ID}

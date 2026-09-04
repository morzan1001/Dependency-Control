"""Characterisation of the scheduled-rescan path as it behaves today."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.core import housekeeping
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
)
from app.core.housekeeping import (
    _build_rescan,
    _create_rescan_for_project,
    _is_rescan_due,
    _process_project_rescan,
    _rescan_targets,
    _resolve_rescan_interval,
    check_scheduled_rescans,
)
from app.models.project import Project, Scan
from app.models.release import Release
from app.models.system import SystemSettings
from app.repositories import DistributedLocksRepository
from app.repositories.system_settings import SystemSettingsRepository
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p1"
_PROJECT_NAME = "proj"
_OTHER_PROJECT_ID = "p2"
_OTHER_PROJECT_NAME = "other"
_UNSCANNED_PROJECT_ID = "p3"
_UNSCANNED_PROJECT_NAME = "unscanned"

_MAIN_BRANCH = "main"
_FEATURE_BRANCH = "feature"
_HOTFIX_BRANCH = "hotfix"
_UNKNOWN_BRANCH = "unknown"

_SOURCE_SCAN_ID = "src-1"
_OLD_SCAN_ID = "src-0"
_FEATURE_SCAN_ID = "src-feature"
_HOTFIX_SCAN_ID = "src-hotfix"
_EMPTY_SBOM_SCAN_ID = "src-no-sboms"
_ABSENT_SBOM_SCAN_ID = "src-sbom-field-missing"
_FAILED_SCAN_ID = "src-failed"
_ACTIVE_SCAN_ID = "src-active"
_FOREIGN_SCAN_ID = "src-foreign"
_OTHER_SOURCE_SCAN_ID = "src-other"
_ROOT_SCAN_ID = "root"
_PREVIOUS_RESCAN_ID = "prev-rescan"
# Seeded high-id first, so insertion order alone would hand it the tip.
_TIED_TIP_HIGH_ID = "src-tie-z"
_TIED_TIP_LOW_ID = "src-tie-a"
_INFLIGHT_RESCAN_ID = "inflight-rescan"
_RELEASED_SCAN_ID = "src-released"
_ROLLED_BACK_SCAN_ID = "src-rolled-back"
_STAGED_SCAN_ID = "src-staged"

_PRODUCTION_ENVIRONMENT = "production"
_STAGING_ENVIRONMENT = "staging"
_RELEASE_ROW_PREFIX = "release:"

_COMMIT_HASH = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
_COMMIT_TAG = "v1.0.0"
_COMMIT_MESSAGE = "bump the parser"
_PROJECT_URL = "https://example.invalid/group/proj"
_PIPELINE_URL = "https://example.invalid/group/proj/-/pipelines/99"
_JOB_STARTED_AT = "2026-08-01T00:00:00Z"
_GRIDFS_ID = "gridfs-1"
_PIPELINE_ID = 99
_PIPELINE_IID = 7
_JOB_ID = 5
_PIPELINE_USER = "ci-bot"
_CBOM_SCAN_TYPE = "cbom"
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

_SCAN_MODEL_FIELDS = frozenset(
    {
        "id",
        "created_at",
        "project_id",
        "branch",
        "commit_hash",
        "pipeline_id",
        "pipeline_iid",
        "project_url",
        "pipeline_url",
        "job_id",
        "job_started_at",
        "project_name",
        "commit_message",
        "commit_tag",
        "pipeline_user",
        "sbom_refs",
        "scan_type",
        "status",
        "retry_count",
        "worker_id",
        "analysis_started_at",
        "error",
        "failed_analyzers",
        "enrichment_failures",
        "findings_summary",
        "findings_count",
        "stats",
        "completed_at",
        "reachability_pending",
        "reachability_pending_since",
        "pinned",
        "is_release",
        "is_rescan",
        "original_scan_id",
        "latest_rescan_id",
        "last_rescanned_at",
        "latest_run",
        "last_result_at",
        "received_results",
    }
)

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

_DEFAULT_INTERVAL_HOURS = 24
_PROJECT_INTERVAL_HOURS = 6
_GLOBAL_INTERVAL_HOURS = 48
_ZERO_INTERVAL_HOURS = 0
_NEGATIVE_INTERVAL_HOURS = -1

_LOCK_TTL_SECONDS = 60
_EXPIRED_LOCK_TTL_SECONDS = -_LOCK_TTL_SECONDS
_RESCAN_LOCK_PREFIX = "rescan_create:"
_FOREIGN_LOCK_HOLDER = "another-pod"
_FAILURE_MESSAGE = "kaboom"

_NOW = datetime.now(timezone.utc)
_WITHIN_INTERVAL = timedelta(hours=1)
_PAST_INTERVAL = timedelta(hours=30)
# _RECENT and everything older must clear _DEFAULT_INTERVAL_HOURS: a source-selection test only
# reaches the selection once the source it expects is due.
_RECENT = timedelta(days=2)
_STALE = timedelta(days=3)
_OLDER = timedelta(days=9)
_ANCIENT = timedelta(days=30)


def _lock_name(project_id: str, source_scan_id: str) -> str:
    return f"{_RESCAN_LOCK_PREFIX}{project_id}:{source_scan_id}"


def _sbom_refs() -> list[dict[str, str]]:
    return [{"gridfs_id": _GRIDFS_ID}]


def _system_settings(**overrides: Any) -> SystemSettings:
    values: dict[str, Any] = {
        "global_rescan_enabled": True,
        "global_rescan_interval": _DEFAULT_INTERVAL_HOURS,
    }
    values.update(overrides)
    return SystemSettings(**values)


def _project_doc(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": _PROJECT_ID,
        "name": _PROJECT_NAME,
        "last_scan_at": _NOW - _STALE,
    }
    doc.update(overrides)
    return doc


def _project(**overrides: Any) -> Project:
    return Project(**_project_doc(**overrides))


def _scan_doc(scan_id: str = _SOURCE_SCAN_ID, **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": _MAIN_BRANCH,
        "commit_hash": _COMMIT_HASH,
        "commit_message": _COMMIT_MESSAGE,
        "commit_tag": _COMMIT_TAG,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": _NOW - _STALE,
        "sbom_refs": _sbom_refs(),
        "pipeline_id": _PIPELINE_ID,
        "pipeline_iid": _PIPELINE_IID,
        "project_url": _PROJECT_URL,
        "pipeline_url": _PIPELINE_URL,
        "job_id": _JOB_ID,
        "job_started_at": _JOB_STARTED_AT,
        "project_name": _PROJECT_NAME,
    }
    doc.update(overrides)
    return doc


def _saturated_scan_doc() -> dict[str, Any]:
    """A source holding every Scan field at a value a freshly built rescan does not hold, so a field
    whose value survives into the rescan is exactly a field the builder copied."""
    return _scan_doc(
        pipeline_user=_PIPELINE_USER,
        scan_type=_CBOM_SCAN_TYPE,
        retry_count=_RETRY_COUNT,
        worker_id=_WORKER_ID,
        analysis_started_at=_NOW - _STALE,
        error=_SCAN_ERROR,
        failed_analyzers=[_FAILED_ANALYZER],
        enrichment_failures=[_ENRICHMENT_FAILURE],
        findings_summary=_FINDINGS_SUMMARY,
        findings_count=_FINDINGS_COUNT,
        stats=_STATS,
        completed_at=_NOW - _RECENT,
        reachability_pending=True,
        reachability_pending_since=_NOW - _RECENT,
        pinned=True,
        is_release=True,
        is_rescan=False,
        original_scan_id=None,
        latest_rescan_id=_PREVIOUS_RESCAN_ID,
        last_rescanned_at=_NOW - _RECENT,
        latest_run=_LATEST_RUN,
        last_result_at=_NOW - _RECENT,
        received_results=_RECEIVED_RESULTS,
    )


def _carried_fields(source: dict[str, Any], rescan: Scan) -> set[str]:
    return {name for name in Scan.model_fields if getattr(rescan, name) == source.get(name)}


async def _seed_scan(db: FakeDatabase, scan_id: str = _SOURCE_SCAN_ID, **overrides: Any) -> dict[str, Any]:
    await db.scans.insert_one(_scan_doc(scan_id, **overrides))
    stored: dict[str, Any] = await db.scans.find_one({"_id": scan_id})
    return stored


async def _seed_release(db: FakeDatabase, environment: str, scan_id: str, released_at: datetime = _NOW) -> None:
    release = Release(
        id=f"{_RELEASE_ROW_PREFIX}{environment}:{scan_id}",
        project_id=_PROJECT_ID,
        environment=environment,
        scan_id=scan_id,
        released_at=released_at,
    )
    await db.releases.insert_one(release.model_dump(by_alias=True))


async def _seed_system_settings(db: FakeDatabase, **overrides: Any) -> None:
    document = _system_settings(**overrides).model_dump(by_alias=True)
    document["_id"] = SystemSettingsRepository.SETTINGS_ID
    await db.system_settings.insert_one(document)


async def _seed_inflight_rescan(db: FakeDatabase, original_scan_id: str = _SOURCE_SCAN_ID) -> None:
    await db.scans.insert_one(
        _scan_doc(
            _INFLIGHT_RESCAN_ID,
            status=SCAN_STATUS_PROCESSING,
            created_at=_NOW,
            is_rescan=True,
            original_scan_id=original_scan_id,
        )
    )


async def _seed_expired_lock(db: FakeDatabase) -> DistributedLocksRepository:
    """A stale entry under the source's lock name: only a take-over of that exact name clears it."""
    locks = DistributedLocksRepository(db)
    await locks.acquire_lock(
        _lock_name(_PROJECT_ID, _SOURCE_SCAN_ID), _FOREIGN_LOCK_HOLDER, ttl_seconds=_EXPIRED_LOCK_TTL_SECONDS
    )
    return locks


async def _rescans(db: FakeDatabase) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = await db.scans.find({"is_rescan": True}).to_list(None)
    return docs


@pytest.fixture
def db() -> FakeDatabase:
    return FakeDatabase()


@pytest.fixture
def worker() -> AsyncMock:
    return AsyncMock()


class TestResolveRescanInterval:
    def test_a_project_opt_in_beats_the_global_switch_being_off(self) -> None:
        project = _project(rescan_enabled=True, rescan_interval=_PROJECT_INTERVAL_HOURS)
        settings = _system_settings(global_rescan_enabled=False)

        assert _resolve_rescan_interval(project, settings) == _PROJECT_INTERVAL_HOURS

    def test_a_project_opt_out_beats_the_global_switch_being_on(self) -> None:
        assert _resolve_rescan_interval(_project(rescan_enabled=False), _system_settings()) is None

    def test_the_global_switch_decides_when_the_project_has_no_opinion(self) -> None:
        assert _resolve_rescan_interval(_project(), _system_settings()) == _DEFAULT_INTERVAL_HOURS
        assert _resolve_rescan_interval(_project(), _system_settings(global_rescan_enabled=False)) is None

    def test_the_project_interval_wins_over_the_global_one(self) -> None:
        project = _project(rescan_interval=_PROJECT_INTERVAL_HOURS)
        settings = _system_settings(global_rescan_interval=_GLOBAL_INTERVAL_HOURS)

        assert _resolve_rescan_interval(project, settings) == _PROJECT_INTERVAL_HOURS

    def test_the_global_interval_applies_when_the_project_sets_none(self) -> None:
        settings = _system_settings(global_rescan_interval=_GLOBAL_INTERVAL_HOURS)

        assert _resolve_rescan_interval(_project(), settings) == _GLOBAL_INTERVAL_HOURS

    def test_an_interval_of_zero_disables_rescans_that_are_otherwise_switched_on(self) -> None:
        project = _project(rescan_enabled=True, rescan_interval=_ZERO_INTERVAL_HOURS)

        assert _resolve_rescan_interval(project, _system_settings()) is None

    def test_a_negative_interval_disables_rescans(self) -> None:
        project = _project(rescan_enabled=True, rescan_interval=_NEGATIVE_INTERVAL_HOURS)

        assert _resolve_rescan_interval(project, _system_settings()) is None


class TestIsRescanDue:
    """The clock is the source scan's own, so CI traffic on the project cannot postpone it."""

    def test_due_once_the_interval_has_elapsed_since_the_source_was_created(self) -> None:
        assert _is_rescan_due(_scan_doc(created_at=_NOW - _PAST_INTERVAL), _DEFAULT_INTERVAL_HOURS) is True

    # Every scan persisted through the model carries this key with a null value, so a
    # never-rescanned source reaches the fallback with the key present, not absent.
    def test_due_when_the_rescan_clock_is_present_but_null_and_the_source_is_old(self) -> None:
        source = _scan_doc(created_at=_NOW - _PAST_INTERVAL, last_rescanned_at=None)

        assert "last_rescanned_at" in source
        assert _is_rescan_due(source, _DEFAULT_INTERVAL_HOURS) is True

    def test_not_due_while_the_interval_is_still_running(self) -> None:
        assert _is_rescan_due(_scan_doc(created_at=_NOW - _WITHIN_INTERVAL), _DEFAULT_INTERVAL_HOURS) is False

    def test_a_source_rescanned_inside_the_interval_is_not_due_however_old_it_is(self) -> None:
        source = _scan_doc(created_at=_NOW - _ANCIENT, last_rescanned_at=_NOW - _WITHIN_INTERVAL)

        assert _is_rescan_due(source, _DEFAULT_INTERVAL_HOURS) is False

    def test_due_again_once_the_interval_has_elapsed_since_the_last_rescan(self) -> None:
        source = _scan_doc(created_at=_NOW - _ANCIENT, last_rescanned_at=_NOW - _PAST_INTERVAL)

        assert _is_rescan_due(source, _DEFAULT_INTERVAL_HOURS) is True

    def test_a_source_carrying_no_timestamp_at_all_is_never_due(self) -> None:
        source = _scan_doc()
        del source["created_at"]

        assert _is_rescan_due(source, _DEFAULT_INTERVAL_HOURS) is False

    def test_a_naive_timestamp_as_mongo_returns_it_is_read_as_utc(self) -> None:
        naive = (_NOW - _PAST_INTERVAL).replace(tzinfo=None)

        assert _is_rescan_due(_scan_doc(created_at=naive), _DEFAULT_INTERVAL_HOURS) is True


class TestBuildRescan:
    def test_carries_the_source_ci_metadata_into_a_fresh_pending_scan(self) -> None:
        rescan = _build_rescan(_project(), _scan_doc())

        assert rescan.id != _SOURCE_SCAN_ID
        assert rescan.status == SCAN_STATUS_PENDING
        assert rescan.is_rescan is True
        assert rescan.original_scan_id == _SOURCE_SCAN_ID
        assert rescan.project_id == _PROJECT_ID
        assert rescan.branch == _MAIN_BRANCH
        assert rescan.commit_hash == _COMMIT_HASH
        assert rescan.commit_message == _COMMIT_MESSAGE
        assert rescan.commit_tag == _COMMIT_TAG
        assert rescan.sbom_refs == _sbom_refs()
        assert rescan.pipeline_iid == _PIPELINE_IID
        assert rescan.job_id == _JOB_ID
        assert rescan.job_started_at == _JOB_STARTED_AT
        assert rescan.project_url == _PROJECT_URL
        assert rescan.pipeline_url == _PIPELINE_URL
        assert rescan.project_name == _PROJECT_NAME

    def test_the_pipeline_id_is_dropped_so_a_rescan_cannot_be_mistaken_for_an_ingest(self) -> None:
        assert _build_rescan(_project(), _scan_doc()).pipeline_id is None

    def test_a_source_carrying_no_branch_field_is_rescanned_as_unknown(self) -> None:
        source = _scan_doc()
        del source["branch"]

        assert _build_rescan(_project(), source).branch == _UNKNOWN_BRANCH

    def test_the_release_flag_is_not_inherited(self) -> None:
        assert _build_rescan(_project(), _scan_doc(is_release=True)).is_release is False

    def test_the_cbom_scan_type_is_carried_so_the_rescan_selects_the_same_analyzers(self) -> None:
        assert _build_rescan(_project(), _scan_doc(scan_type=_CBOM_SCAN_TYPE)).scan_type == _CBOM_SCAN_TYPE

    def test_a_source_carrying_no_scan_type_produces_a_rescan_without_one(self) -> None:
        assert _build_rescan(_project(), _scan_doc()).scan_type is None

    def test_the_pipeline_user_is_not_inherited(self) -> None:
        assert _build_rescan(_project(), _scan_doc(pipeline_user=_PIPELINE_USER)).pipeline_user is None

    def test_the_rescan_clock_is_not_inherited_so_the_fresh_scan_starts_from_its_own_creation(self) -> None:
        assert _build_rescan(_project(), _scan_doc(last_rescanned_at=_NOW)).last_rescanned_at is None

    def test_the_scan_model_holds_exactly_the_pinned_fields(self) -> None:
        """Widening Scan is a decision about what a rescan inherits, so it has to be made here."""
        assert set(Scan.model_fields) == _SCAN_MODEL_FIELDS

    def test_a_rescan_carries_exactly_the_pinned_fields_and_nothing_else(self) -> None:
        source = _saturated_scan_doc()

        assert _carried_fields(source, _build_rescan(_project(), source)) == _CARRIED_FROM_SOURCE


class TestCreateRescanForProject:
    @pytest.mark.asyncio
    async def test_inserts_the_rescan_points_the_source_at_it_and_queues_the_job(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        rescans = await _rescans(db)
        assert len(rescans) == 1
        assert rescans[0]["original_scan_id"] == _SOURCE_SCAN_ID
        stored_source = await db.scans.find_one({"_id": _SOURCE_SCAN_ID})
        assert stored_source["latest_rescan_id"] == rescans[0]["_id"]
        worker.add_job.assert_awaited_once_with(rescans[0]["_id"])

    @pytest.mark.asyncio
    async def test_creating_a_rescan_stamps_the_clock_on_the_source(self, db: FakeDatabase, worker: AsyncMock) -> None:
        source = await _seed_scan(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        stored_source = await db.scans.find_one({"_id": _SOURCE_SCAN_ID})
        assert stored_source["last_rescanned_at"] is not None

    @pytest.mark.asyncio
    async def test_the_source_scan_is_not_given_a_latest_run_summary(self, db: FakeDatabase, worker: AsyncMock) -> None:
        source = await _seed_scan(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        stored_source = await db.scans.find_one({"_id": _SOURCE_SCAN_ID})
        assert stored_source.get("latest_run") is None

    @pytest.mark.asyncio
    async def test_a_lock_held_for_this_source_stops_the_creation(self, db: FakeDatabase, worker: AsyncMock) -> None:
        source = await _seed_scan(db)
        await DistributedLocksRepository(db).acquire_lock(
            _lock_name(_PROJECT_ID, _SOURCE_SCAN_ID), _FOREIGN_LOCK_HOLDER, ttl_seconds=_LOCK_TTL_SECONDS
        )

        await _create_rescan_for_project(_project(), source, db, worker)

        assert await _rescans(db) == []
        worker.add_job.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_lock_held_for_a_different_project_does_not_stop_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await DistributedLocksRepository(db).acquire_lock(
            _lock_name(_OTHER_PROJECT_ID, _SOURCE_SCAN_ID), _FOREIGN_LOCK_HOLDER, ttl_seconds=_LOCK_TTL_SECONDS
        )

        await _create_rescan_for_project(_project(), source, db, worker)

        assert len(await _rescans(db)) == 1

    @pytest.mark.asyncio
    async def test_a_lock_held_for_another_source_of_the_same_project_does_not_stop_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await DistributedLocksRepository(db).acquire_lock(
            _lock_name(_PROJECT_ID, _OTHER_SOURCE_SCAN_ID), _FOREIGN_LOCK_HOLDER, ttl_seconds=_LOCK_TTL_SECONDS
        )

        await _create_rescan_for_project(_project(), source, db, worker)

        assert len(await _rescans(db)) == 1
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_the_lock_is_released_once_the_rescan_is_created(self, db: FakeDatabase, worker: AsyncMock) -> None:
        source = await _seed_scan(db)
        locks = await _seed_expired_lock(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        assert await locks.get_lock_info(_lock_name(_PROJECT_ID, _SOURCE_SCAN_ID)) is None

    @pytest.mark.asyncio
    async def test_the_lock_is_released_when_an_active_rescan_aborts_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await _seed_inflight_rescan(db)
        locks = await _seed_expired_lock(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        assert await locks.get_lock_info(_lock_name(_PROJECT_ID, _SOURCE_SCAN_ID)) is None

    @pytest.mark.asyncio
    async def test_an_active_rescan_of_this_source_stops_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await _seed_inflight_rescan(db)

        await _create_rescan_for_project(_project(), source, db, worker)

        assert [r["_id"] for r in await _rescans(db)] == [_INFLIGHT_RESCAN_ID]
        worker.add_job.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_an_active_scan_on_another_branch_of_the_project_does_not_stop_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await _seed_scan(db, _ACTIVE_SCAN_ID, branch=_FEATURE_BRANCH, status=SCAN_STATUS_PROCESSING, created_at=_NOW)

        await _create_rescan_for_project(_project(), source, db, worker)

        assert len(await _rescans(db)) == 1
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_an_active_rescan_of_another_source_does_not_stop_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await _seed_inflight_rescan(db, original_scan_id=_OTHER_SOURCE_SCAN_ID)

        await _create_rescan_for_project(_project(), source, db, worker)

        created = [r for r in await _rescans(db) if r["_id"] != _INFLIGHT_RESCAN_ID]
        assert len(created) == 1
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_a_pending_scan_of_a_different_project_does_not_stop_the_creation(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)
        await _seed_scan(
            db, _FOREIGN_SCAN_ID, project_id=_OTHER_PROJECT_ID, status=SCAN_STATUS_PENDING, created_at=_NOW
        )

        await _create_rescan_for_project(_project(), source, db, worker)

        assert len(await _rescans(db)) == 1

    @pytest.mark.asyncio
    async def test_the_pending_rescan_of_a_first_run_blocks_a_second_one(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        source = await _seed_scan(db)

        await _create_rescan_for_project(_project(), source, db, worker)
        await _create_rescan_for_project(_project(), source, db, worker)

        assert len(await _rescans(db)) == 1
        assert worker.add_job.await_count == 1


class TestProcessProjectRescan:
    @pytest.mark.asyncio
    async def test_sources_the_newest_completed_scan_that_still_has_sboms(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _OLD_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT)
        await _seed_scan(db, _EMPTY_SBOM_SCAN_ID, created_at=_NOW, sbom_refs=[])
        await _seed_scan(db, _FAILED_SCAN_ID, created_at=_NOW, status=SCAN_STATUS_FAILED)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID]

    @pytest.mark.asyncio
    async def test_a_scan_completed_with_errors_is_still_a_usable_source(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, status=SCAN_STATUS_COMPLETED_WITH_ERRORS)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID]

    @pytest.mark.asyncio
    async def test_a_due_project_whose_scans_all_lack_sboms_gets_nothing(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _EMPTY_SBOM_SCAN_ID, sbom_refs=[])
        absent = _scan_doc(_ABSENT_SBOM_SCAN_ID)
        del absent["sbom_refs"]
        await db.scans.insert_one(absent)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert await _rescans(db) == []
        worker.add_job.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_original_stays_the_source_so_the_lineage_never_grows_past_one_link(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        """A rescan is this loop's own output; sourcing from it would deepen the chain every
        interval and hand the tip to whichever rescan ran last."""
        await _seed_scan(db, _ROOT_SCAN_ID, created_at=_NOW - _OLDER, latest_rescan_id=_PREVIOUS_RESCAN_ID)
        await _seed_scan(
            db,
            _PREVIOUS_RESCAN_ID,
            created_at=_NOW - _RECENT,
            is_rescan=True,
            original_scan_id=_ROOT_SCAN_ID,
        )

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        created = [r for r in await _rescans(db) if r["_id"] != _PREVIOUS_RESCAN_ID]
        assert len(created) == 1
        assert created[0]["original_scan_id"] == _ROOT_SCAN_ID
        root = await db.scans.find_one({"_id": _ROOT_SCAN_ID})
        assert root["latest_rescan_id"] == created[0]["_id"]
        previous = await db.scans.find_one({"_id": _PREVIOUS_RESCAN_ID})
        assert previous.get("latest_rescan_id") is None

    @pytest.mark.asyncio
    async def test_the_tip_is_the_newest_original_even_when_a_rescan_is_newer(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        """Tri-state: the flag is absent on scans predating it, so only an explicit True is skipped."""
        await _seed_scan(db, _OLD_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT, is_rescan=False)
        await _seed_scan(
            db,
            _PREVIOUS_RESCAN_ID,
            created_at=_NOW,
            is_rescan=True,
            original_scan_id=_SOURCE_SCAN_ID,
        )

        targets = await _rescan_targets(_project(), db)

        assert [t["_id"] for t in targets] == [_SOURCE_SCAN_ID]

    @pytest.mark.asyncio
    async def test_the_tip_of_two_scans_sharing_a_created_at_is_the_lower_id(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        """Dates are stored to the millisecond, so parallel CI can land two scans on the same one.
        A tip that alternates between passes hands each alternate a clock it was never rescanned on,
        so the pair rescans every pass instead of once per interval."""
        tied_at = _NOW - _RECENT
        await _seed_scan(db, _TIED_TIP_HIGH_ID, created_at=tied_at)
        await _seed_scan(db, _TIED_TIP_LOW_ID, created_at=tied_at)

        targets = await _rescan_targets(_project(), db)

        assert [t["_id"] for t in targets] == [_TIED_TIP_LOW_ID]

    @pytest.mark.asyncio
    async def test_the_newest_scan_wins_even_when_it_is_not_on_the_default_branch(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, branch=_MAIN_BRANCH, created_at=_NOW - _OLDER)
        await _seed_scan(db, _FEATURE_SCAN_ID, branch=_FEATURE_BRANCH, created_at=_NOW - _RECENT)

        await _process_project_rescan(_project_doc(default_branch=_MAIN_BRANCH), _system_settings(), db, worker)

        rescans = await _rescans(db)
        assert [r["original_scan_id"] for r in rescans] == [_FEATURE_SCAN_ID]
        assert rescans[0]["branch"] == _FEATURE_BRANCH

    @pytest.mark.asyncio
    async def test_a_project_gets_exactly_one_rescan_however_many_branches_are_usable(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, branch=_MAIN_BRANCH, created_at=_NOW - _OLDER)
        await _seed_scan(db, _FEATURE_SCAN_ID, branch=_FEATURE_BRANCH, created_at=_NOW - _STALE)
        await _seed_scan(db, _HOTFIX_SCAN_ID, branch=_HOTFIX_BRANCH, created_at=_NOW - _RECENT)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert len(await _rescans(db)) == 1
        assert worker.add_job.await_count == 1

    @pytest.mark.asyncio
    async def test_another_projects_newer_scan_is_never_taken_as_the_source(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_scan(db, _FOREIGN_SCAN_ID, project_id=_OTHER_PROJECT_ID, created_at=_NOW - _RECENT)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID]

    @pytest.mark.asyncio
    async def test_disabled_rescans_create_nothing(self, db: FakeDatabase, worker: AsyncMock) -> None:
        await _seed_scan(db)

        await _process_project_rescan(_project_doc(), _system_settings(global_rescan_enabled=False), db, worker)

        assert await _rescans(db) == []
        worker.add_job.assert_not_awaited()


class TestReleaseRescanTargets:
    """What runs in an environment is a second identity of the project, and the tip of a branch is
    no evidence about it, so both are re-evaluated."""

    @pytest.mark.asyncio
    async def test_a_release_past_the_interval_is_rescanned_alongside_a_due_tip(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT)
        await _seed_scan(db, _RELEASED_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _RELEASED_SCAN_ID)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        rescans = await _rescans(db)
        assert {r["original_scan_id"] for r in rescans} == {_SOURCE_SCAN_ID, _RELEASED_SCAN_ID}
        assert len(rescans) == 2
        assert worker.add_job.await_count == 2

    @pytest.mark.asyncio
    async def test_an_environment_contributes_only_its_newest_release(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT)
        await _seed_scan(db, _RELEASED_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_scan(db, _ROLLED_BACK_SCAN_ID, created_at=_NOW - _ANCIENT)
        await _seed_scan(db, _STAGED_SCAN_ID, created_at=_NOW - _STALE)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _ROLLED_BACK_SCAN_ID, released_at=_NOW - _OLDER)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _RELEASED_SCAN_ID)
        await _seed_release(db, _STAGING_ENVIRONMENT, _STAGED_SCAN_ID)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert {r["original_scan_id"] for r in await _rescans(db)} == {
            _SOURCE_SCAN_ID,
            _RELEASED_SCAN_ID,
            _STAGED_SCAN_ID,
        }

    @pytest.mark.asyncio
    async def test_a_scan_that_is_both_the_tip_and_a_release_is_rescanned_once(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _SOURCE_SCAN_ID)

        targets = await _rescan_targets(_project(), db)
        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        # The in-lock guard would swallow a duplicate target, so the de-duplication is pinned here.
        assert [t["_id"] for t in targets] == [_SOURCE_SCAN_ID]
        assert len(await _rescans(db)) == 1
        assert worker.add_job.await_count == 1

    @pytest.mark.asyncio
    async def test_a_scan_released_to_two_environments_is_a_single_target(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT)
        await _seed_scan(db, _RELEASED_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _RELEASED_SCAN_ID)
        await _seed_release(db, _STAGING_ENVIRONMENT, _RELEASED_SCAN_ID)

        targets = await _rescan_targets(_project(), db)
        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        # The in-lock guard would swallow the second environment, so the de-duplication is pinned here.
        assert [t["_id"] for t in targets] == [_SOURCE_SCAN_ID, _RELEASED_SCAN_ID]
        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID, _RELEASED_SCAN_ID]
        assert worker.add_job.await_count == 2

    @pytest.mark.asyncio
    async def test_a_marked_scan_carrying_no_sboms_is_not_a_target(self, db: FakeDatabase, worker: AsyncMock) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _RECENT)
        await _seed_scan(db, _EMPTY_SBOM_SCAN_ID, created_at=_NOW - _OLDER, sbom_refs=[])
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _EMPTY_SBOM_SCAN_ID)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID]
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_a_due_release_is_rescanned_while_the_tip_is_still_fresh(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, _SOURCE_SCAN_ID, created_at=_NOW - _WITHIN_INTERVAL)
        await _seed_scan(db, _RELEASED_SCAN_ID, created_at=_NOW - _OLDER)
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _RELEASED_SCAN_ID)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_RELEASED_SCAN_ID]
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_the_target_is_the_marked_scan_rather_than_the_rescan_it_points_at(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        """Sourcing from the rescan would add a link per interval until the chain outruns the bound
        the release resolver walks, and the resolver would then answer with a mid-chain scan."""
        await _seed_scan(db, _RELEASED_SCAN_ID, created_at=_NOW - _OLDER, latest_rescan_id=_PREVIOUS_RESCAN_ID)
        await _seed_scan(
            db,
            _PREVIOUS_RESCAN_ID,
            created_at=_NOW - _RECENT,
            is_rescan=True,
            original_scan_id=_RELEASED_SCAN_ID,
        )
        await _seed_release(db, _PRODUCTION_ENVIRONMENT, _RELEASED_SCAN_ID)

        targets = await _rescan_targets(_project(), db)
        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert [t["_id"] for t in targets] == [_RELEASED_SCAN_ID]
        created = [r for r in await _rescans(db) if r["_id"] != _PREVIOUS_RESCAN_ID]
        assert [r["original_scan_id"] for r in created] == [_RELEASED_SCAN_ID]
        marked = await db.scans.find_one({"_id": _RELEASED_SCAN_ID})
        assert marked["latest_rescan_id"] == created[0]["_id"], "the chain stays one link deep"


class TestRescanClockIsIndependentOfCiTraffic:
    @pytest.mark.asyncio
    async def test_an_ancient_source_is_due_even_when_the_project_was_just_touched_by_ci(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, created_at=_NOW - _ANCIENT)

        await _process_project_rescan(_project_doc(last_scan_at=_NOW), _system_settings(), db, worker)

        assert [r["original_scan_id"] for r in await _rescans(db)] == [_SOURCE_SCAN_ID]
        worker.add_job.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_a_freshly_rescanned_source_is_skipped_even_when_it_is_ancient(
        self, db: FakeDatabase, worker: AsyncMock
    ) -> None:
        await _seed_scan(db, created_at=_NOW - _ANCIENT, last_rescanned_at=_NOW - _WITHIN_INTERVAL)

        await _process_project_rescan(_project_doc(), _system_settings(), db, worker)

        assert await _rescans(db) == []
        worker.add_job.assert_not_awaited()


class TestCheckScheduledRescans:
    @pytest.mark.asyncio
    async def test_a_due_project_gets_a_rescan_inserted_and_queued(
        self, db: FakeDatabase, worker: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _seed_system_settings(db)
        await db.projects.insert_one(_project_doc())
        await _seed_scan(db)
        monkeypatch.setattr(housekeeping, "get_database", AsyncMock(return_value=db))

        await check_scheduled_rescans(worker)

        rescans = await _rescans(db)
        assert [r["original_scan_id"] for r in rescans] == [_SOURCE_SCAN_ID]
        worker.add_job.assert_awaited_once_with(rescans[0]["_id"])

    @pytest.mark.asyncio
    async def test_the_stored_global_switch_can_turn_the_whole_sweep_off(
        self, db: FakeDatabase, worker: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _seed_system_settings(db, global_rescan_enabled=False)
        await db.projects.insert_one(_project_doc())
        await _seed_scan(db)
        monkeypatch.setattr(housekeeping, "get_database", AsyncMock(return_value=db))

        await check_scheduled_rescans(worker)

        assert await _rescans(db) == []
        worker.add_job.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_only_projects_that_have_already_been_scanned_reach_the_per_project_step(
        self, db: FakeDatabase, worker: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _seed_system_settings(db)
        await db.projects.insert_one(_project_doc())
        await db.projects.insert_one({"_id": _OTHER_PROJECT_ID, "name": _OTHER_PROJECT_NAME, "last_scan_at": None})
        await db.projects.insert_one({"_id": _UNSCANNED_PROJECT_ID, "name": _UNSCANNED_PROJECT_NAME})
        seen: list[str] = []

        async def _record(project_data: dict, _settings: Any, _db: Any, _worker: Any) -> None:
            seen.append(project_data["_id"])

        monkeypatch.setattr(housekeeping, "get_database", AsyncMock(return_value=db))
        monkeypatch.setattr(housekeeping, "_process_project_rescan", _record)

        await check_scheduled_rescans(worker)

        assert seen == [_PROJECT_ID]

    @pytest.mark.asyncio
    async def test_one_failing_project_does_not_abort_the_sweep(
        self, db: FakeDatabase, worker: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _seed_system_settings(db)
        await db.projects.insert_one(_project_doc())
        await db.projects.insert_one(_project_doc(_id=_OTHER_PROJECT_ID, name=_OTHER_PROJECT_NAME))
        seen: list[str] = []

        async def _explode(project_data: dict, _settings: Any, _db: Any, _worker: Any) -> None:
            if project_data["_id"] == _PROJECT_ID:
                raise RuntimeError(_FAILURE_MESSAGE)
            seen.append(project_data["_id"])

        monkeypatch.setattr(housekeeping, "get_database", AsyncMock(return_value=db))
        monkeypatch.setattr(housekeeping, "_process_project_rescan", _explode)

        await check_scheduled_rescans(worker)

        assert seen == [_OTHER_PROJECT_ID]

    @pytest.mark.asyncio
    async def test_a_database_failure_is_swallowed_so_the_housekeeping_loop_survives(
        self, worker: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(housekeeping, "get_database", AsyncMock(side_effect=RuntimeError(_FAILURE_MESSAGE)))

        await check_scheduled_rescans(worker)

        worker.add_job.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_without_a_worker_manager_the_database_is_never_opened(self, monkeypatch: pytest.MonkeyPatch) -> None:
        get_database = AsyncMock()
        monkeypatch.setattr(housekeeping, "get_database", get_database)

        await check_scheduled_rescans(None)

        get_database.assert_not_awaited()

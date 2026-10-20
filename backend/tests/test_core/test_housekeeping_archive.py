import asyncio
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import ARCHIVE_BATCH_SIZE, RETENTION_PROTECTED_FLAG_VALUES
from app.core.housekeeping import (
    _archive_scans_and_delete,
    _expire_group,
    _handle_retention_action,
    _retention_can_act,
    _run_retention,
)
from app.models.archive import ArchiveMetadata
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"
# archive_scan is lazy-imported inside _archive_scans_and_delete, so patch it at its source module.
ARCHIVE_SVC = "app.services.archive"


def _mock_db() -> MagicMock:
    """A mock database with a working lock collection, so retention gets past taking its lock."""
    db = MagicMock()
    db.distributed_locks = FakeDatabase().distributed_locks
    return db


async def _store_with(*scan_ids: str) -> FakeDatabase:
    db = FakeDatabase()
    for scan_id in scan_ids:
        await db.scans.insert_one({"_id": scan_id, "status": "completed"})
    return db


async def _remaining(db: FakeDatabase) -> set[str]:
    return {doc["_id"] async for doc in db.scans.find({})}


def _make_archive_metadata(scan_id="scan-1"):
    return ArchiveMetadata(
        project_id="proj-1",
        scan_id=scan_id,
        s3_key=f"proj-1/{scan_id}.json.gz",
        s3_bucket="dc-archives",
    )


class TestArchiveScansAndDelete:
    @pytest.mark.asyncio
    async def test_archives_and_deletes_successfully(self):
        db = await _store_with("scan-1")
        metadata = _make_archive_metadata()

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive:
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        mock_archive.assert_called_once()
        assert await _remaining(db) == set()

    @pytest.mark.asyncio
    async def test_skips_delete_for_failed_archives(self):
        db = await _store_with("scan-1")

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=None) as mock_archive:
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        mock_archive.assert_called_once()
        assert await _remaining(db) == {"scan-1"}

    @pytest.mark.asyncio
    async def test_partial_failure_only_deletes_successful(self):
        db = await _store_with("scan-1", "scan-2")

        async def mock_archive_fn(db, scan_id):
            if scan_id == "scan-1":
                return _make_archive_metadata(scan_id="scan-1")
            return None

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=mock_archive_fn):
            await _archive_scans_and_delete(db, ["scan-1", "scan-2"], "test")

        assert await _remaining(db) == {"scan-2"}

    @pytest.mark.asyncio
    async def test_handles_archive_exception(self):
        db = await _store_with("scan-1")

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=Exception("Archive crashed")):
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        assert await _remaining(db) == {"scan-1"}

    @pytest.mark.asyncio
    async def test_processes_all_provided_scan_ids(self):
        # Chunking is _process_scans_in_batches's job; this must process every ID it receives.
        scan_ids = [f"scan-{i}" for i in range(100)]
        metadata = _make_archive_metadata()

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive:
            await _archive_scans_and_delete(await _store_with(*scan_ids), scan_ids, "test")

        assert mock_archive.call_count == 100

    @pytest.mark.asyncio
    async def test_the_failure_warning_names_the_first_twenty_scans(self, caplog):
        scan_ids = [f"scan-{i:02d}" for i in range(25)]

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=None),
            caplog.at_level(logging.WARNING, logger=MODULE),
        ):
            await _archive_scans_and_delete(await _store_with(*scan_ids), scan_ids, "test")

        (warning,) = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
        assert all(scan_id in warning for scan_id in scan_ids[:20])
        assert not any(scan_id in warning for scan_id in scan_ids[20:])
        assert "25 scan(s)" in warning


class TestHandleRetentionAction:
    def test_delete_action_calls_delete(self):
        with patch(f"{MODULE}._delete_expirable", new_callable=AsyncMock) as mock_delete:
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "delete", "test"))

        mock_delete.assert_called_once()

    def test_archive_action_calls_archive(self):
        with patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive:
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "archive", "test"))

        mock_archive.assert_called_once()

    def test_empty_scan_list_returns_early(self):
        with (
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
            patch(f"{MODULE}._delete_expirable", new_callable=AsyncMock) as mock_delete,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), [], "delete", "test"))

        mock_archive.assert_not_called()
        mock_delete.assert_not_called()


class TestRetentionCanAct:
    @pytest.mark.parametrize(("action", "archive_enabled"), [("delete", False), ("archive", True)])
    def test_an_action_that_expires_scans_can_act(self, action, archive_enabled):
        with patch(f"{MODULE}.is_archive_enabled", return_value=archive_enabled):
            assert _retention_can_act(action, "test") is True

    def test_archive_without_s3_is_reported(self, caplog):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False), caplog.at_level(logging.WARNING, logger=MODULE):
            assert _retention_can_act("archive", "test") is False

        assert "S3 is not configured" in caplog.text

    def test_an_unknown_action_is_reported_by_name(self, caplog):
        """A value stored before the schemas constrained it would otherwise keep every scan forever, unlogged."""
        with caplog.at_level(logging.WARNING, logger=MODULE):
            assert _retention_can_act("Delete", "test") is False

        assert "'Delete'" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["archive", "Delete"], ids=["archive-without-s3", "unknown"])
async def test_an_action_that_cannot_act_walks_no_expired_scan(monkeypatch, caplog, action):
    db = FakeDatabase()
    expired = datetime.now(timezone.utc) - timedelta(days=200)
    for i in range(2 * ARCHIVE_BATCH_SIZE + 1):
        await db.scans.insert_one(
            {"_id": f"scan-{i}", "project_id": "p1", "status": "completed", "created_at": expired}
        )
    unreferenced = AsyncMock(side_effect=lambda _db, batch: [doc["_id"] for doc in batch])
    monkeypatch.setattr(f"{MODULE}._unreferenced", unreferenced)
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)

    with caplog.at_level(logging.WARNING, logger=MODULE):
        await _expire_group(db, 90, {}, action, "retention")

    unreferenced.assert_not_called()
    assert len(caplog.records) == 1
    assert await db.scans.count_documents({}) == 2 * ARCHIVE_BATCH_SIZE + 1


class TestRunRetention:
    def test_global_mode_with_archive_action(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=[{"_id": "scan-1"}])
        mock_db = _mock_db()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}._referenced_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}.release_protected_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._project_heads", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(mock_db))

        mock_handle.assert_called_once()
        call_args = mock_handle.call_args
        assert call_args[0][2] == "archive"

    def test_global_mode_none_action_skips_cleanup(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "none"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(_mock_db()))

        # retention_days > 0 enters the block, but action "none" short-circuits _handle_retention_action.
        mock_handle.assert_not_called()

    def test_global_mode_excludes_pinned_scans(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=[{"_id": "scan-1"}])
        mock_db = _mock_db()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}._referenced_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}.release_protected_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock),
        ):
            asyncio.run(_run_retention(mock_db))

        find_call = mock_db.scans.find.call_args
        query = find_call[0][0]
        assert "pinned" in query
        assert query["pinned"] == {"$nin": RETENTION_PROTECTED_FLAG_VALUES}

    def test_global_mode_zero_retention_days_skips(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 0
        mock_settings.global_retention_action = "delete"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(_mock_db()))

        mock_handle.assert_not_called()


@pytest.mark.asyncio
async def test_housekeeping_global_skips_in_progress_scans(monkeypatch):
    captured_queries: list[dict] = []

    db = _mock_db()

    class _EmptyCursor:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def find_capture(query, projection=None):
        captured_queries.append(query)
        return _EmptyCursor()

    db.scans.find = find_capture

    class _SystemSettings:
        retention_mode = "global"
        global_retention_days = 30
        global_retention_action = "delete"

    settings_repo = MagicMock()
    settings_repo.get = AsyncMock(return_value=_SystemSettings())

    monkeypatch.setattr("app.core.housekeeping.SystemSettingsRepository", lambda _db: settings_repo)
    monkeypatch.setattr("app.core.housekeeping._referenced_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.release_protected_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await _run_retention(db)

    retention_cursors = [q for q in captured_queries if "created_at" in q]
    assert retention_cursors, captured_queries
    for q in retention_cursors:
        assert q["status"] == {"$nin": ["pending", "processing"]}, q


@pytest.mark.asyncio
async def test_housekeeping_project_specific_skips_in_progress_scans(monkeypatch):
    captured_queries: list[dict] = []

    db = _mock_db()

    class _EmptyCursor:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def find_capture(query, projection=None):
        captured_queries.append(query)
        return _EmptyCursor()

    db.scans.find = find_capture

    async def _agg_iter(_pipeline):
        yield {
            "_id": {"days": 30, "action": "delete"},
            "project_ids": ["proj-1"],
        }

    db.projects.aggregate = _agg_iter

    class _SystemSettings:
        retention_mode = "project"
        global_retention_days = 0
        global_retention_action = "none"

    settings_repo = MagicMock()
    settings_repo.get = AsyncMock(return_value=_SystemSettings())

    monkeypatch.setattr("app.core.housekeeping.SystemSettingsRepository", lambda _db: settings_repo)
    monkeypatch.setattr("app.core.housekeeping._referenced_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.release_protected_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await _run_retention(db)

    assert any("status" in q and q["status"] == {"$nin": ["pending", "processing"]} for q in captured_queries), (
        f"Expected status filter in at least one cursor query, got: {captured_queries}"
    )


_OLD = datetime.now(timezone.utc) - timedelta(hours=48)
_RECENT = datetime.now(timezone.utc) - timedelta(hours=2)


async def _reap_listing(monkeypatch, db, *pages, prefix: str = "") -> tuple[int, list[str], list[str]]:
    from app.core.housekeeping import _reap_orphan_s3_objects

    listed_prefixes: list[str] = []
    deleted: list[str] = []

    async def list_objects(prefix=""):
        listed_prefixes.append(prefix)
        for page in pages:
            yield [{"Key": key, "Size": 1, "LastModified": modified} for key, modified in page]

    async def delete_object(key, **_kwargs):
        deleted.append(key)

    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: True)
    monkeypatch.setattr(f"{MODULE}.list_objects", list_objects)
    monkeypatch.setattr(f"{MODULE}.delete_object", delete_object)
    monkeypatch.setattr("app.core.s3.settings", SimpleNamespace(S3_KEY_PREFIX=prefix))
    reaped = await _reap_orphan_s3_objects(db)
    return reaped, sorted(deleted), listed_prefixes


async def _seed_bundle_metadata(db, scan_id: str, s3_key: str) -> None:
    await db.archive_metadata.insert_one(
        _make_archive_metadata(scan_id).model_copy(update={"s3_key": s3_key}).model_dump(by_alias=True)
    )


@pytest.mark.asyncio
async def test_reap_orphan_s3_objects_deletes_only_old_unknown_bundles(monkeypatch):
    db = FakeDatabase()
    await _seed_bundle_metadata(db, "scan-known", "p1/scan-known-1700000500.bundle")

    reaped, deleted, _ = await _reap_listing(
        monkeypatch,
        db,
        [
            ("p1/scan-orphan-1700000000.bundle", _OLD),
            ("p1/scan-fresh-1700000000.bundle", _RECENT),
            ("p1/scan-known-1700000500.bundle", _OLD),
            ("p1/scan-known-1700000000.bundle", _OLD),
        ],
    )

    assert reaped == 2
    assert deleted == ["p1/scan-known-1700000000.bundle", "p1/scan-orphan-1700000000.bundle"]


@pytest.mark.asyncio
async def test_reap_orphan_s3_objects_spares_every_key_that_is_not_one_of_its_bundles(monkeypatch):
    reaped, deleted, _ = await _reap_listing(
        monkeypatch,
        FakeDatabase(),
        [
            ("backups/mongo-1700000000.tar.gz", _OLD),
            ("p1/notes.txt", _OLD),
            ("p1/scan-legacy.bundle", _OLD),
            ("other-dc/p1/scan-x-1700000000.bundle", _OLD),
            ("scan-x-1700000000.bundle", _OLD),
        ],
    )

    assert (reaped, deleted) == (0, [])


@pytest.mark.asyncio
async def test_a_key_prefix_confines_the_reaper_to_its_own_instance(monkeypatch):
    reaped, deleted, listed_prefixes = await _reap_listing(
        monkeypatch,
        FakeDatabase(),
        [("dc-a/p1/scan-x-1700000000.bundle", _OLD), ("p1/scan-y-1700000000.bundle", _OLD)],
        prefix="/dc-a/",
    )

    assert listed_prefixes == ["dc-a/"]
    assert (reaped, deleted) == (1, ["dc-a/p1/scan-x-1700000000.bundle"])


@pytest.mark.asyncio
async def test_reap_orphan_s3_objects_looks_up_each_page_by_its_scan_ids(monkeypatch):
    db = FakeDatabase()
    await _seed_bundle_metadata(db, "scan-a", "p1/scan-a-1.bundle")
    monkeypatch.setattr(f"{MODULE}._reap_stale_metadata", AsyncMock(return_value=0))
    lookups: list[dict] = []
    find = db.archive_metadata.find

    def recording_find(query, *args, **kwargs):
        lookups.append(query)
        return find(query, *args, **kwargs)

    monkeypatch.setattr(db.archive_metadata, "find", recording_find)

    reaped, deleted, _ = await _reap_listing(
        monkeypatch,
        db,
        [("p1/scan-a-1.bundle", _OLD), ("p1/scan-b-1.bundle", _OLD)],
        [("p1/scan-c-1.bundle", _OLD)],
    )

    assert lookups == [{"scan_id": {"$in": ["scan-a", "scan-b"]}}, {"scan_id": {"$in": ["scan-c"]}}]
    assert (reaped, deleted) == (2, ["p1/scan-b-1.bundle", "p1/scan-c-1.bundle"])


@pytest.mark.asyncio
async def test_reap_orphan_skips_when_archive_disabled(monkeypatch):
    from app.core.housekeeping import _reap_orphan_s3_objects

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)
    list_calls = []
    monkeypatch.setattr(
        "app.core.housekeeping.list_objects",
        AsyncMock(side_effect=lambda *a, **kw: list_calls.append(1)),
    )

    db = MagicMock()
    reaped = await _reap_orphan_s3_objects(db)
    assert reaped == 0
    assert list_calls == []


@pytest.mark.asyncio
async def test_reap_orphan_tolerates_list_failure(monkeypatch, caplog):
    from app.core.housekeeping import _reap_orphan_s3_objects

    async def list_objects(_prefix=""):
        raise RuntimeError("S3 unavailable")
        yield []

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: True)
    monkeypatch.setattr("app.core.housekeeping.list_objects", list_objects)

    with caplog.at_level(logging.WARNING, logger=MODULE):
        reaped = await _reap_orphan_s3_objects(FakeDatabase())

    assert reaped == 0
    assert [record.getMessage() for record in caplog.records] == ["Orphan reaper stopped: S3 unavailable"]


_ARCHIVED_AT = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


async def _seed_metadata(db, scan_id: str) -> None:
    metadata = _make_archive_metadata(scan_id).model_copy(update={"archived_at": _ARCHIVED_AT})
    await db.archive_metadata.insert_one(metadata.model_dump(by_alias=True))


async def _seed_archive(db, scan_id: str, *, restored_at=None) -> None:
    scan: dict = {"_id": scan_id, "project_id": "proj-1", "branch": "main"}
    if restored_at is not None:
        scan["restored_at"] = restored_at
    await db.scans.insert_one(scan)
    await _seed_metadata(db, scan_id)


async def _surviving_metadata(db) -> list[str]:
    return sorted([meta["scan_id"] async for meta in db.archive_metadata.find({})])


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_an_archive_in_flight():
    """Archival writes metadata before deleting the scan, so a scan present without restore evidence is mid-archive."""
    from app.core.housekeeping import _reap_stale_metadata
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await _seed_archive(db, "scan-archiving")

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-archiving"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_model_inserted_scan_in_flight():
    """A scan inserted through the model stores an explicit restored_at of null, which is no restore evidence."""
    from app.core.housekeeping import _reap_stale_metadata
    from app.models.project import Scan
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    scan = Scan(project_id="proj-1", branch="main")
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _seed_metadata(db, scan.id)

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == [scan.id]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_restore_that_stopped_after_its_header():
    """A pod that dies mid-restore never rolls back and its lock expires; the bundle is the only complete copy."""
    from app.core.housekeeping import _reap_stale_metadata
    from app.services.archive import _handle_header_event
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await _seed_metadata(db, "scan-partial")
    await _handle_header_event(db, {"scan": {"_id": "scan-partial", "project_id": "proj-1"}}, [])

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-partial"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_scan_still_marked_restore_in_progress():
    from app.core.housekeeping import _reap_stale_metadata
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await _seed_archive(db, "scan-partial", restored_at=_ARCHIVED_AT + timedelta(hours=1))
    await db.scans.update_one({"_id": "scan-partial"}, {"$set": {"restore_in_progress": True}})

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-partial"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_while_the_restore_lock_is_held():
    """A running restore can still fail and roll the scan back out, leaving the bundle as the only copy."""
    from app.core.housekeeping import _reap_stale_metadata
    from app.repositories.distributed_locks import DistributedLocksRepository
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await _seed_archive(db, "scan-restoring", restored_at=_ARCHIVED_AT + timedelta(hours=1))
    assert await DistributedLocksRepository(db).acquire_lock("restore:scan-restoring", "restore-pod", ttl_seconds=600)

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-restoring"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_scan_re_archived_after_its_restore():
    from app.core.housekeeping import _reap_stale_metadata
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await _seed_archive(db, "scan-rearchiving", restored_at=_ARCHIVED_AT - timedelta(days=3))

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-rearchiving"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_reads_scans_and_locks_once_per_batch():
    from app.core.housekeeping import _reap_stale_metadata
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    for i in range(5):
        await _seed_archive(db, f"scan-{i}", restored_at=_ARCHIVED_AT + timedelta(hours=1))

    def spy(collection, calls: list):
        find = collection.find

        def recording_find(query, *args, **kwargs):
            calls.append(query["_id"]["$in"])
            return find(query, *args, **kwargs)

        collection.find = recording_find
        collection.find_one = AsyncMock(side_effect=AssertionError("find_one would make the reap N+1"))

    scan_batches: list = []
    lock_batches: list = []
    spy(db.scans, scan_batches)
    spy(db.distributed_locks, lock_batches)

    reaped = await _reap_stale_metadata(db, batch_size=2)

    assert reaped == 5
    assert scan_batches == [["scan-0", "scan-1"], ["scan-2", "scan-3"], ["scan-4"]]
    assert lock_batches == [
        ["restore:scan-0", "restore:scan-1"],
        ["restore:scan-2", "restore:scan-3"],
        ["restore:scan-4"],
    ]
    assert await _surviving_metadata(db) == []


@pytest.mark.asyncio
async def test_reap_orphan_runs_stale_metadata_pass_first(monkeypatch):
    from app.core.housekeeping import _reap_orphan_s3_objects

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: True)

    call_order: list[str] = []

    async def fake_stale_reap(_db):
        call_order.append("stale_metadata")
        return 0

    async def fake_list(*_a, **_kw):
        call_order.append("list_objects")
        yield []

    monkeypatch.setattr("app.core.housekeeping._reap_stale_metadata", fake_stale_reap)
    monkeypatch.setattr("app.core.housekeeping.list_objects", fake_list)

    await _reap_orphan_s3_objects(FakeDatabase())

    assert call_order == ["stale_metadata", "list_objects"]


@pytest.mark.asyncio
async def test_reap_orphan_callgraphs_deletes_only_orphans_past_the_age_window():
    """The window protects callgraphs uploaded before their scan row exists; an inverted cutoff destroys them."""
    from datetime import datetime, timedelta, timezone

    from app.core.constants import ORPHAN_MIN_AGE_HOURS
    from app.core.housekeeping import _reap_orphan_callgraphs
    from tests.mocks.fake_mongo import FakeDatabase

    now = datetime.now(timezone.utc)
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "scan-known"})
    await db.callgraphs.insert_many(
        [
            {
                "_id": "cg-orphan-old",
                "scan_id": "scan-missing",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
            {"_id": "cg-orphan-fresh", "scan_id": "scan-arriving", "created_at": now - timedelta(minutes=1)},
            {
                "_id": "cg-known-old",
                "scan_id": "scan-known",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
        ]
    )

    deleted = await _reap_orphan_callgraphs(db)

    survivors = sorted([cg["_id"] async for cg in db.callgraphs.find({})])
    assert deleted == 1
    assert survivors == ["cg-known-old", "cg-orphan-fresh"]


@pytest.mark.asyncio
async def test_reap_orphan_callgraphs_spares_a_fresh_upload_reusing_an_orphaned_scan_id():
    """A retry uploading under an abandoned scan_id right now is still in flight and must survive the sweep."""
    from datetime import datetime, timedelta, timezone

    from app.core.constants import ORPHAN_MIN_AGE_HOURS
    from app.core.housekeeping import _reap_orphan_callgraphs
    from tests.mocks.fake_mongo import FakeDatabase

    now = datetime.now(timezone.utc)
    db = FakeDatabase()
    await db.callgraphs.insert_many(
        [
            {
                "_id": "cg-stale",
                "scan_id": "scan-retried",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
            {"_id": "cg-retry", "scan_id": "scan-retried", "created_at": now - timedelta(minutes=1)},
        ]
    )

    deleted = await _reap_orphan_callgraphs(db)

    survivors = [cg["_id"] async for cg in db.callgraphs.find({})]
    assert deleted == 1
    assert survivors == ["cg-retry"]

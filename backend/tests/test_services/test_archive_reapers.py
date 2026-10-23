import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from prometheus_client import REGISTRY

from app.models.archive import ArchiveMetadata
from app.models.project import Scan
from app.repositories.distributed_locks import DistributedLocksRepository
from app.services.archive import _handle_header_event, reap_orphan_s3_objects, reap_stale_metadata
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.services.archive"


def _make_archive_metadata(scan_id="scan-1"):
    return ArchiveMetadata(
        project_id="proj-1",
        scan_id=scan_id,
        s3_key=f"proj-1/{scan_id}.json.gz",
        s3_bucket="dc-archives",
    )


_OLD = datetime.now(timezone.utc) - timedelta(hours=48)
_RECENT = datetime.now(timezone.utc) - timedelta(hours=2)


async def _reap_listing(monkeypatch, db, *pages, prefix: str = "") -> tuple[int, list[str], list[str]]:
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
    reaped = await reap_orphan_s3_objects(db)
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
async def test_each_reaped_orphan_bundle_is_counted_as_one(monkeypatch):
    def counted() -> tuple[float, float]:
        return (
            REGISTRY.get_sample_value("archive_orphan_objects_reaped_total") or 0.0,
            REGISTRY.get_sample_value("archive_housekeeping_scans_processed_total", {"status": "orphan_reaped"}) or 0.0,
        )

    before = counted()

    reaped, _, _ = await _reap_listing(
        monkeypatch,
        FakeDatabase(),
        [("p1/scan-a-1700000000.bundle", _OLD), ("p1/scan-b-1700000000.bundle", _OLD)],
    )

    assert [after - start for after, start in zip(counted(), before, strict=True)] == [reaped, reaped] == [2, 2]


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
    monkeypatch.setattr(f"{MODULE}.reap_stale_metadata", AsyncMock(return_value=0))
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
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)
    list_calls = []
    monkeypatch.setattr(
        f"{MODULE}.list_objects",
        AsyncMock(side_effect=lambda *a, **kw: list_calls.append(1)),
    )

    db = MagicMock()
    reaped = await reap_orphan_s3_objects(db)
    assert reaped == 0
    assert list_calls == []


@pytest.mark.asyncio
async def test_reap_orphan_tolerates_list_failure(monkeypatch, caplog):
    async def list_objects(_prefix=""):
        raise RuntimeError("S3 unavailable")
        yield []

    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: True)
    monkeypatch.setattr(f"{MODULE}.list_objects", list_objects)

    with caplog.at_level(logging.WARNING, logger=MODULE):
        reaped = await reap_orphan_s3_objects(FakeDatabase())

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
    db = FakeDatabase()
    await _seed_archive(db, "scan-archiving")

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-archiving"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_model_inserted_scan_in_flight():
    """A scan inserted through the model stores an explicit restored_at of null, which is no restore evidence."""
    db = FakeDatabase()
    scan = Scan(project_id="proj-1", branch="main")
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _seed_metadata(db, scan.id)

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == [scan.id]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_restore_that_stopped_after_its_header():
    """A pod that dies mid-restore never rolls back and its lock expires; the bundle is the only complete copy."""
    db = FakeDatabase()
    await _seed_metadata(db, "scan-partial")
    await _handle_header_event(db, {"scan": {"_id": "scan-partial", "project_id": "proj-1"}})

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-partial"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_scan_still_marked_restore_in_progress():
    db = FakeDatabase()
    await _seed_archive(db, "scan-partial", restored_at=_ARCHIVED_AT + timedelta(hours=1))
    await db.scans.update_one({"_id": "scan-partial"}, {"$set": {"restore_in_progress": True}})

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-partial"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_while_the_restore_lock_is_held():
    """A running restore can still fail and roll the scan back out, leaving the bundle as the only copy."""
    db = FakeDatabase()
    await _seed_archive(db, "scan-restoring", restored_at=_ARCHIVED_AT + timedelta(hours=1))
    assert await DistributedLocksRepository(db).acquire_lock("restore:scan-restoring", "restore-pod", ttl_seconds=600)

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-restoring"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_keeps_the_metadata_of_a_scan_re_archived_after_its_restore():
    db = FakeDatabase()
    await _seed_archive(db, "scan-rearchiving", restored_at=_ARCHIVED_AT - timedelta(days=3))

    reaped = await reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == ["scan-rearchiving"]


@pytest.mark.asyncio
async def test_reap_stale_metadata_starts_from_the_restored_scans_and_reads_each_batch_once():
    """Almost every archive_metadata row belongs to a scan that is gone, so walking the rows would nearly all miss."""
    db = FakeDatabase()
    for i in range(5):
        await _seed_archive(db, f"scan-{i}", restored_at=_ARCHIVED_AT + timedelta(hours=1))
    for i in range(3):
        await _seed_metadata(db, f"archived-{i}")

    def spy(collection, calls: list, field: str):
        find = collection.find

        def recording_find(query, *args, **kwargs):
            calls.append(query[field]["$in"])
            return find(query, *args, **kwargs)

        collection.find = recording_find
        collection.find_one = AsyncMock(side_effect=AssertionError("find_one would make the reap N+1"))
        return find

    metadata_batches: list = []
    lock_batches: list = []
    read_metadata = spy(db.archive_metadata, metadata_batches, "scan_id")
    spy(db.distributed_locks, lock_batches, "_id")

    reaped = await reap_stale_metadata(db, batch_size=2)
    db.archive_metadata.find = read_metadata

    assert reaped == 5
    assert metadata_batches == [["scan-0", "scan-1"], ["scan-2", "scan-3"], ["scan-4"]]
    assert lock_batches == [
        ["restore:scan-0", "restore:scan-1"],
        ["restore:scan-2", "restore:scan-3"],
        ["restore:scan-4"],
    ]
    assert await _surviving_metadata(db) == ["archived-0", "archived-1", "archived-2"]


@pytest.mark.asyncio
async def test_the_orphan_reaper_keeps_the_bundle_of_metadata_it_leaves_to_the_stale_metadata_step(monkeypatch):
    """A failed stale-metadata step leaves its rows in place, which must keep their bundles out of the sweep."""
    db = FakeDatabase()
    bundle = "proj-1/scan-restored-1700000000.bundle"
    await db.scans.insert_one({"_id": "scan-restored", "restored_at": _ARCHIVED_AT + timedelta(hours=1)})
    await _seed_bundle_metadata(db, "scan-restored", bundle)
    await db.archive_metadata.update_one({"scan_id": "scan-restored"}, {"$set": {"archived_at": _ARCHIVED_AT}})

    reaped, deleted, _ = await _reap_listing(monkeypatch, db, [(bundle, _OLD)])

    assert (reaped, deleted) == (0, [])
    assert await _surviving_metadata(db) == ["scan-restored"]

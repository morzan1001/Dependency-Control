import hashlib
import json
import logging
import zlib
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pymongo.errors import AutoReconnect

from app.core.constants import ENCRYPTION_MAGIC, SCAN_SCOPED_COLLECTIONS
from app.models.archive import ArchiveMetadata
from app.services.archive import RestoreFailed, _gzip_decompress_stream, archive_scan, restore_scan

MODULE = "app.services.archive"
_NO_IDS: list[str] = []


def _make_scan_doc(**overrides):
    doc = {
        "_id": "scan-1",
        "project_id": "proj-1",
        "branch": "main",
        "commit_hash": "abc123",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "completed_at": datetime(2025, 1, 1, 1, 0, tzinfo=timezone.utc),
        "status": "completed",
        "sbom_refs": [],
    }
    doc.update(overrides)
    return doc


def _make_archive_metadata(**overrides):
    defaults = {
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "s3_key": "proj-1/scan-1-1700000000.bundle",
        "s3_bucket": "dc-archives",
        "branch": "main",
        "commit_hash": "abc123",
        "compressed_size_bytes": 200,
    }
    defaults.update(overrides)
    return ArchiveMetadata(**defaults)


class _AsyncCursorMock:
    def __init__(self, docs: list[dict[str, Any]]):
        self._docs = docs

    def batch_size(self, _size: int) -> "_AsyncCursorMock":
        return self

    def __aiter__(self):
        async def _gen():
            for doc in self._docs:
                yield doc

        return _gen()

    async def to_list(self, _length=None):
        return list(self._docs)


def _make_mock_db(
    scan_doc=None,
    findings=None,
    finding_records=None,
    dependencies=None,
    analysis_results=None,
    callgraphs=None,
    crypto_assets=None,
):
    db = MagicMock()
    # Repositories reach collections by name, the fixtures below by attribute.
    db.__getitem__.side_effect = lambda name: getattr(db, name)
    db.scans.find_one = AsyncMock(return_value=scan_doc)
    db.scans.find = MagicMock(return_value=_AsyncCursorMock([scan_doc] if scan_doc else []))
    db.scans.insert_one = AsyncMock()
    db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=1))
    # Nothing in these fixtures is released, so the release-chain guard finds no protection.
    db.scans.distinct = AsyncMock(return_value=_NO_IDS)
    db.releases.distinct = AsyncMock(return_value=_NO_IDS)
    db.findings.find = MagicMock(return_value=_AsyncCursorMock(findings or []))
    db.findings.insert_many = AsyncMock()
    db.finding_records.find = MagicMock(return_value=_AsyncCursorMock(finding_records or []))
    db.finding_records.insert_many = AsyncMock()
    db.dependencies.find = MagicMock(return_value=_AsyncCursorMock(dependencies or []))
    db.dependencies.insert_many = AsyncMock()
    db.analysis_results.find = MagicMock(return_value=_AsyncCursorMock(analysis_results or []))
    db.analysis_results.insert_many = AsyncMock()
    db.analysis_results.distinct = AsyncMock(return_value=_NO_IDS)
    db.callgraphs.find = MagicMock(return_value=_AsyncCursorMock(callgraphs or []))
    db.callgraphs.insert_many = AsyncMock()
    db.callgraphs.distinct = AsyncMock(return_value=_NO_IDS)
    db.crypto_assets.find = MagicMock(return_value=_AsyncCursorMock(crypto_assets or []))
    db.crypto_assets.insert_many = AsyncMock()
    return db


def _patch_repos(lock_acquires: bool = True, existing_metadata=None):
    from contextlib import contextmanager

    @contextmanager
    def cm():
        with (
            patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
            patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
        ):
            RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=existing_metadata)
            RepoCls.return_value.create = AsyncMock()
            RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
            LockCls.return_value.acquire_lock = AsyncMock(return_value=lock_acquires)
            LockCls.return_value.release_lock = AsyncMock(return_value=True)
            LockCls.return_value.renew_lock = AsyncMock(return_value=True)
            LockCls.return_value.held_locks = AsyncMock(return_value=set())
            yield RepoCls, LockCls

    return cm


@pytest.mark.asyncio
async def test_archive_scan_uploads_and_inserts_metadata(archive_env):
    scan_doc = _make_scan_doc()
    findings = [{"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"}]
    dependencies = [{"_id": "d1", "scan_id": "scan-1", "name": "lib"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings, dependencies=dependencies)

    with _patch_repos()() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is not None
    assert result.scan_id == "scan-1"
    assert len(archive_env.objects) == 1
    key = next(iter(archive_env.objects))
    assert key.startswith("proj-1/scan-1-")
    assert key.endswith(".bundle")
    RepoCls.return_value.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_archive_scan_stores_the_bundle_under_its_own_content_type(archive_env):
    db = _make_mock_db(scan_doc=_make_scan_doc())

    with _patch_repos()() as (_, _):
        assert await archive_scan(db, "scan-1") is not None

    key = next(iter(archive_env.objects))
    assert archive_env.objects[key][:2] == b"\x1f\x8b"
    assert archive_env.content_types[key] == "application/gzip"


@pytest.mark.asyncio
async def test_archive_metadata_keeps_critical_and_high_counts_apart(archive_env):
    """The metadata index is the only readable record once the scan documents are gone."""
    findings = [
        {"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"},
        {"_id": "f2", "scan_id": "scan-1", "severity": "HIGH"},
        {"_id": "f3", "scan_id": "scan-1", "severity": "HIGH"},
        {"_id": "f4", "scan_id": "scan-1", "severity": "HIGH"},
    ]
    db = _make_mock_db(scan_doc=_make_scan_doc(), findings=findings)

    with _patch_repos()():
        result = await archive_scan(db, "scan-1")

    assert result is not None
    assert result.critical_findings_count == 1
    assert result.high_findings_count == 3


@pytest.mark.asyncio
async def test_archive_key_carries_the_archive_time(archive_env):
    """Two archives of one scan would otherwise collide on the same key."""
    db = _make_mock_db(scan_doc=_make_scan_doc())

    with _patch_repos()():
        result = await archive_scan(db, "scan-1")

    assert result is not None
    key = next(iter(archive_env.objects))
    assert result.s3_key == key
    archived_at_unix = int(key.removeprefix("proj-1/scan-1-").removesuffix(".bundle"))
    assert abs(archived_at_unix - int(datetime.now(timezone.utc).timestamp())) < 300


@pytest.mark.asyncio
async def test_archive_key_starts_with_the_configured_prefix(archive_env, monkeypatch):
    monkeypatch.setattr("app.core.s3.settings.S3_KEY_PREFIX", "dc-a")
    db = _make_mock_db(scan_doc=_make_scan_doc())

    with _patch_repos()():
        result = await archive_scan(db, "scan-1")

    assert result is not None
    assert result.s3_key.startswith("dc-a/proj-1/scan-1-")
    assert set(archive_env.objects) == {result.s3_key}


@pytest.mark.asyncio
async def test_archive_scan_includes_crypto_assets(archive_env):
    scan_doc = _make_scan_doc()
    crypto_assets = [
        {"_id": "ca1", "scan_id": "scan-1", "name": "MD5", "primitive": "hash"},
        {"_id": "ca2", "scan_id": "scan-1", "name": "SHA-256", "primitive": "hash"},
    ]
    db = _make_mock_db(scan_doc=scan_doc, crypto_assets=crypto_assets)

    with _patch_repos()() as (_, _):
        result = await archive_scan(db, "scan-1")

    assert result is not None
    db.crypto_assets.find.assert_called_once()
    call = db.crypto_assets.find.call_args
    assert call.args[0] == {"scan_id": "scan-1"}


@pytest.mark.asyncio
async def test_archive_scan_skips_when_lock_held(archive_env):
    scan_doc = _make_scan_doc()
    db = _make_mock_db(scan_doc=scan_doc)

    with _patch_repos(lock_acquires=False)() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is None
    assert archive_env.objects == {}
    RepoCls.return_value.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_archive_scan_returns_existing_metadata_if_already_archived(archive_env):
    scan_doc = _make_scan_doc()
    existing = _make_archive_metadata()
    db = _make_mock_db(scan_doc=scan_doc)

    with _patch_repos(existing_metadata=existing)() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is existing
    assert archive_env.objects == {}
    RepoCls.return_value.create.assert_not_awaited()


def _archive_outcomes() -> dict[str, float]:
    from prometheus_client import REGISTRY

    return {
        status: REGISTRY.get_sample_value("archive_operations_total", {"operation": "archive", "status": status}) or 0.0
        for status in ("success", "skipped", "failure")
    }


@pytest.mark.asyncio
async def test_an_archive_that_already_exists_is_counted_as_skipped(archive_env):
    db = _make_mock_db(scan_doc=_make_scan_doc())
    before = _archive_outcomes()

    with _patch_repos(existing_metadata=_make_archive_metadata())():
        await archive_scan(db, "scan-1")

    after = _archive_outcomes()
    assert {status: after[status] - before[status] for status in after} == {
        "success": 0.0,
        "skipped": 1.0,
        "failure": 0.0,
    }


@pytest.mark.asyncio
async def test_an_archive_that_raises_is_counted_as_an_unknown_failure(archive_env):
    from prometheus_client import REGISTRY

    unknown = {"operation": "archive", "reason": "unknown"}
    db = _make_mock_db(scan_doc=_make_scan_doc())
    db.scans.find_one = AsyncMock(side_effect=AutoReconnect("primary stepped down"))
    before = _archive_outcomes()["failure"], REGISTRY.get_sample_value("archive_failures_total", unknown) or 0.0

    with _patch_repos()(), pytest.raises(AutoReconnect):
        await archive_scan(db, "scan-1")

    after = _archive_outcomes()["failure"], REGISTRY.get_sample_value("archive_failures_total", unknown) or 0.0
    assert (after[0] - before[0], after[1] - before[1]) == (1.0, 1.0)


@pytest.mark.asyncio
async def test_archive_scan_returns_none_when_scan_not_found(archive_env):
    db = _make_mock_db(scan_doc=None)

    with _patch_repos()() as (RepoCls, _):
        result = await archive_scan(db, "missing-scan")

    assert result is None
    assert archive_env.objects == {}
    RepoCls.return_value.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_archive_scan_aborts_s3_on_failure(archive_env):
    archive_env.fail_next_upload_part = True
    # Big enough to trigger multipart (>5 MiB)
    big_findings = [{"_id": f"f{i}", "scan_id": "scan-1", "severity": "LOW", "blob": "x" * 1000} for i in range(20000)]
    scan_doc = _make_scan_doc()
    db = _make_mock_db(scan_doc=scan_doc, findings=big_findings)

    with _patch_repos()() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is None
    assert len(archive_env.aborted_uploads) >= 1
    RepoCls.return_value.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_archive_logs_its_scan_and_the_error(archive_env, caplog):
    archive_env.fail_next_upload_part = True
    big_findings = [{"_id": f"f{i}", "scan_id": "scan-1", "severity": "LOW", "blob": "x" * 1000} for i in range(20000)]
    db = _make_mock_db(scan_doc=_make_scan_doc(), findings=big_findings)

    with _patch_repos()(), caplog.at_level(logging.ERROR, logger=MODULE):
        assert await archive_scan(db, "scan-1") is None

    (record,) = caplog.records
    assert "scan-1" in record.getMessage()
    assert "simulated S3 error on upload_part" in caplog.text


@pytest.mark.asyncio
async def test_a_failed_cleanup_of_a_dropped_upload_logs_its_key(monkeypatch, caplog):
    from app.services.archive import _drop_upload

    monkeypatch.setattr(f"{MODULE}.delete_object", AsyncMock(side_effect=RuntimeError("S3 down")))

    with caplog.at_level(logging.ERROR, logger=MODULE):
        await _drop_upload("proj-1/scan-1-1700000000.bundle", "lock_held")

    assert [record.getMessage() for record in caplog.records] == [
        "Cleanup delete of the dropped S3 upload proj-1/scan-1-1700000000.bundle failed"
    ]


@pytest.mark.asyncio
async def test_a_restore_without_metadata_logs_its_scan(archive_env, caplog):
    with _patch_repos()(), caplog.at_level(logging.ERROR, logger=MODULE), pytest.raises(RestoreFailed):
        await restore_scan(_make_mock_db(), "scan-1")

    assert [record.getMessage() for record in caplog.records] == ["No archive metadata for scan scan-1"]


@pytest.mark.asyncio
async def test_restore_scan_roundtrip(archive_env):
    scan_doc = _make_scan_doc()
    findings = [
        {"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"},
        {"_id": "f2", "scan_id": "scan-1", "severity": "HIGH"},
    ]
    dependencies = [{"_id": "d1", "scan_id": "scan-1", "name": "lib"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings, dependencies=dependencies)

    with _patch_repos()() as (RepoCls, _):
        meta = await archive_scan(db, "scan-1")
        assert meta is not None

    db.scans.find_one = AsyncMock(return_value=None)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    assert result.scan_id == "scan-1"
    db.scans.insert_one.assert_awaited()
    inserted = db.scans.insert_one.await_args.args[0]
    assert inserted["pinned"] is True
    db.findings.insert_many.assert_awaited()
    db.dependencies.insert_many.assert_awaited()


@pytest.mark.asyncio
async def test_restore_scan_aborts_when_lock_held(archive_env):
    db = _make_mock_db()
    meta = _make_archive_metadata()

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=False)

        with pytest.raises(RestoreFailed) as failure:
            await restore_scan(db, "scan-1")

    assert failure.value.reason == "lock_held"
    db.scans.insert_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_restore_scan_aborts_when_scan_already_exists(archive_env):
    meta = _make_archive_metadata()
    existing_scan = _make_scan_doc()
    db = _make_mock_db(scan_doc=existing_scan)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        with pytest.raises(RestoreFailed) as failure:
            await restore_scan(db, "scan-1")

    assert failure.value.reason == "already_exists"
    db.scans.insert_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_restore_scan_fails_as_not_found_without_metadata(archive_env):
    db = _make_mock_db()

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=None)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        with pytest.raises(RestoreFailed) as failure:
            await restore_scan(db, "scan-1")

    assert failure.value.reason == "not_found"


@pytest.mark.asyncio
async def test_replay_labels_mongo_error_not_as_s3_error():
    from pymongo.errors import OperationFailure

    from app.services.archive import _replay_bundle

    header = json.dumps({"version": 2, "scan_id": "x", "project_id": "y", "scan": {"_id": "x", "project_id": "y"}}).encode() + b"\n"

    async def src():
        yield header

    db = MagicMock()

    async def fail_insert(_doc):
        raise OperationFailure("simulated mongo failure")

    db.scans.insert_one = fail_insert

    reason, _ = await _replay_bundle(db, "x", "y", src())
    assert reason == "unknown"
    assert reason != "s3_error"


@pytest.mark.asyncio
async def test_replay_labels_invalid_tag_as_encryption():
    from cryptography.exceptions import InvalidTag

    from app.services.archive import _replay_bundle

    class _RaisingStream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise InvalidTag()

    src = _RaisingStream()

    db = MagicMock()
    reason, _ = await _replay_bundle(db, "x", "y", src)
    assert reason == "encryption"


@pytest.mark.asyncio
async def test_replay_labels_a_broken_download_as_s3_error():
    from app.services.archive import _replay_bundle

    async def src():
        raise OSError("connection reset by peer")
        yield b""

    reason, _ = await _replay_bundle(MagicMock(), "x", "y", src())
    assert reason == "s3_error"


@pytest.mark.asyncio
async def test_restore_deletes_metadata_even_when_s3_delete_fails(archive_env):
    scan_doc = _make_scan_doc()
    findings = [{"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings)

    with _patch_repos()() as (RepoCls, _):
        meta = await archive_scan(db, "scan-1")
        assert meta is not None

    db.scans.find_one = AsyncMock(return_value=None)

    delete_metadata = AsyncMock(return_value=True)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
        patch(f"{MODULE}.delete_object", AsyncMock(side_effect=RuntimeError("S3 down"))),
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = delete_metadata
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    delete_metadata.assert_awaited_once_with("scan-1")


@pytest.mark.asyncio
async def test_restore_rolls_back_partial_state_on_replay_failure(archive_env, monkeypatch):
    meta = _make_archive_metadata()
    db = _make_mock_db()
    db.scans.find_one = AsyncMock(return_value=None)
    db.scans.delete_one = AsyncMock()
    db.findings.delete_many = AsyncMock()
    db.finding_records.delete_many = AsyncMock()
    db.dependencies.delete_many = AsyncMock()
    db.analysis_results.delete_many = AsyncMock()
    db.callgraphs.delete_many = AsyncMock()
    db.crypto_assets.delete_many = AsyncMock()

    monkeypatch.setattr(
        f"{MODULE}._replay_bundle",
        AsyncMock(return_value=("integrity", ["scans"])),
    )
    monkeypatch.setattr(f"{MODULE}._open_bundle_stream", lambda _: None)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        with pytest.raises(RestoreFailed) as failure:
            await restore_scan(db, "scan-1")

    assert failure.value.reason == "integrity"
    db.scans.delete_one.assert_awaited_once_with({"_id": "scan-1"})
    db.findings.delete_many.assert_awaited()
    db.dependencies.delete_many.assert_awaited()


@pytest.mark.asyncio
async def test_archive_scan_labels_duplicate_key_as_already_exists(archive_env, monkeypatch):
    from pymongo.errors import DuplicateKeyError

    from app.core.metrics import archive_failures_total

    seen_reasons: list[str] = []
    orig_labels = archive_failures_total.labels

    def capture_labels(**kw):
        if kw.get("operation") == "archive":
            seen_reasons.append(kw.get("reason"))
        return orig_labels(**kw)

    monkeypatch.setattr(archive_failures_total, "labels", capture_labels)

    scan_doc = _make_scan_doc()
    db = _make_mock_db(scan_doc=scan_doc, findings=[{"_id": "f1", "scan_id": "scan-1"}])

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=None)
        RepoCls.return_value.create = AsyncMock(side_effect=DuplicateKeyError("dup"))
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)
        LockCls.return_value.held_locks = AsyncMock(return_value=set())

        result = await archive_scan(db, "scan-1")

    assert result is None
    assert "already_exists" in seen_reasons
    assert "unknown" not in seen_reasons
    assert archive_env.objects == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("renewal", "reason"),
    [({"return_value": False}, "lock_held"), ({"side_effect": AutoReconnect("primary stepped down")}, "s3_error")],
    ids=["lock-taken-over", "renewal-failed"],
)
async def test_a_failed_replay_rolls_back_only_while_holding_its_lock(archive_env, monkeypatch, renewal, reason):
    count_failure = MagicMock()
    monkeypatch.setattr(f"{MODULE}.count_archive_failure", count_failure)
    db = _make_mock_db()
    db.scans.find_one = AsyncMock(return_value=None)
    # An unguarded rollback stops at the first delete that is not awaitable, so every target must be one.
    db.scans.delete_one = AsyncMock()
    for coll in SCAN_SCOPED_COLLECTIONS:
        getattr(db, coll).delete_many = AsyncMock()
    monkeypatch.setattr(f"{MODULE}._replay_bundle", AsyncMock(return_value=("s3_error", ["scans"])))
    monkeypatch.setattr(f"{MODULE}._open_bundle_stream", lambda _: None)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=_make_archive_metadata())
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(**renewal)

        with pytest.raises(RestoreFailed) as failure:
            await restore_scan(db, "scan-1")

    assert failure.value.reason == reason
    assert [coll for coll in SCAN_SCOPED_COLLECTIONS if getattr(db, coll).delete_many.await_count] == []
    db.scans.delete_one.assert_not_awaited()
    count_failure.assert_called_once_with("restore", reason)


@pytest.mark.asyncio
async def test_restore_succeeds_when_metadata_delete_fails(archive_env, monkeypatch):
    meta = _make_archive_metadata()
    db = _make_mock_db()
    db.scans.find_one = AsyncMock(return_value=None)

    monkeypatch.setattr(
        f"{MODULE}._replay_bundle",
        AsyncMock(return_value=(None, ["scans"])),
    )
    monkeypatch.setattr(f"{MODULE}._open_bundle_stream", lambda _: None)
    archive_env.objects[meta.s3_key] = b"bundle"

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(side_effect=RuntimeError("Mongo hiccup"))
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    assert result.scan_id == "scan-1"
    assert meta.s3_key in archive_env.objects


async def _aiter(items):
    for item in items:
        yield item


@pytest.mark.asyncio
async def test_archive_aborts_when_gridfs_read_fails(archive_env, monkeypatch):
    """Dropping an unreadable SBOM silently would let housekeeping delete the source scan."""
    scan_doc = _make_scan_doc(
        sbom_refs=[
            {
                "type": "gridfs_reference",
                "gridfs_id": "507f1f77bcf86cd799439011",
                "filename": "sbom.json",
            }
        ]
    )
    db = _make_mock_db(scan_doc=scan_doc)

    class _BrokenGridFS:
        def __init__(self, _db):
            pass

        async def open_download_stream(self, _oid):
            raise RuntimeError("missing chunk / transient GridFS error")

    monkeypatch.setattr(f"{MODULE}.AsyncIOMotorGridFSBucket", _BrokenGridFS)
    monkeypatch.setattr("app.db.mongodb.asyncio", SimpleNamespace(sleep=AsyncMock()))

    with _patch_repos()() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is None
    # No metadata written -> housekeeping will NOT delete the source scan.
    RepoCls.return_value.create.assert_not_awaited()
    assert archive_env.objects == {}


@pytest.mark.asyncio
async def test_archive_retries_a_gridfs_file_that_is_not_readable_yet(archive_env, monkeypatch):
    scan_doc = _make_scan_doc(
        sbom_refs=[{"type": "gridfs_reference", "gridfs_id": "507f1f77bcf86cd799439011", "filename": "sbom.json"}]
    )
    db = _make_mock_db(scan_doc=scan_doc)
    opens: list[object] = []

    class _Stream:
        filename = "sbom.json"

        def __init__(self) -> None:
            self._chunks = [b'{"components": []}']

        async def readchunk(self) -> bytes:
            return self._chunks.pop() if self._chunks else b""

        def close(self) -> None:
            return None

    class _GridFSReadableOnSecondTry:
        def __init__(self, _db):
            pass

        async def open_download_stream(self, oid):
            opens.append(oid)
            if len(opens) == 1:
                raise RuntimeError("just-committed file not visible yet")
            return _Stream()

    monkeypatch.setattr(f"{MODULE}.AsyncIOMotorGridFSBucket", _GridFSReadableOnSecondTry)
    monkeypatch.setattr("app.db.mongodb.asyncio", SimpleNamespace(sleep=AsyncMock()))

    with _patch_repos()():
        result = await archive_scan(db, "scan-1")

    from app.services.archive_bundle import read_bundle_frames

    assert result is not None
    assert len(opens) == 2
    bundle = zlib.decompress(archive_env.objects[result.s3_key], wbits=31)
    events = [event async for event in read_bundle_frames(_aiter([bundle]))]
    assert [e["data"]["data"] for e in events if e.get("collection") == "gridfs_chunks"] == [b'{"components": []}']


@pytest.mark.asyncio
async def test_an_encrypted_archive_restores_its_findings(archive_env, monkeypatch):
    db = _make_mock_db(scan_doc=_make_scan_doc(), findings=[{"_id": "f1", "scan_id": "scan-1", "severity": "HIGH"}])
    monkeypatch.setattr(f"{MODULE}.is_encryption_enabled", lambda: True)
    monkeypatch.setattr("app.core.encryption.settings", SimpleNamespace(ARCHIVE_ENCRYPTION_KEY="0" * 64))

    with _patch_repos()():
        meta = await archive_scan(db, "scan-1")
    stored = archive_env.objects[meta.s3_key]
    db.scans.find_one = AsyncMock(return_value=None)
    with _patch_repos(existing_metadata=meta)():
        restored = await restore_scan(db, "scan-1")

    assert stored.startswith(ENCRYPTION_MAGIC)
    assert restored is not None
    assert [doc["_id"] for doc in db.findings.insert_many.await_args.args[0]] == ["f1"]


@pytest.mark.asyncio
async def test_restore_succeeds_when_encryption_flag_toggled_after_plaintext_archive(archive_env, monkeypatch):
    """Restore sniffs the bundle, not the live flag, so a plaintext bundle restores after encryption is enabled."""
    scan_doc = _make_scan_doc()
    findings = [{"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings)

    # 1. Archive with encryption OFF (archive_env sets is_encryption_enabled -> False).
    with _patch_repos()() as (RepoCls, _):
        meta = await archive_scan(db, "scan-1")
        assert meta is not None

    # 2. Operator enables encryption AFTER the plaintext bundle was written.
    db.scans.find_one = AsyncMock(return_value=None)
    monkeypatch.setattr(f"{MODULE}.is_encryption_enabled", lambda: True)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    assert result.scan_id == "scan-1"
    db.findings.insert_many.assert_awaited()


@pytest.mark.asyncio
async def test_replay_rejects_unknown_collection_marker():
    """The footer is a plain sha256, not an HMAC, so a crafted marker must not reach a collection off the allowlist."""
    from app.services.archive import _replay_bundle
    from app.services.archive_bundle import BundleFrames, BundleStats

    async def bundle():
        async for chunk in BundleFrames.write(
            scan_doc={"_id": "scan-1", "project_id": "p"},
            collections={"users": _aiter([{"_id": "u1", "username": "attacker"}])},
            stats=BundleStats(),
        ):
            yield chunk

    db = _make_mock_db(scan_doc={"_id": "scan-1"})

    reason, _ = await _replay_bundle(db, "scan-1", "p", bundle())

    assert reason == "integrity"
    db.users.insert_many.assert_not_called()


@pytest.mark.asyncio
async def test_replay_maps_bad_version_to_version_mismatch():
    from app.services.archive import _replay_bundle

    header = json.dumps({"version": 99, "scan": {"_id": "x"}}).encode() + b"\n"

    async def src():
        yield header

    db = _make_mock_db()

    reason, _ = await _replay_bundle(db, "x", "y", src())
    assert reason == "version_mismatch"


def _bundle_with_collection(name: str) -> AsyncIterator[bytes]:
    from app.services.archive_bundle import BundleFrames, BundleStats

    return BundleFrames.write(
        scan_doc={"_id": "scan-1", "project_id": "p"}, collections={name: _aiter([{"_id": "a1"}])}, stats=BundleStats()
    )


def _bundle_with_a_list_line() -> AsyncIterator[bytes]:
    header = json.dumps({"version": 2, "scan": {"_id": "scan-1", "project_id": "p"}}).encode() + b"\n"
    return _aiter([header + b'{"collection":"findings"}\n' + b"[1, 2]\n"])


def _unknown_encryption_version() -> AsyncIterator[bytes]:
    from app.core.encryption import decrypt_stream

    return decrypt_stream(_aiter([ENCRYPTION_MAGIC + b"\x99" + b"\x00\x80\x00\x00" + b"\x00\x00\x00\x00"]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (lambda: _bundle_with_collection("version_audit"), "integrity"),
        (lambda: _gzip_decompress_stream(_aiter([b"not a gzip stream"])), "integrity"),
        (_bundle_with_a_list_line, "integrity"),
        (_unknown_encryption_version, "version_mismatch"),
    ],
    ids=["collection-named-version", "not-gzip", "line-not-an-object", "unknown-encryption-version"],
)
async def test_replay_labels_a_broken_bundle_by_its_cause(monkeypatch, source, reason):
    from app.services.archive import _replay_bundle

    monkeypatch.setattr("app.core.encryption.settings", SimpleNamespace(ARCHIVE_ENCRYPTION_KEY="0" * 64))

    failure, _ = await _replay_bundle(_make_mock_db(), "scan-1", "p", source())

    assert failure == reason


@pytest.mark.asyncio
async def test_replay_hashes_the_plaintext_secret_of_a_legacy_trufflehog_result():
    """A bundle archived with a plaintext Raw must not put it back into Mongo on restore."""
    from app.services.archive import _replay_bundle
    from app.services.archive_bundle import BundleFrames, BundleStats

    secret = "AKIAIOSFODNN7EXAMPLE"
    legacy_result = {
        "_id": "r1",
        "scan_id": "scan-1",
        "analyzer_name": "trufflehog",
        "result": {"findings": [{"DetectorType": "2", "Raw": secret}]},
    }

    async def bundle():
        async for chunk in BundleFrames.write(
            scan_doc={"_id": "scan-1", "project_id": "p"},
            collections={"analysis_results": _aiter([legacy_result])},
            stats=BundleStats(),
        ):
            yield chunk

    db = _make_mock_db()

    reason, _ = await _replay_bundle(db, "scan-1", "p", bundle())

    assert reason is None
    (restored,) = db.analysis_results.insert_many.await_args.args[0]
    assert secret not in json.dumps(restored)
    assert restored["result"]["findings"][0]["RawHash"] == hashlib.md5(secret.encode()).hexdigest()[:8]


@pytest.mark.asyncio
async def test_replay_inserts_each_legacy_inline_analysis_result_on_its_own():
    """A legacy row inlines a whole scanner report, so a batch of them would hold many reports in memory."""
    from app.services.archive import _replay_bundle
    from app.services.archive_bundle import BundleFrames, BundleStats

    rows = [{"_id": f"r{i}", "scan_id": "scan-1", "analyzer_name": "grype", "result": {"matches": []}} for i in range(3)]

    async def bundle():
        async for chunk in BundleFrames.write(
            scan_doc={"_id": "scan-1", "project_id": "p"},
            collections={"analysis_results": _aiter(rows)},
            stats=BundleStats(),
        ):
            yield chunk

    db = _make_mock_db()

    reason, _ = await _replay_bundle(db, "scan-1", "p", bundle())

    assert reason is None
    assert [call.args[0] for call in db.analysis_results.insert_many.await_args_list] == [[row] for row in rows]


@pytest.mark.asyncio
async def test_replay_strips_the_bundle_license_parameters_an_old_bundle_stored():
    from app.services.archive import _replay_bundle
    from app.services.archive_bundle import BundleFrames, BundleStats

    purl = "pkg:maven/org.apache.logging.log4j/log4j-api@2.25.5"
    dependencies = [
        {"_id": "d1", "scan_id": "scan-1", "purl": purl, "license": '"Apache-2.0";link="https://a.example"'},
        {
            "_id": "d2",
            "scan_id": "scan-1",
            "purl": purl,
            "license": 'Apache-2.0;link="https://a.example",MIT;link="https://b.example"',
            "license_url": "https://kept.example",
        },
        {"_id": "d3", "scan_id": "scan-1", "purl": purl, "license": "MIT"},
        {"_id": "d4", "scan_id": "scan-1", "purl": purl, "license": 'MIT OR "Apache-2.0";link="https://c.example"'},
        {
            "_id": "d5",
            "scan_id": "scan-1",
            "purl": purl,
            "license": "Apache-2.0",
            "license_url": "https://www.apache.org/licenses/LICENSE-2.0;description=Apache-2.0",
        },
    ]

    async def bundle():
        async for chunk in BundleFrames.write(
            scan_doc={"_id": "scan-1", "project_id": "p"},
            collections={"dependencies": _aiter(dependencies)},
            stats=BundleStats(),
        ):
            yield chunk

    db = _make_mock_db()

    reason, _ = await _replay_bundle(db, "scan-1", "p", bundle())

    assert reason is None
    restored = db.dependencies.insert_many.await_args.args[0]
    assert [(d["license"], d.get("license_url")) for d in restored] == [
        ("Apache-2.0", "https://a.example"),
        ("Apache-2.0 OR MIT", "https://kept.example"),
        ("MIT", None),
        ("MIT OR Apache-2.0", "https://c.example"),
        ("Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0"),
    ]


@pytest.mark.asyncio
async def test_archive_hashes_the_plaintext_secret_of_a_legacy_trufflehog_row(archive_env):
    """A Mongo row from before ingest hashed Raw must not carry the plaintext into a new bundle."""
    from app.services.archive_bundle import read_bundle_frames

    secret = "AKIAIOSFODNN7EXAMPLE"
    legacy_row = {
        "_id": "r1",
        "scan_id": "scan-1",
        "analyzer_name": "trufflehog",
        "result": {"findings": [{"DetectorType": "2", "Raw": secret}]},
    }
    db = _make_mock_db(scan_doc=_make_scan_doc(), analysis_results=[legacy_row])

    with _patch_repos()():
        result = await archive_scan(db, "scan-1")

    assert result is not None
    bundle = zlib.decompress(archive_env.objects[result.s3_key], wbits=31)
    assert secret.encode() not in bundle
    events = [event async for event in read_bundle_frames(_aiter([bundle]))]
    (archived,) = [e["data"] for e in events if e.get("collection") == "analysis_results"]
    assert archived["result"]["findings"][0]["RawHash"] == hashlib.md5(secret.encode()).hexdigest()[:8]


@pytest.mark.asyncio
async def test_replay_inserts_the_scan_as_a_restore_in_progress():
    """The header drops the bundle's restored_at, the reaper's sign of a finished restore, and a cut cascade's mark."""
    from app.services.archive import _replay_bundle
    from app.services.archive_bundle import BundleFrames, BundleStats

    earlier_restore = datetime(2025, 6, 1, tzinfo=timezone.utc)

    async def bundle():
        async for chunk in BundleFrames.write(
            scan_doc={"_id": "scan-1", "project_id": "p", "restored_at": earlier_restore, "retention_deleting": True},
            collections={},
            stats=BundleStats(),
        ):
            yield chunk

    db = _make_mock_db()

    reason, _ = await _replay_bundle(db, "scan-1", "p", bundle())

    assert reason is None
    inserted = db.scans.insert_one.await_args.args[0]
    assert inserted["restore_in_progress"] is True
    assert inserted["pinned"] is True
    assert "restored_at" not in inserted
    assert "retention_deleting" not in inserted


@pytest.mark.asyncio
async def test_restore_stamps_completion_on_the_scan_it_left_in_progress(archive_env, monkeypatch):
    meta = _make_archive_metadata()
    db = _make_mock_db()
    db.scans.find_one = AsyncMock(return_value=None)
    monkeypatch.setattr(f"{MODULE}._replay_bundle", AsyncMock(return_value=(None, ["scans"])))
    monkeypatch.setattr(f"{MODULE}._open_bundle_stream", lambda _: None)
    monkeypatch.setattr(f"{MODULE}.delete_object", AsyncMock(return_value=None))
    db.scans.update_one = AsyncMock(return_value=MagicMock(matched_count=1))
    before = datetime.now(timezone.utc)

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        LockCls.return_value.renew_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    query, update = db.scans.update_one.await_args.args
    assert query == {"_id": "scan-1", "restore_in_progress": True}
    assert update["$unset"] == {"restore_in_progress": ""}
    restored_at = update["$set"]["restored_at"]
    assert restored_at.tzinfo == timezone.utc
    assert before <= restored_at <= datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_download_hashes_trufflehog_secrets_and_passes_sbom_lines_through_undecoded(archive_env, monkeypatch):
    from bson import json_util

    from app.services.archive import _gzip_compress_stream, stream_bundle_for_download
    from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

    secret = "AKIAIOSFODNN7EXAMPLE"
    original = b"".join(
        [
            chunk
            async for chunk in BundleFrames.write(
                scan_doc={"_id": "scan-1", "project_id": "proj-1"},
                collections={
                    "analysis_results": _aiter(
                        [
                            {"_id": "r0", "scan_id": "scan-1", "analyzer_name": "grype", "result": {}},
                            {
                                "_id": "r1",
                                "scan_id": "scan-1",
                                "analyzer_name": "trufflehog",
                                "result": {"findings": [{"DetectorType": "2", "Raw": secret}]},
                            },
                        ]
                    ),
                    "gridfs_sboms": _aiter(
                        [
                            {
                                "gridfs_id": "507f1f77bcf86cd799439011",
                                "filename": "sbom.json",
                                "data": {"components": [{"name": f"sbom-component-{i}"} for i in range(5000)]},
                            }
                        ]
                    ),
                },
                stats=BundleStats(),
            )
        ]
    )
    archive_env.objects["proj-1/scan-1.bundle"] = b"".join(
        [chunk async for chunk in _gzip_compress_stream(_aiter([original]))]
    )
    decoded: list[str | bytes] = []
    loads = json_util.loads

    def recording_loads(s, *args, **kwargs):
        decoded.append(s)
        return loads(s, *args, **kwargs)

    monkeypatch.setattr(json_util, "loads", recording_loads)
    metadata = _make_archive_metadata(s3_key="proj-1/scan-1.bundle", s3_bucket="test-bucket")

    downloaded = zlib.decompress(
        b"".join([chunk async for chunk in stream_bundle_for_download(metadata)]),
        wbits=31,
    )

    assert decoded, "the header, markers and the trufflehog result still need decoding"
    assert not any("sbom-component" in (s.decode() if isinstance(s, bytes) else s) for s in decoded)
    (sbom_line,) = [line for line in original.splitlines(keepends=True) if b"sbom-component" in line]
    assert sbom_line in downloaded
    assert secret.encode() not in downloaded
    events = [event async for event in read_bundle_frames(_aiter([downloaded]))]
    results = {e["data"]["_id"]: e["data"] for e in events if e.get("collection") == "analysis_results"}
    assert results["r0"] == {"_id": "r0", "scan_id": "scan-1", "analyzer_name": "grype", "result": {}}
    assert results["r1"]["result"]["findings"][0]["RawHash"] == hashlib.md5(secret.encode()).hexdigest()[:8]
    assert events[-1]["type"] == "footer"


@pytest.mark.asyncio
async def test_gzip_compression_of_a_large_chunk_leaves_the_event_loop_running():
    import asyncio

    from app.services.archive import _gzip_compress_stream

    chunk = b"sbom-component " * (1 << 17)
    ticks = 0

    async def tick():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    ticker = asyncio.create_task(tick())
    try:
        compressed = b"".join([out async for out in _gzip_compress_stream(_aiter([chunk]))])
    finally:
        ticker.cancel()

    assert ticks > 0
    assert zlib.decompress(compressed, wbits=31) == chunk


@pytest.mark.asyncio
async def test_decompress_hands_out_a_highly_compressed_chunk_in_pieces_of_at_most_one_mib():
    plaintext = b"\0" * (8 << 20) + b"tail"
    compressor = zlib.compressobj(wbits=31)
    gzipped = compressor.compress(plaintext) + compressor.flush()

    pieces = [piece async for piece in _gzip_decompress_stream(_aiter([gzipped[:10], gzipped[10:]]))]

    assert b"".join(pieces) == plaintext
    assert max(map(len, pieces)) <= 1 << 20

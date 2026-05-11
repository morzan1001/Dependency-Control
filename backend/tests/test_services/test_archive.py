"""Tests for archive service (archive_scan, restore_scan)."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.archive import ArchiveMetadata
from app.services.archive import archive_scan, restore_scan

MODULE = "app.services.archive"


# ---------------------------------------------------------------------------
# Helpers — copy these verbatim from the existing test_archive.py
# ---------------------------------------------------------------------------


def _make_scan_doc(**overrides):
    """Create a minimal scan document for testing."""
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
        "original_size_bytes": 1000,
        "compressed_size_bytes": 200,
    }
    defaults.update(overrides)
    return ArchiveMetadata(**defaults)


class _AsyncCursorMock:
    def __init__(self, docs: List[Dict[str, Any]]):
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
    scan_doc=None, findings=None, finding_records=None, dependencies=None,
    analysis_results=None, callgraphs=None,
):
    db = MagicMock()
    db.scans.find_one = AsyncMock(return_value=scan_doc)
    db.scans.find = MagicMock(return_value=_AsyncCursorMock([scan_doc] if scan_doc else []))
    db.scans.insert_one = AsyncMock()
    db.findings.find = MagicMock(return_value=_AsyncCursorMock(findings or []))
    db.findings.insert_many = AsyncMock()
    db.finding_records.find = MagicMock(return_value=_AsyncCursorMock(finding_records or []))
    db.finding_records.insert_many = AsyncMock()
    db.dependencies.find = MagicMock(return_value=_AsyncCursorMock(dependencies or []))
    db.dependencies.insert_many = AsyncMock()
    db.analysis_results.find = MagicMock(return_value=_AsyncCursorMock(analysis_results or []))
    db.analysis_results.insert_many = AsyncMock()
    db.callgraphs.find = MagicMock(return_value=_AsyncCursorMock(callgraphs or []))
    db.callgraphs.insert_many = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Archive environment fixture: patches S3 + lock + encryption + bucket settings
# ---------------------------------------------------------------------------


@pytest.fixture
def archive_env(monkeypatch):
    """Set up S3 fake, lock repo, encryption off, bucket name."""
    from tests.helpers.fake_s3 import FakeS3Client, fake_get_s3_client

    fake = FakeS3Client()

    monkeypatch.setattr("app.core.s3.get_s3_client", lambda: fake_get_s3_client(fake))
    monkeypatch.setattr("app.core.s3.is_archive_enabled", lambda: True)
    monkeypatch.setattr("app.services.archive.is_archive_enabled", lambda: True)
    monkeypatch.setattr("app.services.archive.is_encryption_enabled", lambda: False)

    class _S:
        S3_BUCKET_NAME = "test-bucket"

    monkeypatch.setattr("app.core.s3.settings", _S)
    monkeypatch.setattr("app.core.config.settings", _S, raising=False)

    return fake


def _patch_repos(lock_acquires: bool = True, existing_metadata=None):
    """Returns a contextmanager that patches the metadata repo and lock repo."""
    from contextlib import contextmanager

    @contextmanager
    def cm():
        with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
            f"{MODULE}.DistributedLocksRepository"
        ) as LockCls:
            RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=existing_metadata)
            RepoCls.return_value.create = AsyncMock()
            RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
            LockCls.return_value.acquire_lock = AsyncMock(return_value=lock_acquires)
            LockCls.return_value.release_lock = AsyncMock(return_value=True)
            yield RepoCls, LockCls

    return cm


# ---------------------------------------------------------------------------
# archive_scan tests
# ---------------------------------------------------------------------------


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
    # An object was uploaded to S3
    assert len(archive_env.objects) == 1
    key = next(iter(archive_env.objects))
    assert key.startswith("proj-1/scan-1-")
    assert key.endswith(".bundle")
    # Metadata was created
    RepoCls.return_value.create.assert_awaited_once()


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
    # No upload happens
    assert archive_env.objects == {}
    RepoCls.return_value.create.assert_not_awaited()


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
    """When an S3 upload_part fails, the multipart upload must be aborted and no metadata written."""
    archive_env.fail_next_upload_part = True
    # Big enough to trigger multipart (>5 MiB)
    big_findings = [
        {"_id": f"f{i}", "scan_id": "scan-1", "severity": "LOW", "blob": "x" * 1000}
        for i in range(20000)
    ]
    scan_doc = _make_scan_doc()
    db = _make_mock_db(scan_doc=scan_doc, findings=big_findings)

    with _patch_repos()() as (RepoCls, _):
        result = await archive_scan(db, "scan-1")

    assert result is None
    assert len(archive_env.aborted_uploads) >= 1
    RepoCls.return_value.create.assert_not_awaited()


# ---------------------------------------------------------------------------
# restore_scan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restore_scan_roundtrip(archive_env):
    """Archive a scan, then restore it. All collections must be re-inserted."""
    scan_doc = _make_scan_doc()
    findings = [
        {"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"},
        {"_id": "f2", "scan_id": "scan-1", "severity": "HIGH"},
    ]
    dependencies = [{"_id": "d1", "scan_id": "scan-1", "name": "lib"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings, dependencies=dependencies)

    # 1. Archive
    with _patch_repos()() as (RepoCls, _):
        meta = await archive_scan(db, "scan-1")
        assert meta is not None

    # 2. Restore — simulate that the scan no longer exists, metadata still does
    db.scans.find_one = AsyncMock(return_value=None)

    # Repo returns the metadata we just created
    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None
    assert result.scan_id == "scan-1"
    # Scan was reinserted (with pinned=True)
    db.scans.insert_one.assert_awaited()
    inserted = db.scans.insert_one.await_args.args[0]
    assert inserted["pinned"] is True
    # Findings + dependencies were reinserted
    db.findings.insert_many.assert_awaited()
    db.dependencies.insert_many.assert_awaited()


@pytest.mark.asyncio
async def test_restore_scan_aborts_when_lock_held(archive_env):
    db = _make_mock_db()
    meta = _make_archive_metadata()

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=False)

        result = await restore_scan(db, "scan-1")

    assert result is None
    db.scans.insert_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_restore_scan_aborts_when_scan_already_exists(archive_env):
    """If the scan exists in MongoDB, restore must abort to avoid partial state."""
    meta = _make_archive_metadata()
    existing_scan = _make_scan_doc()
    db = _make_mock_db(scan_doc=existing_scan)

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is None
    db.scans.insert_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_restore_scan_returns_none_when_no_metadata(archive_env):
    db = _make_mock_db()

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=None)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is None


# ---------------------------------------------------------------------------
# Regression tests for follow-up review bugs #2–#5
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_labels_mongo_error_not_as_s3_error():
    """A PyMongoError during replay must produce reason=UNKNOWN, not S3_ERROR."""
    import json

    from pymongo.errors import OperationFailure

    from app.services.archive import _replay_bundle

    header = json.dumps(
        {"version": 2, "scan_id": "x", "project_id": "y", "scan": {"_id": "x"}}
    ).encode() + b"\n"

    async def src():
        yield header

    db = MagicMock()

    async def fail_insert(_doc):
        raise OperationFailure("simulated mongo failure")

    db.scans.insert_one = fail_insert

    reason, _, _ = await _replay_bundle(db, "x", src())
    assert reason == "unknown"
    assert reason != "s3_error"


@pytest.mark.asyncio
async def test_replay_labels_invalid_tag_as_encryption():
    """An InvalidTag during replay (e.g. wrong key) must produce reason=ENCRYPTION."""
    from cryptography.exceptions import InvalidTag

    from app.services.archive import _replay_bundle

    class _RaisingStream:
        """Async iterator that raises InvalidTag on the first iteration."""

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise InvalidTag()

    src = _RaisingStream()

    db = MagicMock()
    reason, _, _ = await _replay_bundle(db, "x", src)
    assert reason == "encryption"


@pytest.mark.asyncio
async def test_restore_deletes_metadata_even_when_s3_delete_fails(archive_env):
    """Bug #3: S3 delete failure must NOT leave a zombie metadata record."""
    scan_doc = _make_scan_doc()
    findings = [{"_id": "f1", "scan_id": "scan-1", "severity": "CRITICAL"}]
    db = _make_mock_db(scan_doc=scan_doc, findings=findings)

    # 1. Archive normally
    with _patch_repos()() as (RepoCls, _):
        meta = await archive_scan(db, "scan-1")
        assert meta is not None

    # 2. Set up restore with: scan doesn't exist, metadata exists, S3 DELETE will fail
    db.scans.find_one = AsyncMock(return_value=None)

    delete_metadata = AsyncMock(return_value=True)

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls, patch(f"{MODULE}.delete_object", AsyncMock(side_effect=RuntimeError("S3 down"))):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = delete_metadata
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is not None  # restore is still successful
    delete_metadata.assert_awaited_once_with("scan-1")


@pytest.mark.asyncio
async def test_restore_rolls_back_partial_state_on_replay_failure(archive_env, monkeypatch):
    """Bug #4: when _replay_bundle fails, partial scan + collections must be cleaned up."""
    meta = _make_archive_metadata()
    db = _make_mock_db()
    db.scans.find_one = AsyncMock(return_value=None)  # scan not yet present
    db.scans.delete_one = AsyncMock()
    db.findings.delete_many = AsyncMock()
    db.finding_records.delete_many = AsyncMock()
    db.dependencies.delete_many = AsyncMock()
    db.analysis_results.delete_many = AsyncMock()
    db.callgraphs.delete_many = AsyncMock()

    # Force _replay_bundle to return a failure reason
    monkeypatch.setattr(
        f"{MODULE}._replay_bundle",
        AsyncMock(return_value=("integrity", ["scans"], [])),
    )
    # Bypass the S3 stream construction
    monkeypatch.setattr(f"{MODULE}._open_restore_stream", lambda _: None)

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await restore_scan(db, "scan-1")

    assert result is None  # failure
    # Rollback was attempted across the touched collections
    db.scans.delete_one.assert_awaited_once_with({"_id": "scan-1"})
    db.findings.delete_many.assert_awaited()
    db.dependencies.delete_many.assert_awaited()


@pytest.mark.asyncio
async def test_archive_scan_labels_duplicate_key_as_already_exists(archive_env, monkeypatch):
    """Bug #5: a DuplicateKeyError from repo.create must be labeled ALREADY_EXISTS, not UNKNOWN."""
    from pymongo.errors import DuplicateKeyError

    from app.core.metrics import archive_failures_total

    # Capture which reason label was used
    seen_reasons: list[str] = []
    orig_labels = archive_failures_total.labels

    def capture_labels(**kw):
        if kw.get("operation") == "archive":
            seen_reasons.append(kw.get("reason"))
        return orig_labels(**kw)

    monkeypatch.setattr(archive_failures_total, "labels", capture_labels)

    scan_doc = _make_scan_doc()
    db = _make_mock_db(scan_doc=scan_doc, findings=[{"_id": "f1", "scan_id": "scan-1"}])

    with patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls, patch(
        f"{MODULE}.DistributedLocksRepository"
    ) as LockCls:
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=None)
        RepoCls.return_value.create = AsyncMock(side_effect=DuplicateKeyError("dup"))
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)

        result = await archive_scan(db, "scan-1")

    assert result is None
    assert "already_exists" in seen_reasons
    assert "unknown" not in seen_reasons

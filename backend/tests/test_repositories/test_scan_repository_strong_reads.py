"""Tests for read-after-write safe reads on ScanRepository.

These tests cover the *_strong variants that pin reads to the Mongo Primary
to avoid stale reads on a replica set when MONGODB_READ_PREFERENCE is
secondaryPreferred. They are exercised by worker/engine/housekeeping paths
that read scan state immediately after a write.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from pymongo import ReadPreference

from app.repositories.scans import ScanRepository
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _scan_doc(scan_id: str = "scan-1") -> dict:
    return {"_id": scan_id, "project_id": "p1", "branch": "main"}


def _wrap_with_primary(primary_coll):
    """Build a collection mock whose with_options(...) returns ``primary_coll``."""
    base = MagicMock()
    base.with_options = MagicMock(return_value=primary_coll)
    return base


class TestGetByIdStrong:
    def test_uses_primary_read_preference(self):
        primary = create_mock_collection(find_one=_scan_doc())
        base = _wrap_with_primary(primary)
        db = create_mock_db({"scans": base})
        repo = ScanRepository(db)

        asyncio.run(repo.get_by_id_strong("scan-1"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        primary.find_one.assert_called_once_with({"_id": "scan-1"})

    def test_returns_scan_when_found(self):
        primary = create_mock_collection(find_one=_scan_doc("scan-42"))
        base = _wrap_with_primary(primary)
        db = create_mock_db({"scans": base})
        repo = ScanRepository(db)

        result = asyncio.run(repo.get_by_id_strong("scan-42"))

        assert result is not None
        assert result.id == "scan-42"

    def test_returns_none_when_not_found(self):
        primary = create_mock_collection(find_one=None)
        base = _wrap_with_primary(primary)
        db = create_mock_db({"scans": base})
        repo = ScanRepository(db)

        result = asyncio.run(repo.get_by_id_strong("missing"))

        assert result is None

    def test_default_get_by_id_does_not_force_primary(self):
        """The non-strong variant must keep the global readPreference (Secondary OK)."""
        base = create_mock_collection(find_one=_scan_doc())
        # Make with_options blow up so we'd notice if get_by_id accidentally calls it.
        base.with_options = MagicMock(side_effect=AssertionError("default get_by_id must not pin Primary"))
        db = create_mock_db({"scans": base})
        repo = ScanRepository(db)

        asyncio.run(repo.get_by_id("scan-1"))

        base.with_options.assert_not_called()


class TestGetMinimalByIdStrong:
    def test_uses_primary_read_preference(self):
        primary = create_mock_collection(
            find_one={"_id": "scan-1", "project_id": "p1", "status": "processing"},
        )
        base = _wrap_with_primary(primary)
        db = create_mock_db({"scans": base})
        repo = ScanRepository(db)

        asyncio.run(repo.get_minimal_by_id_strong("scan-1"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        # projection arg is the second positional/kwarg
        args, kwargs = primary.find_one.call_args
        assert args[0] == {"_id": "scan-1"}

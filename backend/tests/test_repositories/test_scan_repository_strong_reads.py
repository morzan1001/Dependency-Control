"""Strong-read variants on ScanRepository must hit Primary."""

import asyncio
from unittest.mock import MagicMock

from pymongo import ReadPreference

from app.repositories.scans import ScanRepository
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _scan_doc(scan_id: str = "scan-1") -> dict:
    return {"_id": scan_id, "project_id": "p1", "branch": "main"}


def _wrap_with_primary(primary_coll):
    base = MagicMock()
    base.with_options = MagicMock(return_value=primary_coll)
    return base


class TestGetByIdStrong:
    def test_reads_from_primary_and_returns_scan(self):
        primary = create_mock_collection(find_one=_scan_doc("scan-42"))
        base = _wrap_with_primary(primary)
        repo = ScanRepository(create_mock_db({"scans": base}))

        result = asyncio.run(repo.get_by_id_strong("scan-42"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        primary.find_one.assert_called_once_with({"_id": "scan-42"})
        assert result is not None and result.id == "scan-42"

    def test_returns_none_when_not_found(self):
        primary = create_mock_collection(find_one=None)
        repo = ScanRepository(create_mock_db({"scans": _wrap_with_primary(primary)}))

        assert asyncio.run(repo.get_by_id_strong("missing")) is None

    def test_default_get_by_id_does_not_force_primary(self):
        base = create_mock_collection(find_one=_scan_doc())
        base.with_options = MagicMock(side_effect=AssertionError("default get_by_id must not pin Primary"))
        repo = ScanRepository(create_mock_db({"scans": base}))

        asyncio.run(repo.get_by_id("scan-1"))

        base.with_options.assert_not_called()


class TestGetMinimalByIdStrong:
    def test_reads_from_primary_with_minimal_projection(self):
        primary = create_mock_collection(
            find_one={"_id": "scan-1", "project_id": "p1", "status": "processing"},
        )
        base = _wrap_with_primary(primary)
        repo = ScanRepository(create_mock_db({"scans": base}))

        asyncio.run(repo.get_minimal_by_id_strong("scan-1"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        call = primary.find_one.call_args
        assert call.args[0] == {"_id": "scan-1"}
        assert "project_id" in call.args[1]

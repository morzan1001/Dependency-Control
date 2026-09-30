"""Tests for BaseRepository.replace_many_raw: whole-document upserts by _id and partial-failure behavior."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from pymongo.errors import BulkWriteError, OperationFailure

from app.repositories.findings import FindingRepository
from tests.mocks.fake_mongo import FakeDatabase


def _make_repo(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return FindingRepository(db)


def _write_error(n_upserted: int, n_matched: int, n_errors: int) -> BulkWriteError:
    return BulkWriteError(
        {
            "nUpserted": n_upserted,
            "nMatched": n_matched,
            "writeErrors": [
                {"index": i, "code": 17420, "errmsg": "Resulting document after update is larger than 16777216"}
                for i in range(n_errors)
            ],
        }
    )


class TestReplaceManyRawWritesWholeDocuments:
    def test_the_same_ids_written_twice_leave_one_doc_each_holding_the_second_content(self):
        db = FakeDatabase()
        repo = FindingRepository(db)
        asyncio.run(repo.replace_many_raw([{"_id": "f-1", "waived": True, "severity": "LOW"}, {"_id": "f-2"}]))

        written = asyncio.run(repo.replace_many_raw([{"_id": "f-1", "severity": "HIGH"}, {"_id": "f-2", "n": 2}]))

        assert written == 2
        assert db.findings._docs == {"f-1": {"_id": "f-1", "severity": "HIGH"}, "f-2": {"_id": "f-2", "n": 2}}

    def test_the_bulk_write_is_unordered(self):
        collection = MagicMock()
        collection.bulk_write = AsyncMock(return_value=MagicMock(upserted_count=1, matched_count=0))
        repo = _make_repo(collection)

        asyncio.run(repo.replace_many_raw([{"_id": "1"}]))

        assert collection.bulk_write.call_args.kwargs.get("ordered") is False


class TestReplaceManyRawWriteErrors:
    def test_partial_write_count_returned(self):
        collection = MagicMock()
        collection.bulk_write = AsyncMock(side_effect=_write_error(n_upserted=2, n_matched=1, n_errors=2))
        repo = _make_repo(collection)

        written = asyncio.run(repo.replace_many_raw([{"_id": str(i)} for i in range(5)]))
        assert written == 3

    def test_write_errors_are_logged(self, caplog):
        collection = MagicMock()
        collection.bulk_write = AsyncMock(side_effect=_write_error(n_upserted=2, n_matched=1, n_errors=2))
        repo = _make_repo(collection)

        with caplog.at_level(logging.WARNING, logger="app.repositories.base"):
            asyncio.run(repo.replace_many_raw([{"_id": str(i)} for i in range(5)]))

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        message = warnings[0].getMessage()
        assert "findings" in message
        assert "2 of 5" in message

    def test_clean_write_logs_nothing(self, caplog):
        collection = MagicMock()
        collection.bulk_write = AsyncMock(return_value=MagicMock(upserted_count=1, matched_count=1))
        repo = _make_repo(collection)

        with caplog.at_level(logging.WARNING, logger="app.repositories.base"):
            written = asyncio.run(repo.replace_many_raw([{"_id": "1"}, {"_id": "2"}]))

        assert written == 2
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


class TestReplaceManyRawLetsOtherFailuresThrough:
    def test_an_error_without_a_details_document_surfaces_as_itself(self):
        collection = MagicMock()
        collection.bulk_write = AsyncMock(side_effect=OperationFailure("not authorized", code=13))
        repo = _make_repo(collection)

        with pytest.raises(OperationFailure, match="not authorized"):
            asyncio.run(repo.replace_many_raw([{"_id": "1"}]))

    def test_an_unacknowledged_write_concern_is_not_reported_as_success(self):
        failure = BulkWriteError(
            {
                "nUpserted": 2,
                "nMatched": 0,
                "writeErrors": [],
                "writeConcernErrors": [{"code": 64, "errmsg": "waiting for replication"}],
            }
        )
        collection = MagicMock()
        collection.bulk_write = AsyncMock(side_effect=failure)
        repo = _make_repo(collection)

        with pytest.raises(BulkWriteError):
            asyncio.run(repo.replace_many_raw([{"_id": "1"}, {"_id": "2"}]))

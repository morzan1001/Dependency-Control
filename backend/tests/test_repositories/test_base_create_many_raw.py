"""Tests for BaseRepository.create_many_raw partial-failure behavior."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

from pymongo.errors import BulkWriteError

from app.repositories.dependencies import DependencyRepository


def _make_repo(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return DependencyRepository(db)


def _duplicate_key_error(n_inserted: int, n_errors: int) -> BulkWriteError:
    return BulkWriteError(
        {
            "nInserted": n_inserted,
            "writeErrors": [
                {"index": i, "code": 11000, "errmsg": "E11000 duplicate key error collection: dependencies"}
                for i in range(n_errors)
            ],
        }
    )


class TestCreateManyRawWriteErrors:
    def test_partial_insert_count_returned(self):
        collection = MagicMock()
        collection.insert_many = AsyncMock(side_effect=_duplicate_key_error(n_inserted=3, n_errors=2))
        repo = _make_repo(collection)

        inserted = asyncio.run(repo.create_many_raw([{"_id": str(i)} for i in range(5)]))
        assert inserted == 3

    def test_write_errors_are_logged(self, caplog):
        collection = MagicMock()
        collection.insert_many = AsyncMock(side_effect=_duplicate_key_error(n_inserted=3, n_errors=2))
        repo = _make_repo(collection)

        with caplog.at_level(logging.WARNING, logger="app.repositories.base"):
            asyncio.run(repo.create_many_raw([{"_id": str(i)} for i in range(5)]))

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        message = warnings[0].getMessage()
        assert "dependencies" in message
        assert "2" in message

    def test_clean_insert_logs_nothing(self, caplog):
        collection = MagicMock()
        collection.insert_many = AsyncMock(return_value=MagicMock(inserted_ids=["1", "2"]))
        repo = _make_repo(collection)

        with caplog.at_level(logging.WARNING, logger="app.repositories.base"):
            inserted = asyncio.run(repo.create_many_raw([{"_id": "1"}, {"_id": "2"}]))

        assert inserted == 2
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

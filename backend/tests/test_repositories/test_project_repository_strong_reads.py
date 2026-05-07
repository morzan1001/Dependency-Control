"""Tests for read-after-write safe reads on ProjectRepository.

Used by the analysis engine to load fresh project config immediately after
a worker pickup, where stale Secondary reads would race the just-applied
status flip on the corresponding scan.
"""

import asyncio
from unittest.mock import MagicMock

from pymongo import ReadPreference

from app.repositories.projects import ProjectRepository
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _project_doc(project_id: str = "p1") -> dict:
    return {"_id": project_id, "name": "test-project"}


def _wrap_with_primary(primary_coll):
    base = MagicMock()
    base.with_options = MagicMock(return_value=primary_coll)
    return base


class TestGetByIdStrong:
    def test_uses_primary_read_preference(self):
        primary = create_mock_collection(find_one=_project_doc())
        base = _wrap_with_primary(primary)
        db = create_mock_db({"projects": base})
        repo = ProjectRepository(db)

        asyncio.run(repo.get_by_id_strong("p1"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        primary.find_one.assert_called_once_with({"_id": "p1"})

    def test_returns_project_when_found(self):
        primary = create_mock_collection(find_one=_project_doc("p-42"))
        base = _wrap_with_primary(primary)
        db = create_mock_db({"projects": base})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.get_by_id_strong("p-42"))

        assert result is not None
        assert result.id == "p-42"

    def test_returns_none_when_not_found(self):
        primary = create_mock_collection(find_one=None)
        base = _wrap_with_primary(primary)
        db = create_mock_db({"projects": base})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.get_by_id_strong("missing"))

        assert result is None

    def test_default_get_by_id_does_not_force_primary(self):
        base = create_mock_collection(find_one=_project_doc())
        base.with_options = MagicMock(side_effect=AssertionError("default get_by_id must not pin Primary"))
        db = create_mock_db({"projects": base})
        repo = ProjectRepository(db)

        asyncio.run(repo.get_by_id("p1"))

        base.with_options.assert_not_called()

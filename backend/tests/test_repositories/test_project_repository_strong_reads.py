"""Strong-read variant on ProjectRepository must hit Primary."""

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
    def test_reads_from_primary_and_returns_project(self):
        primary = create_mock_collection(find_one=_project_doc("p-42"))
        base = _wrap_with_primary(primary)
        repo = ProjectRepository(create_mock_db({"projects": base}))

        result = asyncio.run(repo.get_by_id_strong("p-42"))

        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)
        primary.find_one.assert_called_once_with({"_id": "p-42"})
        assert result is not None and result.id == "p-42"

    def test_returns_none_when_not_found(self):
        primary = create_mock_collection(find_one=None)
        repo = ProjectRepository(create_mock_db({"projects": _wrap_with_primary(primary)}))

        assert asyncio.run(repo.get_by_id_strong("missing")) is None

    def test_default_get_by_id_does_not_force_primary(self):
        base = create_mock_collection(find_one=_project_doc())
        base.with_options = MagicMock(side_effect=AssertionError("default get_by_id must not pin Primary"))
        repo = ProjectRepository(create_mock_db({"projects": base}))

        asyncio.run(repo.get_by_id("p1"))

        base.with_options.assert_not_called()

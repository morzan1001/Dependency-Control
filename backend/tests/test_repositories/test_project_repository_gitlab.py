"""Tests for ProjectRepository GitLab multi-instance methods.

Tests composite key lookups, instance-based queries, and pagination using mocked MongoDB.
"""

import asyncio

from app.repositories.projects import ProjectRepository
from tests.mocks.mongodb import create_mock_collection, create_mock_db


class TestCompositeKeyLookup:
    def test_queries_both_fields(self):
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        asyncio.run(repo.get_by_gitlab_composite_key("instance-a", 12345))

        collection.find_one.assert_called_once_with(
            {
                "gitlab_instance_id": "instance-a",
                "gitlab_project_id": 12345,
            }
        )

    def test_returns_project_when_found(self):
        doc = {
            "_id": "proj-id",
            "name": "Test Project",
            "owner_id": "user-1",
            "gitlab_instance_id": "instance-a",
            "gitlab_project_id": 12345,
        }
        collection = create_mock_collection(find_one=doc)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.get_by_gitlab_composite_key("instance-a", 12345))
        assert result is not None
        assert result.name == "Test Project"
        assert result.gitlab_instance_id == "instance-a"

    def test_returns_none_when_not_found(self):
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.get_by_gitlab_composite_key("wrong", 99999))
        assert result is None

    def test_raw_returns_dict(self):
        doc = {
            "_id": "proj-id",
            "name": "Test",
            "owner_id": "user-1",
            "gitlab_instance_id": "instance-a",
            "gitlab_project_id": 12345,
        }
        collection = create_mock_collection(find_one=doc)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.get_raw_by_gitlab_composite_key("instance-a", 12345))
        assert isinstance(result, dict)
        assert result["gitlab_instance_id"] == "instance-a"
        assert result["gitlab_project_id"] == 12345


class TestInstanceQueries:
    def test_list_by_instance_filters_correctly(self):
        docs = [
            {"_id": "1", "name": "P1", "owner_id": "u1", "gitlab_instance_id": "instance-a"},
            {"_id": "2", "name": "P2", "owner_id": "u1", "gitlab_instance_id": "instance-a"},
        ]
        collection = create_mock_collection(find=docs)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.list_by_instance("instance-a"))

        collection.find.assert_called_once_with({"gitlab_instance_id": "instance-a"})
        assert len(result) == 2

    def test_list_by_instance_pagination(self):
        collection = create_mock_collection(find=[])
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        asyncio.run(repo.list_by_instance("instance-a", skip=10, limit=5))

        collection.find.assert_called_once_with({"gitlab_instance_id": "instance-a"})
        cursor = collection.find.return_value
        cursor.skip.assert_called_once_with(10)
        cursor.limit.assert_called_once_with(5)

    def test_count_by_instance(self):
        collection = create_mock_collection(count_documents=3)
        db = create_mock_db({"projects": collection})
        repo = ProjectRepository(db)

        result = asyncio.run(repo.count_by_instance("instance-a"))

        assert result == 3
        collection.count_documents.assert_called_once_with({"gitlab_instance_id": "instance-a"})

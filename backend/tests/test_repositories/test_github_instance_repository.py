"""Tests for GitHubInstanceRepository.

Tests query logic, URL normalization, and CRUD operations using mocked MongoDB.
Mirrors the pattern in test_gitlab_instance_repository.py.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.repositories.github_instances import GitHubInstanceRepository
from tests.mocks.github import make_github_instance
from tests.mocks.mongodb import create_mock_collection, create_mock_db


class TestGetByUrl:
    def test_normalizes_trailing_slash(self):
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        asyncio.run(repo.get_by_url("https://token.actions.githubusercontent.com/"))

        collection.find_one.assert_called_once_with({"url": "https://token.actions.githubusercontent.com"})

    def test_returns_instance_when_found(self):
        doc = {
            "_id": "test-id",
            "name": "GitHub.com",
            "url": "https://token.actions.githubusercontent.com",
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=doc)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.get_by_url("https://token.actions.githubusercontent.com"))
        assert result is not None
        assert result.name == "GitHub.com"

    def test_returns_none_when_not_found(self):
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.get_by_url("https://nonexistent.com"))
        assert result is None


class TestExistsByUrl:
    def test_normalizes_url(self):
        collection = create_mock_collection(count_documents=0)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        asyncio.run(repo.exists_by_url("https://token.actions.githubusercontent.com/"))

        collection.count_documents.assert_called_once_with({"url": "https://token.actions.githubusercontent.com"})

    def test_returns_true_when_exists(self):
        collection = create_mock_collection(count_documents=1)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.exists_by_url("https://token.actions.githubusercontent.com"))
        assert result is True

    def test_returns_false_when_not_exists(self):
        collection = create_mock_collection(count_documents=0)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.exists_by_url("https://nonexistent.com"))
        assert result is False

    def test_exclude_id_adds_ne_filter(self):
        collection = create_mock_collection(count_documents=0)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        asyncio.run(repo.exists_by_url("https://token.actions.githubusercontent.com", exclude_id="excluded-id"))

        collection.count_documents.assert_called_once_with(
            {
                "url": "https://token.actions.githubusercontent.com",
                "_id": {"$ne": "excluded-id"},
            }
        )


class TestExistsByName:
    def test_returns_true_when_exists(self):
        collection = create_mock_collection(count_documents=1)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.exists_by_name("GitHub.com"))
        assert result is True

    def test_returns_false_when_not_exists(self):
        collection = create_mock_collection(count_documents=0)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.exists_by_name("Nonexistent"))
        assert result is False

    def test_exclude_id_adds_ne_filter(self):
        collection = create_mock_collection(count_documents=0)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        asyncio.run(repo.exists_by_name("GitHub.com", exclude_id="some-id"))

        collection.count_documents.assert_called_once_with({"name": "GitHub.com", "_id": {"$ne": "some-id"}})


class TestCRUD:
    def test_create(self):
        instance = make_github_instance()
        collection = create_mock_collection()
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.create(instance))

        collection.insert_one.assert_called_once()
        assert result.id == instance.id

    def test_get_by_id_found(self):
        doc = {
            "_id": "test-id",
            "name": "GitHub.com",
            "url": "https://token.actions.githubusercontent.com",
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=doc)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.get_by_id("test-id"))
        assert result is not None
        assert result.name == "GitHub.com"

    def test_get_by_id_not_found(self):
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.get_by_id("nonexistent"))
        assert result is None

    def test_update_returns_true(self):
        collection = create_mock_collection()
        collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.update("test-id", {"name": "Updated"}))
        assert result is True
        collection.update_one.assert_called_once_with({"_id": "test-id"}, {"$set": {"name": "Updated"}})

    def test_update_returns_false_when_not_found(self):
        collection = create_mock_collection()
        collection.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.update("nonexistent", {"name": "Updated"}))
        assert result is False

    def test_delete_returns_true(self):
        collection = create_mock_collection()
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.delete("test-id"))
        assert result is True

    def test_delete_returns_false_when_not_found(self):
        collection = create_mock_collection()
        collection.delete_one = AsyncMock(return_value=MagicMock(deleted_count=0))
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.delete("nonexistent"))
        assert result is False

    def test_list_active_queries_active_only(self):
        docs = [
            {"_id": "1", "name": "Active", "url": "https://a.com", "is_active": True, "created_by": "admin"},
        ]
        collection = create_mock_collection(find=docs)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.list_active())

        collection.find.assert_called_once_with({"is_active": True})
        assert len(result) == 1

    def test_list_all_queries_empty_filter(self):
        collection = create_mock_collection(find=[])
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        asyncio.run(repo.list_all())

        collection.find.assert_called_once_with({})

    def test_count_active(self):
        collection = create_mock_collection(count_documents=3)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.count_active())

        assert result == 3
        collection.count_documents.assert_called_once_with({"is_active": True})

    def test_count_all(self):
        collection = create_mock_collection(count_documents=5)
        db = create_mock_db({"github_instances": collection})
        repo = GitHubInstanceRepository(db)

        result = asyncio.run(repo.count_all())

        assert result == 5
        collection.count_documents.assert_called_once_with({})

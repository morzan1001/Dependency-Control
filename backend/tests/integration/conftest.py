"""
Fixtures for integration tests.

These tests exercise endpoint behaviour end-to-end via ``httpx.AsyncClient``
against the real FastAPI app, but with the MongoDB and auth dependencies
replaced by lightweight in-process mocks so that no live database or API key
infrastructure is required.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.models.project import Project


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project(project_id: str = "test-project-id", name: str = "test-project") -> Project:
    return Project(id=project_id, name=name)


class _FakeCollection:
    """Minimal in-process collection that supports the operations used by the
    CBOM ingest endpoint and the CryptoAssetRepository."""

    def __init__(self):
        self._docs: dict = {}

    async def update_one(self, query, update, upsert=False):
        key = query.get("_id")
        if key and upsert and key not in self._docs:
            doc = {"_id": key}
            on_insert = update.get("$setOnInsert", {})
            doc.update(on_insert)
            set_ops = update.get("$set", {})
            doc.update(set_ops)
            self._docs[key] = doc
        elif key and key in self._docs:
            set_ops = update.get("$set", {})
            self._docs[key].update(set_ops)
        result = MagicMock()
        result.modified_count = 1
        return result

    async def find_one(self, query):
        key = query.get("_id") or query.get("_id")
        if key:
            return self._docs.get(key)
        # search by field
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in query.items()):
                return doc
        return None

    async def count_documents(self, query):
        count = 0
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in query.items()):
                count += 1
        return count

    async def bulk_write(self, ops, ordered=True):
        for op in ops:
            # Each op is a pymongo UpdateOne
            flt = op._filter
            upd = op._doc
            upsert = op._upsert

            matched = [k for k, d in self._docs.items() if all(d.get(fk) == fv for fk, fv in flt.items())]
            if matched:
                key = matched[0]
                set_ops = upd.get("$set", {})
                self._docs[key].update(set_ops)
            elif upsert:
                on_insert = upd.get("$setOnInsert", {})
                set_ops = upd.get("$set", {})
                doc = {}
                doc.update(set_ops)
                doc.update(on_insert)
                key = doc.get("_id") or flt.get("bom_ref", str(len(self._docs)))
                self._docs[key] = doc
        result = MagicMock()
        result.modified_count = len(ops)
        return result

    async def create_index(self, *args, **kwargs):
        return None


class _FakeDb:
    """Minimal in-process database exposing only the collections needed by the
    CBOM ingest path."""

    def __init__(self):
        self.scans = _FakeCollection()
        self.crypto_assets = _FakeCollection()
        self.projects = _FakeCollection()
        self.dependencies = _FakeCollection()
        self.system_settings = _FakeCollection()

    def __getattr__(self, name):
        # Return a fresh collection for any collection the dep chain happens to
        # touch (e.g. `users`, `gitlab_instances`, `github_instances`) so that
        # repository constructors don't AttributeError before auth logic fires.
        col = _FakeCollection()
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name):
        return getattr(self, name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def _project():
    return _make_project()


@pytest_asyncio.fixture
async def db():
    """In-process fake database shared across a single test."""
    return _FakeDb()


@pytest_asyncio.fixture
async def client(db, _project):
    """AsyncClient wired to the real FastAPI app with auth and DB overridden."""
    from app.main import app
    from app.api.deps import get_project_for_ingest
    from app.db.mongodb import get_database

    async def _fake_project_for_ingest():
        return _project

    async def _fake_get_database():
        return db

    app.dependency_overrides[get_project_for_ingest] = _fake_project_for_ingest
    app.dependency_overrides[get_database] = _fake_get_database

    # Pre-populate the project so tests can look it up
    await db.projects.update_one(
        {"_id": str(_project.id)},
        {"$setOnInsert": {"_id": str(_project.id), "name": _project.name}},
        upsert=True,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    # Clean up overrides after each test
    app.dependency_overrides.pop(get_project_for_ingest, None)
    app.dependency_overrides.pop(get_database, None)


@pytest.fixture
def api_key_headers():
    """Dummy API key header value — auth is bypassed via dep override."""
    return {"X-API-Key": "test-project-id.dummy-secret"}

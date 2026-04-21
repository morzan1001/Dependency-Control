"""
Fixtures for unit tests.

Provides in-process fake database for testing repositories and services
without requiring MongoDB.
"""

from unittest.mock import MagicMock

import pytest_asyncio


_EXISTS = "$exists"
_REGEX = "$regex"


class _FakeCursor:
    """Chainable cursor returned by _FakeCollection.find()."""

    def __init__(self, docs: dict, query: dict):
        self._docs = docs
        self._query = query
        self._skip_n = 0
        self._limit_n = 0
        self._iter: list | None = None

    def skip(self, n: int) -> "_FakeCursor":
        self._skip_n = n
        return self

    def limit(self, n: int) -> "_FakeCursor":
        self._limit_n = n
        return self

    def _matches(self, doc: dict) -> bool:
        import re
        for k, v in self._query.items():
            if not isinstance(v, dict):
                if doc.get(k) != v:
                    return False
            elif _REGEX in v:
                flags = re.IGNORECASE if v.get("$options") == "i" else 0
                if not re.search(v[_REGEX], str(doc.get(k, "")), flags):
                    return False
            elif _EXISTS in v:
                field_present = k in doc
                if bool(v[_EXISTS]) != field_present:
                    return False
            elif doc.get(k) != v:
                return False
        return True

    def _filtered(self) -> list:
        results = [d for d in self._docs.values() if self._matches(d)]
        results = results[self._skip_n:]
        if self._limit_n:
            results = results[: self._limit_n]
        return results

    async def to_list(self, length=None) -> list:
        return self._filtered()

    def __aiter__(self) -> "_FakeCursor":
        self._iter = iter(self._filtered())
        return self

    async def __anext__(self) -> dict:
        try:
            return next(self._iter)  # type: ignore[arg-type]
        except StopIteration:
            raise StopAsyncIteration


class _FakeCollection:
    """Minimal in-process collection that supports the operations used by
    repositories."""

    def __init__(self):
        self._docs: dict = {}

    async def update_one(self, query, update, upsert=False):
        # Try to find an existing document matching the query
        matched_key = None
        for key, doc in self._docs.items():
            if all(doc.get(k) == v for k, v in query.items()):
                matched_key = key
                break

        if matched_key:
            # Update existing document
            set_ops = update.get("$set", {})
            self._docs[matched_key].update(set_ops)
        elif upsert:
            # Insert new document
            set_ops = update.get("$set", {})
            on_insert = update.get("$setOnInsert", {})
            doc = {}
            doc.update(set_ops)
            doc.update(on_insert)
            # Use _id if present, otherwise generate a key
            key = doc.get("_id") or query.get("_id") or str(len(self._docs))
            self._docs[key] = doc

        result = MagicMock()
        result.modified_count = 1
        return result

    async def insert_one(self, doc: dict):
        key = doc.get("_id", str(len(self._docs)))
        self._docs[key] = dict(doc)
        result = MagicMock()
        result.inserted_id = key
        return result

    async def find_one(self, query, projection=None):
        # search by _id
        key = query.get("_id")
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
        modified = 0
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
                modified += 1
            elif upsert:
                on_insert = upd.get("$setOnInsert", {})
                set_ops = upd.get("$set", {})
                doc = {}
                doc.update(set_ops)
                doc.update(on_insert)
                key = doc.get("_id") or flt.get("bom_ref", str(len(self._docs)))
                self._docs[key] = doc
        result = MagicMock()
        result.modified_count = modified
        return result

    async def create_index(self, *args, **kwargs):
        return None

    def find(self, query=None, projection=None, **kwargs):
        """Return a chainable cursor over matching documents."""
        return _FakeCursor(self._docs, query or {})

    async def delete_one(self, query):
        key = query.get("_id")
        if key and key in self._docs:
            del self._docs[key]
        result = MagicMock()
        result.deleted_count = 1
        return result


class _FakeDb:
    """Minimal in-process database exposing collections needed by repositories."""

    def __init__(self):
        self.crypto_policies = _FakeCollection()
        self.crypto_assets = _FakeCollection()
        self.projects = _FakeCollection()
        self.dependencies = _FakeCollection()
        self.system_settings = _FakeCollection()
        self.scans = _FakeCollection()
        self.findings = _FakeCollection()

    def __getattr__(self, name):
        # Return a fresh collection for any collection the dep chain happens to
        # touch so that repository constructors don't AttributeError.
        col = _FakeCollection()
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name):
        return getattr(self, name)


@pytest_asyncio.fixture
async def db():
    """In-process fake database for unit tests."""
    return _FakeDb()

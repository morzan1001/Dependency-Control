"""Startup builds each findings or dependencies index declared here over ~19M rows; every insert writes its key."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock

from pymongo import ASCENDING, DESCENDING

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_KeyPattern = tuple[tuple[str, int], ...]


def _declared(collection: str) -> dict[_KeyPattern, dict[str, Any]]:
    db = FakeDatabase()
    db[collection].create_index = AsyncMock()
    asyncio.run(create_indexes(db))
    declared: dict[_KeyPattern, dict[str, Any]] = {}
    for call in db[collection].create_index.await_args_list:
        spec = call.args[0]
        pairs = [(spec, ASCENDING)] if isinstance(spec, str) else spec.items() if isinstance(spec, dict) else spec
        keys = tuple(pairs)
        assert keys not in declared, f"{collection} declares {keys} twice"
        declared[keys] = call.kwargs
    return declared


def test_findings_declare_only_the_indexes_a_read_needs():
    assert _declared("findings") == {
        (("scan_id", ASCENDING), ("severity", ASCENDING), ("type", ASCENDING), ("finding_id", ASCENDING)): {},
        (("scan_id", ASCENDING), ("waived", ASCENDING)): {},
        (("scan_id", ASCENDING), ("type", ASCENDING)): {},
        (("scan_id", ASCENDING), ("component", ASCENDING), ("version", ASCENDING)): {},
        (
            ("project_id", ASCENDING),
            ("component", ASCENDING),
            ("type", ASCENDING),
            ("finding_id", ASCENDING),
            ("version", ASCENDING),
            ("first_seen_at", ASCENDING),
            ("scan_created_at", ASCENDING),
        ): {},
        (
            ("project_id", ASCENDING),
            ("type", ASCENDING),
            ("finding_id", ASCENDING),
            ("created_at", DESCENDING),
            ("component", ASCENDING),
            ("version", ASCENDING),
            ("first_seen_at", ASCENDING),
        ): {},
        (("type", ASCENDING), ("scan_created_at", ASCENDING)): {},
    }


def test_dependencies_declare_only_the_indexes_a_read_needs():
    assert _declared("dependencies") == {
        (("scan_id", ASCENDING), ("name", ASCENDING), ("version", ASCENDING), ("purl", ASCENDING)): {
            "unique": True,
            "sparse": True,
        },
        (("scan_id", ASCENDING), ("version", ASCENDING)): {},
        (("scan_id", ASCENDING), ("direct", ASCENDING)): {},
        (("scan_id", ASCENDING), ("purl", ASCENDING)): {},
    }

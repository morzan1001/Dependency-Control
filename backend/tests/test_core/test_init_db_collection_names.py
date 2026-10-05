"""create_indexes must build indexes on the collections the app uses (crypto_policy_history)."""

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def _spy(db, name):
    col = db[name]
    col.create_index = AsyncMock()
    return col


def test_policy_audit_indexes_target_crypto_policy_history_collection():
    db = FakeDatabase()
    real = _spy(db, "crypto_policy_history")
    wrong = _spy(db, "policy_audit_entries")

    asyncio.run(create_indexes(db))

    assert wrong.create_index.await_count == 0, (
        "No index should be created on the unused 'policy_audit_entries' collection"
    )
    # All four policy-audit indexes must land on 'crypto_policy_history'.
    assert real.create_index.await_count == 4

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def test_no_scans_index_is_keyed_on_pipeline_id_alone():
    db = FakeDatabase()
    db.scans.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    assert "pipeline_id" not in [call.args[0] for call in db.scans.create_index.await_args_list]

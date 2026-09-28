import pytest

from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_scans_stream_raw_documents_under_the_base_repository_name():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "project_id": "p1", "branch": "main"})
    await db.scans.insert_one({"_id": "s2", "project_id": "other", "branch": "main"})

    rows = [doc async for doc in ScanRepository(db).iterate_raw({"project_id": "p1"}, {"_id": 1})]

    assert rows == [{"_id": "s1"}]

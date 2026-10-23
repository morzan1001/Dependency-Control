"""mongod aborts a runaway aggregate just before the client socket times out, as the driver would resend the read."""

import pytest

from app.db.mongodb import DEFAULT_MAX_TIME_MS, DEFAULT_SOCKET_TIMEOUT_MS
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]


@pytest.mark.parametrize("repository", [DependencyRepository, ScanRepository])
async def test_a_materialised_aggregate_carries_a_time_limit_below_the_socket_timeout(db, repository):
    repo = repository(db)
    await repo.collection.insert_one({"_id": "row"})

    _, entries = await profiled(db, repo.aggregate([{"$match": {}}]))

    sent = [e["command"].get("maxTimeMS") for e in entries if "aggregate" in e.get("command", {})]
    assert sent == [DEFAULT_MAX_TIME_MS]
    assert DEFAULT_SOCKET_TIMEOUT_MS - 1000 <= DEFAULT_MAX_TIME_MS < DEFAULT_SOCKET_TIMEOUT_MS

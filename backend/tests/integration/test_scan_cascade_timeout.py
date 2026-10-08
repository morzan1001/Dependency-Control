import pytest

from app.db.mongodb import create_client
from app.services.scan_cascade import delete_scans_and_related_data
from tests.integration.conftest import _LIVE_MONGO_URL

_SCAN_IDS = [f"scan-{i}" for i in range(10)]
_FINDINGS = 20_000
_SOCKET_TIMEOUT_MS = 5


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_cascade_longer_than_the_socket_timeout_still_deletes_everything(db):
    await db.scans.insert_many([{"_id": scan_id, "project_id": "p"} for scan_id in _SCAN_IDS])
    await db.findings.insert_many([{"scan_id": _SCAN_IDS[i % len(_SCAN_IDS)]} for i in range(_FINDINGS)])

    client = create_client(_LIVE_MONGO_URL, socketTimeoutMS=_SOCKET_TIMEOUT_MS)
    try:
        assert await delete_scans_and_related_data(client[db.name], _SCAN_IDS) == len(_SCAN_IDS)
    finally:
        client.close()

    assert await db.findings.count_documents({}) == 0
    assert await db.scans.count_documents({}) == 0

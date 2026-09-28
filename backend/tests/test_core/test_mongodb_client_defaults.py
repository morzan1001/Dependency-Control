from datetime import timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReadPreference

from app.core.config import Settings
from app.db import mongodb


@pytest.mark.asyncio
async def test_client_reads_primary_and_hands_back_aware_utc(monkeypatch):
    """The Helm chart used to export secondaryPreferred; neither it nor the URI may move reads off the primary."""
    monkeypatch.setenv("MONGODB_READ_PREFERENCE", "secondaryPreferred")
    monkeypatch.setenv("MONGODB_URL", "mongodb://h:27017/?readPreference=secondaryPreferred")
    monkeypatch.setattr(mongodb, "settings", Settings())
    captured: dict = {}

    def _client(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        client = MagicMock()
        client.admin.command = AsyncMock()
        return client

    monkeypatch.setattr(mongodb, "AsyncIOMotorClient", _client)

    await mongodb.connect_to_mongo()
    await mongodb.close_mongo_connection()

    real = AsyncIOMotorClient(captured["url"], **captured["kwargs"])
    try:
        assert real.read_preference == ReadPreference.PRIMARY
        assert real.codec_options.tz_aware is True
        assert real.codec_options.tzinfo is timezone.utc
    finally:
        real.close()

"""What WaiverRepository stores for a waiver."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.waiver import Waiver
from app.repositories.waivers import WaiverRepository
from app.schemas.waiver import WaiverResponse
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_a_stored_waiver_carries_no_frozen_is_active():
    db = FakeDatabase()
    waiver = Waiver(
        reason="r", created_by="u", finding_id="F", expiration_date=datetime.now(timezone.utc) + timedelta(days=1)
    )

    await WaiverRepository(db).create(waiver)

    stored = await db.waivers.find_one({"_id": waiver.id})
    assert "is_active" not in stored
    assert WaiverResponse.model_validate(await WaiverRepository(db).get_by_id(waiver.id)).is_active is True

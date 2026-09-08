"""WaiverRepository.find_active_global: the waivers that apply to every project, still live."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.waiver import Waiver
from app.repositories.waivers import WaiverRepository
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "project-1"
_REASON = "accepted"
_CREATED_BY = "admin"
_CVE = "CVE-2024-0001"
_DAY = timedelta(days=1)


async def _seed(db: FakeDatabase, **fields) -> Waiver:
    waiver = Waiver(reason=_REASON, created_by=_CREATED_BY, vulnerability_id=_CVE, **fields)
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))
    return waiver


@pytest.mark.asyncio
async def test_a_global_waiver_without_an_expiry_is_returned():
    db = FakeDatabase()
    waiver = await _seed(db, project_id=None)

    assert [w.id for w in await WaiverRepository(db).find_active_global()] == [waiver.id]


@pytest.mark.asyncio
async def test_a_project_scoped_waiver_is_excluded():
    db = FakeDatabase()
    await _seed(db, project_id=_PROJECT_ID)

    assert await WaiverRepository(db).find_active_global() == []


@pytest.mark.asyncio
async def test_an_expired_global_waiver_is_excluded():
    db = FakeDatabase()
    await _seed(db, project_id=None, expiration_date=datetime.now(timezone.utc) - _DAY)

    assert await WaiverRepository(db).find_active_global() == []


@pytest.mark.asyncio
async def test_a_global_waiver_expiring_in_the_future_is_returned():
    db = FakeDatabase()
    waiver = await _seed(db, project_id=None, expiration_date=datetime.now(timezone.utc) + _DAY)

    assert [w.id for w in await WaiverRepository(db).find_active_global()] == [waiver.id]

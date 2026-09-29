"""Run the one waiver restamp over seeded finding documents and read back what it stamped."""

from collections.abc import Mapping
from typing import Any

from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.waivers import WaiverRepository
from app.services.waivers.apply import restamp_waivers
from tests.mocks.fake_mongo import FakeDatabase


class RecordingWaiverRepository(WaiverRepository):
    """Keeps what the restamp wrote about each waiver."""

    def __init__(self, db: Any):
        super().__init__(db)
        self.writes: dict[str, dict[str, Any]] = {}

    async def set_fields_many(self, fields_by_id: Mapping[str, dict[str, Any]]) -> None:
        for wid, fields in fields_by_id.items():
            self.writes.setdefault(wid, {}).update(fields)
        await super().set_fields_many(fields_by_id)


async def restamp_docs(
    docs: list[dict[str, Any]], waivers: list[Waiver], scan_id: str, *, record: bool = True
) -> tuple[FakeDatabase, RecordingWaiverRepository]:
    db = FakeDatabase()
    if docs:
        await db.findings.insert_many([dict(doc) for doc in docs])
    waiver_repo = RecordingWaiverRepository(db)
    await restamp_waivers(FindingRepository(db), waiver_repo if record else None, scan_id, waivers)
    return db, waiver_repo


async def waived(db: Any, scan_id: str) -> dict[str, str | None]:
    return {
        doc["_id"]: doc.get("waiver_reason") async for doc in db.findings.find({"scan_id": scan_id, "waived": True})
    }


async def lapsed(db: Any, scan_id: str) -> dict[str, str]:
    query = {"scan_id": scan_id, "waiver_lapsed": True}
    return {doc["_id"]: doc["lapsed_waiver_id"] async for doc in db.findings.find(query)}

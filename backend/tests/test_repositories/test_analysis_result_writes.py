import pytest

from app.repositories.analysis_results import AnalysisResultRepository
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = "scan-1"
_RESCAN = "scan-2"


@pytest.mark.asyncio
async def test_carry_over_copies_the_external_rows_once():
    db = FakeDatabase()
    repo = AnalysisResultRepository(db)
    for row_id, analyzer, result in (
        ("r1", "trufflehog", {"secrets": 1}),
        ("r2", "trufflehog", {"secrets": 2}),
        ("r3", "osv", {"regenerated": True}),
    ):
        await db.analysis_results.insert_one(
            {"_id": row_id, "scan_id": _SCAN, "analyzer_name": analyzer, "result": result}
        )

    await repo.carry_over(_SCAN, _RESCAN, exclude_names=["osv"])
    await repo.carry_over(_SCAN, _RESCAN, exclude_names=["osv"])

    copied = await repo.find_by_scan(_RESCAN, limit=10)
    assert sorted(row.result["secrets"] for row in copied) == [1, 2]
    assert {row.analyzer_name for row in copied} == {"trufflehog"}

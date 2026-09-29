import pytest

from app.repositories.analysis_results import AnalysisResultRepository
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = "scan-1"
_RESCAN = "scan-2"


@pytest.mark.asyncio
async def test_each_insert_appends_a_row_of_its_own():
    db = FakeDatabase()
    repo = AnalysisResultRepository(db)

    await repo.insert_result(_SCAN, "trufflehog", {"findings": [1]})
    await repo.insert_result(_SCAN, "trufflehog", {"findings": [2]})

    rows = await repo.find_by_scan(_SCAN, limit=10)
    assert [row.result for row in rows] == [{"findings": [1]}, {"findings": [2]}]
    assert len({row.id for row in rows}) == 2


@pytest.mark.asyncio
async def test_replace_keeps_one_row_per_scan_and_analyzer():
    db = FakeDatabase()
    repo = AnalysisResultRepository(db)

    await repo.replace_result(_SCAN, "reachability", {"run": 1})
    await repo.replace_result(_SCAN, "reachability", {"run": 2})

    rows = await repo.find_by_scan(_SCAN, limit=10)
    assert [(row.analyzer_name, row.result) for row in rows] == [("reachability", {"run": 2})]


@pytest.mark.asyncio
async def test_carry_over_copies_the_external_rows_once():
    db = FakeDatabase()
    repo = AnalysisResultRepository(db)
    await repo.insert_result(_SCAN, "trufflehog", {"secrets": 1})
    await repo.insert_result(_SCAN, "trufflehog", {"secrets": 2})
    await repo.insert_result(_SCAN, "osv", {"regenerated": True})

    await repo.carry_over(_SCAN, _RESCAN, exclude_names=["osv"])
    await repo.carry_over(_SCAN, _RESCAN, exclude_names=["osv"])

    copied = await repo.find_by_scan(_RESCAN, limit=10)
    assert sorted(row.result["secrets"] for row in copied) == [1, 2]
    assert {row.analyzer_name for row in copied} == {"trufflehog"}

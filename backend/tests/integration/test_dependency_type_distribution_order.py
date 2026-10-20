import pytest

from app.core.init_db import create_indexes
from app.repositories.dependencies import DependencyRepository
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_SCAN_ID = "type-order-scan"
_TIED_TYPES = ["swift", "maven", "cargo", "pypi", "golang", "nuget", "gem", "hex", "composer", "conan"]


async def test_types_with_equal_counts_come_in_name_order(db):
    await db.dependencies.insert_many(
        [{"scan_id": _SCAN_ID, "name": f"lib-{t}", "type": t} for t in _TIED_TYPES]
        + [{"scan_id": _SCAN_ID, "name": f"npm-lib-{i}", "type": "npm"} for i in range(3)]
    )

    rows = await DependencyRepository(db).get_type_distribution([_SCAN_ID])

    assert [row["_id"] for row in rows] == ["npm", *sorted(_TIED_TYPES)]


async def test_types_with_equal_counts_come_in_name_order_whatever_their_case(db):
    await db.dependencies.insert_many(
        [{"scan_id": _SCAN_ID, "name": f"lib-{t}", "type": t} for t in ["swift", "Maven", "cargo", "Golang"]]
    )

    rows = await DependencyRepository(db).get_type_distribution([_SCAN_ID])

    assert [row["_id"] for row in rows] == ["cargo", "Golang", "Maven", "swift"]


async def test_the_type_distribution_is_counted_off_the_scan_type_index_alone(db):
    await create_indexes(db)
    await db.dependencies.insert_many(
        [
            {"scan_id": scan_id, "name": f"lib-{i}", "version": "1.0", "purl": f"pkg:npm/lib-{i}@1.0", "type": "npm"}
            for scan_id in (_SCAN_ID, "other-scan")
            for i in range(50)
        ]
    )

    rows, entries = await profiled(db, DependencyRepository(db).get_type_distribution([_SCAN_ID]))

    assert [(row["_id"], row["count"]) for row in rows] == [("npm", 50)]
    plans = [
        (e["planSummary"], e["docsExamined"])
        for e in entries
        if e["ns"].endswith(".dependencies") and "aggregate" in e["command"]
    ]
    assert plans == [("IXSCAN { scan_id: 1, type: 1 }", 0)]

import pytest

from app.repositories.dependencies import DependencyRepository

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

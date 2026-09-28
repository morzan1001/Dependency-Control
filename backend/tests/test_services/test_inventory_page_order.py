"""Inventory pages cut from a sort that repeats keys overlap; each sort ends on a key unique within the scan."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.models.project import Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.services.inventory.components import get_components_page
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_SCAN = Scan(id="s1", project_id="p1", branch="main", created_at=datetime(2026, 9, 1, tzinfo=timezone.utc))


def _mock_db() -> tuple:
    dependencies = create_mock_collection()
    db = create_mock_db(
        {
            "dependencies": dependencies,
            "findings": create_mock_collection(),
            "dependency_enrichments": create_mock_collection(),
        }
    )
    return db, dependencies


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sort_by", "direction", "expected"),
    [
        ("name", 1, [("name", 1), ("version", 1), ("purl", 1)]),
        ("name", -1, [("name", -1), ("version", -1), ("purl", -1)]),
        ("type", -1, [("type", -1), ("name", 1), ("version", 1), ("_id", 1)]),
        ("direct", 1, [("direct", 1), ("name", 1), ("version", 1), ("_id", 1)]),
    ],
)
async def test_the_components_page_sorts_on_a_unique_key(sort_by, direction, expected):
    db, dependencies = _mock_db()

    await get_components_page(db, _SCAN, page=2, page_size=25, search=None, sort_by=sort_by, direction=direction)

    assert dependencies.find.return_value.sort.call_args.args == (expected,)


@pytest.mark.asyncio
async def test_license_sorted_components_with_one_name_order_by_version():
    db = FakeDatabase()
    for version in ("2.0.0", "1.0.0"):
        await db.dependencies.insert_one(
            {"scan_id": "s1", "name": "lib", "version": version, "license": "MIT", "purl": f"pkg:npm/lib@{version}"}
        )

    items, _ = await get_components_page(db, _SCAN, page=1, page_size=10, search=None, sort_by="license", direction=1)

    assert [item.version for item in items] == ["1.0.0", "2.0.0"]


@pytest.mark.asyncio
async def test_the_crypto_page_breaks_name_ties_on_the_bom_ref():
    assets = create_mock_collection()
    repo = CryptoAssetRepository(create_mock_db({"crypto_assets": assets}))

    await repo.list_by_scan("p1", "s1", limit=25, skip=25)

    assert assets.find.return_value.sort.call_args.args == ([("name", 1), ("bom_ref", 1)],)


@pytest.mark.asyncio
async def test_an_enrichment_lookup_is_cut_into_bounded_in_lists():
    enrichments = create_mock_collection()
    enrichments.find.return_value.to_list = AsyncMock(return_value=[])
    repo = DependencyEnrichmentRepository(create_mock_db({"dependency_enrichments": enrichments}))

    await repo.get_many_by_purls([f"pkg:npm/p{i}@1.0.0" for i in range(1200)])

    widths = [len(call.args[0]["purl"]["$in"]) for call in enrichments.find.call_args_list]
    assert widths == [500, 500, 200]

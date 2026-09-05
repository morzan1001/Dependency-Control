"""A license category is a conclusion about the estate, not a sample of five purls."""

import pytest

from app.models.project import Scan
from app.services.inventory.licenses import _FIRST_PASS_PURLS_PER_LICENSE, build_license_rows
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "proj-1"
_SCAN_ID = "scan-1"
_LICENSE = "GPL-3.0-only"
_CATEGORY = "strong_copyleft"
_RISK = "source_disclosure"
_COMPONENTS = _FIRST_PASS_PURLS_PER_LICENSE * 4


def _scan() -> Scan:
    return Scan(id=_SCAN_ID, project_id=_PROJECT_ID, branch="main", status="completed")


async def _seed(db: FakeDatabase, enriched_index: int | None) -> None:
    for index in range(_COMPONENTS):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{index}",
                "project_id": _PROJECT_ID,
                "scan_id": _SCAN_ID,
                "name": f"pkg{index:03d}",
                "version": "1.0.0",
                "license": _LICENSE,
                "purl": f"pkg:npm/pkg{index:03d}@1.0.0",
            }
        )
    if enriched_index is not None:
        await db.dependency_enrichments.insert_one(
            {
                "_id": "enr-1",
                "purl": f"pkg:npm/pkg{enriched_index:03d}@1.0.0",
                "license_category": _CATEGORY,
                "license_risks": [_RISK],
            }
        )


@pytest.mark.asyncio
async def test_a_license_categorised_only_past_the_sample_is_still_categorised():
    db = FakeDatabase()
    await _seed(db, enriched_index=_COMPONENTS - 1)

    rows = await build_license_rows(db, _scan())

    assert [(row.license, row.category, row.risks) for row in rows] == [(_LICENSE, _CATEGORY, [_RISK])]


@pytest.mark.asyncio
async def test_the_sample_still_answers_without_walking_further():
    db = FakeDatabase()
    await _seed(db, enriched_index=0)

    rows = await build_license_rows(db, _scan())

    assert rows[0].category == _CATEGORY


@pytest.mark.asyncio
async def test_a_license_no_component_answers_stays_uncategorised():
    db = FakeDatabase()
    await _seed(db, enriched_index=None)

    rows = await build_license_rows(db, _scan())

    assert rows[0].category is None
    assert rows[0].component_count == _COMPONENTS

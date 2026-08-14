"""A document-level-malformed SBOM must fail the ingest instead of silently replacing a scan's dependencies with an empty set (pipeline retries reuse the same uuid5 scan_id)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.endpoints.ingest import _process_sboms
from app.repositories.dependencies import DependencyRepository

_PROJECT_ID = "test-project-id"
_SCAN_ID = "8e0d76a5-1291-5949-8e0d-0d90b4bd9e01"

_MALFORMED_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": [],
    "components": [{"type": "library", "name": "valid", "version": "1.0", "purl": "pkg:pypi/valid@1.0"}],
}


def _fake_gridfs_bucket() -> MagicMock:
    fs = MagicMock()
    fs.upload_from_stream = AsyncMock(return_value="69d5332257c8763c8d8c82d7")
    return fs


async def _seed_existing_dependencies(db) -> None:
    for name, version in (("requests", "2.31.0"), ("urllib3", "2.1.0")):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{name}",
                "project_id": _PROJECT_ID,
                "scan_id": _SCAN_ID,
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )


@pytest.mark.asyncio
async def test_malformed_sbom_does_not_wipe_previous_scan_dependencies(db):
    await _seed_existing_dependencies(db)
    dep_repo = DependencyRepository(db)

    _, warnings, processed, failed, inserted = await _process_sboms(
        [_MALFORMED_CYCLONEDX], _fake_gridfs_bucket(), _PROJECT_ID, _SCAN_ID, dep_repo
    )

    assert failed == 1
    assert processed == 0
    assert inserted == 0
    assert any("Failed to parse" in w for w in warnings)
    survivors = await db.dependencies.count_documents({"scan_id": _SCAN_ID})
    assert survivors == 2

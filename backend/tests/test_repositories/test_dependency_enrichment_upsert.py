import pytest

from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.services.analyzers.purl_utils import canonical_purl
from tests.mocks.fake_mongo import FakeDatabase

_QUALIFIED = "pkg:npm/left-pad@1.0.0?download_url=https://example.test/left-pad.tgz"


@pytest.mark.asyncio
async def test_entries_are_stored_under_the_key_every_lookup_reads():
    db = FakeDatabase()
    repo = DependencyEnrichmentRepository(db)
    entries = [
        {"purl": _QUALIFIED, "name": "left-pad", "version": "1.0.0", "data": {"license": "MIT"}},
        {"purl": None, "name": "no-purl", "version": "1", "data": {"license": "MIT"}},
    ]

    assert await repo.upsert_many(entries) == 1

    stored = await repo.get_by_purl(_QUALIFIED)
    assert stored is not None
    assert (stored["purl"], stored["name"], stored["license"]) == (canonical_purl(_QUALIFIED), "left-pad", "MIT")

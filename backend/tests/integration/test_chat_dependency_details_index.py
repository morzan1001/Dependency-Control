"""The enrichment collection grows with every package ever scanned, so a name lookup that walks it is the cost."""

import pytest

from app.core.init_db import create_indexes
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_DECOYS = 40


def _entry(name: str, version: str) -> dict:
    return {"name": name, "version": version, "purl": f"pkg:maven/{name}@{version}", "data": {"license": "MIT"}}


async def _seed(db) -> int:
    await create_indexes(db)
    # Stored before the decoys, so a newest-first walk of the whole collection meets them last.
    entries = [_entry("log4j-core", "2.14.1"), _entry("log4j-core", "2.17.1")]
    entries += [_entry(f"decoy-{i}", "1.0.0") for i in range(_DECOYS)]
    await DependencyEnrichmentRepository(db).upsert_many(entries)
    return len(entries)


async def _lookup(db, name: str) -> tuple[dict, list[dict]]:
    result, entries = await profiled(
        db, ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": name}, make_admin(), db)
    )
    return result, [e for e in entries if e["ns"].endswith(".dependency_enrichments") and e["op"] == "query"]


async def test_a_whole_name_in_any_case_is_an_index_seek_to_its_newest_enrichment(db):
    await _seed(db)

    result, reads = await _lookup(db, "LOG4J-Core")

    assert result["dependency"]["version"] == "2.17.1"
    assert sum(read["docsExamined"] for read in reads) == 1


async def test_a_name_no_enrichment_carries_walks_the_collection_once(db):
    stored = await _seed(db)

    result, reads = await _lookup(db, "no-such-package")

    assert "dependency" not in result
    assert sum(read["docsExamined"] for read in reads) == stored

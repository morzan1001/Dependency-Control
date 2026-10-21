from datetime import datetime, timedelta, timezone

import pymongo
import pytest

from app.core.init_db import create_indexes
from app.repositories.archive_metadata import ArchiveMetadataRepository
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
_ARCHIVES = 30


async def _seed(db) -> None:
    await create_indexes(db)
    await db.archive_metadata.insert_many(
        {
            "_id": f"meta-{i}",
            "project_id": f"proj-{i % 3}",
            "scan_id": f"scan-{i}",
            "s3_key": f"proj-{i % 3}/scan-{i}-1.bundle",
            "s3_bucket": "dc-archives",
            "branch": f"branch-{i % 2}",
            "archived_at": _NOW - timedelta(hours=i),
        }
        for i in range(_ARCHIVES)
    )


async def test_the_listing_across_all_projects_pages_the_newest_archives_off_an_index(db):
    await _seed(db)

    rows, entries = await profiled(db, ArchiveMetadataRepository(db).find_all(skip=20, limit=20))

    assert [row.scan_id for row in rows] == [f"scan-{i}" for i in range(20, _ARCHIVES)]
    reads = [
        (entry["planSummary"], entry.get("hasSortStage", False))
        for entry in entries
        if entry["ns"].endswith(".archive_metadata") and entry["op"] == "query"
    ]
    assert reads == [("IXSCAN { archived_at: -1, _id: 1 }", False)]


async def test_the_chat_newest_first_read_walks_the_same_index(db):
    await _seed(db)

    cursor = db.archive_metadata.find({}, limit=20).sort("archived_at", pymongo.DESCENDING)
    plan = str((await cursor.explain())["queryPlanner"]["winningPlan"])

    assert "'indexName': 'archived_at_-1__id_1'" in plan
    assert "'stage': 'SORT'" not in plan


async def test_the_unfiltered_total_counts_every_archive(db):
    await _seed(db)

    assert await ArchiveMetadataRepository(db).count_all() == _ARCHIVES


async def test_a_branch_filtered_listing_reads_only_that_branchs_archives_newest_first(db):
    await _seed(db)
    query = {"project_id": "proj-0", "branch": "branch-1"}

    cursor = db.archive_metadata.find(query).sort("archived_at", pymongo.DESCENDING).limit(20)
    explained = await cursor.explain()
    plan = str(explained["queryPlanner"]["winningPlan"])

    assert "'stage': 'SORT'" not in plan
    assert explained["executionStats"]["totalDocsExamined"] == await db.archive_metadata.count_documents(query)

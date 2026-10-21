from datetime import datetime, timedelta, timezone

import pymongo
import pytest

from app.core.init_db import create_indexes
from app.repositories.archive_metadata import ArchiveMetadataRepository

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


async def test_the_listing_across_all_projects_reads_the_newest_archives_off_an_index(db):
    await _seed(db)

    cursor = db.archive_metadata.find({}).sort("archived_at", pymongo.DESCENDING).skip(20).limit(20)
    plan = str((await cursor.explain())["queryPlanner"]["winningPlan"])

    assert "'indexName': 'archived_at_-1'" in plan
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

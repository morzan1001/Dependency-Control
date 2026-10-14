"""A tag build's predecessors come off an index of the tag builds, not a walk over every build of the project."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.init_db import create_indexes
from app.repositories.scans import ScanRepository
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_NOW = datetime.now(timezone.utc)
# Branch builds between the releases, all of which a walk over the project's builds examines.
_BRANCH_BUILDS = 50


def _build(scan_id: str, hours_old: int, branch: str, commit_tag: str) -> dict:
    return {
        "_id": scan_id,
        "project_id": "p",
        "branch": branch,
        "commit_tag": commit_tag,
        "status": "completed",
        "created_at": _NOW - timedelta(hours=hours_old),
        "sbom_refs": [{"type": "gridfs_reference", "gridfs_id": "g"}],
    }


async def test_a_tag_builds_predecessors_are_read_off_the_tag_build_index(db):
    await create_indexes(db)
    releases = [_build(tag, hours, tag, tag) for tag, hours in (("v1.2", 0), ("v1.1", 30), ("v1.0", 60))]
    await db.scans.insert_many(releases + [_build(f"main-{i}", i + 1, "main", "") for i in range(_BRANCH_BUILDS)])

    preceding, entries = await profiled(db, ScanRepository(db).get_preceding_scans("v1.2", 9))

    assert [scan.id for scan in preceding] == ["v1.1", "v1.0"]
    [read] = [e for e in entries if e["ns"].endswith(".scans") and "commit_tag" in e["command"].get("filter", {})]
    assert read["docsExamined"] == len(preceding)

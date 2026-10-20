"""A mark finds its commit's newest build in one index seek, however many builds the project holds."""

from datetime import datetime, timedelta, timezone

import pytest

from app.api.v1.endpoints.releases import mark_release
from app.core.init_db import create_indexes
from app.schemas.release import ReleaseMarkRequest
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT = "p"
_COMMIT = "c" * 40
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_OTHER_BUILDS = 300


@pytest.mark.parametrize("status", ["completed", "failed"])
async def test_the_commit_lookup_seeks_its_builds_and_reads_only_what_the_mark_uses(db, status):
    await create_indexes(db)
    await db.projects.insert_one({"_id": _PROJECT, "name": "p", "default_branch": "main", "deleted_branches": []})
    builds = [
        {"_id": f"other-{i:03d}", "commit_hash": f"{i:040d}", "created_at": _T0 + timedelta(minutes=i)}
        for i in range(_OTHER_BUILDS)
    ]
    builds += [
        {"_id": f"build-{i}", "commit_hash": _COMMIT, "created_at": _T0 + timedelta(minutes=i), "commit_tag": "v1"}
        for i in range(2)
    ]
    await db.scans.insert_many(
        [{**b, "project_id": _PROJECT, "branch": "main", "status": status, "sbom_refs": [{"id": "x"}]} for b in builds]
    )

    item, entries = await profiled(db, mark_release(_PROJECT, ReleaseMarkRequest(commit_hash=_COMMIT), db))

    assert (item.scan_id, item.version) == ("build-1", "v1")
    lookups = [
        e
        for e in entries
        if e["ns"].endswith(".scans") and e["command"].get("filter", {}).get("commit_hash") == _COMMIT
    ]
    assert lookups
    assert [e for e in lookups if e.get("hasSortStage") or e.get("docsExamined", 0) > 2] == []
    assert {frozenset(e["command"].get("projection", {})) for e in lookups} == {
        frozenset({"_id", "commit_tag", "commit_hash", "branch", "status"})
    }

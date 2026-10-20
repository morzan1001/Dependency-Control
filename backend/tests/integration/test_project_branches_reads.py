"""The branch list groups names off an index and reads one scan per name, not every scan of the project."""

from datetime import datetime, timedelta, timezone

import pytest

from app.api.v1.endpoints.projects import read_project_branches
from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.models.user import User
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_READER = User(id="r", username="r", email="r@corp.com", permissions=[Permissions.PROJECT_READ_ALL])
_T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
_BUILDS_PER_BRANCH = 10


async def test_the_branch_list_reads_one_scan_per_name(db):
    await create_indexes(db)
    await db.projects.insert_one({"_id": "p", "name": "p", "members": [], "team_ids": []})
    builds = [
        {
            "_id": f"{branch}-{i}",
            "project_id": "p",
            "branch": branch,
            "status": "completed",
            "created_at": _T0 + timedelta(minutes=i),
        }
        for branch in ("main", "develop")
        for i in range(_BUILDS_PER_BRANCH)
    ]
    tag_build = {**builds[0], "_id": "tag", "branch": "v1.0", "commit_tag": "v1.0"}
    await db.scans.insert_many([*builds, tag_build])

    branches, entries = await profiled(db, read_project_branches("p", _READER, db))

    assert [(b.name, b.last_scan_at) for b in branches] == [
        ("develop", _T0 + timedelta(minutes=_BUILDS_PER_BRANCH - 1)),
        ("main", _T0 + timedelta(minutes=_BUILDS_PER_BRANCH - 1)),
    ]
    grouping = [e for e in entries if e["ns"].endswith(".scans") and "$group" in str(e["command"].get("pipeline"))]
    assert [e["docsExamined"] for e in grouping] == [0]

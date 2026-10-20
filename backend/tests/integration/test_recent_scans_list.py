"""The scans list across projects: a reader of every project pages scans without first listing every project."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.projects import read_all_scans
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.scans import ScanRepository
from app.services.analytics import scopes
from tests.helpers.databases import DATABASES

pytestmark = pytest.mark.asyncio

_T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
_MEMBER = "member"


async def _seed(db) -> None:
    await db.projects.insert_many(
        [
            {"_id": "p-own", "name": "own", "members": [{"user_id": _MEMBER, "role": "viewer"}], "team_ids": []},
            {"_id": "p-other", "name": "other", "members": [], "team_ids": []},
        ]
    )
    await db.scans.insert_many(
        [
            {"_id": "s-own", "project_id": "p-own", "branch": "main", "status": "completed", "created_at": _T0},
            {
                "_id": "s-other",
                "project_id": "p-other",
                "branch": "main",
                "status": "completed",
                "created_at": _T0 + timedelta(minutes=1),
            },
            {
                "_id": "s-orphan",
                "project_id": "p-gone",
                "branch": "main",
                "status": "completed",
                "created_at": _T0 + timedelta(minutes=2),
            },
        ]
    )


def _user(*permissions: str) -> User:
    return User(id=_MEMBER, username=_MEMBER, email=f"{_MEMBER}@corp.com", permissions=list(permissions))


@pytest.mark.parametrize("database", DATABASES)
async def test_a_reader_of_every_project_is_not_held_to_the_scope_ceiling(db, database, monkeypatch):
    monkeypatch.setattr(scopes, "ANALYTICS_MAX_SCOPE_PROJECTS", 1)
    await _seed(db)

    rows = await read_all_scans(_user(Permissions.PROJECT_READ_ALL), db, limit=20, skip=0)

    assert [(row["_id"], row["project_name"]) for row in rows] == [("s-other", "other"), ("s-own", "own")]
    assert all("project_info" not in row for row in rows)


@pytest.mark.parametrize("database", DATABASES)
async def test_a_member_sees_the_scans_of_its_own_projects_only(db, database):
    await _seed(db)

    rows = await read_all_scans(_user(Permissions.PROJECT_READ), db, limit=20, skip=0)

    assert [(row["_id"], row["project_name"]) for row in rows] == [("s-own", "own")]


async def test_the_project_join_reads_only_the_name(db):
    aggregate = AsyncMock(return_value=[])
    with patch.object(ScanRepository, "aggregate", aggregate):
        await read_all_scans(_user(Permissions.PROJECT_READ_ALL), db, limit=20, skip=0)

    [lookup] = [stage["$lookup"] for stage in aggregate.await_args.args[0] if "$lookup" in stage]
    assert lookup["pipeline"] == [{"$project": {"name": 1}}]

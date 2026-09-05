"""Branch sync writes deleted_branches, which the head resolver then trusts.

A branch wrongly listed there takes the project's head off the branch it is really on, and the
same pass can clear latest_scan_id and the stats block the project tile renders.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.housekeeping import sync_project_branches
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"

_PROJECT_ID = "p1"
_MAIN = "main"
_GONE = "feature/gone"
_RELEASE = "release/1.x"
_TAG = "v1.2.3"
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_HOUR = timedelta(hours=1)
_MAIN_CRITICALS = 4


def _project(**overrides) -> dict:
    project = {
        "_id": _PROJECT_ID,
        "name": "demo",
        "default_branch": _MAIN,
        "deleted_branches": [],
        "gitlab_instance_id": "inst-1",
        "gitlab_project_id": 100,
    }
    project.update(overrides)
    return project


def _scan(scan_id: str, branch: str, created_at: datetime, **overrides) -> dict:
    scan = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": branch,
        "status": "completed",
        "created_at": created_at,
    }
    scan.update(overrides)
    return scan


async def _run(monkeypatch, project: dict, scans: list[dict], vcs_branches: list[str] | None) -> dict:
    db = FakeDatabase()
    await db.projects.insert_one(dict(project))
    for scan in scans:
        await db.scans.insert_one(scan)
    monkeypatch.setattr(f"{MODULE}._fetch_vcs_branches", AsyncMock(return_value=vcs_branches))
    monkeypatch.setattr(f"{MODULE}._fetch_vcs_default_branch", AsyncMock(return_value=None))

    await sync_project_branches(project, db)

    return await db.projects.find_one({"_id": _PROJECT_ID})


@pytest.mark.asyncio
async def test_only_branches_the_provider_no_longer_lists_are_marked_deleted(monkeypatch):
    stored = await _run(
        monkeypatch,
        _project(),
        [_scan("s-main", _MAIN, _T0), _scan("s-gone", _GONE, _T0)],
        vcs_branches=[_MAIN],
    )

    assert stored["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_a_tag_build_is_not_filed_as_a_deleted_branch(monkeypatch):
    """A tag pipeline names no branch, so its commit_tag would otherwise look like a lost branch."""
    stored = await _run(
        monkeypatch,
        _project(),
        [_scan("s-main", _MAIN, _T0), _scan("s-tag", _TAG, _T0, commit_tag=_TAG)],
        vcs_branches=[_MAIN],
    )

    assert stored["deleted_branches"] == []


@pytest.mark.asyncio
async def test_a_provider_that_lists_nothing_leaves_the_project_untouched(monkeypatch):
    """An outage answering with no branches would otherwise declare every branch deleted."""
    project = _project(latest_scan_id="s-main")
    stored = await _run(monkeypatch, project, [_scan("s-main", _MAIN, _T0)], vcs_branches=[])

    assert stored == project


@pytest.mark.asyncio
async def test_a_head_on_a_deleted_branch_moves_to_the_newest_live_one(monkeypatch):
    stored = await _run(
        monkeypatch,
        _project(latest_scan_id="s-gone"),
        [
            _scan("s-main-old", _MAIN, _T0),
            _scan("s-main", _MAIN, _T0 + _HOUR, stats={"critical": _MAIN_CRITICALS}),
            _scan("s-gone", _GONE, _T0 + 2 * _HOUR),
        ],
        vcs_branches=[_MAIN],
    )

    assert stored["latest_scan_id"] == "s-main"
    assert stored["stats"]["critical"] == _MAIN_CRITICALS


@pytest.mark.asyncio
async def test_a_head_on_a_live_branch_is_left_where_it_is(monkeypatch):
    """Repairing a branch deletion is this pass's only claim on the pointer: a head parked on a
    live non-default branch must not be quietly rebased onto the default one."""
    stored = await _run(
        monkeypatch,
        _project(latest_scan_id="s-release"),
        [
            _scan("s-release", _RELEASE, _T0),
            _scan("s-main", _MAIN, _T0 + 2 * _HOUR),
            _scan("s-gone", _GONE, _T0 + _HOUR),
        ],
        vcs_branches=[_MAIN, _RELEASE],
    )

    assert stored["latest_scan_id"] == "s-release"
    assert "stats" not in stored


@pytest.mark.asyncio
async def test_losing_the_last_live_branch_clears_the_head_and_its_stats(monkeypatch):
    stored = await _run(
        monkeypatch,
        _project(default_branch=_GONE, latest_scan_id="s-gone"),
        [_scan("s-gone", _GONE, _T0, stats={"critical": _MAIN_CRITICALS})],
        vcs_branches=[_MAIN],
    )

    assert stored["latest_scan_id"] is None
    assert stored["stats"] is None

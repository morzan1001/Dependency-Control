"""Branch sync writes deleted_branches and default_branch, which the head resolver then trusts.

A branch wrongly listed there takes the project's head off the branch it is really on, and the
same pass rewrites latest_scan_id and the stats block the project tile renders.
"""

import logging
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import HTTPException

from app.models.project import Project
from app.models.user import User
from app.services.branch_sync import sync_project_branches
from app.services.github import GitHubService
from app.services.gitlab import GitLabService
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

MODULE = "app.services.branch_sync"
ENDPOINTS = "app.api.v1.endpoints.projects"

_PROJECT_ID = "p1"
_MAIN = "main"
_DEVELOP = "develop"
_GONE = "feature/gone"
_RELEASE = "release/1.x"
_TAG = "v1.2.3"
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_HOUR = timedelta(hours=1)
_CRITICALS = 4
_USABLE_INSTANCE = {"_id": "inst-1", "name": "gl", "url": "https://gl", "access_token": "t", "created_by": "admin"}


def _project(**overrides: Any) -> dict[str, Any]:
    return {
        "_id": _PROJECT_ID,
        "name": "demo",
        "default_branch": _MAIN,
        "deleted_branches": [],
        "gitlab_instance_id": "inst-1",
        "gitlab_project_id": 100,
        **overrides,
    }


def _scan(scan_id: str, branch: str, created_at: datetime = _T0, **overrides: Any) -> dict[str, Any]:
    return {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": branch,
        "status": "completed",
        "created_at": created_at,
        **overrides,
    }


async def _db(project: dict[str, Any], scans: list[dict[str, Any]]) -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one(dict(project))
    for scan in scans:
        await db.scans.insert_one(scan)
    return db


async def _run(
    project: dict[str, Any], scans: list[dict[str, Any]], vcs_branches: list[str], vcs_default: str | None = None
) -> dict[str, Any]:
    db = await _db(project, scans)
    fetch_default = AsyncMock(return_value=vcs_default)
    with patch(f"{MODULE}._vcs_repo", AsyncMock(return_value=(AsyncMock(return_value=vcs_branches), fetch_default))):
        await sync_project_branches(project, db)
    stored: dict[str, Any] = await db.projects.find_one({"_id": _PROJECT_ID})
    stored["_fetch_default_calls"] = fetch_default.await_count
    return stored


@pytest.mark.asyncio
async def test_only_branches_the_provider_no_longer_lists_are_marked_deleted():
    stored = await _run(_project(), [_scan("s-main", _MAIN), _scan("s-gone", _GONE)], [_MAIN])

    assert stored["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_a_tag_build_is_not_filed_as_a_deleted_branch():
    """A tag pipeline names no branch, so its commit_tag would otherwise look like a lost branch."""
    stored = await _run(_project(), [_scan("s-main", _MAIN), _scan("s-tag", _TAG, commit_tag=_TAG)], [_MAIN])

    assert stored["deleted_branches"] == []


@pytest.mark.asyncio
async def test_a_tagged_build_of_a_real_branch_still_counts_that_branch():
    """The new scanner reports the default branch on a tag pipeline, so branch and tag differ."""
    stored = await _run(_project(), [_scan("s-tagged", _GONE, commit_tag=_TAG)], [_MAIN])

    assert stored["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_the_branch_census_reads_branch_names_without_a_document_filter():
    """A filter comparing two fields keeps MongoDB from answering the distinct from the index alone."""
    db = await _db(_project(), [_scan("s-main", _MAIN), _scan("s-gone", _GONE)])
    real_distinct = db.scans.distinct
    census_filters: list[dict[str, Any]] = []

    async def spy(field: str, query: dict[str, Any]) -> list[Any]:
        census_filters.append(query)
        return await real_distinct(field, query)

    db.scans.distinct = spy
    with patch(f"{MODULE}._vcs_repo", AsyncMock(return_value=(AsyncMock(return_value=[_MAIN]), AsyncMock()))):
        await sync_project_branches(_project(), db)

    assert census_filters == [{"project_id": _PROJECT_ID}]
    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_a_provider_that_lists_nothing_leaves_the_project_untouched():
    """An outage answering with no branches would otherwise declare every branch deleted."""
    project = _project(latest_scan_id="s-main")
    db = await _db(project, [_scan("s-main", _MAIN)])
    with patch(f"{MODULE}._vcs_repo", AsyncMock(return_value=(AsyncMock(return_value=[]), AsyncMock()))):
        assert await sync_project_branches(project, db) is False

    assert await db.projects.find_one({"_id": _PROJECT_ID}) == project


@pytest.mark.asyncio
async def test_an_inactive_instance_is_never_called():
    """An admin deactivates an instance to stop its token being used."""
    project = _project()
    db = await _db(project, [_scan("s-main", _MAIN)])
    await db.gitlab_instances.insert_one({**_USABLE_INSTANCE, "is_active": False})
    with patch.object(GitLabService, "list_branches", AsyncMock(return_value=[_MAIN])) as list_branches:
        assert await sync_project_branches(project, db) is False

    list_branches.assert_not_awaited()
    assert await db.projects.find_one({"_id": _PROJECT_ID}) == project


@pytest.mark.asyncio
async def test_an_active_instance_lists_the_projects_branches():
    project = _project()
    db = await _db(project, [_scan("s-main", _MAIN), _scan("s-gone", _GONE)])
    await db.gitlab_instances.insert_one(_USABLE_INSTANCE)
    with patch.object(GitLabService, "list_branches", AsyncMock(return_value=[_MAIN])) as list_branches:
        assert await sync_project_branches(project, db) is True

    list_branches.assert_awaited_once_with(100)
    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_a_head_on_a_deleted_branch_moves_to_the_newest_live_one():
    stored = await _run(
        _project(latest_scan_id="s-gone"),
        [
            _scan("s-main-old", _MAIN),
            _scan("s-main", _MAIN, _T0 + _HOUR, stats={"critical": _CRITICALS}),
            _scan("s-gone", _GONE, _T0 + 2 * _HOUR),
        ],
        [_MAIN],
    )

    assert stored["latest_scan_id"] == "s-main"
    assert stored["stats"]["critical"] == _CRITICALS


@pytest.mark.asyncio
async def test_a_head_the_rule_no_longer_names_is_repointed_in_the_same_pass():
    """The resolver would not trust a pointer parked on a live non-default branch, so leaving it would
    keep project.stats on a branch analytics no longer reports."""
    stored = await _run(
        _project(latest_scan_id="s-release"),
        [
            _scan("s-release", _RELEASE),
            _scan("s-main", _MAIN, _T0 + 2 * _HOUR, stats={"critical": _CRITICALS}),
            _scan("s-gone", _GONE, _T0 + _HOUR),
        ],
        [_MAIN, _RELEASE],
    )

    assert stored["latest_scan_id"] == "s-main"
    assert stored["stats"]["critical"] == _CRITICALS


@pytest.mark.asyncio
async def test_losing_the_last_live_branch_clears_the_head_and_its_stats():
    stored = await _run(
        _project(default_branch=_GONE, latest_scan_id="s-gone"),
        [_scan("s-gone", _GONE, stats={"critical": _CRITICALS})],
        [_MAIN],
    )

    assert stored["latest_scan_id"] is None
    assert stored["stats"] is None


@pytest.mark.asyncio
async def test_a_head_cleared_while_its_branch_was_gone_comes_back_with_the_branch():
    """A re-created branch would otherwise leave stats empty until the next build."""
    stored = await _run(
        _project(deleted_branches=[_MAIN], latest_scan_id=None, stats=None),
        [_scan("s-main", _MAIN, stats={"critical": _CRITICALS})],
        [_MAIN],
    )

    assert stored["deleted_branches"] == []
    assert stored["latest_scan_id"] == "s-main"
    assert stored["stats"] == {"critical": _CRITICALS}


@pytest.mark.asyncio
async def test_a_head_a_finalizer_moved_during_the_vcs_call_is_not_overwritten():
    """The head derived here may predate the scan the finalizer just committed and pointed the project at."""
    project = _project(latest_scan_id="s-gone")
    db = await _db(project, [_scan("s-main", _MAIN), _scan("s-gone", _GONE, _T0 + _HOUR)])

    async def list_branches_while_a_scan_finalizes() -> list[str]:
        await db.scans.insert_one(_scan("s-finalized", _MAIN, _T0 + 2 * _HOUR, stats={"critical": _CRITICALS}))
        finalized = {"latest_scan_id": "s-finalized", "stats": {"critical": _CRITICALS}}
        await db.projects.update_one({"_id": _PROJECT_ID}, {"$set": finalized})
        return [_MAIN]

    with patch(f"{MODULE}._vcs_repo", AsyncMock(return_value=(list_branches_while_a_scan_finalizes, AsyncMock()))):
        assert await sync_project_branches(project, db) is True

    stored = await db.projects.find_one({"_id": _PROJECT_ID})
    assert stored["deleted_branches"] == [_GONE]
    assert stored["latest_scan_id"] == "s-finalized"
    assert stored["stats"] == {"critical": _CRITICALS}


@pytest.mark.asyncio
async def test_missing_default_branch_is_backfilled_from_the_vcs():
    stored = await _run(
        _project(default_branch=None),
        [_scan("s-main", _MAIN, _T0), _scan("s-develop", _DEVELOP, _T0 - _HOUR)],
        [_MAIN, _DEVELOP],
        vcs_default=_DEVELOP,
    )

    assert stored["default_branch"] == _DEVELOP


@pytest.mark.asyncio
async def test_a_backfilled_default_branch_takes_the_cached_head_along():
    stored = await _run(
        _project(default_branch=None, latest_scan_id="s-main"),
        [_scan("s-main", _MAIN, _T0), _scan("s-develop", _DEVELOP, _T0 - _HOUR, stats={"critical": _CRITICALS})],
        [_MAIN, _DEVELOP],
        vcs_default=_DEVELOP,
    )

    assert stored["latest_scan_id"] == "s-develop"
    assert stored["stats"]["critical"] == _CRITICALS


@pytest.mark.asyncio
async def test_a_default_branch_the_vcs_deleted_is_replaced_by_the_vcs_default():
    """A renamed default branch (main to develop) would otherwise leave head roaming over whichever
    branch built last."""
    stored = await _run(
        _project(latest_scan_id="s-main"),
        [_scan("s-main", _MAIN, _T0), _scan("s-develop", _DEVELOP, _T0 - _HOUR)],
        [_DEVELOP],
        vcs_default=_DEVELOP,
    )

    assert stored["default_branch"] == _DEVELOP
    assert stored["deleted_branches"] == [_MAIN]
    assert stored["latest_scan_id"] == "s-develop"


@pytest.mark.asyncio
async def test_a_stored_default_the_vcs_lacks_is_replaced_even_without_scans_on_it():
    """A default renamed before this instance ever scanned it never shows up as deleted."""
    stored = await _run(
        _project(default_branch="master", latest_scan_id="s-feature"),
        [_scan("s-main", _MAIN, _T0), _scan("s-feature", "feature", _T0 + _HOUR)],
        [_MAIN, "feature"],
        vcs_default=_MAIN,
    )

    assert stored["default_branch"] == _MAIN
    assert stored["latest_scan_id"] == "s-main"


@pytest.mark.asyncio
async def test_an_existing_live_default_branch_is_kept_without_asking_the_vcs():
    stored = await _run(
        _project(),
        [_scan("s-main", _MAIN, _T0), _scan("s-develop", _DEVELOP, _T0 - _HOUR)],
        [_MAIN, _DEVELOP],
        vcs_default=_DEVELOP,
    )

    assert stored["default_branch"] == _MAIN
    assert stored["_fetch_default_calls"] == 0


def _not_found(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, request=request)


def _timed_out(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("", request=request)


_LIST_BRANCHES = [
    pytest.param(lambda: GitLabService(make_gitlab_instance()).list_branches(100), id="gitlab"),
    pytest.param(
        lambda: GitHubService(make_github_instance(access_token="ghp-x")).list_branches("acme", "api"),
        id="github",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("list_branches", _LIST_BRANCHES)
@pytest.mark.parametrize(("vcs_answer", "cause"), [(_not_found, "404"), (_timed_out, "ReadTimeout")])
async def test_a_failed_branch_listing_logs_one_warning_line_without_a_traceback(
    monkeypatch, caplog, list_branches, vcs_answer, cause
):
    """A sync logs every project whose repo the token cannot see, so an ERROR or traceback each buries real alerts."""
    transport = httpx.MockTransport(vcs_answer)
    monkeypatch.setattr(httpx, "AsyncClient", partial(httpx.AsyncClient, transport=transport))

    with caplog.at_level(logging.WARNING, logger="app.services"):
        assert await list_branches() is None

    logged = [(r.levelname, r.exc_info) for r in caplog.records if r.levelno >= logging.WARNING]
    assert logged == [("WARNING", None)]
    assert cause in caplog.records[-1].getMessage()


_LISTED_BRANCHES = [*(f"bugfix/{n:04d}" for n in range(1, 1001)), _MAIN]


def _branch_pages(request: httpx.Request) -> httpx.Response:
    """Both providers' branch listing as they answer it: a Link header, which GitLab sends with its x-total-pages."""
    if "page" not in request.url.params:
        return httpx.Response(200, json={"default_branch": _MAIN}, request=request)
    page, per_page = int(request.url.params["page"]), int(request.url.params["per_page"])
    last = -(-len(_LISTED_BRANCHES) // per_page)
    links = [f'<{request.url.copy_set_param("page", last)}>; rel="last"']
    if page < last:
        links.insert(0, f'<{request.url.copy_set_param("page", page + 1)}>; rel="next"')
    names = _LISTED_BRANCHES[(page - 1) * per_page : page * per_page]
    headers = {"link": ", ".join(links), "x-total-pages": str(last), "x-total": str(len(_LISTED_BRANCHES))}
    return httpx.Response(200, json=[{"name": name} for name in names], headers=headers, request=request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("link", "instances", "instance"),
    [
        pytest.param({}, "gitlab_instances", _USABLE_INSTANCE, id="gitlab"),
        pytest.param(
            {"gitlab_instance_id": None, "github_instance_id": "inst-1", "github_repository_path": "acme/api"},
            "github_instances",
            {**_USABLE_INSTANCE, "github_url": "https://github.com"},
            id="github",
        ),
    ],
)
async def test_a_branch_past_the_thousandth_is_not_filed_as_deleted(monkeypatch, link, instances, instance):
    monkeypatch.setattr(httpx, "AsyncClient", partial(httpx.AsyncClient, transport=httpx.MockTransport(_branch_pages)))
    project = _project(latest_scan_id="s-main", stats={"critical": 9}, **link)
    db = await _db(
        project,
        [
            _scan("s-main", _MAIN, stats={"critical": 9}),
            _scan("s-bugfix", "bugfix/0001", _T0 - timedelta(days=3), stats={"critical": 0}),
        ],
    )
    await getattr(db, instances).insert_one(dict(instance))

    assert await sync_project_branches(project, db) is True

    stored = await db.projects.find_one({"_id": _PROJECT_ID})
    assert stored["deleted_branches"] == []
    assert stored["latest_scan_id"] == "s-main"
    assert stored["stats"] == {"critical": 9}


async def _call_endpoint(project: Project, db: FakeDatabase | None = None) -> list[Any]:
    from app.api.v1.endpoints.projects import sync_project_branches_endpoint

    db = db or await _db(project.model_dump(by_alias=True), [])
    with patch(f"{ENDPOINTS}.check_project_access", AsyncMock(return_value=project)):
        return await sync_project_branches_endpoint(project.id, User(id="u1", username="u1", email="u1@t.com"), db)


@pytest.mark.asyncio
async def test_the_endpoint_syncs_the_project_it_was_granted():
    project = Project(id=_PROJECT_ID, name="p", default_branch=_MAIN, gitlab_instance_id="inst-1", gitlab_project_id=1)
    db = await _db(project.model_dump(by_alias=True), [_scan("s-main", _MAIN), _scan("s-gone", _GONE)])
    with patch(f"{MODULE}._vcs_repo", AsyncMock(return_value=(AsyncMock(return_value=[_MAIN]), AsyncMock()))):
        branches = await _call_endpoint(project, db)

    assert {branch.name for branch in branches} == {_MAIN, _GONE}
    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["deleted_branches"] == [_GONE]


@pytest.mark.asyncio
async def test_the_endpoint_reports_an_unreachable_vcs_as_502():
    """A failed VCS call answered 200 with the unchanged list, so the failure read as 'nothing changed'."""
    with pytest.raises(HTTPException) as raised:
        await _call_endpoint(Project(id=_PROJECT_ID, name="p", gitlab_instance_id="missing", gitlab_project_id=1))

    assert raised.value.status_code == 502


@pytest.mark.asyncio
async def test_the_endpoint_rejects_a_link_without_repository_coordinates():
    with pytest.raises(HTTPException) as raised:
        await _call_endpoint(Project(id=_PROJECT_ID, name="p", gitlab_instance_id="inst-1"))

    assert raised.value.status_code == 400

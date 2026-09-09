"""Every completed scan must reach both VCS decorators."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.project import Scan
from app.models.stats import Stats
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _db_with_project():
    # engine reads the project through with_options(read_preference=PRIMARY).
    projects = create_mock_collection(find_one={"_id": "p1", "name": "Proj"})
    projects.with_options = MagicMock(return_value=projects)
    return create_mock_db({"projects": projects})


def test_both_decorators_run_for_one_scan():
    from app.services.analysis import engine

    scan_doc = Scan(project_id="p1", branch="main", commit_hash="abc")
    with (
        patch.object(engine, "decorate_gitlab_mr", new_callable=AsyncMock) as gitlab,
        patch.object(engine, "decorate_github_pr", new_callable=AsyncMock) as github,
        patch.object(engine, "send_scan_notifications", new_callable=AsyncMock),
    ):
        asyncio.run(
            engine._send_integrations_and_notifications("p1", "s1", scan_doc, Stats(), [], [], _db_with_project())
        )

    gitlab.assert_awaited_once()
    github.assert_awaited_once()
    assert github.await_args.args[0] == "s1"
    assert github.await_args.args[2] is scan_doc
    assert github.await_args.args == gitlab.await_args.args


def test_nothing_runs_without_a_project_id():
    from app.services.analysis import engine

    with (
        patch.object(engine, "decorate_gitlab_mr", new_callable=AsyncMock) as gitlab,
        patch.object(engine, "decorate_github_pr", new_callable=AsyncMock) as github,
        patch.object(engine, "send_scan_notifications", new_callable=AsyncMock),
    ):
        asyncio.run(engine._send_integrations_and_notifications(None, "s1", None, Stats(), [], [], _db_with_project()))

    gitlab.assert_not_awaited()
    github.assert_not_awaited()

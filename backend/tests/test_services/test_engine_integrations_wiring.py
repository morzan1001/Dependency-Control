"""Every completed scan must reach both VCS decorators and the notifier with the run's outcome."""

import asyncio
from unittest.mock import AsyncMock, patch

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.models.project import Scan
from app.models.stats import Stats
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _db_with_project():
    projects = create_mock_collection(find_one={"_id": "p1", "name": "Proj"})
    return create_mock_db({"projects": projects})


def test_both_decorators_get_the_scans_outcome():
    from app.services.analysis import engine

    scan_doc = Scan(project_id="p1", branch="main", commit_hash="abc")
    error = "analyzers failed or returned partial results: grype"
    with (
        patch.object(engine, "decorate_gitlab_mr", new_callable=AsyncMock) as gitlab,
        patch.object(engine, "decorate_github_pr", new_callable=AsyncMock) as github,
        patch.object(engine, "send_scan_notifications", new_callable=AsyncMock),
    ):
        asyncio.run(
            engine._send_integrations_and_notifications(
                "p1",
                "s1",
                scan_doc,
                Stats(),
                SCAN_STATUS_COMPLETED_WITH_ERRORS,
                error,
                ["grype"],
                [],
                {"grype": "Failed"},
                _db_with_project(),
            )
        )

    gitlab.assert_awaited_once()
    assert github.await_args.args[:4] == ("s1", Stats(), SCAN_STATUS_COMPLETED_WITH_ERRORS, error)
    assert github.await_args.args[4] is scan_doc
    assert github.await_args.args == gitlab.await_args.args


def test_the_notifier_counts_the_analyzers_but_not_the_enrichments():
    from app.services.analysis import engine

    outcomes = {"grype": "Success", "osv": "Success", "epss_kev": "Success (3 enriched)", "reachability": "Failed"}
    with (
        patch.object(engine, "decorate_gitlab_mr", new_callable=AsyncMock),
        patch.object(engine, "decorate_github_pr", new_callable=AsyncMock),
        patch.object(engine, "send_scan_notifications", new_callable=AsyncMock) as notify,
    ):
        asyncio.run(
            engine._send_integrations_and_notifications(
                "p1", "s1", None, Stats(), SCAN_STATUS_COMPLETED, None, [], [], outcomes, _db_with_project()
            )
        )

    assert notify.await_args.kwargs["analyzer_count"] == 2

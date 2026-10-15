import asyncio
from unittest.mock import AsyncMock, patch

from app.core.constants import SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.models.project import Scan
from app.models.stats import Stats
from app.services.analysis.runner import AnalyzerOutcome, OutcomeStatus
from tests.helpers.analyzers import run_context, verdict
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _db_with_project():
    projects = create_mock_collection(find_one={"_id": "p1", "name": "Proj"})
    return create_mock_db({"projects": projects})


def test_both_decorators_get_the_scans_outcome():
    from app.services.analysis import engine

    scan_doc = Scan(id="s1", project_id="p1", branch="main", commit_hash="abc")
    error = "analyzers failed or returned partial results: grype"
    outcomes = [AnalyzerOutcome("grype", OutcomeStatus.FAILED)]
    with (
        patch.object(engine, "decorate_gitlab_mr", new_callable=AsyncMock) as gitlab,
        patch.object(engine, "decorate_github_pr", new_callable=AsyncMock) as github,
        patch.object(engine, "send_scan_notifications", new_callable=AsyncMock) as notify,
    ):
        asyncio.run(
            engine._send_integrations_and_notifications(
                run_context(_db_with_project(), scan_doc),
                verdict(
                    SCAN_STATUS_COMPLETED_WITH_ERRORS,
                    error=error,
                    failed_analyzers=["grype"],
                    outcomes=outcomes,
                ),
                [],
            )
        )

    gitlab.assert_awaited_once()
    assert github.await_args.args[:4] == ("s1", Stats(), SCAN_STATUS_COMPLETED_WITH_ERRORS, error)
    assert github.await_args.args[4] is scan_doc
    assert github.await_args.args == gitlab.await_args.args
    assert notify.await_args.args[3:] == (Stats(), SCAN_STATUS_COMPLETED_WITH_ERRORS, ["grype"], outcomes)

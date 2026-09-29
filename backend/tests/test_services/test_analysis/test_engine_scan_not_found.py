"""A missing scan must terminate cleanly."""

import asyncio

from app.services.analysis.engine import run_analysis
from tests.mocks.fake_mongo import FakeDatabase


def test_a_missing_scan_has_no_outcome_for_the_worker_to_retry():
    db = FakeDatabase()

    assert asyncio.run(run_analysis("missing-scan", [], [], db, worker_id="pod-a/worker-0")) is None
    assert asyncio.run(db.scans.count_documents({})) == 0

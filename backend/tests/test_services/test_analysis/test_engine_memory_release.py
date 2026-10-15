import weakref

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analysis import engine
from app.services.analysis.runner import OutcomeStatus
from tests.helpers.analyzers import run_context, serve_analyzer

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"type": "library", "name": "requests", "version": "2.30.0", "purl": "pkg:pypi/requests@2.30.0"}],
}


class _Raising:
    async def analyze(self, sbom, settings=None, parsed_components=None):
        raise RuntimeError("license feed down")


@pytest.mark.asyncio
async def test_a_raising_analyzer_leaves_the_sbom_and_the_aggregator_free_while_its_outcome_is_held(
    monkeypatch, automatic_gc_off
):
    serve_analyzer(monkeypatch, "license_compliance", _Raising())
    # pytest's log capture keeps every record's exc_info, and with it the traceback under test.
    monkeypatch.setattr(engine.logger, "disabled", True)
    parsed, sbom = engine._parse_and_track_sbom(_SBOM)
    aggregator = ResultAggregator()
    released = [weakref.ref(sbom), weakref.ref(aggregator)]

    outcomes = await engine._process_sbom(run_context(None, "scan-1", ["license_compliance"]), aggregator, parsed, sbom)
    del sbom, aggregator

    assert [outcome.status for outcome in outcomes] == [OutcomeStatus.FAILED]
    assert [ref() for ref in released] == [None, None]

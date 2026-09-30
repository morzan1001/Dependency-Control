"""The reachability metrics count what apply_reachability persisted, on the engine and the upload path alike."""

import pytest
from prometheus_client import REGISTRY

from app.schemas.projections import CallgraphMinimal
from app.services.reachability_enrichment import apply_reachability, build_component_language_map
from tests.mocks.fake_mongo import FakeDatabase

_SCAN_ID = "scan-1"
_LEVELS = ("import", "symbol", "none", "unknown")


def _finding(component: str) -> dict:
    return {
        "_id": f"f-{component}",
        "finding_id": f"CVE-{component}",
        "type": "vulnerability",
        "component": component,
        "version": "1.0.0",
        "severity": "HIGH",
        "details": {"risk_score": 40.0},
    }


def _sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _counters() -> dict[str, float]:
    counters = {"enriched": _sample("analysis_enrichment_total", {"type": "reachability"})}
    for level in _LEVELS:
        counters[level] = _sample("analysis_reachable_vulnerabilities_total", {"reachability_level": level})
    return counters


async def _seeded_db() -> FakeDatabase:
    db = FakeDatabase()
    for name, ecosystem in (("requests", "pypi"), ("urllib3", "pypi"), ("left-pad", "npm")):
        await db.dependencies.insert_one({"scan_id": _SCAN_ID, "name": name, "purl": f"pkg:{ecosystem}/{name}@1.0.0"})
    return db


_PYTHON_CALLGRAPH = CallgraphMinimal(
    _id="cg-1",
    language="python",
    analyzed_modules=["requests", "urllib3"],
    module_usage={"requests": {"module": "requests", "import_locations": ["app/client.py"]}},
)


@pytest.mark.asyncio
async def test_only_reachable_verdicts_are_counted_under_their_persisted_level():
    db = await _seeded_db()
    findings = [_finding("requests"), _finding("urllib3"), _finding("left-pad")]
    before = _counters()

    _languages, enriched = await apply_reachability(db, _SCAN_ID, findings, [_PYTHON_CALLGRAPH])

    assert [finding["reachable"] for finding in findings] == [True, False, None]
    after = _counters()
    assert {key: after[key] - before[key] for key in before} == {
        "enriched": enriched,
        "import": 1,
        "symbol": 0,
        "none": 0,
        "unknown": 0,
    }


@pytest.mark.asyncio
async def test_the_inventory_map_it_built_is_handed_on_for_the_stats():
    db = await _seeded_db()

    languages, _enriched = await apply_reachability(db, _SCAN_ID, [_finding("requests")], [_PYTHON_CALLGRAPH])

    assert languages == await build_component_language_map(db, _SCAN_ID)

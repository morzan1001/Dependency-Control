"""Ad-hoc runs are bounded: an input-shape ceiling, a findings ceiling that keeps the worst first."""

import time

import pytest

from app.core.constants import (
    ADHOC_MAX_SBOM_COMPONENTS,
    ADHOC_MAX_SBOM_EVIDENCE_ENTRIES,
    ADHOC_MAX_SCANNER_FINDINGS,
)
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis import adhoc
from app.services.analysis.adhoc import AdhocInputTooLarge, run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_OSV = "osv"
_CVE = "CVE-2024-99999"
_CRITICAL = "CRITICAL"
_COMPONENT = "requests"
_VERSION = "2.31.0"

# Every measurement below is on the shapes an adversarial pass timed against this pipeline:
# 40 000 occurrences on one component parsed for 4.36 s, and 2 000 findings crowded onto one
# path cross-linked for 24.27 s. Neither yields to a deadline: both run without an await.
_OCCURRENCE_ATTACK = 40_000
_CROWDED_FINDINGS = 2_000
_CROWDED_PATH = "app/handlers.py"
# Forty times the post-guard measurement, so a loaded runner cannot make this flap.
_AFFORDABLE_SECONDS = 5.0

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
            "name": _COMPONENT,
            "version": _VERSION,
            "purl": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
        }
    ],
}


def _sbom_with_occurrences(count: int) -> dict:
    component = dict(_SBOM["components"][0])
    component["evidence"] = {"occurrences": [{"location": f"src/module_{i}.py"} for i in range(count)]}
    return {**_SBOM, "components": [component]}


def _sbom_with_components(count: int) -> dict:
    return {
        **_SBOM,
        "components": [
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/pkg{i}@1.0.0",
                "name": f"pkg{i}",
                "version": "1.0.0",
                "purl": f"pkg:pypi/pkg{i}@1.0.0",
            }
            for i in range(count)
        ],
    }


def _opengrep(count: int, path: str) -> dict:
    return {
        "findings": [
            {
                "check_id": f"python.rule.{i}",
                "path": path,
                "start": {"line": i + 1},
                "end": {"line": i + 1},
                "extra": {"severity": "INFO", "message": "review this"},
            }
            for i in range(count)
        ]
    }


class _FakeOsv:
    """One critical advisory on the parsed component, in the shape ``normalize_osv`` reads."""

    name = _OSV

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {
            "osv_vulnerabilities": [
                {
                    "component": _COMPONENT,
                    "version": _VERSION,
                    "vulnerabilities": [{"id": _CVE, "severity": _CRITICAL, "summary": "remote code execution"}],
                }
            ]
        }


@pytest.fixture
def _osv(monkeypatch):
    from app.services.analysis import registry

    monkeypatch.setitem(registry.analyzers, _OSV, _FakeOsv())


async def _run(request: AdhocAnalyzeRequest):
    return await run_adhoc_analysis(request, FakeDatabase())


# ── The findings ceiling


@pytest.mark.asyncio
async def test_under_the_ceiling_is_not_truncated(monkeypatch):
    monkeypatch.setattr(adhoc, "ADHOC_MAX_FINDINGS", 10)
    request = AdhocAnalyzeRequest(
        scanners={"opengrep": _opengrep(5, _CROWDED_PATH)}, analyzers=[], apply_global_waivers=False
    )

    response = await _run(request)

    assert response.truncated is False
    assert len(response.findings) == 5


@pytest.mark.asyncio
async def test_over_the_ceiling_is_cut_and_flagged(monkeypatch):
    monkeypatch.setattr(adhoc, "ADHOC_MAX_FINDINGS", 3)
    request = AdhocAnalyzeRequest(
        scanners={"opengrep": _opengrep(10, _CROWDED_PATH)}, analyzers=[], apply_global_waivers=False
    )

    response = await _run(request)

    assert response.truncated is True
    assert len(response.findings) == 3
    # The cap is applied before the fold, so the stats describe exactly the returned set.
    stats = response.stats
    bucketed = stats.critical + stats.high + stats.medium + stats.low + stats.negligible + stats.info + stats.unknown
    assert bucketed == 3


@pytest.mark.asyncio
async def test_the_cut_keeps_the_most_severe_findings(monkeypatch, _osv):
    """The aggregator orders by type name, where ``vulnerability`` sorts last of all."""
    monkeypatch.setattr(adhoc, "ADHOC_MAX_FINDINGS", 3)
    request = AdhocAnalyzeRequest(
        sboms=[_SBOM],
        scanners={"opengrep": _opengrep(8, _CROWDED_PATH)},
        analyzers=[_OSV],
        apply_global_waivers=False,
    )

    response = await _run(request)

    assert response.truncated is True
    assert [record["severity"] for record in response.findings] == [_CRITICAL, "LOW", "LOW"]
    assert response.stats.critical == 1


# ── The input-shape ceiling


@pytest.mark.asyncio
async def test_the_shape_that_parses_for_seconds_is_refused():
    request = AdhocAnalyzeRequest(
        sboms=[_sbom_with_occurrences(_OCCURRENCE_ATTACK)], analyzers=[], apply_global_waivers=False
    )

    with pytest.raises(AdhocInputTooLarge, match=str(ADHOC_MAX_SBOM_EVIDENCE_ENTRIES)):
        await _run(request)


@pytest.mark.asyncio
async def test_evidence_entries_at_the_ceiling_are_still_analysed():
    request = AdhocAnalyzeRequest(
        sboms=[_sbom_with_occurrences(ADHOC_MAX_SBOM_EVIDENCE_ENTRIES)], analyzers=[], apply_global_waivers=False
    )

    started = time.perf_counter()
    response = await _run(request)

    assert response.analyzers.skipped_inputs == {}
    assert time.perf_counter() - started < _AFFORDABLE_SECONDS


@pytest.mark.asyncio
async def test_too_many_components_are_refused():
    request = AdhocAnalyzeRequest(
        sboms=[_sbom_with_components(ADHOC_MAX_SBOM_COMPONENTS + 1)], analyzers=[], apply_global_waivers=False
    )

    with pytest.raises(AdhocInputTooLarge, match=str(ADHOC_MAX_SBOM_COMPONENTS)):
        await _run(request)


@pytest.mark.asyncio
async def test_the_component_budget_is_shared_across_posted_sboms():
    """Splitting the same components over two documents must not buy a second budget."""
    half = ADHOC_MAX_SBOM_COMPONENTS // 2 + 1
    request = AdhocAnalyzeRequest(
        sboms=[_sbom_with_components(half), _sbom_with_components(half)],
        analyzers=[],
        apply_global_waivers=False,
    )

    with pytest.raises(AdhocInputTooLarge, match=str(ADHOC_MAX_SBOM_COMPONENTS)):
        await _run(request)


@pytest.mark.asyncio
async def test_too_many_posted_scanner_findings_are_refused():
    request = AdhocAnalyzeRequest(
        scanners={"opengrep": _opengrep(ADHOC_MAX_SCANNER_FINDINGS + 1, _CROWDED_PATH)},
        analyzers=[],
        apply_global_waivers=False,
    )

    with pytest.raises(AdhocInputTooLarge, match=str(ADHOC_MAX_SCANNER_FINDINGS)):
        await _run(request)


@pytest.mark.asyncio
async def test_findings_crowded_onto_one_path_stay_affordable():
    """Admitted, not refused: the ceiling bounds the count and the cross-link cap bounds the pairing."""
    request = AdhocAnalyzeRequest(
        scanners={"opengrep": _opengrep(_CROWDED_FINDINGS, _CROWDED_PATH)},
        analyzers=[],
        apply_global_waivers=False,
    )

    started = time.perf_counter()
    response = await _run(request)

    assert len(response.findings) == _CROWDED_FINDINGS
    assert time.perf_counter() - started < _AFFORDABLE_SECONDS

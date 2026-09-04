"""Reachability runs off the posted callgraph, never off the database."""

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_OSV = "osv"
_REACHABILITY = "reachability"
_NO_CALLGRAPH = "no callgraph supplied"
_TYPE_VULNERABILITY = "vulnerability"
_PYTHON = "python"
_IMPORTED_PACKAGE = "requests"
_ANALYZED_BUT_UNUSED_PACKAGE = "urllib3"
_IMPORTING_FILE = "app/client.py"
_VULNERABILITY_ID = "CVE-2024-0001"
_ANALYZED_COUNT = 1

_COMPONENTS = {
    _IMPORTED_PACKAGE: {
        "type": "library",
        "bom-ref": f"pkg:pypi/{_IMPORTED_PACKAGE}@2.31.0",
        "name": _IMPORTED_PACKAGE,
        "version": "2.31.0",
        "purl": f"pkg:pypi/{_IMPORTED_PACKAGE}@2.31.0",
    },
    _ANALYZED_BUT_UNUSED_PACKAGE: {
        "type": "library",
        "bom-ref": f"pkg:pypi/{_ANALYZED_BUT_UNUSED_PACKAGE}@2.1.0",
        "name": _ANALYZED_BUT_UNUSED_PACKAGE,
        "version": "2.1.0",
        "purl": f"pkg:pypi/{_ANALYZED_BUT_UNUSED_PACKAGE}@2.1.0",
    },
}


def _sbom(*component_names: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [_COMPONENTS[name] for name in component_names],
    }


# The generic wire format: an import list plus the coverage universe the producer inspected.
_CALLGRAPH = {
    "language": _PYTHON,
    "format": "generic",
    "analyzed_modules": [_IMPORTED_PACKAGE, _ANALYZED_BUT_UNUSED_PACKAGE],
    "imports": [{"module": _IMPORTED_PACKAGE, "file": _IMPORTING_FILE, "line": 1, "symbols": ["get"]}],
}

# madge output is {file: [imported modules]} with no format or language of its own.
_MADGE_CALLGRAPH = {"src/index.js": ["lodash"], "__analyzed_modules__": ["lodash"]}

_UNREADABLE_CALLGRAPH = {"nonsense": 1}
_CALLGRAPH_WITHOUT_LANGUAGE = {k: v for k, v in _CALLGRAPH.items() if k != "language"}


class _FakeOsv:
    """The OSV analyzer's own wire shape: ``osv_vulnerabilities`` per component, advisories nested."""

    name = _OSV

    def __init__(self, component: str = _IMPORTED_PACKAGE, version: str = "2.31.0") -> None:
        self._component = component
        self._version = version

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {
            "osv_vulnerabilities": [
                {
                    "component": self._component,
                    "version": self._version,
                    "vulnerabilities": [
                        {"id": _VULNERABILITY_ID, "severity": "HIGH", "summary": "demo"},
                    ],
                }
            ]
        }


@pytest.fixture
def _osv(monkeypatch):
    from app.services.analysis import registry

    monkeypatch.setitem(registry.analyzers, _OSV, _FakeOsv())


@pytest.fixture
def _osv_on_the_unused_package(monkeypatch):
    from app.services.analysis import registry

    monkeypatch.setitem(registry.analyzers, _OSV, _FakeOsv(_ANALYZED_BUT_UNUSED_PACKAGE, "2.1.0"))


def _vulnerabilities(response):
    return [f for f in response.findings if f["type"] == _TYPE_VULNERABILITY]


@pytest.mark.asyncio
async def test_no_callgraph_means_no_summary_and_a_skip_reason(_osv):
    request = AdhocAnalyzeRequest(sboms=[_sbom(_IMPORTED_PACKAGE)], analyzers=[_OSV], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.reachability_summary is None
    assert response.analyzers.skipped[_REACHABILITY] == _NO_CALLGRAPH
    assert _REACHABILITY not in response.analyzers.ran


@pytest.mark.asyncio
async def test_posted_callgraph_produces_a_summary_and_a_verdict(_osv):
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_CALLGRAPH,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.reachability_summary is not None
    assert response.reachability_summary["languages"] == [_PYTHON]
    assert response.reachability_summary["analyzed"] == _ANALYZED_COUNT
    assert _REACHABILITY in response.analyzers.ran
    assert _REACHABILITY not in response.analyzers.skipped

    vulnerabilities = _vulnerabilities(response)
    assert vulnerabilities
    assert vulnerabilities[0]["details"]["reachability"]["is_reachable"] is True
    assert vulnerabilities[0]["details"]["reachability"]["import_locations"] == [_IMPORTING_FILE]


@pytest.mark.asyncio
async def test_the_verdict_is_mirrored_onto_the_records_the_response_carries(_osv):
    """The stats fold reads the top level, so enriching a copy would leave every counter at zero."""
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_CALLGRAPH,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert [f["reachable"] for f in _vulnerabilities(response)] == [True]


@pytest.mark.asyncio
async def test_an_analyzed_package_that_is_never_imported_is_ruled_unreachable(_osv_on_the_unused_package):
    """Only the SBOM's own ecosystem map licenses that verdict; without it absence proves nothing."""
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE, _ANALYZED_BUT_UNUSED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_CALLGRAPH,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert [f["reachable"] for f in _vulnerabilities(response)] == [False]


@pytest.mark.asyncio
async def test_a_madge_payload_is_auto_detected_and_read_as_javascript(_osv):
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_MADGE_CALLGRAPH,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.reachability_summary is not None
    assert response.reachability_summary["languages"] == ["javascript"]


@pytest.mark.asyncio
async def test_a_generic_payload_without_a_language_is_rejected(_osv):
    """The language decides which findings the graph may falsify; guessing it fabricates verdicts."""
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_CALLGRAPH_WITHOUT_LANGUAGE,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.reachability_summary is None
    assert _REACHABILITY in response.analyzers.errored


@pytest.mark.asyncio
async def test_unparseable_callgraph_is_reported_not_fatal(_osv):
    request = AdhocAnalyzeRequest(
        sboms=[_sbom(_IMPORTED_PACKAGE)],
        analyzers=[_OSV],
        callgraph=_UNREADABLE_CALLGRAPH,
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.reachability_summary is None
    assert response.analyzers.errored[_REACHABILITY]
    assert _REACHABILITY not in response.analyzers.ran
    assert response.findings

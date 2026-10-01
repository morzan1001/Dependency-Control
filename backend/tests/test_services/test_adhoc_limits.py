"""What large ad-hoc inputs cost: crowded findings, a large callgraph, and parsing kept off the event loop."""

import threading
import time

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis import adhoc
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.reachability_enrichment import _prepare_callgraph
from tests.mocks.fake_mongo import FakeDatabase

_COMPONENT = "requests"
_VERSION = "2.31.0"

# 2 000 findings crowded onto one path cross-linked for 24.27 s before the cross-link cap, without an await.
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


async def _run(request: AdhocAnalyzeRequest):
    return await run_adhoc_analysis(request, FakeDatabase())


@pytest.mark.asyncio
async def test_findings_crowded_onto_one_path_stay_affordable():
    """The cross-link cap bounds the pairing of findings that share a file."""
    request = AdhocAnalyzeRequest(
        scanners={"opengrep": _opengrep(_CROWDED_FINDINGS, _CROWDED_PATH)},
        analyzers=[],
        apply_global_waivers=False,
    )

    started = time.perf_counter()
    response = await _run(request)

    assert len(response.findings) == _CROWDED_FINDINGS
    assert time.perf_counter() - started < _AFFORDABLE_SECONDS


def _symbols_on_one_import(symbols: int) -> dict:
    return {
        "language": "python",
        "imports": [{"module": _COMPONENT, "file": "app/client.py", "symbols": [f"s{i}" for i in range(symbols)]}],
    }


_LARGE_CALLGRAPH_FILES = 2000
_LARGE_CALLGRAPH_MODULES = ("requests", "urllib3", "yaml", "jinja2", "click")
_SHARED_SYMBOLS = ["sym0", "common", "sym1", "sym2", "sym3"]


def _large_callgraph() -> dict:
    """Every file imports a submodule of every package, naming one rotating symbol and one shared one."""
    imports = [
        {
            "module": f"{module}.sub{file % 3}",
            "file": f"app/f{file}.py",
            "line": 1,
            "symbols": [f"sym{file % 4}", "common"],
        }
        for file in range(_LARGE_CALLGRAPH_FILES)
        for module in _LARGE_CALLGRAPH_MODULES
    ]
    calls = [
        {
            "caller_file": f"app/f{file}.py",
            "callee_module": "requests",
            "callee_function": "get" if file % 2 else "post",
        }
        for file in range(_LARGE_CALLGRAPH_FILES)
    ]
    analyzed = [*_LARGE_CALLGRAPH_MODULES, *(module.upper() for module in _LARGE_CALLGRAPH_MODULES)]
    return {"language": "python", "format": "generic", "imports": imports, "calls": calls, "analyzed_modules": analyzed}


def test_a_large_valid_callgraph_prepares_to_the_pinned_result():
    payload = _large_callgraph()

    callgraph = adhoc._prepare_posted_callgraph(payload)
    prepared = _prepare_callgraph(callgraph)

    every_file = [f"app/f{file}.py" for file in range(_LARGE_CALLGRAPH_FILES)]
    submodules = [f"{module}.sub{n}" for n in range(3) for module in _LARGE_CALLGRAPH_MODULES]
    assert callgraph.total_imports == _LARGE_CALLGRAPH_FILES * len(_LARGE_CALLGRAPH_MODULES)
    assert callgraph.analyzed_modules == list(_LARGE_CALLGRAPH_MODULES)
    assert list(callgraph.module_usage or {}) == [*submodules, "requests"]
    assert (callgraph.module_usage or {})["requests"]["used_symbols"] == ["post", "get"]
    for module in _LARGE_CALLGRAPH_MODULES:
        folded = prepared.usage_index[module]
        extra_symbols = {"post", "get"} if module == "requests" else set()
        assert sorted(folded["import_locations"]) == sorted(every_file)
        assert set(folded["used_symbols"]) == {*_SHARED_SYMBOLS, *extra_symbols}


@pytest.mark.asyncio
async def test_the_posted_inputs_are_parsed_off_the_event_loop(monkeypatch):
    threads = {}
    real_parse, real_prepare = adhoc.parse_sbom, adhoc._prepare_posted_callgraph

    def _parse(sbom):
        threads["sbom"] = threading.current_thread()
        return real_parse(sbom)

    def _prepare(payload):
        threads["callgraph"] = threading.current_thread()
        return real_prepare(payload)

    monkeypatch.setattr(adhoc, "parse_sbom", _parse)
    monkeypatch.setattr(adhoc, "_prepare_posted_callgraph", _prepare)
    request = AdhocAnalyzeRequest(
        sboms=[_SBOM], callgraph=_symbols_on_one_import(1), analyzers=[], apply_global_waivers=False
    )

    await _run(request)

    assert set(threads) == {"sbom", "callgraph"}
    assert threading.main_thread() not in threads.values()

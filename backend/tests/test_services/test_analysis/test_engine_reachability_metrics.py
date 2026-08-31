"""The reachability metric must read the persisted tri-state and the persisted level name."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from app.services.analysis.engine import _run_reachability_enrichment


def _finding(is_reachable, analysis_level):
    return {
        "finding_id": "CVE-1",
        "component": "requests",
        "version": "2.0.0",
        "severity": "HIGH",
        "details": {"reachability": {"is_reachable": is_reachable, "analysis_level": analysis_level}},
    }


def _run(monkeypatch, findings):
    labels: list[str] = []

    metric = SimpleNamespace(
        labels=lambda reachability_level: SimpleNamespace(inc=lambda: labels.append(reachability_level))
    )
    monkeypatch.setattr("app.services.analysis.engine.analysis_reachable_vulnerabilities_total", metric)
    monkeypatch.setattr("app.services.analysis.engine.analysis_enrichment_total", None)
    monkeypatch.setattr(
        "app.services.analysis.engine.enrich_findings_with_reachability",
        AsyncMock(return_value=len(findings)),
    )

    callgraph_repo = SimpleNamespace(
        find_all_minimal_by_scan=AsyncMock(
            return_value=[SimpleNamespace(model_dump=lambda by_alias: {"language": "python", "module_usage": {}})]
        ),
        find_all_minimal_by_pipeline=AsyncMock(return_value=[]),
    )

    asyncio.run(
        _run_reachability_enrichment(
            vulnerability_findings=findings,
            scan_id="scan-1",
            project_id="proj-1",
            scan_doc=SimpleNamespace(pipeline_id=None),  # type: ignore[arg-type]
            db=MagicMock(),
            callgraph_repo=callgraph_repo,  # type: ignore[arg-type]
            result_repo=SimpleNamespace(collection=SimpleNamespace(update_one=AsyncMock())),  # type: ignore[arg-type]
            scan_repo=SimpleNamespace(update_raw=AsyncMock()),  # type: ignore[arg-type]
            results_summary=[],
        )
    )
    return labels


def test_reachable_finding_is_labelled_with_its_analysis_level(monkeypatch):
    assert _run(monkeypatch, [_finding(True, "symbol")]) == ["symbol"]


def test_unanalysed_and_unreachable_findings_are_not_counted(monkeypatch):
    assert _run(monkeypatch, [_finding(None, "none"), _finding(False, "none")]) == []

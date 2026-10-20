from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from prometheus_client import REGISTRY

from app.core.constants import (
    NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
)
from app.core.init_db import create_indexes
from app.models.project import Project, Scan
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.analysis import engine
from app.services.analysis.registry import CRYPTO_ANALYZERS, crypto_evaluators
from app.services.notifications import notification_service
from app.services.webhooks import webhook_service
from tests.helpers.analyzers import serve_analyzer
from tests.helpers.sboms import store_sbom

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT_ID = "outcome-project"
_WORKER = "pod-a/worker-0"
_REQUESTS = {"name": "requests", "version": "2.30.0", "purl": "pkg:pypi/requests@2.30.0"}
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", **_REQUESTS}]}
_GRYPE_MATCH = {
    "matches": [{"vulnerability": {"id": "CVE-2023-32681", "severity": "Medium"}, "artifact": dict(_REQUESTS)}]
}
_TRIVY_TIMEOUT = {"error": "trivy analysis failed", "details": "trivy timed out after 300 seconds"}
_OSV_PARTIAL = {"osv_vulnerabilities": [], "partial_components_skipped": 7}
_SBOM_ANALYZERS = ["end_of_life", "grype", "license_compliance", "osv", "trivy"]


class _Scripted:
    def __init__(self, *answers):
        self._answers = list(answers)

    async def analyze(self, sbom, settings=None, parsed_components=None):
        answer = self._answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def sent(monkeypatch) -> SimpleNamespace:
    channels = SimpleNamespace(notify=AsyncMock(), completed=AsyncMock())
    monkeypatch.setattr(notification_service, "notify_project_members", channels.notify)
    monkeypatch.setattr(webhook_service, "trigger_scan_completed", channels.completed)
    monkeypatch.setattr(webhook_service, "trigger_vulnerability_found", AsyncMock())
    return channels


def _completion_notice(sent: SimpleNamespace) -> dict:
    (notice,) = [
        call.kwargs
        for call in sent.notify.await_args_list
        if call.kwargs["event_type"] == NOTIFICATION_EVENT_ANALYSIS_COMPLETED
    ]
    return notice


def _results_lines(sent: SimpleNamespace) -> list[str]:
    return _completion_notice(sent)["message"].split("Results:\n", 1)[1].splitlines()


def _sample(name: str, analyzer: str) -> float:
    return REGISTRY.get_sample_value(name, {"analyzer": analyzer}) or 0.0


async def _run(
    db, analyzers: list[str], *, sboms: int = 2, scan_type: str | None = None, external: dict | None = None
) -> str:
    await create_indexes(db)
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="outcomes").model_dump(by_alias=True))
    refs = [await store_sbom(db, _SBOM) for _ in range(sboms)]
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=refs,
        status="processing",
        worker_id=_WORKER,
        scan_type=scan_type,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    for name, result in (external or {}).items():
        await db.analysis_results.insert_one({"scan_id": scan.id, "analyzer_name": name, "result": result})
    await engine.run_analysis(scan.id, refs, analyzers, db, worker_id=_WORKER)
    return scan.id


async def _mixed_run(db, monkeypatch) -> str:
    serve_analyzer(monkeypatch, "end_of_life", _Scripted({}, {}))
    serve_analyzer(monkeypatch, "grype", _Scripted(_GRYPE_MATCH, {"matches": []}))
    serve_analyzer(monkeypatch, "license_compliance", _Scripted({}, RuntimeError("license feed down")))
    serve_analyzer(monkeypatch, "osv", _Scripted({}, _OSV_PARTIAL))
    serve_analyzer(monkeypatch, "trivy", _Scripted(_TRIVY_TIMEOUT, _TRIVY_TIMEOUT))
    monkeypatch.setattr(
        engine.vulnerability_enrichment_service, "enrich_findings", AsyncMock(return_value=({}, ["KEV"]))
    )
    external = {"trufflehog": {"error": "scanner container OOM-killed"}, "kics": {"queries": []}}
    return await _run(db, [*_SBOM_ANALYZERS, "epss_kev"], external=external)


async def test_the_notice_lists_each_analyzer_once_with_its_worst_outcome_in_first_reported_order(
    db, monkeypatch, sent
):
    await _mixed_run(db, monkeypatch)

    assert _results_lines(sent) == [
        "end_of_life: Success",
        "grype: Success",
        "license_compliance: Failed",
        "osv: Partial (7 component(s) were not scanned)",
        "trivy: Failed",
        "kics: Success",
        "trufflehog: Failed",
        "epss_kev: Partial (KEV unavailable) (1 enriched)",
    ]


async def test_of_two_outcomes_of_equal_rank_the_notice_keeps_the_first_reported(db, monkeypatch, sent):
    serve_analyzer(monkeypatch, "osv", _Scripted({**_OSV_PARTIAL, "partial_components_skipped": 2}, _OSV_PARTIAL))

    await _run(db, ["osv"])

    assert _results_lines(sent) == ["osv: Partial (2 component(s) were not scanned)"]


async def test_every_channel_counts_the_analyzers_but_not_the_enrichment(db, monkeypatch, sent):
    await _mixed_run(db, monkeypatch)

    notice = _completion_notice(sent)
    assert "7 analyzers ran" in notice["html_message"]
    assert "*Analyzers (7)*" in str(notice["slack_blocks"])
    assert "**Analyzers (7)**" in notice["mattermost_props"]["attachments"][0]["text"]


async def test_the_scan_and_its_webhook_carry_the_verdict_of_the_outcomes(db, monkeypatch, sent):
    scan_id = await _mixed_run(db, monkeypatch)

    failed = ["license_compliance", "osv", "trivy", "trufflehog"]
    scan = await db.scans.find_one({"_id": scan_id})
    assert (scan["status"], scan["error"], scan["failed_analyzers"], scan["enrichment_failures"]) == (
        SCAN_STATUS_COMPLETED_WITH_ERRORS,
        f"analyzers failed or returned partial results: {', '.join(failed)}",
        failed,
        ["epss_kev"],
    )
    webhook = sent.completed.await_args.kwargs
    assert (webhook["scan_status"], webhook["failed_analyzers"], webhook["revision"]) == (
        SCAN_STATUS_COMPLETED_WITH_ERRORS,
        failed,
        1,
    )


async def test_each_failed_or_partial_analyzer_leaves_one_scan_error_finding(db, monkeypatch, sent):
    scan_id = await _mixed_run(db, monkeypatch)

    scan_errors = {
        doc["finding_id"]: doc["description"]
        async for doc in db.findings.find({"scan_id": scan_id, "finding_id": {"$regex": "^SCAN-ERROR-"}})
    }
    assert scan_errors == {
        "SCAN-ERROR-license_compliance": "Scanner 'license_compliance' failed: license feed down",
        "SCAN-ERROR-osv": "Scanner 'osv' returned partial results: 7 component(s) were not scanned",
        "SCAN-ERROR-trivy": "Scanner 'trivy' failed: trivy analysis failed",
        "SCAN-ERROR-trufflehog": "Scanner 'trufflehog' failed: scanner container OOM-killed",
    }


async def test_each_analyzer_run_is_counted_timed_and_its_failures_counted(db, monkeypatch, sent):
    series = ("analysis_scans_total", "analysis_duration_seconds_count", "analysis_errors_total")
    before = {name: [_sample(s, name) for s in series] for name in _SBOM_ANALYZERS}

    await _mixed_run(db, monkeypatch)

    moved = {name: [_sample(s, name) - start for s, start in zip(series, before[name], strict=True)] for name in before}
    assert moved == {
        "end_of_life": [2, 2, 0],
        "grype": [2, 2, 0],
        "license_compliance": [2, 1, 1],
        "osv": [2, 2, 0],
        "trivy": [2, 2, 2],
    }


async def test_unreadable_crypto_inputs_fail_every_crypto_analyzer_with_a_scan_error(db, monkeypatch, sent):
    monkeypatch.setattr(engine.CryptoPolicyResolver, "resolve", AsyncMock(side_effect=RuntimeError("policy gone")))
    before = {name: _sample("analysis_errors_total", name) for name in CRYPTO_ANALYZERS}

    scan_id = await _run(db, [], sboms=0, scan_type="cbom")

    names = sorted(CRYPTO_ANALYZERS)
    assert _results_lines(sent) == [f"{name}: Failed" for name in names]
    scan = await db.scans.find_one({"_id": scan_id})
    assert (scan["status"], scan["failed_analyzers"]) == (SCAN_STATUS_COMPLETED_WITH_ERRORS, names)
    scan_errors = {doc["finding_id"]: doc["description"] async for doc in db.findings.find({"scan_id": scan_id})}
    assert scan_errors == {f"SCAN-ERROR-{name}": f"Scanner '{name}' failed: policy gone" for name in names}
    assert {name: _sample("analysis_errors_total", name) - before[name] for name in names} == dict.fromkeys(names, 1)


async def test_a_crypto_result_that_cannot_be_stored_fails_its_analyzer_with_a_scan_error(db, monkeypatch, sent):
    from app.services.crypto_policy.seeder import seed_crypto_policies

    await seed_crypto_policies(db)
    save_result = AnalysisResultRepository.save_result

    async def _crypto_rows_rejected(self, scan_id, analyzer_name, result, source=None):
        if analyzer_name in CRYPTO_ANALYZERS:
            raise RuntimeError("row rejected")
        return await save_result(self, scan_id, analyzer_name, result, source=source)

    monkeypatch.setattr(AnalysisResultRepository, "save_result", _crypto_rows_rejected)

    scan_id = await _run(db, [], sboms=0, scan_type="cbom")

    names = list(crypto_evaluators({}))
    assert _results_lines(sent) == [f"{name}: Failed" for name in names]
    scan_errors = {doc["finding_id"]: doc["description"] async for doc in db.findings.find({"scan_id": scan_id})}
    assert scan_errors == {f"SCAN-ERROR-{name}": f"Scanner '{name}' failed: row rejected" for name in names}


async def _reachability_run(db, monkeypatch, apply_reachability: AsyncMock, callgraphs: list) -> str:
    serve_analyzer(monkeypatch, "grype", _Scripted(_GRYPE_MATCH))
    monkeypatch.setattr(engine, "fetch_callgraphs", AsyncMock(return_value=callgraphs))
    monkeypatch.setattr(engine, "apply_reachability", apply_reachability)
    return await _run(db, ["grype", "reachability"], sboms=1)


async def test_a_failing_reachability_pass_is_reported_as_a_failed_enrichment(db, monkeypatch, sent):
    scan_id = await _reachability_run(
        db, monkeypatch, AsyncMock(side_effect=RuntimeError("graph broken")), [SimpleNamespace()]
    )

    assert _results_lines(sent) == ["grype: Success", "reachability: Failed"]
    scan = await db.scans.find_one({"_id": scan_id})
    assert (scan["status"], scan["enrichment_failures"]) == (SCAN_STATUS_COMPLETED, ["reachability"])


async def test_a_reachability_pass_reports_how_many_findings_it_judged(db, monkeypatch, sent):
    scan_id = await _reachability_run(db, monkeypatch, AsyncMock(return_value=(None, 3)), [SimpleNamespace()])

    assert _results_lines(sent) == ["grype: Success", "reachability: Success (3 enriched)"]
    assert (await db.scans.find_one({"_id": scan_id}))["enrichment_failures"] is None


async def test_without_a_callgraph_reachability_reports_nothing_and_waits_for_the_upload(db, monkeypatch, sent):
    judge = AsyncMock()

    scan_id = await _reachability_run(db, monkeypatch, judge, [])

    assert _results_lines(sent) == ["grype: Success"]
    assert (await db.scans.find_one({"_id": scan_id}))["reachability_pending"] is True
    judge.assert_not_awaited()

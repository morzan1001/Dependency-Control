"""A compliance report may not claim a verdict it did not compute over the whole scope.

Against a live MongoDB, a project holding 20 050 findings — 50 of them criticals 400 days past
their SLA — produced a report whose CVE-SLA-CRITICAL control read `passed`, because the 50 sat
past the engine's 20 000-finding cap. Only the server log said so. The verdict is unchanged; what
changes is that every renderer now states what it was computed over.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.schemas.compliance import EvaluationCoverage, ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance import engine as engine_module
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.compliance.renderers.base import coverage_statement
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from app.services.compliance.renderers.json_renderer import JsonRenderer
from app.services.compliance.renderers.sarif_renderer import SarifRenderer
from tests.unit.test_renderer_json import _evaluation, _report

_PROJECT = "p1"
_SCAN = "s1"
_CAP = 4
_POPULATION = 6
_TEMPLATE_DIR = Path(engine_module.__file__).resolve().parent / "templates"

_EVALUATED = 20000
_IN_SCOPE = 20050
_MISSING = _IN_SCOPE - _EVALUATED


def _partial() -> EvaluationCoverage:
    return EvaluationCoverage(findings_evaluated=_EVALUATED, findings_in_scope=_IN_SCOPE, limit=_EVALUATED)


def _complete() -> EvaluationCoverage:
    return EvaluationCoverage(findings_evaluated=_IN_SCOPE, findings_in_scope=_IN_SCOPE, limit=_EVALUATED)


def _finding(index: int) -> dict:
    return {
        "_id": f"{_SCAN}-{index}",
        "project_id": _PROJECT,
        "scan_id": _SCAN,
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": f"lib-{index}",
    }


def _evaluation_with(coverage: EvaluationCoverage | None):
    evaluation = _evaluation()
    evaluation.coverage = coverage
    return evaluation


@pytest.mark.asyncio
async def test_a_capped_collection_reports_the_scope_it_did_not_read(db, monkeypatch):
    monkeypatch.setattr(engine_module, "_FINDINGS_LIMIT", _CAP)
    for index in range(_POPULATION):
        doc = _finding(index)
        db.findings._docs[doc["_id"]] = doc
    resolved = ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT])

    findings, in_scope = await ComplianceReportEngine()._collect_findings(
        db, resolved, [_SCAN], CveRemediationSlaFramework()
    )

    assert len(findings) == _CAP
    assert in_scope == _POPULATION


@pytest.mark.asyncio
async def test_an_uncapped_collection_counts_what_it_read(db):
    for index in range(_POPULATION):
        doc = _finding(index)
        db.findings._docs[doc["_id"]] = doc
    resolved = ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT])

    findings, in_scope = await ComplianceReportEngine()._collect_findings(
        db, resolved, [_SCAN], CveRemediationSlaFramework()
    )

    assert len(findings) == _POPULATION
    assert in_scope == _POPULATION


@pytest.mark.asyncio
async def test_the_engine_hands_coverage_to_the_renderer_and_to_the_stored_report():
    """A framework builds its own FrameworkEvaluation and knows nothing of the cap, so a coverage
    the engine does not attach reaches neither the artifact nor the API."""
    report = _report()
    report.framework = ReportFramework.NIST_SP_800_131A
    inputs = EvaluationInput(
        resolved=ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT]),
        scope_description=f"project '{_PROJECT}'",
        crypto_assets=[],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=2,
        scan_ids=[_SCAN],
        coverage=_partial(),
    )
    evaluation = _evaluation_with(None)
    framework = MagicMock(spec=["evaluate"])
    framework.evaluate = MagicMock(return_value=evaluation)
    update_status = AsyncMock()
    engine = ComplianceReportEngine()
    rendered: dict = {}

    def capture_render(fmt, fw, ev, rep):
        rendered["coverage"] = ev.coverage
        return b"{}", "x.json", "application/json"

    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=update_status),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=MagicMock(resolve=AsyncMock(return_value=inputs.resolved)),
        ),
        patch.dict(
            "app.services.compliance.engine.FRAMEWORK_REGISTRY",
            {ReportFramework.NIST_SP_800_131A: framework},
            clear=False,
        ),
        patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)),
        patch.object(engine, "_render", side_effect=capture_render),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        await engine.generate(report=report, db=MagicMock(), user=MagicMock(id="u1", permissions=frozenset()))

    assert rendered["coverage"] == _partial()
    assert update_status.call_args_list[-1].kwargs["coverage"] == _partial()


def test_the_partial_statement_names_the_verdicts_it_undermines():
    statement = coverage_statement(_partial())

    assert str(_EVALUATED) in statement
    assert str(_IN_SCOPE) in statement
    assert str(_MISSING) in statement
    assert "not evidence of compliance" in statement


def test_the_complete_statement_says_the_scope_was_covered():
    statement = coverage_statement(_complete())

    assert statement == f"Evaluated all {_IN_SCOPE} findings in scope."


def test_json_carries_the_statement_and_the_numbers():
    body, _, _ = JsonRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["findings_in_scope"] == _IN_SCOPE
    assert "not evidence of compliance" in payload["coverage"]["statement"]


def test_csv_states_coverage_even_without_a_disclaimer():
    """The '#' header block used to be written only when a disclaimer existed."""
    body, _, _ = CsvRenderer().render(_evaluation_with(_partial()), _report())

    assert f"# Coverage: {coverage_statement(_partial())}" in body.decode()


def test_sarif_carries_the_statement_on_the_run():
    body, _, _ = SarifRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert "not evidence of compliance" in payload["runs"][0]["properties"]["coverage"]


def test_a_renderer_given_no_coverage_prints_nothing_about_it():
    body, _, _ = JsonRenderer().render(_evaluation_with(None), _report())

    assert "coverage" not in json.loads(body)


@pytest.mark.parametrize(
    ("coverage", "expects_alarm"),
    [(_partial(), True), (_complete(), False)],
    ids=["partial-is-alarming", "complete-is-not"],
)
def test_the_pdf_cover_prints_the_coverage_banner(coverage, expects_alarm):
    """WeasyPrint's native stack is not needed to see what the page says."""
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    html = env.get_template("base_report.html").render(
        framework_name="CVE Remediation SLA",
        framework_version="1",
        generated_at=datetime(2026, 9, 5, tzinfo=timezone.utc).isoformat(),
        scope_description=f"project '{_PROJECT}'",
        inputs_fingerprint="sha256:abc",
        requested_by="u1",
        disclaimer=None,
        coverage_statement=coverage_statement(coverage),
        coverage_complete=coverage.complete,
        summary={"passed": 1, "failed": 0, "waived": 0, "not_applicable": 0, "total": 1},
        controls=[],
        residual_risks=[],
    )

    assert "Coverage:" in html
    assert ('class="coverage-partial"' in html) is expects_alarm

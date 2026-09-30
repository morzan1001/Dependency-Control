"""A compliance report may not claim a verdict it did not compute over the whole scope.

A verdict whose evidence is the absence of a match is withheld as `not_evaluated` once a gap leaves
part of the scope unread; a failure stands, because a partial scope can under-report a violation but
cannot invent one.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.models.project import Project, Scan
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    EvaluationCoverage,
    InputCoverage,
    ReportFramework,
)
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.cbom_parser import parse_cbom
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance import engine as engine_module
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    build_residual_risks,
    build_summary,
    default_evaluator,
)
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.compliance.renderers.base import coverage_statement
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from app.services.compliance.renderers.json_renderer import JsonRenderer
from app.services.compliance.renderers.pdf_renderer import build_template_context
from app.services.compliance.renderers.sarif_renderer import SarifRenderer
from app.services.crypto_policy.seeder import seed_crypto_policies
from tests.helpers.cbom import cbom_of, filler_components
from tests.helpers.compliance import evaluation_input
from tests.unit.test_renderer_json import _evaluation, _report

_PROJECT = "p1"
_SCAN = "s1"
_POPULATION = 6
_TEMPLATE_DIR = Path(engine_module.__file__).resolve().parent / "templates"

_WITHHELD_STATEMENT = "would have rested on finding no match in a capped input"
_PLAN_ITEM_CAP = 1000
_PLAN_ITEMS_IN_SCOPE = 4200
_PLAN_ITEMS_MISSING = _PLAN_ITEMS_IN_SCOPE - _PLAN_ITEM_CAP
_PLAN_ITEM_STATEMENT = f"Evaluated {_PLAN_ITEM_CAP} of {_PLAN_ITEMS_IN_SCOPE} migration plan items"
_ASSETS_PAST_THE_OLD_BUDGET = 10_001
_FIPS = FRAMEWORK_REGISTRY[ReportFramework.FIPS_140_3]


def _plan_items(in_scope: int) -> EvaluationCoverage:
    return EvaluationCoverage(
        plan_items=InputCoverage(evaluated=min(in_scope, _PLAN_ITEM_CAP), in_scope=in_scope, limit=_PLAN_ITEM_CAP)
    )


def _complete() -> EvaluationCoverage:
    return _plan_items(_PLAN_ITEM_CAP)


def _partial() -> EvaluationCoverage:
    return _plan_items(_PLAN_ITEMS_IN_SCOPE)


def _finding(index: int) -> dict:
    return {
        "_id": f"{_SCAN}-{index}",
        "project_id": _PROJECT,
        "scan_id": _SCAN,
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": f"lib-{index}",
    }


def _evaluation_with(coverage: EvaluationCoverage):
    evaluation = _evaluation()
    evaluation.coverage = coverage
    return evaluation


def _render_report(evaluation, disclaimer: str | None = None) -> str:
    """The page the PDF renderer renders, built through its own context so the two cannot diverge."""
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    return env.get_template("base_report.html").render(**build_template_context(evaluation, _report(), disclaimer))


@pytest.mark.asyncio
async def test_the_collection_reads_every_finding_in_scope(db):
    for index in range(_POPULATION):
        doc = _finding(index)
        db.findings._docs[doc["_id"]] = doc

    engine = ComplianceReportEngine()
    clause, fields, _ = engine._finding_type_filter(CveRemediationSlaFramework())

    findings = await engine._collect_findings(db, [_SCAN], clause, fields)

    assert len(findings) == _POPULATION


@pytest.mark.asyncio
async def test_the_engine_hands_the_coverage_to_the_renderer_and_to_the_stored_report():
    report = _report()
    report.framework = ReportFramework.CVE_REMEDIATION_SLA
    inputs = _sla_input([], _partial())
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
        patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)),
        patch.object(engine, "_render", side_effect=capture_render),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        await engine.generate(report=report, db=MagicMock(), user=MagicMock(id="u1", permissions=frozenset()))

    assert rendered["coverage"] == _partial()
    assert update_status.call_args_list[-1].kwargs["coverage"] == _partial()


def test_the_partial_statement_counts_the_unread_remainder_against_the_scope():
    """A cut input has read exactly its cap, so a remainder measured against the cap is always zero."""
    assert f"the remaining {_PLAN_ITEMS_MISSING} were not read" in coverage_statement(_partial())


def test_the_complete_statement_says_the_scope_was_covered():
    assert coverage_statement(_complete()) == f"Evaluated all {_PLAN_ITEM_CAP} migration plan items in scope."


def test_the_statement_names_the_plan_items_left_out():
    statement = coverage_statement(_partial())

    assert _PLAN_ITEM_STATEMENT in statement
    assert _WITHHELD_STATEMENT in statement


def test_json_carries_the_statement_and_the_numbers():
    body, _, _ = JsonRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["plan_items"]["in_scope"] == _PLAN_ITEMS_IN_SCOPE
    assert "crypto_assets" not in payload["coverage"]
    assert _WITHHELD_STATEMENT in payload["coverage"]["statement"]


def test_csv_states_coverage_even_without_a_disclaimer():
    """The '#' header block used to be written only when a disclaimer existed."""
    body, _, _ = CsvRenderer().render(_evaluation_with(_partial()), _report())

    assert f"# Coverage: {coverage_statement(_partial())}" in body.decode()


def test_sarif_carries_the_statement_on_the_run():
    body, _, _ = SarifRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert _WITHHELD_STATEMENT in payload["runs"][0]["properties"]["coverage"]


@pytest.mark.parametrize(
    ("coverage", "expects_alarm"),
    [(_partial(), True), (_complete(), False)],
    ids=["partial-is-alarming", "complete-is-not"],
)
def test_the_pdf_cover_prints_the_coverage_banner(coverage, expects_alarm):
    """WeasyPrint's native stack is not needed to see what the page says."""
    html = _render_report(_evaluation_with(coverage))

    assert "Coverage:" in html
    assert ('class="coverage-partial"' in html) is expects_alarm


_SLA_OVERDUE_DAYS = 400
_GAP = "project 'payments' has no usable scan"


def _sla_input(findings: list[dict], coverage: EvaluationCoverage) -> EvaluationInput:
    return evaluation_input(
        resolved=ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT]),
        scope_description=f"project '{_PROJECT}'",
        findings=findings,
        scan_ids=[_SCAN],
        coverage=coverage,
    )


def _overdue_critical(*, waived: bool = False) -> dict:
    doc = _finding(0)
    doc["first_seen_at"] = datetime.now(timezone.utc) - timedelta(days=_SLA_OVERDUE_DAYS)
    if waived:
        doc["waived"] = True
        doc["waiver_reason"] = "risk accepted"
    return doc


def _by_id(evaluation) -> dict[str, ControlResult]:
    return {c.control_id: c for c in evaluation.controls}


@pytest.mark.asyncio
async def test_the_same_pass_stands_when_the_scope_was_fully_read():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _complete()))

    critical = _by_id(evaluation)["CVE-SLA-CRITICAL"]
    assert critical.status == ControlStatus.PASSED.value
    assert critical.status_reason is None


@pytest.mark.asyncio
async def test_the_summary_counts_the_withheld_verdicts():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(_GAP)))

    assert evaluation.summary["not_evaluated"] == evaluation.summary["total"]
    assert evaluation.summary["passed"] == 0


def _algorithm(name: str, primitive: CryptoPrimitive) -> CryptoAsset:
    return CryptoAsset(
        _id=f"a-{name}",
        project_id=_PROJECT,
        scan_id=_SCAN,
        bom_ref=f"ref-{name}",
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
    )


async def _fips_input(assets: list[CryptoAsset], coverage: EvaluationCoverage):
    data = _sla_input([], coverage)
    data.crypto_assets = assets
    return await _FIPS.evaluate(data)


@pytest.mark.asyncio
async def test_a_fips_failure_survives_a_scope_with_a_gap():
    evaluation = await _fips_input([_algorithm("MD5", CryptoPrimitive.HASH)], _with_gaps(_GAP))

    control = _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"]
    assert control.status == ControlStatus.FAILED.value
    assert control.status_reason is None


@pytest.mark.asyncio
async def test_the_same_fips_pass_stands_when_the_inventory_covered_the_scope():
    evaluation = await _fips_input([_algorithm("SHA-256", CryptoPrimitive.HASH)], _complete())

    assert _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"].status == ControlStatus.PASSED.value


def _rule(*, enabled: bool, match_primitive: CryptoPrimitive | None = None) -> CryptoRule:
    return CryptoRule(
        rule_id="rule-1",
        name="r",
        description="d",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        match_primitive=match_primitive,
        enabled=enabled,
        source=CryptoPolicySource.NIST_SP_800_131A,
    )


def test_a_not_applicable_decided_by_the_policy_stands_over_a_scope_with_a_gap():
    """Only the inventory-read answer is unsafe; a control whose backing rules are all disabled
    cannot change whatever the unread assets hold."""
    control = ControlDefinition(
        control_id="C1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        remediation="r",
        maps_to_rule_ids=["rule-1"],
    )
    data = _sla_input([], _with_gaps(_GAP))
    data.crypto_assets = [_algorithm("SHA-256", CryptoPrimitive.HASH)]
    data.policy_rules = [_rule(enabled=False)]

    result = default_evaluator(control, data)

    assert result.status == ControlStatus.NOT_APPLICABLE.value
    assert result.status_reason is None


def test_a_not_applicable_read_off_the_inventory_is_withheld_over_a_scope_with_a_gap():
    control = ControlDefinition(
        control_id="C1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        remediation="r",
        maps_to_rule_ids=["rule-1"],
    )
    data = _sla_input([], _with_gaps(_GAP))
    data.crypto_assets = [_algorithm("SHA-256", CryptoPrimitive.HASH)]
    data.policy_rules = [_rule(enabled=True, match_primitive=CryptoPrimitive.BLOCK_CIPHER)]

    result = default_evaluator(control, data)

    assert result.status == ControlStatus.NOT_EVALUATED.value
    assert "crypto assets" in (result.status_reason or "")


@pytest.mark.asyncio
async def test_a_crypto_control_is_evaluated_over_every_asset_past_the_old_budget(db):
    await seed_crypto_policies(db)
    await db.projects.insert_one(Project(id=_PROJECT, name=_PROJECT, latest_scan_id=_SCAN).model_dump(by_alias=True))
    scan = Scan(id=_SCAN, project_id=_PROJECT, branch="main", status=SCAN_STATUS_COMPLETED)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    for parsed in parse_cbom(cbom_of(filler_components(range(_ASSETS_PAST_THE_OLD_BUDGET)))).assets:
        doc = CryptoAsset(project_id=_PROJECT, scan_id=_SCAN, **parsed.model_dump()).model_dump(by_alias=True)
        db.crypto_assets._docs[doc["_id"]] = doc

    inputs, evaluation = await ComplianceReportEngine().evaluate(
        db, ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT]), _FIPS
    )

    assert len(inputs.crypto_assets) == _ASSETS_PAST_THE_OLD_BUDGET
    assert _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"].status == ControlStatus.PASSED.value


@pytest.mark.asyncio
async def test_sarif_reports_a_withheld_verdict_as_open_rather_than_pass():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(_GAP)))

    body, _, _ = SarifRenderer().render(evaluation, _report())
    results = json.loads(body)["runs"][0]["results"]

    assert {r["kind"] for r in results} == {"open"}
    assert all(_GAP in r["message"]["text"] for r in results)


@pytest.mark.asyncio
async def test_csv_and_json_carry_the_reason_beside_the_withheld_status():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(_GAP)))

    csv_body, _, _ = CsvRenderer().render(evaluation, _report())
    json_body, _, _ = JsonRenderer().render(evaluation, _report())

    assert "status_reason" in csv_body.decode().splitlines()[1]
    assert _GAP in csv_body.decode()
    controls = json.loads(json_body)["controls"]
    assert all(c["status"] == ControlStatus.NOT_EVALUATED.value for c in controls)
    assert all(_GAP in c["status_reason"] for c in controls)


@pytest.mark.asyncio
async def test_the_pdf_prints_the_withheld_count_and_the_per_control_reason():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(_GAP)))

    html = _render_report(evaluation)

    assert "Not Evaluated" in html
    assert 'class="status-reason"' in html
    assert "has no usable scan" in html


def _control(control_id: str, status: ControlStatus) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title=f"Control {control_id}",
        description="desc",
        status=status,
        severity=Severity.HIGH,
        remediation="fix it",
    )


def test_residual_risks_lists_the_failed_control_and_nothing_else():
    """The auditor reads this section as the outstanding exposure, so a sign flip here would
    publish the controls that passed as the ones still open."""
    results = [
        _control("c-failed", ControlStatus.FAILED),
        _control("c-passed", ControlStatus.PASSED),
        _control("c-waived", ControlStatus.WAIVED),
        _control("c-not-evaluated", ControlStatus.NOT_EVALUATED),
    ]

    risks = build_residual_risks(results)

    assert [risk.control_id for risk in risks] == ["c-failed"]


def test_a_report_over_findings_alone_states_that_it_covered_the_whole_scope():
    coverage = EvaluationCoverage()

    assert coverage.complete is True
    assert coverage_statement(coverage) == "The verdicts cover the whole scope."


def _with_gaps(*gaps: str) -> EvaluationCoverage:
    return _complete().model_copy(update={"gaps": list(gaps)})


def test_a_gap_makes_the_coverage_partial_and_the_statement_names_it_once():
    statement = coverage_statement(_with_gaps(_GAP))

    assert _with_gaps(_GAP).complete is False
    assert statement.count(_GAP) == 1
    assert _WITHHELD_STATEMENT not in statement


def test_json_carries_the_gaps():
    body, _, _ = JsonRenderer().render(_evaluation_with(_with_gaps(_GAP)), _report())

    assert json.loads(body)["coverage"]["gaps"] == [_GAP]


@pytest.mark.asyncio
async def test_a_pass_over_a_scope_with_a_gap_is_withheld_and_names_the_gap():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(_GAP)))

    critical = _by_id(evaluation)["CVE-SLA-CRITICAL"]
    assert critical.status == ControlStatus.NOT_EVALUATED.value
    assert _GAP in (critical.status_reason or "")


@pytest.mark.asyncio
async def test_a_waived_verdict_over_a_scope_with_a_gap_is_withheld():
    evaluation = await CveRemediationSlaFramework().evaluate(
        _sla_input([_overdue_critical(waived=True)], _with_gaps(_GAP))
    )

    assert _by_id(evaluation)["CVE-SLA-CRITICAL"].status == ControlStatus.NOT_EVALUATED.value


@pytest.mark.asyncio
async def test_a_failure_stands_over_a_scope_with_a_gap():
    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([_overdue_critical()], _with_gaps(_GAP)))

    assert _by_id(evaluation)["CVE-SLA-CRITICAL"].status == ControlStatus.FAILED.value


@pytest.mark.asyncio
async def test_a_long_gap_list_is_named_in_part():
    gaps = [f"project 'p{index}' has no usable scan" for index in range(7)]

    evaluation = await CveRemediationSlaFramework().evaluate(_sla_input([], _with_gaps(*gaps)))

    reason = _by_id(evaluation)["CVE-SLA-CRITICAL"].status_reason or ""
    assert gaps[4] in reason
    assert gaps[5] not in reason
    assert "and 2 more" in reason


@pytest.mark.asyncio
async def test_an_inventory_verdict_over_a_scope_with_a_gap_is_withheld():
    evaluation = await _fips_input([_algorithm("SHA-256", CryptoPrimitive.HASH)], _with_gaps(_GAP))

    control = _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"]
    assert control.status == ControlStatus.NOT_EVALUATED.value
    assert _GAP in (control.status_reason or "")


def test_the_pdf_draws_no_passed_bar_for_a_report_without_controls():
    evaluation = _evaluation()
    evaluation.controls = []
    evaluation.summary = build_summary([])

    html = _render_report(evaluation)

    assert "No controls were evaluated for this scope." in html
    assert 'class="seg passed"' not in html

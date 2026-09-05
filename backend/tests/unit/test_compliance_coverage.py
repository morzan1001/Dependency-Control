"""A compliance report may not claim a verdict it did not compute over the whole scope.

Against a live MongoDB, a project holding 20 050 findings — 50 of them criticals 400 days past
their SLA — produced a report whose CVE-SLA-CRITICAL control read `passed`, because the 50 sat
past the engine's 20 000-finding cap. The same project holding 10 001 crypto assets, the last of
them MD5, produced a FIPS-140-3 report whose hash-function control read `passed`.

A verdict whose evidence is the absence of a match is withheld as `not_evaluated` once the input
it rests on stops covering the scope; a failure stands, because a cut input can under-report a
violation but cannot invent one. Which input a verdict rests on is per control, so a truncated
finding set may not suppress a verdict read off a complete inventory, or the other way round.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    EvaluationCoverage,
    InputCoverage,
    ReportFramework,
)
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance import engine as engine_module
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks.base import EvaluationInput, default_evaluator
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework
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
_ASSET_CAP = 10000
_ASSETS_IN_SCOPE = 10001
_ASSETS_MISSING = _ASSETS_IN_SCOPE - _ASSET_CAP
_WITHHELD_STATEMENT = "would have rested on finding no match in a capped input"


def _findings_coverage(evaluated: int) -> InputCoverage:
    return InputCoverage(evaluated=evaluated, in_scope=_IN_SCOPE, limit=_EVALUATED)


def _assets_coverage(evaluated: int) -> InputCoverage:
    return InputCoverage(evaluated=evaluated, in_scope=_ASSETS_IN_SCOPE, limit=_ASSET_CAP)


def _partial() -> EvaluationCoverage:
    """The findings stop short of the scope; the inventory covers it."""
    return EvaluationCoverage(
        findings=_findings_coverage(_EVALUATED),
        crypto_assets=_assets_coverage(_ASSETS_IN_SCOPE),
    )


def _complete() -> EvaluationCoverage:
    return EvaluationCoverage(
        findings=_findings_coverage(_IN_SCOPE),
        crypto_assets=_assets_coverage(_ASSETS_IN_SCOPE),
    )


def _assets_partial() -> EvaluationCoverage:
    """The inventory stops short of the scope; the findings cover it."""
    return EvaluationCoverage(
        findings=_findings_coverage(_IN_SCOPE),
        crypto_assets=_assets_coverage(_ASSET_CAP),
    )


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


def test_the_partial_statement_names_the_verdicts_it_withholds():
    statement = coverage_statement(_partial())

    assert str(_EVALUATED) in statement
    assert str(_IN_SCOPE) in statement
    assert str(_MISSING) in statement
    assert _WITHHELD_STATEMENT in statement


def test_the_complete_statement_says_the_scope_was_covered():
    statement = coverage_statement(_complete())

    assert statement == (
        f"Evaluated all {_IN_SCOPE} findings in scope. Evaluated all {_ASSETS_IN_SCOPE} crypto assets in scope."
    )


def test_the_statement_names_whichever_input_was_capped():
    statement = coverage_statement(_assets_partial())

    assert f"Evaluated all {_IN_SCOPE} findings in scope." in statement
    assert f"Evaluated {_ASSET_CAP} of {_ASSETS_IN_SCOPE} crypto assets" in statement
    assert _WITHHELD_STATEMENT in statement


def test_json_carries_the_statement_and_the_numbers():
    body, _, _ = JsonRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["findings"]["in_scope"] == _IN_SCOPE
    assert payload["coverage"]["crypto_assets"]["in_scope"] == _ASSETS_IN_SCOPE
    assert _WITHHELD_STATEMENT in payload["coverage"]["statement"]


def test_csv_states_coverage_even_without_a_disclaimer():
    """The '#' header block used to be written only when a disclaimer existed."""
    body, _, _ = CsvRenderer().render(_evaluation_with(_partial()), _report())

    assert f"# Coverage: {coverage_statement(_partial())}" in body.decode()


def test_sarif_carries_the_statement_on_the_run():
    body, _, _ = SarifRenderer().render(_evaluation_with(_partial()), _report())
    payload = json.loads(body)

    assert _WITHHELD_STATEMENT in payload["runs"][0]["properties"]["coverage"]


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
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "not_evaluated": 1, "total": 1},
        controls=[],
        residual_risks=[],
    )

    assert "Coverage:" in html
    assert ('class="coverage-partial"' in html) is expects_alarm


_SLA_OVERDUE_DAYS = 400
_WITHHELD_REASON_FRAGMENT = "would have rested on finding no match"


def _sla_input(findings: list[dict], coverage: EvaluationCoverage) -> EvaluationInput:
    return EvaluationInput(
        resolved=ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT]),
        scope_description=f"project '{_PROJECT}'",
        crypto_assets=[],
        findings=findings,
        policy_rules=[],
        policy_version=None,
        iana_catalog_version=None,
        scan_ids=[_SCAN],
        coverage=coverage,
    )


def _overdue_critical(*, waived: bool = False) -> dict:
    doc = _finding(0)
    doc["first_seen_at"] = datetime.now(timezone.utc) - timedelta(days=_SLA_OVERDUE_DAYS)
    doc["status"] = "open"
    if waived:
        doc["waived"] = True
        doc["waiver_reason"] = "risk accepted"
    return doc


def _by_id(evaluation) -> dict[str, ControlResult]:
    return {c.control_id: c for c in evaluation.controls}


@pytest.mark.asyncio
async def test_a_pass_over_a_truncated_finding_set_is_withheld():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _partial()))

    critical = _by_id(evaluation)["CVE-SLA-CRITICAL"]
    assert critical.status == ControlStatus.NOT_EVALUATED.value
    assert _WITHHELD_REASON_FRAGMENT in (critical.status_reason or "")
    assert str(_MISSING) in (critical.status_reason or "")


@pytest.mark.asyncio
async def test_the_same_pass_stands_when_the_scope_was_fully_read():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _complete()))

    critical = _by_id(evaluation)["CVE-SLA-CRITICAL"]
    assert critical.status == ControlStatus.PASSED.value
    assert critical.status_reason is None


@pytest.mark.asyncio
async def test_a_failure_survives_truncation_because_a_cut_list_cannot_invent_a_finding():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([_overdue_critical()], _partial()))

    assert _by_id(evaluation)["CVE-SLA-CRITICAL"].status == ControlStatus.FAILED.value


@pytest.mark.asyncio
async def test_a_waived_verdict_is_withheld_because_it_rests_on_no_active_match():
    evaluation = await CveRemediationSlaFramework().evaluate_async(
        _sla_input([_overdue_critical(waived=True)], _partial())
    )

    assert _by_id(evaluation)["CVE-SLA-CRITICAL"].status == ControlStatus.NOT_EVALUATED.value


@pytest.mark.asyncio
async def test_the_summary_counts_the_withheld_verdicts():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _partial()))

    assert evaluation.summary["not_evaluated"] == evaluation.summary["total"]
    assert evaluation.summary["passed"] == 0


def test_a_verdict_read_from_the_asset_inventory_survives_a_truncated_finding_set():
    """The findings cap says nothing about the crypto assets FIPS reads, so blanket-suppressing
    every absence-backed status would claim the report skipped work it actually did."""
    asset = CryptoAsset(
        _id="a1",
        project_id=_PROJECT,
        scan_id=_SCAN,
        bom_ref="ref-a",
        name="AES",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.BLOCK_CIPHER,
    )
    data = _sla_input([], _partial())
    data.crypto_assets = [asset]

    evaluation = Fips1403Framework().evaluate(data)

    assert _by_id(evaluation)["FIPS-140-3-SYMMETRIC_CIPHERS"].status == ControlStatus.PASSED.value


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


def _fips_input(assets: list[CryptoAsset], coverage: EvaluationCoverage):
    data = _sla_input([], coverage)
    data.crypto_assets = assets
    return Fips1403Framework().evaluate(data)


def test_a_fips_pass_over_a_truncated_inventory_is_withheld():
    """The verdict rests on no disallowed algorithm being present, and a cut inventory fakes that."""
    evaluation = _fips_input([_algorithm("SHA-256", CryptoPrimitive.HASH)], _assets_partial())

    control = _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"]
    assert control.status == ControlStatus.NOT_EVALUATED.value
    assert "crypto assets" in (control.status_reason or "")
    assert str(_ASSETS_MISSING) in (control.status_reason or "")


def test_a_fips_not_applicable_over_a_truncated_inventory_is_withheld():
    evaluation = _fips_input([_algorithm("AES-256", CryptoPrimitive.BLOCK_CIPHER)], _assets_partial())

    assert _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"].status == ControlStatus.NOT_EVALUATED.value


def test_a_fips_failure_survives_a_truncated_inventory():
    evaluation = _fips_input([_algorithm("MD5", CryptoPrimitive.HASH)], _assets_partial())

    control = _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"]
    assert control.status == ControlStatus.FAILED.value
    assert control.status_reason is None


def test_the_same_fips_pass_stands_when_the_inventory_covered_the_scope():
    evaluation = _fips_input([_algorithm("SHA-256", CryptoPrimitive.HASH)], _partial())

    assert _by_id(evaluation)["FIPS-140-3-HASH_FUNCTIONS"].status == ControlStatus.PASSED.value


def _rule(*, enabled: bool, match_primitive: str | None = None) -> dict:
    return {
        "rule_id": "rule-1",
        "name": "r",
        "description": "d",
        "finding_type": FindingType.CRYPTO_WEAK_ALGORITHM.value,
        "default_severity": Severity.HIGH.value,
        "match_primitive": match_primitive,
        "enabled": enabled,
        "source": "nist-sp-800-131a",
    }


def test_a_not_applicable_decided_by_the_policy_stands_over_a_truncated_inventory():
    """Only the inventory-read answer is unsafe; a control whose backing rules are all disabled
    cannot change whatever the unread assets hold."""
    control = ControlDefinition(
        control_id="C1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        remediation="r",
        maps_to_rule_ids=["rule-1"],
        maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
    )
    data = _sla_input([], _assets_partial())
    data.crypto_assets = [_algorithm("SHA-256", CryptoPrimitive.HASH)]
    data.policy_rules = [_rule(enabled=False)]

    result = default_evaluator(control, data)

    assert result.status == ControlStatus.NOT_APPLICABLE.value
    assert result.status_reason is None


def test_a_not_applicable_read_off_the_inventory_is_withheld_over_a_truncated_one():
    control = ControlDefinition(
        control_id="C1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        remediation="r",
        maps_to_rule_ids=["rule-1"],
        maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM],
    )
    data = _sla_input([], _assets_partial())
    data.crypto_assets = [_algorithm("SHA-256", CryptoPrimitive.HASH)]
    data.policy_rules = [_rule(enabled=True, match_primitive=CryptoPrimitive.BLOCK_CIPHER.value)]

    result = default_evaluator(control, data)

    assert result.status == ControlStatus.NOT_EVALUATED.value
    assert "crypto assets" in (result.status_reason or "")


@pytest.mark.asyncio
async def test_the_asset_budget_spans_the_report_rather_than_each_scan(db, monkeypatch):
    """A global-scope report over many scans would otherwise hold the per-scan cap times the
    scan count, which bounds nothing."""
    monkeypatch.setattr(engine_module, "_CRYPTO_ASSETS_LIMIT", _CAP)
    scans = ["s1", "s2", "s3"]
    for scan in scans:
        for index in range(_POPULATION):
            doc = {
                "_id": f"{scan}-a{index}",
                "project_id": _PROJECT,
                "scan_id": scan,
                "bom_ref": f"ref-{scan}-{index}",
                "name": f"ALG-{index}",
                "asset_type": CryptoAssetType.ALGORITHM.value,
                "primitive": CryptoPrimitive.HASH.value,
            }
            db.crypto_assets._docs[doc["_id"]] = doc

    assets, in_scope = await ComplianceReportEngine()._collect_crypto_assets(db, [(_PROJECT, scan) for scan in scans])

    assert len(assets) == _CAP
    assert in_scope == _POPULATION * len(scans)


@pytest.mark.asyncio
async def test_an_uncapped_asset_collection_counts_what_it_read(db):
    for index in range(_POPULATION):
        doc = {
            "_id": f"a{index}",
            "project_id": _PROJECT,
            "scan_id": _SCAN,
            "bom_ref": f"ref-{index}",
            "name": f"ALG-{index}",
            "asset_type": CryptoAssetType.ALGORITHM.value,
            "primitive": CryptoPrimitive.HASH.value,
        }
        db.crypto_assets._docs[doc["_id"]] = doc

    assets, in_scope = await ComplianceReportEngine()._collect_crypto_assets(db, [(_PROJECT, _SCAN)])

    assert len(assets) == _POPULATION
    assert in_scope == _POPULATION


@pytest.mark.asyncio
async def test_sarif_reports_a_withheld_verdict_as_open_rather_than_pass():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _partial()))
    evaluation.coverage = _partial()

    body, _, _ = SarifRenderer().render(evaluation, _report())
    results = json.loads(body)["runs"][0]["results"]

    assert {r["kind"] for r in results} == {"open"}
    assert all(_WITHHELD_REASON_FRAGMENT in r["message"]["text"] for r in results)


@pytest.mark.asyncio
async def test_csv_and_json_carry_the_reason_beside_the_withheld_status():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _partial()))
    evaluation.coverage = _partial()

    csv_body, _, _ = CsvRenderer().render(evaluation, _report())
    json_body, _, _ = JsonRenderer().render(evaluation, _report())

    assert "status_reason" in csv_body.decode().splitlines()[1]
    assert _WITHHELD_REASON_FRAGMENT in csv_body.decode()
    controls = json.loads(json_body)["controls"]
    assert all(c["status"] == ControlStatus.NOT_EVALUATED.value for c in controls)
    assert all(_WITHHELD_REASON_FRAGMENT in c["status_reason"] for c in controls)


@pytest.mark.asyncio
async def test_the_pdf_prints_the_withheld_count_and_the_per_control_reason():
    evaluation = await CveRemediationSlaFramework().evaluate_async(_sla_input([], _partial()))
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    html = env.get_template("base_report.html").render(
        framework_name="CVE Remediation SLA",
        framework_version="1",
        generated_at=datetime(2026, 9, 5, tzinfo=timezone.utc).isoformat(),
        scope_description=f"project '{_PROJECT}'",
        inputs_fingerprint="sha256:abc",
        requested_by="u1",
        disclaimer=None,
        coverage_statement=coverage_statement(_partial()),
        coverage_complete=False,
        summary=evaluation.summary,
        controls=[
            {
                "control_id": c.control_id,
                "title": c.title,
                "description": c.description,
                "status": c.status,
                "severity": c.severity,
                "evidence_finding_ids": [],
                "evidence_asset_bom_refs": [],
                "waiver_reasons": [],
                "remediation": c.remediation,
                "status_reason": c.status_reason,
            }
            for c in evaluation.controls
        ],
        residual_risks=[],
    )

    assert "Not Evaluated" in html
    assert 'class="status-reason"' in html
    assert _WITHHELD_REASON_FRAGMENT in html

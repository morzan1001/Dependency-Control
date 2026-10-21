"""A crypto finding names the asset it flags, so a control's evidence count counts the two once."""

import csv
import re

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.models.crypto_asset import CryptoAssetType, CryptoPrimitive
from app.services.compliance.frameworks.base import ControlDefinition
from app.schemas.compliance import ControlResult
from app.models.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.compliance.frameworks.base import default_evaluator
from app.services.compliance.renderers.csv_renderer import CsvRenderer
from app.services.compliance.renderers.pdf_renderer import report_html
from tests.helpers.compliance import evaluation_input
from tests.unit.test_renderer_json import _evaluation, _report

_RSA_RULE = CryptoRule(
    rule_id="nist-131a-rsa-min-2048",
    name="RSA keys shorter than 2048 bits are disallowed",
    description="",
    finding_type=FindingType.CRYPTO_WEAK_KEY,
    default_severity=Severity.HIGH,
    source=CryptoPolicySource.NIST_SP_800_131A,
    match_name_patterns=["RSA"],
    match_primitive=CryptoPrimitive.PKE,
    match_min_key_size_bits=2048,
)
_RSA_CONTROL = ControlDefinition(
    control_id="NIST-131A-rsa-min-2048",
    title="RSA keys >= 2048 bits",
    description="",
    severity=Severity.HIGH,
    remediation="",
    maps_to_rule_ids=[_RSA_RULE.rule_id],
)
_PDF_EVIDENCE_CELL = re.compile(r'<td class="severity">[^<]*</td>\s*<td>([^<]*)</td>')


def _weak_rsa_control() -> ControlResult:
    weak = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref="rsa-1024",
        name="RSA",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.PKE,
        key_size_bits=1024,
    )
    (finding,) = crypto_findings_for_assets([weak], [_RSA_RULE], scanner="crypto_weak_key")
    data = evaluation_input(
        crypto_assets=[weak],
        findings=[finding | {"_id": "f1", "finding_id": finding["id"], "scan_id": weak.scan_id}],
        policy_rules=[_RSA_RULE],
    )
    return default_evaluator(_RSA_CONTROL, data)


def _with_evidence(finding_ids: list[str], asset_bom_refs: list[str]) -> ControlResult:
    evidence = {"evidence_finding_ids": finding_ids, "evidence_asset_bom_refs": asset_bom_refs}
    return _evaluation().controls[0].model_copy(update=evidence)


def _csv_count(control: ControlResult) -> str:
    evaluation = _evaluation()
    evaluation.controls = [control]
    body = CsvRenderer().render(evaluation, _report()).decode("utf-8-sig")
    (row,) = csv.DictReader(line for line in body.splitlines() if not line.startswith("#"))
    return row["evidence_count"]


def _pdf_count(control: ControlResult) -> str:
    evaluation = _evaluation()
    evaluation.controls = [control]
    (cell,) = _PDF_EVIDENCE_CELL.findall(report_html(evaluation, _report()))
    return cell.strip()


_RENDERERS = [pytest.param(_csv_count, id="csv"), pytest.param(_pdf_count, id="pdf")]


@pytest.mark.parametrize("count", _RENDERERS)
def test_a_crypto_finding_and_the_asset_it_flags_count_once(count):
    control = _weak_rsa_control()
    assert (control.evidence_finding_ids, control.evidence_asset_bom_refs) == (
        ["CRYPTO-crypto_weak_key-rsa-1024"],
        ["rsa-1024"],
    )

    assert count(control) == "1"


@pytest.mark.parametrize("count", _RENDERERS)
@pytest.mark.parametrize(
    ("finding_ids", "asset_bom_refs", "expected"),
    [
        pytest.param([], ["a1", "a2"], "2", id="assets-only-as-the-migration-plan-emits"),
        pytest.param(["f1", "f2"], [], "2", id="findings-only-as-the-cve-and-license-audits-emit"),
        pytest.param(["f1"], ["a1", "a2", "a3"], "3", id="disallowed-assets-carrying-no-finding-still-count"),
        pytest.param(["f1", "f2"], ["a1"], "2", id="one-bom-ref-flagged-in-two-scans"),
    ],
)
def test_the_evidence_count_is_the_longer_of_the_two_lists(count, finding_ids, asset_bom_refs, expected):
    assert count(_with_evidence(finding_ids, asset_bom_refs)) == expected


@pytest.mark.asyncio
async def test_the_evidence_names_each_finding_by_the_id_it_keeps_across_scans():
    """A stored record's _id is minted per scan, so only the finding id lets an auditor look the finding up."""
    from datetime import datetime, timezone

    from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework

    overdue = {
        "finding_id": "log4j-core:2.14.1",
        "type": "vulnerability",
        "severity": "CRITICAL",
        "waived": False,
        "first_seen_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "details": {"vulnerabilities": [{"id": "CVE-2021-44228", "severity": "CRITICAL"}]},
    }
    findings = [
        overdue | {"_id": "uuid5-of-scan-1", "scan_id": "s1"},
        overdue | {"_id": "uuid5-of-scan-2", "scan_id": "s2"},
    ]

    evaluation = await CveRemediationSlaFramework().evaluate(evaluation_input(findings=findings, scan_ids=["s1", "s2"]))

    critical = next(c for c in evaluation.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.evidence_finding_ids == ["log4j-core:2.14.1", "log4j-core:2.14.1"]
    assert critical.evidence_count == 2

"""Unit tests for LicenseAuditFramework."""

import pytest

from app.schemas.project import LicensePolicySchema
from app.services.compliance.frameworks.license_audit import LicenseAuditFramework
from tests.helpers.analyzers import analyze_cyclonedx
from tests.helpers.compliance import evaluation_input


def _eval_input(findings=None, policy=None):
    return evaluation_input(findings=findings or [], license_policy=LicensePolicySchema(**(policy or {})))


@pytest.mark.asyncio
async def test_no_findings_all_controls_pass():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False, "allow_network_copyleft": False}
    result = await fw.evaluate(_eval_input(findings=[], policy=policy))
    assert result.summary["failed"] == 0
    assert result.summary["total"] == 5


@pytest.mark.asyncio
async def test_strong_copyleft_violation_fails():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False, "allow_network_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license": "GPL-3.0-only", "category": "strong_copyleft"},
            "waived": False,
        }
    ]
    result = await fw.evaluate(_eval_input(findings=findings, policy=policy))
    failed = [c for c in result.controls if c.status == "failed"]
    assert any(c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT" for c in failed)


@pytest.mark.asyncio
async def test_allowed_category_is_not_applicable():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": True, "allow_network_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license": "GPL-3.0-only", "category": "strong_copyleft"},
            "waived": False,
        }
    ]
    result = await fw.evaluate(_eval_input(findings=findings, policy=policy))
    strong_ctrl = next(c for c in result.controls if c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT")
    assert strong_ctrl.status == "not_applicable"


@pytest.mark.asyncio
async def test_network_copyleft_violation_fails():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False, "allow_network_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license": "AGPL-3.0-only", "category": "network_copyleft"},
            "waived": False,
        }
    ]
    result = await fw.evaluate(_eval_input(findings=findings, policy=policy))
    failed = [c for c in result.controls if c.status == "failed"]
    assert any(c.control_id == "LICENSE-AUDIT-NETWORK-COPYLEFT" for c in failed)


@pytest.mark.asyncio
async def test_unknown_license_fails_identified_control():
    fw = LicenseAuditFramework()
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license": "UNKNOWN", "category": "unknown"},
            "waived": False,
        }
    ]
    result = await fw.evaluate(_eval_input(findings=findings, policy={}))
    ctrl = next(c for c in result.controls if c.control_id == "LICENSE-AUDIT-LICENSE-IDENTIFIED")
    assert ctrl.status == "failed"
    assert ctrl.evidence_finding_ids == ["f1"]


@pytest.mark.asyncio
async def test_waived_finding_produces_waived_control():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license": "GPL-3.0-only", "category": "strong_copyleft"},
            "waived": True,
            "waiver_reason": "accepted risk",
        },
        {
            "_id": "f2",
            "type": "license",
            "details": {"license": "GPL-2.0-only", "category": "strong_copyleft"},
            "waived": True,
            "waiver_reason": None,
        },
    ]
    result = await fw.evaluate(_eval_input(findings=findings, policy=policy))
    strong_ctrl = next(c for c in result.controls if c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT")
    assert strong_ctrl.status == "waived"
    assert strong_ctrl.waiver_reasons == ["accepted risk"]


@pytest.mark.asyncio
async def test_analyzer_output_reaches_the_identified_control():
    """The analyzer counts unlicensed components; the control has to see them as findings."""
    from app.services.aggregation import ResultAggregator
    from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
    from app.services.normalizers.license import normalize_license

    components = [
        {"type": "library", "name": "mit-lib", "version": "1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "undeclared-lib", "version": "2.0.0"},
    ]
    result = await analyze_cyclonedx(LicenseAnalyzer(), components)
    assert result["summary"]["unknown"] == 1

    aggregator = ResultAggregator()
    normalize_license(aggregator, result, source="sbom.json")
    findings = [f.model_dump() | {"_id": f.id} for f in aggregator.get_findings()]

    evaluation = await LicenseAuditFramework().evaluate(_eval_input(findings=findings, policy={}))
    ctrl = next(c for c in evaluation.controls if c.control_id == "LICENSE-AUDIT-LICENSE-IDENTIFIED")
    assert ctrl.status == "failed"
    assert len(ctrl.evidence_finding_ids) == 1


_RESTRICTED_LICENSES = [
    {"type": "library", "name": "nc-lib", "version": "1.0.0", "licenses": [{"license": {"id": "CC-BY-NC-4.0"}}]},
    {"type": "library", "name": "gpl2-lib", "version": "1.0.0", "licenses": [{"license": {"id": "GPL-2.0-only"}}]},
    {"type": "library", "name": "gpl3-lib", "version": "1.0.0", "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
    {"type": "library", "name": "agpl-lib", "version": "1.0.0", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
]


async def _analyzer_statuses(policy: dict) -> dict[str, str]:
    from app.services.aggregation import ResultAggregator
    from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
    from app.services.normalizers.license import normalize_license

    result = await analyze_cyclonedx(LicenseAnalyzer(), _RESTRICTED_LICENSES, policy)
    aggregator = ResultAggregator()
    normalize_license(aggregator, result, source="sbom.json")
    findings = [f.model_dump() | {"_id": f.id} for f in aggregator.get_findings()]

    evaluation = await LicenseAuditFramework().evaluate(_eval_input(findings=findings, policy=policy))
    return {c.control_id: c.status for c in evaluation.controls}


@pytest.mark.asyncio
async def test_a_non_commercial_license_fails_the_proprietary_control():
    statuses = await _analyzer_statuses({})

    assert statuses["LICENSE-AUDIT-NO-PROPRIETARY"] == "failed"


@pytest.mark.asyncio
async def test_a_gpl2_and_gpl3_conflict_fails_the_compatibility_control():
    statuses = await _analyzer_statuses({})

    assert statuses["LICENSE-AUDIT-LICENSE-COMPATIBILITY"] == "failed"


@pytest.mark.asyncio
async def test_internal_only_distribution_skips_the_compatibility_control_but_not_the_proprietary_one():
    """A conflict binds only a distributed work, while non-commercial terms bind every use."""
    statuses = await _analyzer_statuses({"distribution_model": "internal_only"})

    assert statuses["LICENSE-AUDIT-LICENSE-COMPATIBILITY"] == "not_applicable"
    assert statuses["LICENSE-AUDIT-NO-PROPRIETARY"] == "failed"


@pytest.mark.asyncio
async def test_an_open_source_project_passes_the_strong_copyleft_control():
    """The analyzer downgrades GPL to INFO for an open-source project; the audit must not fail it."""
    statuses = await _analyzer_statuses({"distribution_model": "open_source"})

    assert statuses["LICENSE-AUDIT-STRONG-COPYLEFT"] == "passed"


@pytest.mark.asyncio
@pytest.mark.parametrize(("distribution_model", "status"), [("internal_only", "failed"), ("open_source", "passed")])
async def test_network_copyleft_counts_at_medium_and_not_at_info(distribution_model, status):
    """The analyzer rates AGPL MEDIUM in an internal service and INFO in an open-source project."""
    statuses = await _analyzer_statuses({"distribution_model": distribution_model})

    assert statuses["LICENSE-AUDIT-NETWORK-COPYLEFT"] == status

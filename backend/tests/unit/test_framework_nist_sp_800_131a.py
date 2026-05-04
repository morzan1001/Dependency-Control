from app.schemas.compliance import (
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.nist_sp_800_131a import (
    NistSp800_131aFramework,
)
from app.services.compliance.frameworks.base import EvaluationInput


def _eval_input(findings=None, assets=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user 'alice'",
        crypto_assets=assets or [],
        findings=findings or [],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_framework_identity():
    fw = NistSp800_131aFramework()
    assert fw.key == ReportFramework.NIST_SP_800_131A
    assert fw.name.startswith("NIST SP 800-131A")
    assert fw.version
    assert "csrc.nist.gov" in fw.source_url
    assert len(fw.controls) >= 5  # at least 5 seed rules exist in Phase-1 yaml


def test_passing_evaluation_with_no_findings():
    fw = NistSp800_131aFramework()
    result = fw.evaluate(
        _eval_input(
            findings=[],
            assets=[
                # Give at least one asset so controls aren't ALL not_applicable
                {"name": "AES", "asset_type": "algorithm"},
            ],
        )
    )
    assert isinstance(result, FrameworkEvaluation)
    # No findings -> no control failed
    assert result.summary["failed"] == 0


def test_failing_control_on_md5_finding():
    fw = NistSp800_131aFramework()
    findings = [
        {
            "_id": "f1",
            "type": "crypto_weak_algorithm",
            "details": {"rule_id": "nist-131a-md5", "bom_ref": "algo-1"},
            "waived": False,
        }
    ]
    assets = [{"name": "MD5", "asset_type": "algorithm"}]
    result = fw.evaluate(_eval_input(findings=findings, assets=assets))
    failed_controls = [
        c for c in result.controls if c.status == ControlStatus.FAILED.value or c.status == ControlStatus.FAILED
    ]
    assert len(failed_controls) >= 1
    # Control referencing rule_id nist-131a-md5 is failed
    md5_control = next(
        c for c in result.controls if "md5" in c.control_id.lower() or "nist-131a-md5" in c.description.lower()
    )
    assert md5_control.status == "failed" or md5_control.status == ControlStatus.FAILED


def test_waived_finding_produces_waived_control():
    fw = NistSp800_131aFramework()
    findings = [
        {
            "_id": "f1",
            "type": "crypto_weak_algorithm",
            "details": {"rule_id": "nist-131a-md5"},
            "waived": True,
            "waiver_reason": "accepted risk",
        }
    ]
    assets = [{"name": "MD5", "asset_type": "algorithm"}]
    result = fw.evaluate(_eval_input(findings=findings, assets=assets))
    md5_control = next(
        c for c in result.controls if "nist-131a-md5" in c.description.lower() or "md5" in c.title.lower()
    )
    assert md5_control.status == "waived"


def test_summary_counts_add_up_to_total():
    fw = NistSp800_131aFramework()
    result = fw.evaluate(_eval_input())
    s = result.summary
    assert s["passed"] + s["failed"] + s["waived"] + s["not_applicable"] == s["total"]

from app.schemas.compliance import ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.bsi_tr_02102 import BsiTr02102Framework


def _input():
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user scope",
        crypto_assets=[], findings=[], policy_rules=[],
        policy_version=1, iana_catalog_version=1, scan_ids=["s1"],
    )


def test_bsi_framework_identity():
    fw = BsiTr02102Framework()
    assert fw.key == ReportFramework.BSI_TR_02102
    assert "BSI TR-02102" in fw.name
    assert len(fw.controls) >= 2  # Phase-1 seed has 3 rules


def test_bsi_evaluation_runs():
    fw = BsiTr02102Framework()
    result = fw.evaluate(_input())
    assert result.framework_key == ReportFramework.BSI_TR_02102.value or result.framework_key == ReportFramework.BSI_TR_02102
    assert "total" in result.summary

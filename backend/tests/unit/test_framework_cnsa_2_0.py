from app.schemas.compliance import ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cnsa_2_0 import Cnsa20Framework


def _input():
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user scope",
        crypto_assets=[], findings=[], policy_rules=[],
        policy_version=1, iana_catalog_version=1, scan_ids=["s1"],
    )


def test_cnsa_framework_identity():
    fw = Cnsa20Framework()
    assert fw.key == ReportFramework.CNSA_2_0
    assert "CNSA" in fw.name
    assert len(fw.controls) >= 1


def test_cnsa_evaluation_runs():
    fw = Cnsa20Framework()
    result = fw.evaluate(_input())
    assert "total" in result.summary

from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework


def _eval_input(assets=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user",
        crypto_assets=assets or [],
        findings=[], policy_rules=[],
        policy_version=1, iana_catalog_version=1, scan_ids=["s1"],
    )


def test_fips_framework_identity():
    fw = Fips1403Framework()
    assert fw.key == ReportFramework.FIPS_140_3
    assert "FIPS 140-3" in fw.name
    assert fw.disclaimer and "module-level" in fw.disclaimer.lower()


def test_fips_disallowed_algorithm_fails():
    fw = Fips1403Framework()
    class A:
        name = "MD5"
        asset_type = "algorithm"
    result = fw.evaluate(_eval_input(assets=[A()]))
    disallowed_hash_control = next(
        c for c in result.controls if "hash" in c.title.lower() and ("md5" in c.description.lower() or "md5" in c.title.lower())
    )
    assert disallowed_hash_control.status == ControlStatus.FAILED.value or \
           disallowed_hash_control.status == "failed"


def test_fips_approved_algorithm_passes():
    fw = Fips1403Framework()
    class A:
        name = "AES-256"
        asset_type = "algorithm"
    result = fw.evaluate(_eval_input(assets=[A()]))
    disallowed_failed = [
        c for c in result.controls
        if "disallowed" in c.title.lower() and (c.status == "failed" or c.status == ControlStatus.FAILED.value)
    ]
    assert disallowed_failed == []


def test_fips_control_count_reasonable():
    fw = Fips1403Framework()
    # 3 disallowed-category controls (hashes, ciphers, kdfs) + 1 RSA-min-2048.
    # The previous ECDSA-APPROVED-CURVES phantom control was removed because
    # its empty rule_id filter meant it either never matched or double-counted.
    assert len(fw.controls) >= 4

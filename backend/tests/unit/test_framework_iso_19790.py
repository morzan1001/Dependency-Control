from app.schemas.compliance import ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.iso_19790 import Iso19790Framework


def _input(assets=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="u",
        crypto_assets=assets or [],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_iso_identity_and_disclaimer():
    fw = Iso19790Framework()
    assert fw.key == ReportFramework.ISO_19790
    assert "ISO/IEC 19790" in fw.name
    assert fw.disclaimer
    assert "Annex D" in fw.disclaimer


def test_iso_control_ids_rewritten():
    fw = Iso19790Framework()
    for c in fw.controls:
        assert c.control_id.startswith("ISO-19790-")
    # Mirror of FIPS controls (ECDSA phantom control removed upstream).
    assert len(fw.controls) >= 4


def test_iso_evaluation_matches_fips_behaviour():
    class A:
        name = "MD5"
        asset_type = "algorithm"

    fw = Iso19790Framework()
    result = fw.evaluate(_input(assets=[A()]))
    assert result.summary["failed"] >= 1

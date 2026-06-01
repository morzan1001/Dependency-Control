from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.services.stats import _is_signature_waiver


def _waiver(finding_type=None, match=None):
    return Waiver(reason="r", created_by="u", finding_type=finding_type, match=match)


class TestIsSignatureWaiver:
    def test_untyped_non_location_waiver_goes_legacy(self):
        # finding_type=None, no match -> must NOT be routed to the signature path (regression guard)
        assert _is_signature_waiver(_waiver(finding_type=None, match=None)) is False

    def test_typed_license_waiver_goes_legacy(self):
        assert _is_signature_waiver(_waiver(finding_type="license", match=None)) is False

    def test_location_typed_waiver_goes_signature(self):
        assert _is_signature_waiver(_waiver(finding_type="sast", match=None)) is True
        assert _is_signature_waiver(_waiver(finding_type="iac", match=None)) is True

    def test_waiver_with_match_goes_signature(self):
        sig = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fp1", anchor_kind="scanner_fp")
        assert _is_signature_waiver(_waiver(finding_type=None, match=sig)) is True

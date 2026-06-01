from app.models.finding import Finding
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.services.scan_manager import ScanManager


def _finding(anchor):
    return Finding(id="OPENGREP-r-a.py-10", type="sast", severity="HIGH", component="a.py",
                   description="d", scanners=["opengrep"],
                   match=MatchSignature(rule_key="opengrep:r", file_key="a.py", anchor=anchor,
                                        anchor_kind="scanner_fp", content_hash="c1", last_line=10))


def _waiver(anchor, status="false_positive"):
    return Waiver(reason="r", created_by="u", status=status,
                  match=MatchSignature(rule_key="opengrep:r", file_key="a.py", anchor=anchor,
                                       anchor_kind="scanner_fp", content_hash="c1", last_line=10))


class TestInMemoryStrongMatch:
    def test_exact_anchor_matches(self):
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpA"), _waiver("fpA")) is True

    def test_different_anchor_no_match(self):
        # ingest is best-effort exact-only: a moved/edited finding is NOT matched here (recalc handles it)
        assert ScanManager._finding_matches_waiver(ScanManager, _finding("fpB"), _waiver("fpA")) is False

from app.models.finding import Finding
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver


class TestMatchSignature:
    def test_minimal(self):
        sig = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor_kind="scanner_fp")
        assert sig.anchor is None
        assert sig.content_hash is None
        assert sig.last_line is None

    def test_finding_accepts_match_and_lapsed_fields(self):
        sig = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fp1", anchor_kind="scanner_fp")
        f = Finding(
            id="OPENGREP-r-a.py-10", type="sast", severity="HIGH", component="a.py",
            description="x", scanners=["opengrep"], match=sig, waiver_lapsed=True,
            lapsed_waiver_id="w1",
        )
        assert f.match.anchor == "fp1"
        assert f.waiver_lapsed is True
        assert f.lapsed_waiver_id == "w1"

    def test_finding_match_defaults_none(self):
        f = Finding(id="x", type="vulnerability", severity="LOW", component="c", description="d", scanners=["s"])
        assert f.match is None
        assert f.waiver_lapsed is False

    def test_waiver_accepts_match(self):
        sig = MatchSignature(rule_key="KICS:q", file_key="main.tf", anchor="sim1", anchor_kind="similarity_id")
        w = Waiver(reason="r", created_by="u", match=sig)
        assert w.match.anchor_kind == "similarity_id"

    def test_effective_rule_keys_falls_back_to_single_rule_key(self):
        s = MatchSignature(rule_key="bearer:X", file_key="a.py", anchor="fp",
                           anchor_kind="scanner_fp", content_hash="c", last_line=1)
        assert s.rule_keys == []
        assert s.effective_rule_keys == {"bearer:X"}

    def test_effective_rule_keys_uses_list_when_present(self):
        s = MatchSignature(rule_key="bearer:X", file_key="a.py", anchor="fp",
                           anchor_kind="scanner_fp", content_hash="c", last_line=1,
                           rule_keys=["bearer:X", "opengrep:X"])
        assert s.effective_rule_keys == {"bearer:X", "opengrep:X"}

    def test_effective_rule_keys_does_not_inject_primary_when_list_present(self):
        from app.models.match_signature import MatchSignature
        s = MatchSignature(rule_key="bearer:X", file_key="a.py", anchor="fp",
                           anchor_kind="scanner_fp", content_hash="c", last_line=1,
                           rule_keys=["opengrep:Y", "semgrep:Z"])
        assert s.effective_rule_keys == {"opengrep:Y", "semgrep:Z"}
        assert "bearer:X" not in s.effective_rule_keys

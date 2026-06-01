from app.models.match_signature import MatchSignature
from app.services.waivers.matching import waiver_strong_match


def sig(rule="OPENGREP:r", file="a.py", anchor="fp1", kind="scanner_fp", ch="c1", line=10):
    return MatchSignature(rule_key=rule, file_key=file, anchor=anchor, anchor_kind=kind,
                          content_hash=ch, last_line=line)


class TestWaiverStrongMatch:
    def test_exact_fp_false_positive(self):
        assert waiver_strong_match(sig(), sig(), "false_positive") is True

    def test_different_anchor_no_match(self):
        assert waiver_strong_match(sig(anchor="fp1"), sig(anchor="fp2"), "false_positive") is False

    def test_different_rule_or_file_no_match(self):
        assert waiver_strong_match(sig(rule="X:y"), sig(), "false_positive") is False
        assert waiver_strong_match(sig(file="b.py"), sig(), "false_positive") is False

    def test_empty_anchor_never_matches(self):
        assert waiver_strong_match(sig(anchor=None), sig(anchor=None), "false_positive") is False

    def test_content_kind_never_strong_matches(self):
        # content_hash is NOT a strong anchor; Pass-1 must reject it even if equal
        a = sig(anchor="c1", kind="content_hash")
        assert waiver_strong_match(a, a, "false_positive") is False

    def test_accepted_risk_scanner_fp_implies_content(self):
        # scanner_fp encodes content; equal fp => accepted_risk matches regardless of content_hash
        assert waiver_strong_match(sig(ch="c1"), sig(ch="c2"), "accepted_risk") is True

    def test_accepted_risk_search_key_requires_content_equal(self):
        f = sig(anchor="k", kind="search_key", ch="c1")
        w_same = sig(anchor="k", kind="search_key", ch="c1")
        w_diff = sig(anchor="k", kind="search_key", ch="c2")
        assert waiver_strong_match(f, w_same, "accepted_risk") is True
        assert waiver_strong_match(f, w_diff, "accepted_risk") is False

    def test_accepted_risk_search_key_sentinel_content_fails_closed(self):
        f = sig(anchor="k", kind="search_key", ch=None)
        w = sig(anchor="k", kind="search_key", ch=None)
        assert waiver_strong_match(f, w, "accepted_risk") is False

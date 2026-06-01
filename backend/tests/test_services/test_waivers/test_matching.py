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


from app.services.waivers.matching import apply_waivers_to_findings, MatchFinding


class _W:
    """Minimal waiver stand-in (id, status, match)."""
    def __init__(self, id, status, match):
        self.id = id
        self.status = status
        self.match = match


def mf(id, **kw):
    return MatchFinding(id=id, sig=sig(**kw))


class TestOrchestrator:
    def test_pass1_exact_waives_one(self):
        findings = [mf("f1", anchor="fpA"), mf("f2", anchor="fpB")]
        w = _W("w1", "false_positive", sig(anchor="fpA"))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        assert res.lapsed == {}

    def test_line_shift_same_content_reanchors(self):
        # finding lost its strong anchor (degraded) but content matches -> Pass 2 follow
        findings = [mf("f1", anchor="newfp", kind="scanner_fp", ch="c1", line=80)]
        w = _W("w1", "false_positive", sig(anchor="oldfp", kind="scanner_fp", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        assert "w1" in res.reanchored  # new signature captured

    def test_two_instances_one_waived_other_active(self):
        findings = [mf("f1", anchor="fpA", ch="c1"), mf("f2", anchor="fpB", ch="c1")]
        w = _W("w1", "false_positive", sig(anchor="fpA", ch="c1"))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        assert "f2" not in res.waived  # sibling stays active despite identical content

    def test_accepted_risk_content_change_lapses(self):
        findings = [mf("f1", anchor="fp2", ch="c2", line=12)]
        w = _W("w1", "accepted_risk", sig(anchor="fp1", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert res.lapsed == {"f1": "w1"}

    def test_false_positive_follows_content_change_when_unique(self):
        findings = [mf("f1", anchor="fp2", ch="c2", line=12)]
        w = _W("w1", "false_positive", sig(anchor="fp1", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}

    def test_false_positive_ambiguous_lapses(self):
        findings = [mf("f1", anchor="fpX", ch="cX", line=11), mf("f2", anchor="fpY", ch="cY", line=12)]
        w = _W("w1", "false_positive", sig(anchor="fp1", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert set(res.lapsed.values()) == {"w1"}

    def test_far_single_candidate_outside_window_lapses(self):
        findings = [mf("f1", anchor="fp2", ch="c2", line=500)]
        w = _W("w1", "false_positive", sig(anchor="fp1", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert res.lapsed == {"f1": "w1"}

    def test_degraded_anchor_fp_does_not_follow_content_change(self):
        findings = [mf("f1", anchor="c2", kind="content_hash", ch="c2", line=12)]
        w = _W("w1", "false_positive", sig(anchor="c1", kind="content_hash", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert res.lapsed == {"f1": "w1"}

    def test_finding_without_signature_ignored(self):
        findings = [MatchFinding(id="f1", sig=None)]
        w = _W("w1", "false_positive", sig())
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}

from app.models.match_signature import MatchSignature
from app.services.waivers.matching import (
    MatchFinding,
    apply_waivers_to_findings,
    waiver_strong_match,
)


def sig(rule="OPENGREP:r", file="a.py", anchor="fp1", kind="scanner_fp", ch="c1", line=10):
    return MatchSignature(
        rule_key=rule, file_key=file, anchor=anchor, anchor_kind=kind, content_hash=ch, last_line=line
    )


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


class _W:
    """Minimal waiver stand-in."""

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
        # finding lost its strong anchor but content matches -> Pass 2 follows
        findings = [mf("f1", anchor="newfp", kind="scanner_fp", ch="c1", line=80)]
        w = _W("w1", "false_positive", sig(anchor="oldfp", kind="scanner_fp", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        assert "w1" in res.reanchored

    def test_reanchor_captures_finding_line_as_distinct_copy(self):
        # reanchored sig must copy the finding's current line, not alias its sig object
        f = mf("f1", anchor="newfp", kind="scanner_fp", ch="c1", line=80)
        w = _W("w1", "false_positive", sig(anchor="oldfp", kind="scanner_fp", ch="c1", line=10))
        res = apply_waivers_to_findings([f], [w])
        new_sig = res.reanchored["w1"]
        assert new_sig.last_line == 80
        assert new_sig is not f.sig
        assert new_sig == f.sig

    def test_two_instances_one_waived_other_active(self):
        findings = [mf("f1", anchor="fpA", ch="c1"), mf("f2", anchor="fpB", ch="c1")]
        w = _W("w1", "false_positive", sig(anchor="fpA", ch="c1"))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        # sibling stays active despite identical content
        assert "f2" not in res.waived

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

    def test_finding_not_both_waived_and_lapsed(self):
        # A lapsing accepted_risk waiver and a following false_positive waiver on the same
        # candidate must never place the finding in both waived and lapsed, in either order.
        findings = [mf("f1", anchor="cur", kind="scanner_fp", ch="c1", line=20)]
        w_lapse = _W("wB", "accepted_risk", sig(anchor="old", kind="scanner_fp", ch="cX", line=10))
        w_follow = _W("wA", "false_positive", sig(anchor="old2", kind="scanner_fp", ch="c1", line=10))
        for order in ([w_lapse, w_follow], [w_follow, w_lapse]):
            res = apply_waivers_to_findings(findings, order)
            overlap = set(res.waived) & set(res.lapsed)
            assert not overlap, f"finding in both waived and lapsed for order {[w.id for w in order]}"


def test_waiver_with_no_candidates_is_recorded_dormant():
    waiver = _W("w1", "false_positive", sig(rule="bearer:r", anchor="fpA", ch="c1", line=100))
    # finding is in a different group, so the waiver binds nothing
    other = mf("f1", rule="opengrep:x", anchor="z", ch="c", line=5)
    app = apply_waivers_to_findings([other], [waiver])
    assert "f1" not in app.waived
    assert app.dormant.get("w1") == "no_candidates_in_group"
    assert app.lapsed == {}


def test_scanner_flip_waiver_matches_via_rule_key_intersection():
    # Waiver was snapshotted when both scanners detected the finding.
    waiver = _W(
        "w1",
        "false_positive",
        MatchSignature(
            rule_key="opengrep:X",
            file_key="a.py",
            anchor="fpA",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
            rule_keys=["bearer:X", "opengrep:X"],
        ),
    )
    # Re-scan carries only the bearer entry with a drifted anchor but same content_hash and file.
    finding = MatchFinding(
        id="f1",
        sig=MatchSignature(
            rule_key="bearer:X",
            file_key="a.py",
            anchor="fpB",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=12,
            rule_keys=["bearer:X"],
        ),
    )
    app = apply_waivers_to_findings([finding], [waiver])
    # rule_key sets intersect on "bearer:X" -> re-anchored
    assert app.waived.get("f1") == "w1"


def test_backcompat_single_rule_key_unchanged():
    # No rule_keys list on either side -> exact rule_key match.
    waiver = _W(
        "w1",
        "false_positive",
        MatchSignature(
            rule_key="bearer:X",
            file_key="a.py",
            anchor="fpA",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
        ),
    )
    finding = MatchFinding(
        id="f1",
        sig=MatchSignature(
            rule_key="bearer:X",
            file_key="a.py",
            anchor="fpA",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
        ),
    )
    app = apply_waivers_to_findings([finding], [waiver])
    assert app.waived.get("f1") == "w1"


def test_backcompat_pass2_reanchor_with_no_rule_keys_list():
    # Empty rule_keys falls back to {rule_key}; different anchor + same content_hash -> Pass-2 move.
    waiver = _W(
        "w1",
        "false_positive",
        MatchSignature(
            rule_key="bearer:X",
            file_key="a.py",
            anchor="fpOLD",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=10,
        ),
    )
    finding = MatchFinding(
        id="f1",
        sig=MatchSignature(
            rule_key="bearer:X",
            file_key="a.py",
            anchor="fpNEW",
            anchor_kind="scanner_fp",
            content_hash="c1",
            last_line=12,
        ),
    )
    app = apply_waivers_to_findings([finding], [waiver])
    assert app.waived.get("f1") == "w1"

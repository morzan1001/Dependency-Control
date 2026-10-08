import pytest

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
        findings = [mf("f1", anchor="newfp", kind="scanner_fp", ch="c1", line=40)]
        w = _W("w1", "false_positive", sig(anchor="oldfp", kind="scanner_fp", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {"f1": "w1"}
        assert "w1" in res.reanchored

    def test_reanchor_captures_finding_line(self):
        f = mf("f1", anchor="newfp", kind="scanner_fp", ch="c1", line=40)
        w = _W("w1", "false_positive", sig(anchor="oldfp", kind="scanner_fp", ch="c1", line=10))
        res = apply_waivers_to_findings([f], [w])
        assert res.reanchored["w1"] == f.sig

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

    def test_far_single_candidate_outside_window_stays_dormant(self):
        findings = [mf("f1", anchor="fp2", ch="c2", line=500)]
        w = _W("w1", "false_positive", sig(anchor="fp1", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert res.lapsed == {}
        assert res.dormant == {"w1": "no_candidate_in_window"}

    def test_degraded_anchor_fp_does_not_follow_content_change(self):
        findings = [mf("f1", anchor="c2", kind="content_hash", ch="c2", line=12)]
        w = _W("w1", "false_positive", sig(anchor="c1", kind="content_hash", ch="c1", line=10))
        res = apply_waivers_to_findings(findings, [w])
        assert res.waived == {}
        assert res.lapsed == {"f1": "w1"}

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


def _scan(normalize, result):
    from app.services.aggregation import ResultAggregator

    aggregator = ResultAggregator()
    normalize(aggregator, result)
    return aggregator.get_findings()


def _bearer_scan(hits):
    """One Bearer run over app/db.py; Bearer numbers a rule's hits in a file by position."""
    from app.services.normalizers.sast import normalize_bearer

    items = [
        {
            "id": "python_lang_sqli",
            "filename": "app/db.py",
            "line_number": line,
            "code_extract": code,
            "fingerprint": f"{'e' * 32}_{ordinal}",
            "severity": "high",
            "title": "SQLi",
        }
        for ordinal, (line, code) in enumerate(hits)
    ]
    return {
        f.details["sast_findings"][0]["details"]["code_extract"]: f
        for f in _scan(normalize_bearer, {"findings": items})
    }


_A, _B, _C, _NEW = "cursor.execute(q_a)", "cursor.execute(q_b)", "cursor.execute(q_c + user)", "cursor.execute(q_n)"


def _waived_codes(scan, waiver):
    app = apply_waivers_to_findings([MatchFinding(id=f.id, sig=f.match) for f in scan.values()], [waiver])
    return {code for code, f in scan.items() if f.id in app.waived}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_fixing_a_bearer_hit_above_keeps_the_waiver_on_its_own_finding(status):
    before = _bearer_scan([(10, _A), (20, _B), (30, _C)])
    waiver = _W("W", status, before[_B].match)

    after = _bearer_scan([(19, _B), (29, _C)])

    assert _waived_codes(after, waiver) == {_B}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_a_new_bearer_hit_above_does_not_take_over_the_waiver(status):
    before = _bearer_scan([(10, _A), (20, _B), (30, _C)])
    waiver = _W("W", status, before[_B].match)

    after = _bearer_scan([(5, _NEW), (11, _A), (21, _B), (31, _C)])

    assert _waived_codes(after, waiver) == {_B}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_semgrep_login_placeholder_waiver_binds_only_the_waived_line(status):
    from app.services.normalizers.sast import normalize_opengrep

    def item(line):
        return {
            "check_id": "python.lang.sqli",
            "path": "app/db.py",
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 9},
            "extra": {"severity": "ERROR", "message": "m", "fingerprint": "requires login", "lines": "requires login"},
        }

    line_10, line_50 = _scan(normalize_opengrep, {"results": [item(10), item(50)]})
    waiver = _W("W", status, line_50.match)

    app = apply_waivers_to_findings([MatchFinding(id=f.id, sig=f.match) for f in (line_10, line_50)], [waiver])

    assert app.waived == {line_50.id: "W"}


def _secret(anchor):
    return MatchSignature(
        rule_key="17", file_key="config/settings.py", anchor=anchor, anchor_kind="secret_hash", content_hash=anchor
    )


def test_a_false_positive_secret_waiver_never_moves_to_another_secret():
    app = apply_waivers_to_findings(
        [MatchFinding(id="F-real", sig=_secret("bbbb2222"))], [_W("W", "false_positive", _secret("aaaa1111"))]
    )

    assert app.waived == {}
    assert app.reanchored == {}
    assert app.lapsed == {}
    assert "W" in app.dormant


def test_a_lone_candidate_without_a_known_line_does_not_bind():
    finding = mf("f1", anchor="fp2", ch="c2", line=None)
    app = apply_waivers_to_findings([finding], [_W("w1", "false_positive", sig(anchor="fp1", ch="c1", line=None))])

    assert app.waived == {}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_a_content_anchored_waiver_follows_its_lone_code_at_any_distance(status):
    finding = mf("f1", anchor="c1", kind="content_hash", ch="c1", line=400)
    app = apply_waivers_to_findings(
        [finding], [_W("w1", status, sig(anchor="c1", kind="content_hash", ch="c1", line=10))]
    )

    assert app.waived == {"f1": "w1"}
    assert app.reanchored == {"w1": finding.sig}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_a_bearer_waiver_follows_its_finding_past_a_large_insertion_above(status):
    before = _bearer_scan([(10, _A), (20, _B), (30, _C)])
    waiver = _W("W", status, before[_B].match)

    after = _bearer_scan([(10, _A), (90, _B), (100, _C)])

    assert _waived_codes(after, waiver) == {_B}


def _kics(anchor, line, ch="acl"):
    return sig(rule="KICS:q1", file="main.tf", anchor=anchor, kind="similarity_id", ch=ch, line=line)


@pytest.mark.parametrize("line", [12, 400])
def test_an_accepted_risk_iac_waiver_does_not_move_to_another_resource_with_the_same_message(line):
    other = MatchFinding(id="private_data", sig=_kics("simB", line))
    app = apply_waivers_to_findings([other], [_W("W", "accepted_risk", _kics("simA", 10))])

    assert app.waived == {}
    assert app.reanchored == {}


def test_a_false_positive_iac_waiver_follows_its_renamed_resource_only_nearby():
    near = apply_waivers_to_findings(
        [MatchFinding(id="r", sig=_kics("simB", 12))], [_W("W", "false_positive", _kics("simA", 10))]
    )
    far = apply_waivers_to_findings(
        [MatchFinding(id="r", sig=_kics("simB", 400))], [_W("W", "false_positive", _kics("simA", 10))]
    )

    assert near.waived == {"r": "W"}
    assert far.waived == {}


def test_a_duplicate_waiver_is_shadowed_instead_of_moving_to_a_neighbour():
    findings = [mf("F", anchor="fpF", ch="cF", line=10), mf("G", anchor="fpG", ch="cG", line=30)]
    waivers = [
        _W("W1", "false_positive", sig(anchor="fpF", ch="cF", line=10)),
        _W("W2", "false_positive", sig(anchor="fpF", ch="cF", line=10)),
    ]

    app = apply_waivers_to_findings(findings, waivers)

    assert app.waived == {"F": "W1"}
    assert app.reanchored == {}
    assert app.dormant == {"W2": "shadowed"}


def test_a_lapsed_waiver_next_to_its_rewaived_finding_does_not_take_a_neighbour():
    findings = [mf("F", anchor="fpF2", ch="cF2", line=10), mf("G", anchor="fpG", ch="cG", line=30)]
    rewaived = _W("W2", "false_positive", sig(anchor="fpF2", ch="cF2", line=10))
    lapsed = _W("W1", "false_positive", sig(anchor="fpF1", ch="cF1", line=10))

    app = apply_waivers_to_findings(findings, [lapsed, rewaived])

    assert app.waived == {"F": "W2"}
    assert app.dormant == {"W1": "shadowed"}


def test_a_same_content_match_wins_over_another_waivers_proximity_in_either_order():
    fb = mf("Fb", anchor="cB", kind="content_hash", ch="cB", line=20)
    w1 = _W("W1", "false_positive", sig(anchor="gone", ch="cA", line=18))
    w2 = _W("W2", "false_positive", sig(anchor="cB", kind="content_hash", ch="cB", line=21))

    for order in ([w1, w2], [w2, w1]):
        app = apply_waivers_to_findings([fb], order)
        assert app.waived == {"Fb": "W2"}
        assert "W1" in app.dormant
        assert "W1" not in app.reanchored


def test_ambiguous_same_content_lapses_instead_of_binding_a_different_finding():
    findings = [
        mf("copy80", anchor="x80", ch="cW", line=80),
        mf("copy121", anchor="x121", ch="cW", line=121),
        mf("other102", anchor="x102", ch="cO", line=102),
    ]
    app = apply_waivers_to_findings(findings, [_W("w", "false_positive", sig(anchor="gone", ch="cW", line=100))])

    assert app.waived == {}
    assert app.lapsed == {"copy80": "w"}
    assert app.reanchored == {}


def test_an_accepted_risk_waiver_far_from_any_candidate_is_dormant_not_lapsed():
    app = apply_waivers_to_findings(
        [mf("f1", anchor="fp2", ch="c2", line=400)], [_W("w1", "accepted_risk", sig(anchor="fp1", ch="c1", line=10))]
    )

    assert app.lapsed == {}
    assert "w1" in app.dormant


def test_a_pass1_match_refreshes_the_waivers_location():
    waiver = _W("w1", "false_positive", sig(anchor="fpA", ch="c1", line=100))
    app = apply_waivers_to_findings([mf("f1", anchor="fpA", ch="c2", line=300)], [waiver])

    assert app.waived == {"f1": "w1"}
    assert app.refreshed["w1"] == sig(anchor="fpA", ch="c2", line=300)


def test_an_accepted_risk_refresh_keeps_the_accepted_content():
    waiver = _W("w1", "accepted_risk", sig(anchor="fpA", ch="c1", line=100))
    app = apply_waivers_to_findings([mf("f1", anchor="fpA", ch="c2", line=300)], [waiver])

    assert app.refreshed["w1"] == sig(anchor="fpA", ch="c1", line=300)


def test_an_unmoved_waiver_records_no_signature_change():
    exact = apply_waivers_to_findings([mf("f1", anchor="fpA")], [_W("w1", "false_positive", sig(anchor="fpA"))])
    weak = sig(anchor="c1", kind="content_hash")
    content = apply_waivers_to_findings([MatchFinding(id="f1", sig=weak)], [_W("w1", "false_positive", weak)])

    assert exact.waived == content.waived == {"f1": "w1"}
    assert exact.refreshed == exact.reanchored == content.refreshed == content.reanchored == {}


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_a_content_anchored_waiver_keeps_its_unmoved_finding_beside_an_identical_snippet(status):
    """Bearer stores no fingerprint, so two identical snippets on adjacent lines share their content anchor."""
    findings = [
        mf("f10", rule="BEARER:rule_x", anchor="cLog", kind="content_hash", ch="cLog", line=10),
        mf("f11", rule="BEARER:rule_x", anchor="cLog", kind="content_hash", ch="cLog", line=11),
    ]
    waiver = _W("w", status, sig(rule="BEARER:rule_x", anchor="cLog", kind="content_hash", ch="cLog", line=10))

    app = apply_waivers_to_findings(findings, [waiver])

    assert (app.waived, app.lapsed) == ({"f10": "w"}, {})

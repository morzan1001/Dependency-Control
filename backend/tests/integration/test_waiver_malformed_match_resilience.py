"""A malformed stored `match` dict for one waiver/finding is logged and skipped; well-formed waivers still apply during recalc."""

import pytest

from app.models.match_signature import MatchSignature
from app.services.stats import _apply_waivers_signature


def _finding_doc(scan_id, fid, anchor, ch, line, rule="OPENGREP:r", file="a.py", match=None):
    if match is None:
        match = MatchSignature(
            rule_key=rule,
            file_key=file,
            anchor=anchor,
            anchor_kind="scanner_fp",
            content_hash=ch,
            last_line=line,
        ).model_dump()
    return {
        "_id": fid,
        "scan_id": scan_id,
        "finding_id": fid,
        "type": "sast",
        "component": file,
        "severity": "HIGH",
        "description": "d",
        "waived": False,
        "match": match,
    }


class _Repo:
    def __init__(self, docs):
        self.docs = {d["_id"]: d for d in docs}
        self.waived = {}
        self.lapsed = {}

    async def find_location_findings(self, scan_id):
        return list(self.docs.values())

    async def set_waived(self, scan_id, finding_ids, reason):
        for fid in finding_ids:
            self.waived[fid] = reason

    async def set_lapsed(self, scan_id, mapping):
        self.lapsed.update(mapping)


class _WRepo:
    def __init__(self):
        self.updates = {}

    async def update(self, wid, data):
        self.updates[wid] = data


class _Waiver:
    def __init__(self, id, status, match, finding_id=None):
        self.id = id
        self.status = status
        self.match = match
        self.finding_id = finding_id


@pytest.mark.asyncio
async def test_malformed_waiver_match_dict_is_skipped_others_applied():
    scan = "s1"
    repo = _Repo(
        [
            _finding_doc(scan, "f1", "fpA", "c1", 10),
            _finding_doc(scan, "f2", "fpB", "c2", 20),
        ]
    )
    wrepo = _WRepo()

    # w_bad carries a malformed stored match dict (invalid anchor_kind => ValidationError).
    w_bad = _Waiver("w_bad", "false_positive", {"rule_key": "OPENGREP:r", "anchor_kind": "NOT_A_KIND"})
    # w_good is a well-formed waiver targeting f2.
    w_good = _Waiver(
        "w_good",
        "false_positive",
        MatchSignature(
            rule_key="OPENGREP:r",
            file_key="a.py",
            anchor="fpB",
            anchor_kind="scanner_fp",
            content_hash="c2",
            last_line=20,
        ),
    )

    # Must NOT raise; the malformed one is skipped, the good one is applied.
    await _apply_waivers_signature(repo, wrepo, scan, [w_bad, w_good])

    assert "f2" in repo.waived
    assert repo.waived.get("f2") is not None or "f2" in repo.waived


@pytest.mark.asyncio
async def test_malformed_finding_match_dict_is_skipped_recalc_completes():
    scan = "s1"
    # f_bad has a malformed stored match dict; f_good is well-formed.
    repo = _Repo(
        [
            _finding_doc(scan, "f_bad", "x", "x", 1, match={"rule_key": "r", "anchor_kind": "bogus"}),
            _finding_doc(scan, "f_good", "fpB", "c2", 20),
        ]
    )
    wrepo = _WRepo()
    w_good = _Waiver(
        "w_good",
        "false_positive",
        MatchSignature(
            rule_key="OPENGREP:r",
            file_key="a.py",
            anchor="fpB",
            anchor_kind="scanner_fp",
            content_hash="c2",
            last_line=20,
        ),
    )

    # Must NOT raise despite the malformed finding match; f_good still matched + waived.
    await _apply_waivers_signature(repo, wrepo, scan, [w_good])

    assert "f_good" in repo.waived

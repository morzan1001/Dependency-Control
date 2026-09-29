"""A malformed stored `match` dict on one finding is logged and skipped; the other findings are still matched during recalc."""

import pytest

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
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


def _Waiver(id, status, match):
    return Waiver(id=id, status=status, match=match, reason=f"reason {id}", created_by="u")


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

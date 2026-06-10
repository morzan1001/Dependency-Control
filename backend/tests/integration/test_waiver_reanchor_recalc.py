"""Recalc applies waivers via signature matching, follows line shifts, lapses on content change."""
import pytest

from app.models.match_signature import MatchSignature
from app.services.stats import _apply_waivers_signature  # new orchestrated entry point


def _finding_doc(scan_id, fid, anchor, ch, line, rule="OPENGREP:r", file="a.py"):
    return {
        "_id": fid, "scan_id": scan_id, "finding_id": fid, "type": "sast", "component": file,
        "severity": "HIGH", "description": "d", "waived": False,
        "match": MatchSignature(rule_key=rule, file_key=file, anchor=anchor,
                                anchor_kind="scanner_fp", content_hash=ch, last_line=line).model_dump(),
    }


class _Repo:
    """Minimal in-memory finding repo capturing waive writes."""
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
    def __init__(self, updates=None):
        self.updates = updates if updates is not None else {}
    async def update(self, wid, data):
        self.updates[wid] = data


class _Waiver:
    def __init__(self, id, status, match):
        self.id = id
        self.status = status
        self.match = match


@pytest.mark.asyncio
async def test_line_shift_keeps_waived():
    scan = "s1"
    repo = _Repo([_finding_doc(scan, "f1", "fpA", "c1", 80)])
    wrepo = _WRepo()
    w = _Waiver("w1", "false_positive",
                MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fpA",
                               anchor_kind="scanner_fp", content_hash="c1", last_line=10))
    await _apply_waivers_signature(repo, wrepo, scan, [w])
    assert "f1" in repo.waived


@pytest.mark.asyncio
async def test_content_change_accepted_risk_lapses():
    scan = "s1"
    repo = _Repo([_finding_doc(scan, "f1", "fpZ", "c2", 12)])
    wrepo = _WRepo()
    w = _Waiver("w1", "accepted_risk",
                MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fpA",
                               anchor_kind="scanner_fp", content_hash="c1", last_line=10))
    await _apply_waivers_signature(repo, wrepo, scan, [w])
    assert "f1" not in repo.waived
    assert repo.lapsed.get("f1") == "w1"


def _finding_doc_no_match(scan_id, fid, finding_id, fingerprint, line, file="a.py"):
    """A location finding doc with NO stored `match` but with the merged SAST details."""
    return {
        "_id": fid, "scan_id": scan_id, "finding_id": finding_id, "type": "sast",
        "component": file, "severity": "HIGH", "description": "d", "waived": False,
        "details": {
            "line": line,
            "sast_findings": [
                {"scanner": "bearer", "id": "java_lang_hardcoded_secret",
                 "details": {"fingerprint": fingerprint, "code_extract": "X=\"s\"", "start": {"line": line}}},
            ],
        },
    }


@pytest.mark.asyncio
async def test_self_heals_finding_without_persisted_match():
    scan = "s1"
    # Re-scanned finding drifted to line 94 and (the bug) has NO stored match signature.
    repo = _Repo([_finding_doc_no_match(scan, "f94", "BEARER-r-a.py-94", "fpNEW_2", 94)])
    wrepo = _WRepo()
    # Waiver anchored at the old line 100 with a (now stale) strong anchor.
    w = _Waiver("w1", "false_positive",
                MatchSignature(rule_key="bearer:java_lang_hardcoded_secret", file_key="a.py",
                               anchor="fpOLD_2", anchor_kind="scanner_fp", content_hash="c1", last_line=100))
    await _apply_waivers_signature(repo, wrepo, scan, [w])
    assert "f94" in repo.waived          # recovered: recomputed sig made it a Pass-2 candidate
    assert "w1" in wrepo.updates          # re-anchored signature persisted


@pytest.mark.asyncio
async def test_backfill_waiver_without_match_from_current_finding():
    scan = "s1"
    repo = _Repo([_finding_doc(scan, "f1", "fpA", "c1", 10)])
    wrepo = _WRepo()
    # legacy waiver: no match signature, only legacy finding_id equal to the finding
    w = _Waiver("w1", "false_positive", None)
    w.finding_id = "f1"
    await _apply_waivers_signature(repo, wrepo, scan, [w])
    assert "f1" in repo.waived
    assert "w1" in wrepo.updates  # signature back-filled and persisted

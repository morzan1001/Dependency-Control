"""How _apply_waivers_signature back-fills, hydrates and reports waivers against one scan's location findings."""

import logging

import pytest

from app.models.match_signature import MatchSignature
from app.services.stats import _apply_waivers_signature

_SCAN = "s1"


def _sig(anchor: str, content_hash: str = "c", rule: str = "OPENGREP:r", file: str = "a.py") -> MatchSignature:
    return MatchSignature(
        rule_key=rule, file_key=file, anchor=anchor, anchor_kind="scanner_fp", content_hash=content_hash, last_line=10
    )


def _doc(fid: str, match: dict | None) -> dict:
    return {"_id": fid, "scan_id": _SCAN, "finding_id": fid, "type": "sast", "component": "a.py", "match": match}


class _FindingRepo:
    def __init__(self, docs):
        self.docs = docs
        self.waived: dict[str, str | None] = {}

    async def find_location_findings(self, scan_id):
        return self.docs

    async def set_waived(self, scan_id, finding_ids, reason):
        for fid in finding_ids:
            self.waived[fid] = reason

    async def set_lapsed(self, scan_id, mapping):
        raise AssertionError("no finding is expected to lapse")


class _WaiverRepo:
    def __init__(self):
        self.updates: list[tuple[str, dict]] = []

    async def update(self, wid, data):
        self.updates.append((wid, data))


class _Waiver:
    def __init__(self, id, match, finding_id=None):
        self.id = id
        self.status = "false_positive"
        self.reason = f"reason {id}"
        self.match = match
        self.finding_id = finding_id


@pytest.mark.asyncio
async def test_a_legacy_waiver_naming_no_finding_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="absent")
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(_FindingRepo([_doc("f1", _sig("fpA").model_dump())]), waiver_repo, _SCAN, [waiver])

    assert waiver.match is None
    assert waiver_repo.updates == [("w", {"last_eval_scan_id": _SCAN, "last_match_count": 0})]


@pytest.mark.asyncio
async def test_a_legacy_waiver_whose_finding_has_no_stored_signature_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="f1")
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(_FindingRepo([_doc("f1", None)]), waiver_repo, _SCAN, [waiver])

    assert waiver.match is None
    assert waiver_repo.updates == [("w", {"last_eval_scan_id": _SCAN, "last_match_count": 0})]


@pytest.mark.asyncio
async def test_a_legacy_waiver_whose_finding_has_a_malformed_signature_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="f1")
    waiver_repo = _WaiverRepo()
    malformed = {"rule_key": "OPENGREP:r", "anchor_kind": "NOT_A_KIND"}

    await _apply_waivers_signature(_FindingRepo([_doc("f1", malformed)]), waiver_repo, _SCAN, [waiver])

    assert waiver.match is None
    assert waiver_repo.updates == [("w", {"last_eval_scan_id": _SCAN, "last_match_count": 0})]


@pytest.mark.asyncio
async def test_a_waiver_signature_stored_as_a_dict_is_hydrated_and_applied():
    waiver = _Waiver("w", match=_sig("fpA").model_dump())
    finding_repo = _FindingRepo([_doc("f1", _sig("fpA").model_dump())])
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(finding_repo, waiver_repo, _SCAN, [waiver])

    assert waiver.match == _sig("fpA")
    assert finding_repo.waived == {"f1": "reason w"}
    assert waiver_repo.updates == [("w", {"last_eval_scan_id": _SCAN, "last_match_count": 1})]


@pytest.mark.asyncio
async def test_a_dormant_waiver_logs_the_signed_findings_of_its_group_only(caplog):
    claimer = _Waiver("w-claimer", match=_sig("fpA", content_hash="c1"))
    dormant = _Waiver("w-dormant", match=_sig("gone", content_hash="c2"))
    docs = [_doc("f1", _sig("fpA", content_hash="c1").model_dump()), _doc("unsigned", None)]

    with caplog.at_level(logging.WARNING, logger="app.services.stats"):
        await _apply_waivers_signature(_FindingRepo(docs), _WaiverRepo(), _SCAN, [claimer, dormant])

    dormant_logs = [r.getMessage() for r in caplog.records if r.getMessage().startswith("waiver dormant")]
    assert len(dormant_logs) == 1
    assert "waiver=w-dormant" in dormant_logs[0]
    assert "reason=no_candidates_in_group" in dormant_logs[0]
    assert dormant_logs[0].endswith("group_findings=1")

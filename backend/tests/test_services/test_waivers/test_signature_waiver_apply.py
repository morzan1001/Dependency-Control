"""How _apply_waivers_signature back-fills, hydrates and reports waivers against one scan's location findings."""

import logging

import pytest

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
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


def _Waiver(id, match, finding_id=None, status="false_positive"):
    return Waiver(id=id, reason=f"reason {id}", created_by="u", status=status, match=match, finding_id=finding_id)


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
async def test_a_dormant_waiver_logs_its_reason(caplog):
    claimer = _Waiver("w-claimer", match=_sig("fpA", content_hash="c1"))
    dormant = _Waiver("w-dormant", match=_sig("gone", content_hash="c2", file="b.py"))
    docs = [_doc("f1", _sig("fpA", content_hash="c1").model_dump()), _doc("unsigned", None)]

    with caplog.at_level(logging.WARNING, logger="app.services.stats"):
        await _apply_waivers_signature(_FindingRepo(docs), _WaiverRepo(), _SCAN, [claimer, dormant])

    dormant_logs = [r.getMessage() for r in caplog.records if r.getMessage().startswith("waiver dormant")]
    assert len(dormant_logs) == 1
    assert "waiver=w-dormant" in dormant_logs[0]
    assert "reason=no_candidates_in_group" in dormant_logs[0]
    assert "group_findings" not in dormant_logs[0]


class _NoFindingRepo:
    async def find_location_findings(self, scan_id):
        raise AssertionError("no waiver, no finding load")


@pytest.mark.asyncio
async def test_without_signature_waivers_no_finding_is_loaded():
    await _apply_waivers_signature(_NoFindingRepo(), _WaiverRepo(), _SCAN, [])


def _match_updates(waiver_repo):
    return [(wid, MatchSignature(**data["match"])) for wid, data in waiver_repo.updates if "match" in data]


@pytest.mark.asyncio
async def test_a_pass1_match_persists_the_walked_location():
    moved = MatchSignature(**{**_sig("fpA").model_dump(), "last_line": 30})
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(
        _FindingRepo([_doc("f1", moved.model_dump())]), waiver_repo, _SCAN, [_Waiver("w", _sig("fpA"))]
    )

    assert _match_updates(waiver_repo) == [("w", moved)]


@pytest.mark.asyncio
async def test_an_unchanged_signature_is_not_rewritten():
    weak = MatchSignature(
        rule_key="OPENGREP:r", file_key="a.py", anchor="c", anchor_kind="content_hash", content_hash="c", last_line=10
    )
    finding_repo = _FindingRepo([_doc("f1", weak.model_dump())])
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(finding_repo, waiver_repo, _SCAN, [_Waiver("w", weak)])

    assert finding_repo.waived == {"f1": "reason w"}
    assert _match_updates(waiver_repo) == []


@pytest.mark.asyncio
async def test_without_a_waiver_repo_the_scan_is_stamped_and_no_waiver_is_written():
    finding_repo = _FindingRepo([_doc("f1", _sig("fpA").model_dump())])

    await _apply_waivers_signature(finding_repo, None, _SCAN, [_Waiver("w", _sig("fpA"))])

    assert finding_repo.waived == {"f1": "reason w"}


def _crypto_doc(line):
    from app.services.aggregation import ResultAggregator
    from app.services.normalizers.sast import normalize_opengrep

    aggregator = ResultAggregator()
    item = {
        "check_id": "crypto-misuse-hardcoded-key",
        "path": "a.py",
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 9},
        "extra": {"severity": "ERROR", "message": "m", "fingerprint": "fp-crypto", "lines": "key = b'x'"},
    }
    normalize_opengrep(aggregator, {"results": [item]})
    (finding,) = aggregator.get_findings()
    return {
        "_id": finding.id,
        "scan_id": _SCAN,
        "finding_id": finding.id,
        "type": finding.type,
        "component": finding.component,
        "details": finding.details,
        "match": finding.match.model_dump(),
    }


@pytest.mark.asyncio
async def test_a_crypto_misuse_waiver_follows_its_finding_across_a_line_shift():
    waiver = _Waiver("w", MatchSignature(**_crypto_doc(12)["match"]), status="accepted_risk")
    shifted = _crypto_doc(13)
    finding_repo = _FindingRepo([shifted])
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(finding_repo, waiver_repo, _SCAN, [waiver])

    assert finding_repo.waived == {shifted["_id"]: "reason w"}
    assert [sig.last_line for _, sig in _match_updates(waiver_repo)] == [13]


@pytest.mark.asyncio
async def test_a_legacy_waiver_takes_the_recomputed_signature_of_its_unsigned_finding():
    unsigned = {**_crypto_doc(12), "match": None}
    waiver = _Waiver("w", match=None, finding_id=unsigned["finding_id"])
    finding_repo = _FindingRepo([unsigned])
    waiver_repo = _WaiverRepo()

    await _apply_waivers_signature(finding_repo, waiver_repo, _SCAN, [waiver])

    assert waiver.match is not None and waiver.match.anchor == "fp-crypto"
    assert finding_repo.waived == {unsigned["_id"]: "reason w"}

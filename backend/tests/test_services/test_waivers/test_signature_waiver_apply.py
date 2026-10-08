"""How the restamp back-fills, heals and reports signature waivers against one scan's location findings."""

import logging

import pytest

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.waivers.apply import restamp_waivers
from tests.helpers.restamp import restamp_docs, waived
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = "s1"


def _sig(anchor: str, content_hash: str = "c", rule: str = "OPENGREP:r", file: str = "a.py") -> MatchSignature:
    return MatchSignature(
        rule_key=rule, file_key=file, anchor=anchor, anchor_kind="scanner_fp", content_hash=content_hash, last_line=10
    )


def _doc(fid: str, match: dict | None) -> dict:
    return {"_id": fid, "scan_id": _SCAN, "finding_id": fid, "type": "sast", "component": "a.py", "match": match}


def _Waiver(id, match, finding_id=None, status="false_positive"):
    return Waiver(
        id=id, project_id="p", reason=f"reason {id}", created_by="u", status=status, match=match, finding_id=finding_id
    )


def _match_writes(waiver_repo):
    return [(wid, MatchSignature(**data["match"])) for wid, data in waiver_repo.writes.items() if "match" in data]


@pytest.mark.asyncio
async def test_a_legacy_waiver_naming_no_finding_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="absent")

    _, waiver_repo = await restamp_docs([_doc("f1", _sig("fpA").model_dump())], [waiver], _SCAN)

    assert waiver.match is None
    assert waiver_repo.writes == {"w": {"last_eval_scan_id": _SCAN, "last_match_count": 0}}


@pytest.mark.asyncio
async def test_a_legacy_waiver_whose_finding_has_no_stored_signature_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="f1")

    _, waiver_repo = await restamp_docs([_doc("f1", None)], [waiver], _SCAN)

    assert waiver.match is None
    assert waiver_repo.writes == {"w": {"last_eval_scan_id": _SCAN, "last_match_count": 1}}


@pytest.mark.asyncio
async def test_a_legacy_waiver_whose_finding_has_a_malformed_signature_stays_unsigned():
    waiver = _Waiver("w", match=None, finding_id="f1")
    malformed = {"rule_key": "OPENGREP:r", "anchor_kind": "NOT_A_KIND"}

    _, waiver_repo = await restamp_docs([_doc("f1", malformed)], [waiver], _SCAN)

    assert waiver.match is None
    assert waiver_repo.writes == {"w": {"last_eval_scan_id": _SCAN, "last_match_count": 1}}


@pytest.mark.asyncio
async def test_a_dormant_waiver_logs_its_reason(caplog):
    claimer = _Waiver("w-claimer", match=_sig("fpA", content_hash="c1"))
    dormant = _Waiver("w-dormant", match=_sig("gone", content_hash="c2", file="b.py"))
    docs = [_doc("f1", _sig("fpA", content_hash="c1").model_dump()), _doc("unsigned", None)]

    with caplog.at_level(logging.WARNING, logger="app.services.waivers.apply"):
        await restamp_docs(docs, [claimer, dormant], _SCAN)

    dormant_logs = [r.getMessage() for r in caplog.records if r.getMessage().startswith("waiver dormant")]
    assert len(dormant_logs) == 1
    assert "waiver=w-dormant" in dormant_logs[0]
    assert "reason=no_candidates_in_group" in dormant_logs[0]
    assert "group_findings" not in dormant_logs[0]


class _NoLocationLoad(FindingRepository):
    async def find_location_findings(self, scan_id):
        raise AssertionError("no waiver can use a signature, so no finding load")


@pytest.mark.asyncio
async def test_without_a_waiver_that_can_use_a_signature_no_location_finding_is_loaded():
    license_waiver = Waiver(project_id="p", finding_id="LIC-GPL", finding_type="license", reason="r", created_by="u")

    await restamp_waivers(_NoLocationLoad(FakeDatabase()), None, _SCAN, [license_waiver])


@pytest.mark.asyncio
async def test_a_pass1_match_persists_the_walked_location():
    moved = MatchSignature(**{**_sig("fpA").model_dump(), "last_line": 30})

    _, waiver_repo = await restamp_docs([_doc("f1", moved.model_dump())], [_Waiver("w", _sig("fpA"))], _SCAN)

    assert _match_writes(waiver_repo) == [("w", moved)]


@pytest.mark.asyncio
async def test_an_unchanged_signature_is_not_rewritten():
    weak = MatchSignature(
        rule_key="OPENGREP:r", file_key="a.py", anchor="c", anchor_kind="content_hash", content_hash="c", last_line=10
    )
    db, waiver_repo = await restamp_docs([_doc("f1", weak.model_dump())], [_Waiver("w", weak)], _SCAN)

    assert await waived(db, _SCAN) == {"f1": "reason w"}
    assert _match_writes(waiver_repo) == []


@pytest.mark.asyncio
async def test_without_a_waiver_repo_the_scan_is_stamped_and_no_waiver_is_written():
    db, waiver_repo = await restamp_docs(
        [_doc("f1", _sig("fpA").model_dump())], [_Waiver("w", _sig("fpA"))], _SCAN, record=False
    )

    assert await waived(db, _SCAN) == {"f1": "reason w"}
    assert waiver_repo.writes == {}


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

    db, waiver_repo = await restamp_docs([shifted], [waiver], _SCAN)

    assert await waived(db, _SCAN) == {shifted["_id"]: "reason w"}
    assert [sig.last_line for _, sig in _match_writes(waiver_repo)] == [13]


@pytest.mark.asyncio
async def test_a_legacy_waiver_takes_the_recomputed_signature_of_its_unsigned_finding():
    unsigned = {**_crypto_doc(12), "match": None}
    waiver = _Waiver("w", match=None, finding_id=unsigned["finding_id"])

    db, waiver_repo = await restamp_docs([unsigned], [waiver], _SCAN)

    assert waiver.match is not None and waiver.match.anchor == "fp-crypto"
    assert await waived(db, _SCAN) == {unsigned["_id"]: "reason w"}
    assert waiver_repo.writes["w"]["match"] == waiver.match.model_dump()
    assert (await db.findings.find_one({"_id": unsigned["_id"]}))["match"] == waiver.match.model_dump()


_LEAKED_KEY = "SECRET-AWS-aaaa1111"


def _secret_doc(component: str) -> dict:
    """A leaked key keeps one finding id in every file it sits in; each file holds its own finding."""
    return {
        "_id": f"secret:{component}",
        "scan_id": _SCAN,
        "finding_id": _LEAKED_KEY,
        "type": "secret",
        "component": component,
        "details": {"detector": "AWS"},
        "match": None,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("files", [("config/a.env", "config/b.env"), ("config/b.env", "config/a.env")])
async def test_an_unsigned_waiver_naming_a_file_takes_the_signature_of_the_finding_in_that_file(files):
    waiver = Waiver(
        id="w",
        project_id="p",
        reason="reason w",
        created_by="u",
        finding_id=_LEAKED_KEY,
        finding_type="secret",
        package_name="config/a.env",
    )

    db, waiver_repo = await restamp_docs([_secret_doc(file) for file in files], [waiver], _SCAN)

    assert await waived(db, _SCAN) == {"secret:config/a.env": "reason w"}
    assert waiver_repo.writes["w"]["match"]["file_key"] == "config/a.env"


@pytest.mark.asyncio
async def test_a_global_waiver_goes_by_its_criteria_and_loads_no_location_finding_for_a_signature():
    waiver = Waiver(id="w", project_id=None, reason="reason w", created_by="u", finding_id=_LEAKED_KEY)

    db, waiver_repo = await restamp_docs([_secret_doc("config/a.env"), _secret_doc("config/b.env")], [waiver], _SCAN)

    assert await waived(db, _SCAN) == {"secret:config/a.env": "reason w", "secret:config/b.env": "reason w"}
    assert waiver.match is None and waiver_repo.writes == {}

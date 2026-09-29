"""One criteria builder answers the Mongo query and the in-memory check alike, scope and rule_id included."""

import asyncio

import pytest

from app.models.waiver import Waiver
from app.services.waivers.matching import record_matches, waiver_criteria, waiver_query
from tests.mocks.fake_mongo import FakeDatabase

_A10, _A42, _B7 = "BEARER-weak_rng-src/a.js-10", "BEARER-weak_rng-src/a.js-42", "BEARER-weak_rng-src/b.js-7"
_MERGED, _EVAL = "SAST-AGG-src/c.js-5", "BEARER-eval-src/a.js-10"
_SECRET_A, _SECRET_B, _OTHER_DETECTOR = "SECRET-17-aaaa1111", "SECRET-17-bbbb2222", "SECRET-18-cccc3333"
_KICS = "KICS-q1-main.tf-3"


def _finding(fid, ftype, component, details):
    return {"_id": fid, "finding_id": fid, "type": ftype, "component": component, "details": details}


def _sast(fid, component, *rules):
    return _finding(fid, "sast", component, {"sast_findings": [{"id": rule, "scanner": "bearer"} for rule in rules]})


_FINDINGS = [
    _sast(_A10, "src/a.js", "weak_rng"),
    _sast(_A42, "src/a.js", "weak_rng"),
    _sast(_B7, "src/b.js", "weak_rng"),
    _sast(_MERGED, "src/c.js", "weak_rng", "eval"),
    _sast(_EVAL, "src/a.js", "eval"),
    _finding(_SECRET_A, "secret", "src/a.env", {"detector": "17"}),
    _finding(_SECRET_B, "secret", "src/b.env", {"detector": "17"}),
    _finding(_OTHER_DETECTOR, "secret", "src/a.env", {"detector": "18"}),
    _finding(_KICS, "iac", "main.tf", {"rule_id": "q1"}),
]


def _waiver(**fields):
    return Waiver(reason="r", created_by="u", **fields)


_TAKEN_FROM_A10 = {"finding_id": _A10, "package_name": "src/a.js", "finding_type": "sast"}
_CASES = {
    "finding scope is the exact finding": (_waiver(**_TAKEN_FROM_A10), {_A10}),
    "file scope spans one rule's lines in one file": (_waiver(scope="file", **_TAKEN_FROM_A10), {_A10, _A42}),
    "rule scope from a finding id spans the rule's files": (
        _waiver(scope="rule", **_TAKEN_FROM_A10),
        {_A10, _A42, _B7},
    ),
    "a rule_id also reaches merged findings of the rule": (
        _waiver(scope="rule", rule_id="weak_rng", **_TAKEN_FROM_A10),
        {_A10, _A42, _B7, _MERGED},
    ),
    "a global rule waiver waives only its rule": (
        _waiver(scope="rule", rule_id="eval", finding_type="sast"),
        {_MERGED, _EVAL},
    ),
    "a rule waiver without a type still names its rule": (_waiver(scope="rule", rule_id="q1"), {_KICS}),
    "a secret rule waiver spans its detector's files": (
        _waiver(scope="rule", rule_id="17", finding_id=_SECRET_A, package_name="src/a.env", finding_type="secret"),
        {_SECRET_A, _SECRET_B},
    ),
}


async def _queried(waiver):
    db = FakeDatabase()
    await db.findings.insert_many([dict(f) for f in _FINDINGS])
    return {doc["_id"] async for doc in db.findings.find(waiver_query(waiver))}


@pytest.mark.parametrize(("waiver", "expected"), _CASES.values(), ids=_CASES.keys())
def test_the_query_and_the_in_memory_check_agree(waiver, expected):
    criteria = waiver_criteria(waiver)

    assert {f["_id"] for f in _FINDINGS if record_matches(f, criteria)} == expected
    assert asyncio.run(_queried(waiver)) == expected


def test_a_vulnerability_waiver_narrows_documents_by_package_only():
    waiver = _waiver(vulnerability_id="CVE-1", package_name="requests", finding_type="license", rule_id="x")

    assert waiver_criteria(waiver) == {"component": "requests"}

"""Global waivers are read (never written) and applied to the in-memory records."""

import pytest

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import apply_global_waivers_in_memory, run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_OSV = "osv"
_COMPONENT = "requests"
_VERSION = "2.31.0"
_OTHER_COMPONENT = "urllib3"
_PROJECT_ID = "project-1"
_REASON = "accepted"
_CREATED_BY = "admin"
_FIRST_CVE = "CVE-2024-0001"
_SECOND_CVE = "CVE-2024-0002"
_GHSA_ALIAS = "GHSA-aaaa-bbbb-cccc"
_AGGREGATE_ID = f"{_COMPONENT}:{_VERSION}"
_SAST_FILE = "app/handlers.py"
_RULE_KEY = "opengrep:python.lang.eval"
_ANCHOR = "deadbeef"
_MOVED_ANCHOR = "0ddba11"
_CONTENT_HASH = "c0ffee"
_CHANGED_CONTENT_HASH = "decaf0"
_SAST_LINE = 12

_SEVERITY_CRITICAL = "CRITICAL"
_SEVERITY_LOW = "LOW"

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
            "name": _COMPONENT,
            "version": _VERSION,
            "purl": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
        }
    ],
}


class _FakeOsv:
    name = _OSV

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {
            "osv_vulnerabilities": [
                {
                    "component": _COMPONENT,
                    "version": _VERSION,
                    "vulnerabilities": [{"id": _FIRST_CVE, "severity": "HIGH", "summary": "demo"}],
                }
            ]
        }


@pytest.fixture
def _osv(monkeypatch):
    from app.services.analysis import registry

    monkeypatch.setitem(registry.analyzers, _OSV, _FakeOsv())


def _waiver(**fields) -> Waiver:
    return Waiver(project_id=None, reason=_REASON, created_by=_CREATED_BY, **fields)


async def _seed_waiver(db, **fields) -> Waiver:
    waiver = _waiver(**fields)
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))
    return waiver


def _license_record(component: str) -> dict:
    return {
        "id": component,
        "finding_id": component,
        "type": "license",
        "component": component,
        "version": _VERSION,
    }


def _vulnerability_record(component: str = _COMPONENT) -> dict:
    return {
        "id": f"{component}:{_VERSION}",
        "finding_id": f"{component}:{_VERSION}",
        "type": "vulnerability",
        "component": component,
        "version": _VERSION,
        "severity": _SEVERITY_CRITICAL,
        "details": {
            "vulnerabilities": [
                {"id": _FIRST_CVE, "severity": _SEVERITY_CRITICAL, "aliases": [_GHSA_ALIAS]},
                {"id": _SECOND_CVE, "severity": _SEVERITY_LOW},
            ]
        },
    }


def _sast_record(anchor: str, content_hash: str) -> dict:
    return {
        "id": f"OPENGREP-{_SAST_FILE}-{_SAST_LINE}",
        "finding_id": f"OPENGREP-{_SAST_FILE}-{_SAST_LINE}",
        "type": "sast",
        "component": _SAST_FILE,
        "version": "",
        "match": MatchSignature(
            rule_key=_RULE_KEY,
            file_key=_SAST_FILE,
            anchor=anchor,
            anchor_kind="scanner_fp",
            content_hash=content_hash,
            last_line=_SAST_LINE,
        ).model_dump(),
    }


def _signature_waiver(anchor: str, content_hash: str) -> Waiver:
    return _waiver(
        match=MatchSignature(
            rule_key=_RULE_KEY,
            file_key=_SAST_FILE,
            anchor=anchor,
            anchor_kind="scanner_fp",
            content_hash=content_hash,
            last_line=_SAST_LINE,
        )
    )


def test_field_waiver_waives_the_whole_record():
    records = [_license_record(_COMPONENT)]

    assert apply_global_waivers_in_memory(records, [_waiver(finding_type="license", package_name=_COMPONENT)]) == 1
    assert records[0]["waived"] is True
    assert records[0]["waiver_reason"] == _REASON


def test_field_waiver_ignores_a_different_component():
    records = [_license_record(_OTHER_COMPONENT)]

    assert apply_global_waivers_in_memory(records, [_waiver(finding_type="license", package_name=_COMPONENT)]) == 0
    assert records[0].get("waived") is not True


def test_a_waiver_that_constrains_nothing_waives_nothing():
    """An unconstrained waiver would otherwise blanket every finding the caller posted."""
    records = [_license_record(_COMPONENT), _vulnerability_record()]

    assert apply_global_waivers_in_memory(records, [_waiver()]) == 0
    assert [record.get("waived") for record in records] == [None, None]


def test_vulnerability_waiver_demotes_severity_until_every_entry_is_waived():
    records = [_vulnerability_record()]

    assert apply_global_waivers_in_memory(records, [_waiver(vulnerability_id=_FIRST_CVE)]) == 0
    assert records[0].get("waived") is not True
    assert records[0]["severity"] == _SEVERITY_LOW

    assert apply_global_waivers_in_memory(records, [_waiver(vulnerability_id=_SECOND_CVE)]) == 1
    assert records[0]["waived"] is True
    # A fully waived document keeps its own severity, so dropping the waiver restores it.
    assert records[0]["severity"] == _SEVERITY_CRITICAL


def test_vulnerability_waiver_matches_an_advisory_under_its_alias():
    records = [_vulnerability_record()]

    assert apply_global_waivers_in_memory(records, [_waiver(vulnerability_id=_GHSA_ALIAS)]) == 0
    assert records[0]["details"]["vulnerabilities"][0]["waived"] is True
    assert records[0]["severity"] == _SEVERITY_LOW


def test_vulnerability_waiver_scoped_to_another_component_is_not_applied():
    records = [_vulnerability_record()]

    waiver = _waiver(vulnerability_id=_FIRST_CVE, package_name=_OTHER_COMPONENT)

    assert apply_global_waivers_in_memory(records, [waiver]) == 0
    assert records[0]["details"]["vulnerabilities"][0].get("waived") is not True
    assert records[0]["severity"] == _SEVERITY_CRITICAL


def test_a_vulnerability_waiver_reaches_its_advisory_whatever_type_it_names():
    """The scan-backed path drops ``type`` from a vulnerability waiver's scope; this one must too."""
    records = [_vulnerability_record()]

    assert apply_global_waivers_in_memory(records, [_waiver(vulnerability_id=_FIRST_CVE, finding_type="license")]) == 0
    assert records[0]["details"]["vulnerabilities"][0]["waived"] is True


def test_file_scope_waiver_is_left_unapplied():
    """File and rule scope expand through a Mongo regex that has no in-memory counterpart."""
    records = [_license_record(_COMPONENT)]

    waiver = _waiver(finding_id=_COMPONENT, finding_type="license", package_name=_COMPONENT, scope="file")

    assert apply_global_waivers_in_memory(records, [waiver]) == 0
    assert records[0].get("waived") is not True


def test_signature_waiver_waives_the_location_it_was_taken_from():
    records = [_sast_record(_ANCHOR, _CONTENT_HASH)]

    assert apply_global_waivers_in_memory(records, [_signature_waiver(_ANCHOR, _CONTENT_HASH)]) == 1
    assert records[0]["waived"] is True
    assert records[0]["waiver_reason"] == _REASON


def test_a_signature_whose_content_changed_lapses_instead_of_waiving():
    records = [_sast_record(_MOVED_ANCHOR, _CHANGED_CONTENT_HASH)]

    waiver = _signature_waiver(_ANCHOR, _CONTENT_HASH)

    assert apply_global_waivers_in_memory(records, [waiver]) == 0
    assert records[0].get("waived") is not True
    assert records[0]["waiver_lapsed"] is True
    assert records[0]["lapsed_waiver_id"] == waiver.id


@pytest.mark.asyncio
async def test_opt_out_reports_none_and_applies_no_waiver(_osv):
    db = FakeDatabase()
    await _seed_waiver(db, vulnerability_id=_FIRST_CVE)

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, db)

    assert response.waivers_applied == "none"
    assert response.waived_count == 0
    assert [f["waived"] for f in response.findings] == [False]


@pytest.mark.asyncio
async def test_opt_in_applies_the_global_waiver_and_writes_nothing(_osv):
    db = FakeDatabase()
    await _seed_waiver(db, vulnerability_id=_FIRST_CVE)

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV], apply_global_waivers=True)
    response = await run_adhoc_analysis(request, db)

    assert response.waivers_applied == "global"
    assert response.waived_count == 1
    waived = [f for f in response.findings if f.get("waived") is True]
    assert [f["id"] for f in waived] == [_AGGREGATE_ID]

    assert await db.waivers.count_documents({}) == 1
    stored = await db.waivers.find_one({})
    # The persisted path records what each waiver suppressed; this one must not write that back.
    assert stored.get("last_match_count") is None


@pytest.mark.asyncio
async def test_a_project_scoped_waiver_is_not_applied_to_a_project_less_run(_osv):
    db = FakeDatabase()
    scoped = Waiver(project_id=_PROJECT_ID, reason=_REASON, created_by=_CREATED_BY, vulnerability_id=_FIRST_CVE)
    await db.waivers.insert_one(scoped.model_dump(by_alias=True))

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV], apply_global_waivers=True)
    response = await run_adhoc_analysis(request, db)

    assert response.waivers_applied == "global"
    assert response.waived_count == 0

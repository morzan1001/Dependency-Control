"""Global waivers are read (never written) and applied to the in-memory records."""

import pytest

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import apply_global_waivers_in_memory, run_adhoc_analysis
from tests.helpers.analyzers import serve_analyzer
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

_SCOPE_FILE = "file"
_SCOPE_RULE = "rule"
_TYPE_SAST = "sast"
_BEARER = "bearer"
_BEARER_RULE = "javascript_lang_insufficiently_random_values"
_OTHER_BEARER_RULE = "javascript_lang_eval"
_BEARER_FILE = "src/random.js"
_OTHER_FILE = "src/other.js"
_WAIVED_LINE = 102
_MOVED_LINE = 140
_OTHER_FILE_LINE = 7
_SEVERITY_BEARER_HIGH = "high"


def _bearer_finding_id(rule_id: str, file_path: str, line: int) -> str:
    return f"BEARER-{rule_id}-{file_path}-{line}"


_WAIVED_FINDING_ID = _bearer_finding_id(_BEARER_RULE, _BEARER_FILE, _WAIVED_LINE)
_MOVED_FINDING_ID = _bearer_finding_id(_BEARER_RULE, _BEARER_FILE, _MOVED_LINE)
_OTHER_FILE_FINDING_ID = _bearer_finding_id(_BEARER_RULE, _OTHER_FILE, _OTHER_FILE_LINE)
_OTHER_RULE_FINDING_ID = _bearer_finding_id(_OTHER_BEARER_RULE, _BEARER_FILE, _WAIVED_LINE)

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

    serve_analyzer(monkeypatch, _OSV, _FakeOsv())


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


def _bearer_record(finding_id: str, component: str) -> dict:
    return {
        "id": finding_id,
        "finding_id": finding_id,
        "type": _TYPE_SAST,
        "component": component,
        "version": "",
    }


def _bearer_waiver(scope: str) -> Waiver:
    """Taken from the line the scanner first reported, as the UI records it."""
    return _waiver(finding_id=_WAIVED_FINDING_ID, package_name=_BEARER_FILE, scope=scope)


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


def test_a_file_scope_waiver_reaches_the_same_rule_at_another_line_in_that_file():
    records = [
        _bearer_record(_MOVED_FINDING_ID, _BEARER_FILE),
        _bearer_record(_OTHER_FILE_FINDING_ID, _OTHER_FILE),
        _bearer_record(_OTHER_RULE_FINDING_ID, _BEARER_FILE),
    ]

    assert apply_global_waivers_in_memory(records, [_bearer_waiver(_SCOPE_FILE)]) == 1
    assert [record.get("waived") for record in records] == [True, None, None]


def test_a_rule_scope_waiver_reaches_the_same_rule_in_another_file():
    records = [
        _bearer_record(_MOVED_FINDING_ID, _BEARER_FILE),
        _bearer_record(_OTHER_FILE_FINDING_ID, _OTHER_FILE),
        _bearer_record(_OTHER_RULE_FINDING_ID, _BEARER_FILE),
    ]

    assert apply_global_waivers_in_memory(records, [_bearer_waiver(_SCOPE_RULE)]) == 2
    assert [record.get("waived") for record in records] == [True, True, None]


def test_a_widened_scope_is_not_narrowed_by_the_signature_it_carries():
    """The scan-backed path keeps file and rule scope on the query, whatever signature they carry."""
    records = [_bearer_record(_MOVED_FINDING_ID, _BEARER_FILE)]

    waiver = _bearer_waiver(_SCOPE_FILE)
    waiver.match = MatchSignature(
        rule_key=_RULE_KEY,
        file_key=_SAST_FILE,
        anchor=_ANCHOR,
        anchor_kind="scanner_fp",
        content_hash=_CONTENT_HASH,
        last_line=_SAST_LINE,
    )

    assert apply_global_waivers_in_memory(records, [waiver]) == 1


def test_a_scope_that_cannot_be_widened_falls_back_to_the_exact_finding_id():
    """A finding_id with no trailing line number carries no file prefix to widen to."""
    records = [_license_record(_COMPONENT), _license_record(_OTHER_COMPONENT)]

    waiver = _waiver(finding_id=_COMPONENT, finding_type="license", package_name=_COMPONENT, scope=_SCOPE_FILE)

    assert apply_global_waivers_in_memory(records, [waiver]) == 1
    assert [record.get("waived") for record in records] == [True, None]


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
async def test_a_widened_scope_is_covered_by_the_control_the_response_reports():
    """``waivers_applied`` names every scope the run honours, so a widened one must be applied."""
    db = FakeDatabase()
    await _seed_waiver(db, finding_id=_WAIVED_FINDING_ID, package_name=_BEARER_FILE, scope=_SCOPE_FILE)

    payload = {
        "findings": [
            {
                "id": _BEARER_RULE,
                "title": _REASON,
                "filename": _BEARER_FILE,
                "line_number": _MOVED_LINE,
                "severity": _SEVERITY_BEARER_HIGH,
            }
        ]
    }
    request = AdhocAnalyzeRequest(scanners={_BEARER: payload}, analyzers=[], apply_global_waivers=True)
    response = await run_adhoc_analysis(request, db)

    assert response.waivers_applied == "global"
    assert [f["finding_id"] for f in response.findings if f.get("waived") is True] == [_MOVED_FINDING_ID]
    assert response.waived_count == 1


@pytest.mark.asyncio
async def test_a_project_scoped_waiver_is_not_applied_to_a_project_less_run(_osv):
    db = FakeDatabase()
    scoped = Waiver(project_id=_PROJECT_ID, reason=_REASON, created_by=_CREATED_BY, vulnerability_id=_FIRST_CVE)
    await db.waivers.insert_one(scoped.model_dump(by_alias=True))

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV], apply_global_waivers=True)
    response = await run_adhoc_analysis(request, db)

    assert response.waivers_applied == "global"
    assert response.waived_count == 0

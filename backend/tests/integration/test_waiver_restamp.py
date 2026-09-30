"""The one waiver restamp, through the ingest persist, the recalculation and the ad-hoc gate."""

from datetime import datetime, timezone

import pytest

from app.core.init_db import create_indexes
from app.core.metrics import analysis_waivers_applied_total
from app.models.finding import Finding, FindingType, Severity
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.services.analysis.adhoc import apply_global_waivers_in_memory
from app.services.analysis.engine import (
    _finalize_scan_and_project,
    _persist_findings_and_waivers,
    _prepare_finding_records,
)
from app.services.analysis.stats import calculate_comprehensive_stats
from app.services.stats import recalculate_project_stats
from tests.mocks.fake_mongo import FakeDatabase

pytestmark = pytest.mark.asyncio

_PROJECT = "p-restamp"
_HEAD = "scan-head"
_FEATURE = "scan-feature"
_RESCAN = "scan-head-rescan"
_CVE_CRITICAL = "CVE-2024-0001"
_CVE_LOW = "CVE-2024-0002"
_FIELD_REASON = "accepted component"
_CVE_REASON = "not reachable"
_SECRET_FILE = "deploy/values.yaml"
_WORKER = "pod-a/worker-0"

_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]


def _vulnerable_component() -> Finding:
    return Finding(
        id="express:4.18.2",
        type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        component="express",
        version="4.18.2",
        description="two advisories",
        scanners=["trivy"],
        details={
            "vulnerabilities": [
                {"id": _CVE_CRITICAL, "severity": "CRITICAL", "aliases": []},
                {"id": _CVE_LOW, "severity": "LOW", "aliases": []},
            ]
        },
    )


def _secret(line_hash: str) -> Finding:
    return Finding(
        id=f"SECRET-AWS-{line_hash}",
        type=FindingType.SECRET,
        severity=Severity.HIGH,
        component=_SECRET_FILE,
        description="aws key",
        scanners=["trufflehog"],
        details={"detector": "AWS"},
    )


def _field_waiver(project_id: str | None = _PROJECT) -> Waiver:
    return Waiver(
        project_id=project_id,
        finding_id="express:4.18.2",
        finding_type="vulnerability",
        package_name="express",
        reason=_FIELD_REASON,
        created_by="u",
    )


def _partial_cve_waiver(project_id: str | None = _PROJECT) -> Waiver:
    return Waiver(
        project_id=project_id,
        vulnerability_id=_CVE_CRITICAL,
        package_name="express",
        reason=_CVE_REASON,
        created_by="u",
    )


async def _seed_project(db) -> None:
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "p", "latest_scan_id": _HEAD, "default_branch": "main", "deleted_branches": []}
    )
    await db.scans.insert_one(
        {
            "_id": _HEAD,
            "project_id": _PROJECT,
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )


async def _seed_feature_tip(db) -> None:
    await db.scans.insert_one(
        {
            "_id": _FEATURE,
            "project_id": _PROJECT,
            "branch": "feature/x",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )


def _secret_signature(file_key: str = _SECRET_FILE, last_line: int = 40) -> MatchSignature:
    return MatchSignature(
        rule_key="trufflehog:AWS", file_key=file_key, anchor="h-1", anchor_kind="secret_hash", last_line=last_line
    )


def _moved_secret() -> Finding:
    return _secret("aaaa1111").model_copy(update={"match": _secret_signature()})


def _waiver_where_the_secret_last_was() -> Waiver:
    return Waiver(
        project_id=_PROJECT,
        finding_id="SECRET-AWS-aaaa1111",
        finding_type="secret",
        match=_secret_signature(last_line=12),
        reason="rotated",
        created_by="u",
    )


async def _persist(db, scan_id: str, *findings: Finding) -> list[dict]:
    records, _ = _prepare_finding_records(list(findings), scan_id, _PROJECT, datetime.now(timezone.utc))
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)
    return await db.findings.find({"scan_id": scan_id}).to_list(None)


async def _finalize(db, scan_id: str) -> None:
    scan_repo = ScanRepository(db)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing", "worker_id": _WORKER}})
    stats = (await calculate_comprehensive_stats(db, scan_id)).stats
    await _finalize_scan_and_project(
        scan_id,
        await scan_repo.get_by_id(scan_id),
        _PROJECT,
        1,
        0,
        stats,
        {"scan_id": scan_id, "status": "completed", "findings_count": 1, "stats": stats.model_dump()},
        scan_repo,
        worker_id=_WORKER,
        external_load_start=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize("_database", _DATABASES)
async def test_a_partial_cve_waiver_does_not_lift_a_whole_finding_waiver_at_ingest(db, _database):
    for waiver in (_field_waiver(), _partial_cve_waiver()):
        await WaiverRepository(db).create(waiver)

    (doc,) = await _persist(db, _FEATURE, _vulnerable_component())

    assert (doc["waived"], doc["waiver_reason"], doc["severity"]) == (True, _FIELD_REASON, "LOW")
    assert [entry.get("waived") for entry in doc["details"]["vulnerabilities"]] == [True, None]


@pytest.mark.parametrize("_database", _DATABASES)
@pytest.mark.parametrize("cve_first", [False, True], ids=["whole-finding-first", "cve-first"])
async def test_the_stored_scan_and_the_adhoc_gate_agree_on_the_same_waivers(db, _database, cve_first):
    waivers = [_field_waiver(None), _partial_cve_waiver(None)]
    if cve_first:
        waivers.reverse()
    for waiver in waivers:
        await WaiverRepository(db).create(waiver)
    (stored,) = await _persist(db, _FEATURE, _vulnerable_component())

    record = _vulnerable_component().model_dump()
    record["finding_id"] = record["id"]
    apply_global_waivers_in_memory([record], [w.model_copy(deep=True) for w in waivers])

    def outcome(doc):
        return doc.get("waived"), doc.get("waiver_reason"), doc.get("severity")

    assert outcome(stored) == outcome(record) == (True, _FIELD_REASON, "LOW")


class _WriteCounter:
    def __init__(self, collection):
        self.calls: list[str] = []
        for name in ("update_one", "update_many", "bulk_write", "insert_many", "delete_many"):
            original = getattr(collection, name)
            setattr(collection, name, self._counted(name, original))

    def _counted(self, name, original):
        async def counted(*args, **kwargs):
            self.calls.append(name)
            return await original(*args, **kwargs)

        return counted


async def test_restamping_an_unchanged_waiver_set_writes_no_finding():
    db = FakeDatabase()
    await _seed_project(db)
    await _persist(db, _HEAD, _vulnerable_component(), _secret("aaaa1111"))
    for waiver in (_field_waiver(), _partial_cve_waiver()):
        await WaiverRepository(db).create(waiver)
    await recalculate_project_stats(_PROJECT, db)

    writes = _WriteCounter(db.findings)
    await recalculate_project_stats(_PROJECT, db)

    assert writes.calls == []


async def test_a_finding_scope_location_waiver_without_a_finding_id_waives_every_finding_it_describes():
    db = FakeDatabase()
    await _seed_project(db)
    await _persist(db, _HEAD, _secret("aaaa1111"), _secret("bbbb2222"))
    await WaiverRepository(db).create(
        Waiver(
            project_id=None, finding_type="secret", package_name=_SECRET_FILE, reason="test fixtures", created_by="u"
        )
    )

    await recalculate_project_stats(_PROJECT, db)

    assert [doc["waived"] async for doc in db.findings.find({"scan_id": _HEAD})] == [True, True]


async def test_a_waiver_with_a_signature_and_a_vulnerability_id_is_a_cve_waiver_in_the_adhoc_gate():
    record = _vulnerable_component().model_dump()
    record["finding_id"] = record["id"]
    signature = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fp", anchor_kind="scanner_fp")
    waiver = Waiver(vulnerability_id=_CVE_CRITICAL, match=signature, reason=_CVE_REASON, created_by="u")

    apply_global_waivers_in_memory([record], [waiver])

    assert record["details"]["vulnerabilities"][0]["waived"] is True
    assert record["severity"] == "LOW"


def _unsigned_iac_doc() -> dict:
    return {
        "_id": "iac-1",
        "scan_id": _HEAD,
        "project_id": _PROJECT,
        "finding_id": "KICS-q1-main.tf-3",
        "type": "iac",
        "component": "main.tf",
        "match": None,
        "waived": False,
        "details": {"rule_id": "q1", "similarity_id": "sim-1", "actual_value": "open", "start": {"line": 3}},
    }


async def test_a_recomputed_signature_is_persisted_on_its_finding():
    db = FakeDatabase()
    await _seed_project(db)
    await db.findings.insert_one(_unsigned_iac_doc())
    await WaiverRepository(db).create(
        Waiver(project_id=_PROJECT, finding_id="KICS-q1-main.tf-3", finding_type="iac", reason="r", created_by="u")
    )

    await recalculate_project_stats(_PROJECT, db)

    doc = await db.findings.find_one({"_id": "iac-1"})
    assert doc["match"] is not None and doc["waived"] is True


async def test_waiver_bookkeeping_writes_without_reading_each_waiver_back(monkeypatch):
    db = FakeDatabase()
    await _seed_project(db)
    await _persist(db, _HEAD, _vulnerable_component())
    await WaiverRepository(db).create(_field_waiver())

    async def _no_read_back(self, waiver_id):
        raise AssertionError(f"read back {waiver_id}")

    monkeypatch.setattr(WaiverRepository, "get_by_id", _no_read_back)
    await recalculate_project_stats(_PROJECT, db)

    stored = await db.waivers.find_one({})
    assert (stored["last_eval_scan_id"], stored["last_match_count"]) == (_HEAD, 1)


async def test_a_global_waiver_carries_no_one_projects_outcome():
    db = FakeDatabase()
    await _seed_project(db)
    await _persist(db, _HEAD, _vulnerable_component())
    await WaiverRepository(db).create(_field_waiver(None))

    await recalculate_project_stats(_PROJECT, db)

    stored = await db.waivers.find_one({})
    assert stored.get("last_eval_scan_id") is None
    assert (await db.findings.find_one({}))["waived"] is True


def _record_recalc_restamps(monkeypatch) -> list[str]:
    import app.services.stats as stats_module

    restamped: list[str] = []
    original = stats_module.restamp_waivers

    async def recording(finding_repo, waiver_repo, scan_id, waivers):
        restamped.append(scan_id)
        return await original(finding_repo, waiver_repo, scan_id, waivers)

    monkeypatch.setattr(stats_module, "restamp_waivers", recording)
    return restamped


@pytest.mark.parametrize(
    ("waiver", "finding"),
    [
        pytest.param(_field_waiver, _vulnerable_component, id="field"),
        pytest.param(_waiver_where_the_secret_last_was, _moved_secret, id="signature-walking-with-its-finding"),
    ],
)
async def test_heads_analysis_records_each_waivers_outcome_and_leaves_the_recalc_nothing(monkeypatch, waiver, finding):
    db = FakeDatabase()
    await _seed_project(db)
    await _seed_feature_tip(db)
    await WaiverRepository(db).create(waiver())
    await _persist(db, _FEATURE, finding())
    await _persist(db, _HEAD, finding())
    await _finalize(db, _HEAD)
    restamped = _record_recalc_restamps(monkeypatch)

    await recalculate_project_stats(_PROJECT, db)

    stored = await db.waivers.find_one({})
    assert (stored["last_eval_scan_id"], stored["last_match_count"]) == (_HEAD, 1)
    assert restamped == []


@pytest.mark.parametrize("_database", _DATABASES)
async def test_a_waiver_reaches_every_run_that_reports_the_restamped_scan(db, _database):
    """The rescan's run sits on the rescan and on its root; the root's own restamp leaves that run alone."""
    await create_indexes(db)
    await _seed_project(db)
    await db.scans.insert_one(
        {
            "_id": _RESCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": "completed",
            "is_rescan": True,
            "original_scan_id": _HEAD,
            "created_at": datetime.now(timezone.utc),
        }
    )
    await _persist(db, _HEAD, _secret("aaaa1111"))
    await _persist(db, _RESCAN, _vulnerable_component())
    await _finalize(db, _RESCAN)
    await WaiverRepository(db).create(_field_waiver())

    await recalculate_project_stats(_PROJECT, db, restamp=[_HEAD, _RESCAN])

    rescan = await db.scans.find_one({"_id": _RESCAN})
    root = await db.scans.find_one({"_id": _HEAD})
    assert rescan["stats"]["critical"] == 0
    assert rescan["latest_run"]["stats"] == rescan["stats"]
    assert root["latest_run"]["stats"] == rescan["stats"] != root["stats"]


async def test_another_branchs_analysis_leaves_each_waivers_outcome_to_head():
    db = FakeDatabase()
    await WaiverRepository(db).create(_field_waiver())

    await _persist(db, _FEATURE, _vulnerable_component())

    assert (await db.waivers.find_one({})).get("last_eval_scan_id") is None


def _signed_secret_doc(scan_id: str, file_key: str) -> dict:
    return {
        "_id": f"{scan_id}:secret",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "finding_id": "SECRET-AWS-aaaa1111",
        "type": "secret",
        "component": file_key,
        "severity": "HIGH",
        "waived": False,
        "details": {"detector": "AWS"},
        "match": _secret_signature(file_key).model_dump(),
    }


async def test_each_scan_binds_an_unsigned_waiver_to_its_own_finding():
    """The tip holds the secret the waiver names in another file than head does, as its own analysis sees it."""
    db = FakeDatabase()
    await _seed_project(db)
    await _seed_feature_tip(db)
    await db.findings.insert_many(
        [_signed_secret_doc(_HEAD, "config/a.yaml"), _signed_secret_doc(_FEATURE, "config/b.yaml")]
    )
    await WaiverRepository(db).create(
        Waiver(finding_id="SECRET-AWS-aaaa1111", finding_type="secret", reason="rotated", created_by="u")
    )

    await recalculate_project_stats(_PROJECT, db)

    assert {doc["scan_id"]: doc["waived"] async for doc in db.findings.find({})} == {_HEAD: True, _FEATURE: True}


_ROUTES = ("query", "vulnerability", "signature")


def _applied_by_route() -> dict[str, float]:
    return {route: analysis_waivers_applied_total.labels(type=route)._value.get() for route in _ROUTES}


async def test_the_applied_metric_counts_each_waiver_that_matched_by_the_path_it_took():
    db = FakeDatabase()
    unmatched = Waiver(project_id=_PROJECT, finding_id="lodash:4.17.0", reason="r", created_by="u")
    for waiver in (_field_waiver(), _partial_cve_waiver(), unmatched):
        await WaiverRepository(db).create(waiver)
    before = _applied_by_route()

    await _persist(db, _FEATURE, _vulnerable_component())

    after = _applied_by_route()
    assert {route: after[route] - before[route] for route in _ROUTES} == {
        "query": 1,
        "vulnerability": 1,
        "signature": 0,
    }

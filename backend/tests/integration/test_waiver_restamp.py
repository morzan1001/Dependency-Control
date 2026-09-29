"""The one waiver restamp, through the ingest persist, the recalculation and the ad-hoc gate."""

import copy
from datetime import datetime, timezone

import pytest
from pymongo import ReadPreference

from app.models.finding import Finding, FindingType, Severity
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.waivers import WaiverRepository
from app.services.analysis.adhoc import apply_global_waivers_in_memory
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.stats import recalculate_project_stats
from tests.mocks.fake_mongo import FakeCollection, FakeDatabase, _match_doc

pytestmark = pytest.mark.asyncio

_PROJECT = "p-restamp"
_HEAD = "scan-head"
_FEATURE = "scan-feature"
_CVE_CRITICAL = "CVE-2024-0001"
_CVE_LOW = "CVE-2024-0002"
_FIELD_REASON = "accepted component"
_CVE_REASON = "not reachable"
_SECRET_FILE = "deploy/values.yaml"

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
    await db.projects.insert_one({"_id": _PROJECT, "name": "p", "latest_scan_id": _HEAD, "deleted_branches": []})
    await db.scans.insert_one({"_id": _HEAD, "project_id": _PROJECT, "status": "completed"})


async def _persist(db, scan_id: str, *findings: Finding) -> list[dict]:
    records, _ = _prepare_finding_records(list(findings), scan_id, _PROJECT, datetime.now(timezone.utc))
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)
    return await db.findings.find({"scan_id": scan_id}).to_list(None)


@pytest.mark.parametrize("_database", _DATABASES)
async def test_a_partial_cve_waiver_does_not_lift_a_whole_finding_waiver_at_ingest(db, _database):
    for waiver in (_field_waiver(), _partial_cve_waiver()):
        await WaiverRepository(db).create(waiver)

    (doc,) = await _persist(db, _FEATURE, _vulnerable_component())

    assert (doc["waived"], doc["waiver_reason"], doc["severity"]) == (True, _FIELD_REASON, "LOW")
    assert [entry.get("waived") for entry in doc["details"]["vulnerabilities"]] == [True, None]


@pytest.mark.parametrize("_database", _DATABASES)
async def test_the_stored_scan_and_the_adhoc_gate_agree_on_the_same_waivers(db, _database):
    waivers = [_field_waiver(None), _partial_cve_waiver(None)]
    for waiver in waivers:
        await WaiverRepository(db).create(waiver)
    (stored,) = await _persist(db, _FEATURE, _vulnerable_component())

    record = _vulnerable_component().model_dump()
    record["finding_id"] = record["id"]
    apply_global_waivers_in_memory([record], [w.model_copy(deep=True) for w in waivers])

    def outcome(doc):
        return doc.get("waived"), doc.get("waiver_reason"), doc.get("severity")

    assert outcome(stored) == outcome(record) == (True, _FIELD_REASON, "LOW")


class _LaggingFindings(FakeCollection):
    """A secondary that has seen nothing since ``freeze``; primary reads see every write."""

    def freeze(self) -> None:
        self._stale = copy.deepcopy(self._docs)

    def with_options(self, read_preference=None, **_kwargs):
        if read_preference != ReadPreference.PRIMARY:
            return self
        primary = FakeCollection(self._db)
        primary._docs = self._docs
        return primary

    def find(self, query=None, projection=None, **kwargs):
        live, self._docs = self._docs, self._stale
        try:
            return super().find(query, projection, **kwargs)
        finally:
            self._docs = live

    async def count_documents(self, query, limit: int = 0, **_kwargs):
        return sum(1 for doc in self._stale.values() if _match_doc(doc, query))


def _lagging_database() -> FakeDatabase:
    db = FakeDatabase()
    findings = _LaggingFindings(db)
    findings.freeze()
    object.__setattr__(db, "findings", findings)
    return db


async def test_the_restamp_reads_the_findings_it_just_wrote_from_the_primary():
    db = _lagging_database()
    await WaiverRepository(db).create(_partial_cve_waiver())
    await WaiverRepository(db).create(
        Waiver(project_id=_PROJECT, vulnerability_id=_CVE_LOW, package_name="express", reason="r", created_by="u")
    )

    await _persist(db, _FEATURE, _vulnerable_component())

    (doc,) = db.findings._docs.values()
    assert doc["waived"] is True


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

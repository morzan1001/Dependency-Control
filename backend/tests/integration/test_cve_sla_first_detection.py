"""The CVE SLA ages a finding from its first detection in the project, carried forward at persist time.

Retention deletes old scans, so the date has to travel with every scan's copy of the finding: an age
read back from the surviving history could never outgrow the retention window.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core import ensure_utc
from app.core.init_db import create_indexes
from app.models.finding import Finding, FindingType, Severity
from app.repositories.findings import FindingRepository
from app.schemas.compliance import ControlStatus
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from tests.helpers.compliance import evaluation_input

_PROJECT = "sla-project"
_OTHER_PROJECT = "other-project"
# Whole seconds, so the server's millisecond precision cannot move the dates the tests compare.
_NOW = datetime.now(timezone.utc).replace(microsecond=0)

# The value is unread: the marker on the second case is what makes the ``db`` fixture hand out a
# real server instead of the attrappe.
_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]


def _days_ago(days: int) -> datetime:
    return _NOW - timedelta(days=days)


def _critical_cve() -> Finding:
    return Finding(
        id="log4j-core:2.14.1",
        type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        component="log4j-core",
        version="2.14.1",
        description="remote code execution",
        scanners=["trivy"],
    )


def _versionless_sast() -> Finding:
    return Finding(
        id="python.lang.security.eval",
        type=FindingType.SAST,
        severity=Severity.HIGH,
        component="src/app.py",
        description="eval of user input",
        scanners=["opengrep"],
    )


async def _persist(db, scan_id: str, scan_created_at: datetime, *findings: Finding, project_id: str = _PROJECT):
    records, _ = _prepare_finding_records(list(findings), scan_id, project_id, scan_created_at)
    await _persist_findings_and_waivers(records, scan_id, project_id, FindingRepository(db), db)
    return await db.findings.find({"scan_id": scan_id}).to_list(None)


async def _store_legacy_copy(db, scan_created_at: datetime) -> None:
    legacy, _ = _prepare_finding_records([_critical_cve()], "legacy-scan", _PROJECT, scan_created_at)
    await db.findings.insert_many(legacy)


async def _critical_control(db, scan_id: str):
    """The CVE-SLA-CRITICAL verdict over the findings the engine reads for ``scan_id``."""
    engine = ComplianceReportEngine()
    framework = CveRemediationSlaFramework()
    resolved = ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT])
    clause, fields, _ = engine._finding_type_filter(framework)
    findings, _ = await engine._collect_findings(db, resolved, [scan_id], clause, fields)
    evaluation = await framework.evaluate(
        evaluation_input(resolved=resolved, findings=findings, scan_ids=[scan_id], db=db)
    )
    return next(c for c in evaluation.controls if c.control_id == "CVE-SLA-CRITICAL")


def _first_seen(docs: list[dict]) -> list[datetime | None]:
    return [ensure_utc(doc.get("first_seen_at")) for doc in docs]


def _explain_values(node, key: str) -> list:
    """Every value of ``key`` in the plan that ran; the planner's rejected candidates may fetch."""
    if isinstance(node, dict):
        return [
            v
            for k, child in node.items()
            if k != "rejectedPlans"
            for v in ([child] if k == key else _explain_values(child, key))
        ]
    if isinstance(node, list):
        return [v for child in node for v in _explain_values(child, key)]
    return []


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_finding_with_no_history_is_first_seen_by_its_own_scan(db, database):
    docs = await _persist(db, "scan-1", _days_ago(3), _critical_cve())

    assert _first_seen(docs) == [_days_ago(3)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_second_scan_inherits_first_seen_at_from_the_first(db, database):
    await _persist(db, "scan-1", _days_ago(200), _critical_cve())

    docs = await _persist(db, "scan-2", _NOW, _critical_cve())

    assert _first_seen(docs) == [_days_ago(200)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_first_detection_outlives_retention_deleting_the_scan_that_made_it(db, database):
    await _persist(db, "scan-1", _days_ago(200), _critical_cve())
    await _persist(db, "scan-2", _days_ago(100), _critical_cve())
    await db.findings.delete_many({"scan_id": "scan-1"})

    docs = await _persist(db, "scan-3", _NOW, _critical_cve())

    assert _first_seen(docs) == [_days_ago(200)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_reanalysing_a_scan_keeps_the_date_it_had_inherited(db, database):
    await _persist(db, "scan-1", _days_ago(200), _critical_cve())
    await _persist(db, "scan-2", _NOW, _critical_cve())
    await db.findings.delete_many({"scan_id": "scan-1"})

    docs = await _persist(db, "scan-2", _NOW, _critical_cve())

    assert _first_seen(docs) == [_days_ago(200)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_stored_finding_without_first_seen_at_counts_from_its_scan(db, database):
    await _store_legacy_copy(db, _days_ago(150))

    docs = await _persist(db, "scan-1", _NOW, _critical_cve())

    assert _first_seen(docs) == [_days_ago(150)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_another_projects_history_is_not_inherited(db, database):
    await _persist(db, "other-scan", _days_ago(200), _critical_cve(), project_id=_OTHER_PROJECT)

    docs = await _persist(db, "scan-1", _NOW, _critical_cve())

    assert _first_seen(docs) == [_NOW]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_versionless_finding_inherits_like_any_other(db, database):
    await _persist(db, "scan-1", _days_ago(40), _versionless_sast())

    docs = await _persist(db, "scan-2", _NOW, _versionless_sast())

    assert _first_seen(docs) == [_days_ago(40)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_scan_persisted_after_a_newer_one_keeps_its_own_earlier_detection(db, database):
    await _persist(db, "newer-scan", _NOW, _critical_cve())

    docs = await _persist(db, "older-scan", _days_ago(10), _critical_cve())

    assert _first_seen(docs) == [_days_ago(10)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_critical_cve_first_seen_200_days_ago_fails_its_sla(db, database):
    await _persist(db, "scan-1", _days_ago(200), _critical_cve())
    current = await _persist(db, "scan-2", _NOW, _critical_cve())

    critical = await _critical_control(db, "scan-2")

    assert critical.status == ControlStatus.FAILED.value
    assert critical.evidence_finding_ids == [current[0]["_id"]]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_critical_cve_in_a_copy_predating_first_seen_at_fails_its_sla_from_its_scan_date(db, database):
    await _store_legacy_copy(db, _days_ago(400))

    critical = await _critical_control(db, "legacy-scan")

    assert critical.status == ControlStatus.FAILED.value


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_first_detection_lookup_reads_index_entries_only(db, monkeypatch):
    await create_indexes(db)
    await _store_legacy_copy(db, _days_ago(150))
    unrelated = [
        Finding(
            id=f"lib-{n}:1.0",
            type=FindingType.VULNERABILITY,
            severity=Severity.LOW,
            component=f"lib-{n}",
            version="1.0",
            description="noise",
            scanners=["trivy"],
        )
        for n in range(40)
    ]
    for scan in range(3):
        await _persist(db, f"scan-{scan}", _days_ago(30 - scan), _critical_cve(), _versionless_sast(), *unrelated)
    issued: list[list[dict]] = []
    aggregate = FindingRepository.aggregate

    async def _record(self, pipeline, *args, **kwargs):
        issued.append(pipeline)
        return await aggregate(self, pipeline, *args, **kwargs)

    monkeypatch.setattr(FindingRepository, "aggregate", _record)

    docs = await _persist(db, "scan-3", _NOW, _critical_cve(), _versionless_sast())
    explain = await db.command(
        {"explain": {"aggregate": "findings", "pipeline": issued[0], "cursor": {}}, "verbosity": "executionStats"}
    )

    stages = _explain_values(explain, "stage")
    docs_examined = _explain_values(explain, "totalDocsExamined")
    assert "IXSCAN" in stages
    assert "FETCH" not in stages
    assert docs_examined and not any(docs_examined)
    assert max(_explain_values(explain, "totalKeysExamined")) < len(unrelated)
    assert {doc["component"]: ensure_utc(doc["first_seen_at"]) for doc in docs} == {
        "log4j-core": _days_ago(150),
        "src/app.py": _days_ago(30),
    }

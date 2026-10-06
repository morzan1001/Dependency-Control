"""The CVE SLA ages each advisory from its first detection on the component in the project, whatever the
version, carried forward at persist time.

Retention deletes old scans, so the date has to travel with every scan's copy of the finding: an age
read back from the surviving history could never outgrow the retention window.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core import ensure_utc
from app.core.init_db import create_indexes
from app.models.finding import Finding, FindingType, Severity
from app.models.waiver import Waiver
from app.repositories.findings import _DETECTION_CHUNK_COMPONENTS, FindingRepository
from app.repositories.waivers import WaiverRepository
from app.schemas.compliance import ControlResult, ControlStatus
from app.services.aggregation.aggregator import ResultAggregator
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records, _stamp_first_seen
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from tests.helpers.compliance import evaluation_input
from tests.helpers.findings import aggregated_vulnerability

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


@pytest_asyncio.fixture(autouse=True)
async def _indexes(db):
    """Persisting hints indexes that a real server holds only once init_db has run."""
    await create_indexes(db)


def _vulnerable(component: str, version: str, *advisories: tuple[str, Severity]) -> Finding:
    return aggregated_vulnerability(component, version, *({"id": cve, "severity": sev} for cve, sev in advisories))


def _log4j_advisories(*advisories: tuple[str, Severity], version: str = "2.14.1") -> Finding:
    return _vulnerable("log4j-core", version, *advisories)


def _critical_cve() -> Finding:
    return _log4j_advisories(("CVE-2021-44228", Severity.CRITICAL))


def _critical_and_high_cves() -> Finding:
    return _log4j_advisories(("CVE-2021-44228", Severity.CRITICAL), ("CVE-2021-45046", Severity.HIGH))


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


async def _sla_controls(db, scan_id: str) -> dict[str, ControlResult]:
    """The CVE-SLA verdicts by control id over the findings the engine reads for ``scan_id``."""
    engine = ComplianceReportEngine()
    framework = CveRemediationSlaFramework()
    resolved = ResolvedScope(scope="project", scope_id=_PROJECT, project_ids=[_PROJECT])
    clause, fields, _ = engine._finding_type_filter(framework)
    findings = await engine._collect_findings(db, [scan_id], clause, fields)
    evaluation = await framework.evaluate(
        evaluation_input(resolved=resolved, findings=findings, scan_ids=[scan_id], db=db)
    )
    return {c.control_id: c for c in evaluation.controls}


def _first_seen(docs: list[dict]) -> list[datetime | None]:
    return [ensure_utc(doc.get("first_seen_at")) for doc in docs]


def _advisory_first_seen(doc: dict) -> dict[str, datetime | None]:
    return {a["id"]: ensure_utc(a.get("first_seen_at")) for a in doc["details"]["vulnerabilities"]}


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

    critical = (await _sla_controls(db, "scan-2"))["CVE-SLA-CRITICAL"]

    assert critical.status == ControlStatus.FAILED.value
    assert critical.evidence_finding_ids == [current[0]["_id"]]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_critical_cve_in_a_copy_predating_first_seen_at_fails_its_sla_from_its_scan_date(db, database):
    await _store_legacy_copy(db, _days_ago(400))

    critical = (await _sla_controls(db, "legacy-scan"))["CVE-SLA-CRITICAL"]

    assert critical.status == ControlStatus.FAILED.value


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_each_cve_of_a_finding_is_held_to_its_own_severitys_sla(db, database):
    [doc] = await _persist(
        db,
        "scan-1",
        _days_ago(40),
        _critical_and_high_cves(),
    )

    controls = await _sla_controls(db, "scan-1")

    assert controls["CVE-SLA-CRITICAL"].status == ControlStatus.FAILED.value
    assert controls["CVE-SLA-HIGH"].status == ControlStatus.FAILED.value
    assert controls["CVE-SLA-HIGH"].evidence_finding_ids == [doc["_id"]]
    assert controls["CVE-SLA-MEDIUM"].status == ControlStatus.PASSED.value


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_waived_cve_leaves_its_severitys_sla_to_the_findings_live_cves(db, database):
    await WaiverRepository(db).create(
        Waiver(project_id=_PROJECT, vulnerability_id="CVE-2021-45046", reason="not reachable", created_by="u")
    )
    await _persist(
        db,
        "scan-1",
        _days_ago(40),
        _critical_and_high_cves(),
    )

    controls = await _sla_controls(db, "scan-1")

    assert controls["CVE-SLA-CRITICAL"].status == ControlStatus.FAILED.value
    assert controls["CVE-SLA-HIGH"].status == ControlStatus.PASSED.value


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_finding_waived_cve_by_cve_is_waived_evidence_under_each_cves_severity(db, database):
    for cve in ("CVE-2021-44228", "CVE-2021-45046"):
        await WaiverRepository(db).create(
            Waiver(project_id=_PROJECT, vulnerability_id=cve, reason="not reachable", created_by="u")
        )
    await _persist(db, "scan-1", _days_ago(40), _critical_and_high_cves())

    controls = await _sla_controls(db, "scan-1")

    assert controls["CVE-SLA-CRITICAL"].status == ControlStatus.WAIVED.value
    assert controls["CVE-SLA-HIGH"].status == ControlStatus.WAIVED.value
    assert controls["CVE-SLA-HIGH"].waiver_reasons == ["not reachable"]


_LOG4SHELL = ("CVE-2021-44228", Severity.CRITICAL)
_CONTEXT_LOOKUP = ("CVE-2021-45046", Severity.CRITICAL)
_JDBC_APPENDER = ("CVE-2021-44832", Severity.MEDIUM)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_cve_kept_across_a_version_bump_keeps_its_first_detection(db, database):
    await _persist(db, "scan-1", _days_ago(200), _log4j_advisories(_LOG4SHELL, version="2.14.1"))

    [doc] = await _persist(db, "scan-2", _NOW, _log4j_advisories(_LOG4SHELL, version="2.15.0"))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200)}
    assert _first_seen([doc]) == [_days_ago(200)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_critical_cve_kept_across_a_version_bump_stays_overdue(db, database):
    await _persist(db, "scan-1", _days_ago(200), _log4j_advisories(_LOG4SHELL, version="2.14.1"))
    [doc] = await _persist(db, "scan-2", _NOW, _log4j_advisories(_LOG4SHELL, version="2.15.0"))

    critical = (await _sla_controls(db, "scan-2"))["CVE-SLA-CRITICAL"]

    assert critical.status == ControlStatus.FAILED.value
    assert critical.evidence_finding_ids == [doc["_id"]]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_cve_new_to_a_component_is_first_seen_by_its_own_scan(db, database):
    await _persist(db, "scan-1", _days_ago(200), _log4j_advisories(("CVE-2021-44228", Severity.HIGH)))

    [doc] = await _persist(
        db, "scan-2", _days_ago(3), _log4j_advisories(("CVE-2021-44228", Severity.HIGH), _CONTEXT_LOOKUP)
    )
    controls = await _sla_controls(db, "scan-2")

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200), "CVE-2021-45046": _days_ago(3)}
    assert controls["CVE-SLA-HIGH"].status == ControlStatus.FAILED.value
    assert controls["CVE-SLA-CRITICAL"].status == ControlStatus.PASSED.value


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_kept_cve_outlives_retention_deleting_the_version_that_first_had_it(db, database):
    await _persist(db, "scan-1", _days_ago(200), _log4j_advisories(_LOG4SHELL, version="2.14.1"))
    await _persist(db, "scan-2", _days_ago(100), _log4j_advisories(_LOG4SHELL, version="2.15.0"))
    await db.findings.delete_many({"scan_id": "scan-1"})

    [doc] = await _persist(db, "scan-3", _NOW, _log4j_advisories(_LOG4SHELL, version="2.15.0"))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200)}


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_version_another_branch_moved_off_keeps_its_own_cve_dates(db, database):
    await _persist(db, "main-1", _days_ago(200), _log4j_advisories(_LOG4SHELL, version="2.14.1"))
    await _persist(db, "feature-1", _days_ago(10), _log4j_advisories(_JDBC_APPENDER, version="2.17.0"))

    [doc] = await _persist(db, "main-2", _NOW, _log4j_advisories(_LOG4SHELL, version="2.14.1"))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200)}


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_cve_one_scan_of_its_version_missed_keeps_its_first_detection(db, database):
    high, low = ("CVE-2021-44228", Severity.HIGH), ("CVE-2021-45046", Severity.LOW)
    await _persist(db, "scan-1", _days_ago(200), _log4j_advisories(high, low))
    await _persist(db, "scan-2", _days_ago(5), _log4j_advisories(low))

    [doc] = await _persist(db, "scan-3", _days_ago(1), _log4j_advisories(high, low))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200), "CVE-2021-45046": _days_ago(200)}
    assert (await _sla_controls(db, "scan-3"))["CVE-SLA-HIGH"].status == ControlStatus.FAILED.value


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_an_advisory_stored_without_its_own_date_counts_from_its_findings_first_detection(db, database):
    dated, _ = _prepare_finding_records([_critical_cve()], "dated-scan", _PROJECT, _days_ago(30))
    await db.findings.insert_many([{**dated[0], "first_seen_at": _days_ago(150), "created_at": _days_ago(30)}])

    [doc] = await _persist(db, "scan-1", _NOW, _log4j_advisories(_LOG4SHELL, version="2.15.0"))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(150)}


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_cve_matches_its_earlier_detection_under_an_alias(db, database):
    ghsa = Finding(
        id="GHSA-jfh8-c2jp-5v3q",
        type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        component="log4j-core",
        version="2.14.1",
        description="",
        scanners=["osv"],
        aliases=["CVE-2021-44228"],
    )
    aggregator = ResultAggregator()
    aggregator.add_finding(ghsa)
    await _persist(db, "scan-1", _days_ago(200), *aggregator.get_findings())

    [doc] = await _persist(db, "scan-2", _NOW, _log4j_advisories(_LOG4SHELL, version="2.15.0"))

    assert _advisory_first_seen(doc) == {"CVE-2021-44228": _days_ago(200)}


def _outdated(component: str, version: str) -> Finding:
    return Finding(
        id=f"OUTDATED-{component}",
        type=FindingType.OUTDATED,
        severity=Severity.INFO,
        component=component,
        version=version,
        description="a newer release exists",
        scanners=["outdated_packages"],
    )


async def _profiled(db, awaitable) -> list[dict]:
    """What the awaited call ran against findings, as the server's profiler recorded it."""
    await db.command("profile", 2)
    try:
        await awaitable
    finally:
        await db.command("profile", 0)
    return await db["system.profile"].find({"ns": f"{db.name}.findings"}).to_list(None)


def _cold_plan_cache(db):
    """Prod replans these lookups on nearly every persist, so judge the plan a cold cache gets."""
    return db.command({"planCacheClear": "findings"})


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_first_detection_lookup_reads_index_keys_of_the_dated_findings_only(db):
    legacy, _ = _prepare_finding_records([_outdated("left-pad", "1.0")], "legacy-scan", _PROJECT, _days_ago(150))
    await db.findings.insert_many(legacy)
    noise = [_outdated(f"lib-{n}", "1.0") for n in range(40)]
    for scan in range(3):
        await _persist(
            db, f"scan-{scan}", _days_ago(30 - scan), _outdated("left-pad", "1.0"), _versionless_sast(), *noise
        )
    current = [_outdated("left-pad", "1.0"), _versionless_sast()]
    records, _ = _prepare_finding_records(current, "scan-now", _PROJECT, _NOW)
    await _cold_plan_cache(db)

    commands = await _profiled(db, _stamp_first_seen(records, _PROJECT, FindingRepository(db)))

    copies_of_dated_findings = 4 + 3
    assert not any(command.get("fromMultiPlanner") for command in commands)
    assert sum(command["docsExamined"] for command in commands) == 0
    assert 0 < sum(command["keysExamined"] for command in commands) <= copies_of_dated_findings + len(records)
    assert {record["component"]: ensure_utc(record["first_seen_at"]) for record in records} == {
        "left-pad": _days_ago(150),
        "src/app.py": _days_ago(30),
    }


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_advisory_lookup_reads_one_copy_per_stored_version(db):
    for scan in range(4):
        await _persist(db, f"old-{scan}", _days_ago(90 - scan), _log4j_advisories(_LOG4SHELL, version="2.14.1"))
    for scan in range(4):
        kept_and_new = _log4j_advisories(_LOG4SHELL, _CONTEXT_LOOKUP, version="2.15.0")
        await _persist(db, f"new-{scan}", _days_ago(40 - scan), kept_and_new)
    current = _log4j_advisories(_LOG4SHELL, _CONTEXT_LOOKUP, version="2.16.0")
    records, _ = _prepare_finding_records([current], "scan-now", _PROJECT, _NOW)
    await _cold_plan_cache(db)

    commands = await _profiled(db, _stamp_first_seen(records, _PROJECT, FindingRepository(db)))

    stored_versions = 2
    assert not any(command.get("fromMultiPlanner") for command in commands)
    assert sum(command["docsExamined"] for command in commands) == stored_versions
    assert sum(command["keysExamined"] for command in commands) <= 3 * stored_versions + 2
    assert _advisory_first_seen(records[0]) == {
        "CVE-2021-44228": _days_ago(90),
        "CVE-2021-45046": _days_ago(40),
    }


def _module(n: int) -> str:
    return f"github.com/example-org/module-{n:018d}"


def _module_outdated(n: int) -> Finding:
    return _outdated(_module(n), "1.0.0")


def _module_records(*numbers: int) -> list[dict]:
    records, _ = _prepare_finding_records([_module_outdated(n) for n in numbers], "scan-new", _PROJECT, _NOW)
    return records


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_first_detection_lookup_answers_for_400000_components(db):
    await _persist(db, "scan-old", _days_ago(90), _module_outdated(399_999))

    earliest = await FindingRepository(db).earliest_detections(_PROJECT, _module_records(*range(400_000)))

    assert {identity[1]: ensure_utc(date) for identity, date in earliest.items()} == {_module(399_999): _days_ago(90)}


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_copies_across_two_lookup_chunks_give_the_single_chunk_dates(db, database):
    await _persist(db, "scan-a", _days_ago(60), _module_outdated(0))
    await _persist(db, "scan-b", _days_ago(30), _module_outdated(_DETECTION_CHUNK_COMPONENTS))
    repo = FindingRepository(db)

    single_chunk = await repo.earliest_detections(_PROJECT, _module_records(0, _DETECTION_CHUNK_COMPONENTS))
    two_chunks = await repo.earliest_detections(_PROJECT, _module_records(*range(_DETECTION_CHUNK_COMPONENTS + 1)))

    assert two_chunks == single_chunk
    assert sorted(ensure_utc(date) for date in two_chunks.values()) == [_days_ago(60), _days_ago(30)]


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_advisories_across_two_lookup_chunks_give_the_single_chunk_dates(db, database, monkeypatch):
    await _persist(db, "scan-a", _days_ago(60), _vulnerable(_module(0), "1.0.0", _LOG4SHELL))
    await _persist(db, "scan-b", _days_ago(30), _vulnerable(_module(1), "1.0.0", _LOG4SHELL))
    current = [_vulnerable(_module(n), "1.0.0", _LOG4SHELL) for n in (0, 1)]
    records, _ = _prepare_finding_records(current, "scan-new", _PROJECT, _NOW)
    repo = FindingRepository(db)

    single_chunk = await repo.advisory_detections(_PROJECT, records)
    monkeypatch.setattr("app.repositories.findings._DETECTION_CHUNK_COMPONENTS", 1)
    two_chunks = await repo.advisory_detections(_PROJECT, records)

    assert two_chunks == single_chunk
    assert sorted(ensure_utc(date) for date in two_chunks.values()) == [_days_ago(60), _days_ago(30)]

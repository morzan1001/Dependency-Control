import asyncio
import gc
import threading
import time
import weakref
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import settings
from app.core.constants import COMPLIANCE_REPORT_SLOTS, SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.core.metrics import compliance_reports_total
from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.models.crypto_asset import CryptoAsset
from app.models.finding import Severity
from app.models.project import Project, Scan
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.findings import FindingRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFormat, ReportFramework, ReportStatus
from app.schemas.project import LicensePolicySchema
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _prepare_finding_records, _stamp_first_seen
from app.services.analytics.scopes import ResolvedScope, ScopeResolver
from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
from app.services.compliance import engine as engine_module
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.normalizers.license import normalize_license
from tests.helpers.analyzers import analyze_cyclonedx
from tests.helpers.compliance import evaluation_input
from tests.helpers.findings import aggregated_vulnerability


def _report(**overrides):
    base = {
        "scope": "user",
        "scope_id": None,
        "framework": ReportFramework.NIST_SP_800_131A,
        "format": ReportFormat.JSON,
        "status": ReportStatus.PENDING,
        "requested_by": "u1",
        "requested_at": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return ComplianceReport(**base)


@pytest.mark.asyncio
async def test_engine_marks_report_completed_on_success():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    inputs = evaluation_input(policy_version=1, iana_catalog_version=2)
    evaluation = MagicMock(summary={"total": 0})
    fw = MagicMock(evaluate=AsyncMock(return_value=evaluation))

    resolver = MagicMock(resolve=AsyncMock(return_value=ResolvedScope(scope="user", scope_id=None, project_ids=[])))

    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=resolver,
        ),
        patch.dict(
            "app.services.compliance.engine.FRAMEWORK_REGISTRY",
            {ReportFramework.NIST_SP_800_131A: fw},
            clear=False,
        ),
        patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)),
        patch.object(engine, "_render", return_value=(b"{}", "x.json", "application/json")),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        outcome = await engine.generate(report=report, db=db, user=user)

    assert outcome == (ReportStatus.COMPLETED, {"total": 0})
    fw.evaluate.assert_awaited_once_with(inputs)
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED
    assert final_call.kwargs.get("policy_version_snapshot") == 1
    assert final_call.kwargs.get("iana_catalog_version_snapshot") == 2


@pytest.mark.asyncio
async def test_engine_marks_failed_on_exception():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    resolver = MagicMock(resolve=AsyncMock(side_effect=RuntimeError("boom")))
    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=resolver,
        ),
    ):
        await engine.generate(report=report, db=db, user=user)

    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.FAILED
    assert "boom" in (final_call.kwargs.get("error_message") or "")


@pytest.mark.asyncio
async def test_a_failed_report_expires_like_a_completed_one(db):
    """The requester has no access to the project, so the scope does not resolve."""
    report = _report(scope="project", scope_id="p")
    await ComplianceReportRepository(db).create(report)
    before = datetime.now(timezone.utc).replace(microsecond=0)  # stored datetimes keep milliseconds only

    outcome = await ComplianceReportEngine().generate(
        report=report, db=db, user=User(id="u1", username="u1", email="u1@corp.com", permissions=[])
    )

    stored = await ComplianceReportRepository(db).get_by_id(report.id)
    assert outcome == (ReportStatus.FAILED, {})
    assert stored.status == ReportStatus.FAILED
    assert stored.expires_at >= before + timedelta(days=settings.COMPLIANCE_REPORT_RETENTION_DAYS)


@pytest.mark.asyncio
async def test_no_more_reports_evaluate_at_once_than_there_are_slots(monkeypatch):
    monkeypatch.setattr(engine_module, "_REPORT_SLOTS", asyncio.Semaphore(COMPLIANCE_REPORT_SLOTS))
    engine = ComplianceReportEngine()
    framework = MagicMock(evaluate=AsyncMock(return_value=MagicMock()))
    resolved = ResolvedScope(scope="user", scope_id=None, project_ids=[])
    in_flight, peak, release = 0, 0, asyncio.Event()

    async def gather(*_):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await release.wait()
        in_flight -= 1
        return evaluation_input()

    with patch.object(engine, "_gather_inputs", new=gather):
        runs = [
            asyncio.create_task(engine.evaluate(MagicMock(), resolved, framework))
            for _ in range(COMPLIANCE_REPORT_SLOTS + 1)
        ]
        for _ in range(5):
            await asyncio.sleep(0)
        assert peak == COMPLIANCE_REPORT_SLOTS
        release.set()
        await asyncio.gather(*runs)

    assert framework.evaluate.await_count == COMPLIANCE_REPORT_SLOTS + 1


def _reports_counted(status: str) -> float:
    return compliance_reports_total.labels(framework=ReportFramework.NIST_SP_800_131A.value, status=status)._value.get()


@pytest.mark.asyncio
async def test_engine_counts_a_completed_report_under_the_success_status():
    """A success rate reads success/(success+error), so both branches must use these two labels."""
    before = _reports_counted("success")
    engine = ComplianceReportEngine()
    report = _report()
    inputs = evaluation_input()
    fw = MagicMock(evaluate=AsyncMock(return_value=MagicMock(summary={"total": 0})))

    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=AsyncMock(), get=AsyncMock(return_value=report)),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=MagicMock(
                resolve=AsyncMock(return_value=ResolvedScope(scope="user", scope_id=None, project_ids=[]))
            ),
        ),
        patch.dict(
            "app.services.compliance.engine.FRAMEWORK_REGISTRY",
            {ReportFramework.NIST_SP_800_131A: fw},
            clear=False,
        ),
        patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)),
        patch.object(engine, "_render", return_value=(b"{}", "x.json", "application/json")),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        await engine.generate(report=report, db=MagicMock(), user=MagicMock(id="u1", permissions=frozenset()))

    assert _reports_counted("success") == before + 1


@pytest.mark.asyncio
async def test_engine_counts_a_crashed_report_under_the_error_status():
    before = _reports_counted("error")
    engine = ComplianceReportEngine()
    report = _report()

    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=AsyncMock(), get=AsyncMock(return_value=report)),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=MagicMock(resolve=AsyncMock(side_effect=RuntimeError("boom"))),
        ),
    ):
        await engine.generate(report=report, db=MagicMock(), user=MagicMock(id="u1", permissions=frozenset()))

    assert _reports_counted("error") == before + 1


async def _store_project(db, pid, *, scanned=True, failed_analyzers=None, **fields):
    """The project and its head scan as ingest and the analysis engine leave them."""
    scan_id = f"scan-{pid}" if scanned else None
    project = Project(id=pid, name=f"name-{pid}", latest_scan_id=scan_id, members=[{"user_id": "u1"}], **fields)
    await db.projects.insert_one(project.model_dump(by_alias=True))
    if scanned:
        status = SCAN_STATUS_COMPLETED_WITH_ERRORS if failed_analyzers else SCAN_STATUS_COMPLETED
        scan = Scan(id=scan_id, project_id=pid, branch="main", status=status, failed_analyzers=failed_analyzers)
        await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan_id


async def _store_findings(db, pid, scan_id, findings):
    records, _ = _prepare_finding_records(list(findings), scan_id, pid, datetime.now(timezone.utc))
    await _stamp_first_seen(records, pid, FindingRepository(db))
    await db.findings.insert_many(records)


def _vulnerability(component, severity):
    return aggregated_vulnerability(component, "2.14.1", {"id": "CVE-2021-44228", "severity": severity})


def _project_scope(pid="p1"):
    return ResolvedScope(scope="project", scope_id=pid, project_ids=[pid])


async def _user_scope(db):
    user = User(id="u1", username="u1", email="u1@corp.com", permissions=[Permissions.PROJECT_READ])
    return await ScopeResolver(db, user).resolve(scope="user", scope_id=None)


def _reads(collection):
    """Every find the collection serves, as (query, projection, options)."""
    reads: list[tuple] = []
    find = collection.find

    def recording_find(query=None, projection=None, **kwargs):
        reads.append((query, projection, kwargs))
        return find(query, projection, **kwargs)

    collection.find = recording_find
    return reads


async def _gather(db, resolved, key):
    return await ComplianceReportEngine()._gather_inputs(db, resolved, FRAMEWORK_REGISTRY[key])


@pytest.mark.asyncio
async def test_engine_gather_inputs_builds_evaluation_input(db):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")

    result = await _gather(db, await _user_scope(db), ReportFramework.NIST_SP_800_131A)

    assert "user scope" in result.scope_description
    assert result.scan_ids == ["scan-p1"]
    assert result.coverage.gaps == []


@pytest.mark.asyncio
async def test_an_unscanned_project_withholds_a_cve_pass(db):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    await _store_project(db, "p2", scanned=False)

    inputs, evaluation = await ComplianceReportEngine().evaluate(
        db, await _user_scope(db), CveRemediationSlaFramework()
    )

    critical = next(c for c in evaluation.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.status == ControlStatus.NOT_EVALUATED.value
    assert "name-p2" in (critical.status_reason or "")
    assert inputs.coverage.gaps == ["project 'name-p2' has no usable scan"]
    assert evaluation.coverage.complete is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed", "gap_in", "no_gap_in"),
    [
        ("trivy", ReportFramework.CVE_REMEDIATION_SLA, ReportFramework.NIST_SP_800_131A),
        ("crypto_weak_algorithm", ReportFramework.NIST_SP_800_131A, ReportFramework.CVE_REMEDIATION_SLA),
        ("license_compliance", ReportFramework.LICENSE_AUDIT, ReportFramework.FIPS_140_3),
    ],
)
async def test_a_failed_analyzer_is_a_gap_only_for_the_framework_it_feeds(db, failed, gap_in, no_gap_in):
    await seed_crypto_policies(db)
    await _store_project(db, "p1", failed_analyzers=[failed, "end_of_life"])

    affected = await _gather(db, _project_scope(), gap_in)
    unaffected = await _gather(db, _project_scope(), no_gap_in)

    assert affected.coverage.gaps == [f"project 'name-p1': {failed} failed in scan scan-p1"]
    assert unaffected.coverage.gaps == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("active", "key"),
    [(["trivy", "osv"], ReportFramework.LICENSE_AUDIT), (["license_compliance"], ReportFramework.CVE_REMEDIATION_SLA)],
)
async def test_a_project_running_none_of_the_framework_analyzers_is_a_gap(db, active, key):
    await seed_crypto_policies(db)
    await _store_project(db, "p1", active_analyzers=active)
    await _store_project(db, "p2")

    inputs = await _gather(db, await _user_scope(db), key)

    assert len(inputs.coverage.gaps) == 1
    assert inputs.coverage.gaps[0].startswith("project 'name-p1' runs none of ")


@pytest.mark.asyncio
@pytest.mark.parametrize("key", [k for k in ReportFramework if k is not ReportFramework.PQC_MIGRATION_PLAN])
async def test_every_findings_read_projects_named_scalars_and_filters_by_scan_alone(db, key):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    reads = _reads(db.findings)

    await _gather(db, _project_scope(), key)

    ((query, projection, _),) = reads
    assert set(projection.values()) == {1}
    assert "details" not in projection
    assert "project_id" not in query


@pytest.mark.asyncio
async def test_cve_sla_reads_only_the_severities_it_has_a_deadline_for(db):
    await seed_crypto_policies(db)
    scan_id = await _store_project(db, "p1")
    await _store_findings(
        db, "p1", scan_id, [_vulnerability("log4j-core", Severity.CRITICAL), _vulnerability("commons-io", Severity.LOW)]
    )

    inputs = await _gather(db, _project_scope(), ReportFramework.CVE_REMEDIATION_SLA)

    assert [f["severity"] for f in inputs.findings] == [Severity.CRITICAL.value]
    assert inputs.findings[0]["first_seen_at"] is not None


@pytest.mark.asyncio
async def test_license_audit_reads_only_the_categories_its_controls_judge(db):
    await seed_crypto_policies(db)
    scan_id = await _store_project(db, "p1")
    components = [
        {"type": "library", "name": "lgpl-lib", "version": "1.0.0", "licenses": [{"license": {"id": "LGPL-2.1-only"}}]},
        {"type": "library", "name": "bare-lib", "version": "1.0.0"},
    ]
    aggregator = ResultAggregator()
    normalize_license(aggregator, await analyze_cyclonedx(LicenseAnalyzer(), components, {}), source="sbom.json")
    await _store_findings(db, "p1", scan_id, aggregator.get_findings())

    inputs = await _gather(db, _project_scope(), ReportFramework.LICENSE_AUDIT)

    assert [f["details"] for f in inputs.findings] == [{"category": "unknown"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("key", [ReportFramework.NIST_SP_800_131A, ReportFramework.FIPS_140_3])
async def test_a_crypto_framework_reads_only_the_finding_types_its_controls_map_to(db, key):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    reads = _reads(db.findings)

    await _gather(db, _project_scope(), key)

    ((query, _, _),) = reads
    assert query["type"] == {"$in": ["crypto_weak_algorithm", "crypto_weak_key"]}


@pytest.mark.asyncio
async def test_the_pqc_plan_reads_neither_findings_nor_assets(db):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    finding_reads, asset_reads = _reads(db.findings), _reads(db.crypto_assets)

    await _gather(db, _project_scope(), ReportFramework.PQC_MIGRATION_PLAN)

    assert finding_reads == asset_reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("key", [ReportFramework.CVE_REMEDIATION_SLA, ReportFramework.LICENSE_AUDIT])
async def test_a_framework_without_crypto_controls_reads_no_assets(db, key):
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    asset_reads = _reads(db.crypto_assets)

    await _gather(db, _project_scope(), key)

    assert asset_reads == []


def _rsa(pid, scan_id, key_size_bits):
    return CryptoAsset(
        project_id=pid,
        scan_id=scan_id,
        bom_ref=f"crypto/algorithm/rsa-{pid}",
        name="RSA",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.PKE,
        key_size_bits=key_size_bits,
        occurrence_locations=["src/tls.py"],
    )


@pytest.mark.asyncio
async def test_the_inventory_comes_from_one_unsorted_read_across_the_scope(db):
    await seed_crypto_policies(db)
    for pid in ("p1", "p2"):
        scan_id = await _store_project(db, pid)
        await CryptoAssetRepository(db).bulk_upsert(pid, scan_id, [_rsa(pid, scan_id, 4096)])
    asset_reads = _reads(db.crypto_assets)

    inputs = await _gather(db, await _user_scope(db), ReportFramework.NIST_SP_800_131A)

    ((_, projection, options),) = asset_reads
    assert "sort" not in options
    assert set(projection.values()) == {1}
    assert sorted(a.project_id for a in inputs.crypto_assets) == ["p1", "p2"]
    assert inputs.crypto_assets[0].occurrence_locations == []


@pytest.mark.asyncio
async def test_a_stored_rsa_key_size_reaches_the_key_size_control(db):
    await seed_crypto_policies(db)
    scan_id = await _store_project(db, "p1")
    await CryptoAssetRepository(db).bulk_upsert("p1", scan_id, [_rsa("p1", scan_id, 4096)])

    _, evaluation = await ComplianceReportEngine().evaluate(
        db, _project_scope(), FRAMEWORK_REGISTRY[ReportFramework.NIST_SP_800_131A]
    )

    rsa = next(c for c in evaluation.controls if c.control_id == "NIST-131A-nist-131a-rsa-min-2048")
    assert rsa.status == ControlStatus.PASSED.value


@pytest.mark.asyncio
async def test_generate_lets_go_of_the_inputs_before_rendering():
    """Rendering, upload and the status write run long after evaluation, so the findings may not stay alive."""
    engine = ComplianceReportEngine()
    report = _report(framework=ReportFramework.CVE_REMEDIATION_SLA)
    handed_out: list[weakref.ref] = []
    alive_at_render: list[bool] = []

    async def gather(db, resolved, framework):
        inputs = evaluation_input(policy_version=3, iana_catalog_version=4)
        handed_out.append(weakref.ref(inputs))
        return inputs

    def render(fmt, framework, evaluation, rep):
        gc.collect()
        alive_at_render.append(handed_out[0]() is not None)
        return b"{}", "x.json", "application/json"

    update_status = AsyncMock()
    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=update_status),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=MagicMock(resolve=AsyncMock(return_value=_project_scope())),
        ),
        patch.object(engine, "_gather_inputs", new=gather),
        patch.object(engine, "_render", side_effect=render),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        await engine.generate(report=report, db=MagicMock(), user=MagicMock(id="u1", permissions=frozenset()))

    assert alive_at_render == [False]
    assert update_status.call_args_list[-1].kwargs["policy_version_snapshot"] == 3
    assert update_status.call_args_list[-1].kwargs["iana_catalog_version_snapshot"] == 4


@pytest.mark.asyncio
async def test_reports_render_one_at_a_time_while_the_event_loop_keeps_running(monkeypatch):
    """A large-scope PDF lays out for tens of seconds at hundreds of MB; a blocked loop fails the liveness probe."""
    monkeypatch.setattr(engine_module, "_RENDER_SLOT", asyncio.Semaphore(1))
    engine = ComplianceReportEngine()
    loop = asyncio.get_running_loop()
    rendering: list[str] = []
    overlapped: list[bool] = []
    loop_ran_during_render: list[bool] = []

    def slow_render(fmt, framework, evaluation, rep):
        rendering.append(rep.id)
        overlapped.append(len(rendering) > 1)
        loop_ran = threading.Event()
        loop.call_soon_threadsafe(loop_ran.set)
        loop_ran_during_render.append(loop_ran.wait(timeout=5))
        time.sleep(0.2)
        rendering.remove(rep.id)
        return b"{}", "x.json", "application/json"

    with (
        patch(
            "app.services.compliance.engine.ComplianceReportRepository",
            return_value=MagicMock(update_status=AsyncMock()),
        ),
        patch(
            "app.services.compliance.engine.ScopeResolver",
            return_value=MagicMock(resolve=AsyncMock(return_value=_project_scope())),
        ),
        patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=evaluation_input())),
        patch.object(engine, "_render", side_effect=slow_render),
        patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")),
    ):
        outcomes = await asyncio.gather(
            *(
                engine.generate(
                    report=_report(framework=ReportFramework.CVE_REMEDIATION_SLA),
                    db=MagicMock(),
                    user=MagicMock(id="u1", permissions=frozenset()),
                )
                for _ in range(2)
            )
        )

    assert [status for status, _ in outcomes] == [ReportStatus.COMPLETED] * 2
    assert loop_ran_during_render == [True, True]
    assert overlapped == [False, False]


@pytest.mark.asyncio
async def test_gather_inputs_passes_the_saved_license_policy_beside_the_crypto_rules(db):
    await seed_crypto_policies(db)
    await _store_project(db, "p1", analyzer_settings={"license_compliance": {"allow_strong_copyleft": True}})

    result = await _gather(db, _project_scope(), ReportFramework.LICENSE_AUDIT)

    assert result.license_policy == LicensePolicySchema(allow_strong_copyleft=True)


@pytest.mark.asyncio
async def test_gather_inputs_ignores_a_stored_legacy_license_policy(db):
    """The report judges by the analyzer_settings entry the scan grades under, not by a top-level license_policy."""
    await seed_crypto_policies(db)
    await _store_project(db, "p1")
    await db.projects.update_one({"_id": "p1"}, {"$set": {"license_policy": {"allow_strong_copyleft": True}}})

    result = await _gather(db, _project_scope(), ReportFramework.LICENSE_AUDIT)

    assert result.license_policy == LicensePolicySchema()


@pytest.mark.asyncio
async def test_gather_inputs_uses_the_default_license_policy_for_a_multi_project_scope(db):
    await seed_crypto_policies(db)
    for pid in ("p1", "p2"):
        await _store_project(db, pid, analyzer_settings={"license_compliance": {"allow_strong_copyleft": True}})

    result = await _gather(db, await _user_scope(db), ReportFramework.LICENSE_AUDIT)

    assert result.license_policy == LicensePolicySchema()

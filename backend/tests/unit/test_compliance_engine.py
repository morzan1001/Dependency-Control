from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.compliance.frameworks.license_audit import LicenseAuditFramework
from app.services.compliance.frameworks.nist_sp_800_131a import NistSp800_131aFramework


def _report(**overrides):
    base = dict(
        scope="user",
        scope_id=None,
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.PENDING,
        requested_by="u1",
        requested_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return ComplianceReport(**base)


@pytest.mark.asyncio
async def test_engine_marks_report_completed_on_success():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    # Real EvaluationInput (not a MagicMock) so the engine must wire the correct shape.
    inputs = EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=[]),
        scope_description="u",
        crypto_assets=[],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=2,
        scan_ids=["s1"],
    )
    evaluation = MagicMock(summary={"total": 0})
    # spec=["evaluate"] makes hasattr(fw, "evaluate_async") False so the engine takes the sync path.
    fw = MagicMock(spec=["evaluate"])
    fw.evaluate = MagicMock(return_value=evaluation)

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
        await engine.generate(report=report, db=db, user=user)

    assert update_mock.call_count >= 2
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED

    # The engine must pass a real EvaluationInput so evaluators can rely on its attributes.
    fw.evaluate.assert_called_once()
    passed_arg = fw.evaluate.call_args.args[0]
    assert isinstance(passed_arg, EvaluationInput)
    assert passed_arg.policy_version == 1
    assert passed_arg.iana_catalog_version == 2


@pytest.mark.asyncio
async def test_engine_awaits_evaluate_async_when_available():
    """The engine must await evaluate_async when a framework exposes it."""
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    inputs = MagicMock(policy_version=1, iana_catalog_version=2)
    evaluation = MagicMock(summary={"total": 0})
    fw = MagicMock(spec=["evaluate_async"])
    fw.evaluate_async = AsyncMock(return_value=evaluation)

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
        await engine.generate(report=report, db=db, user=user)

    fw.evaluate_async.assert_awaited_once()
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED


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
async def test_engine_gather_inputs_builds_evaluation_input():
    db = MagicMock()
    scan_aggregate = MagicMock()

    async def scan_agg_iter():
        yield {"_id": "p1", "scan_id": "s1"}

    scan_aggregate.__aiter__ = lambda self: scan_agg_iter()
    db.scans.aggregate = MagicMock(return_value=scan_aggregate)

    db.scans.find_one = AsyncMock(return_value={"project_id": "p1"})

    asset_repo_mock = MagicMock(list_by_scan=AsyncMock(return_value=[]))

    findings_cursor = MagicMock()

    async def findings_iter():
        if False:
            yield None
        return

    findings_cursor.__aiter__ = lambda self: findings_iter()
    find_mock = MagicMock(limit=MagicMock(return_value=findings_cursor))
    db.findings.find = MagicMock(return_value=find_mock)

    policy_repo_mock = MagicMock(get_system_policy=AsyncMock(return_value=None))

    resolved = ResolvedScope(scope="user", scope_id=None, project_ids=["p1"])

    engine = ComplianceReportEngine()
    with (
        patch(
            "app.services.compliance.engine.CryptoAssetRepository",
            return_value=asset_repo_mock,
        ),
        patch(
            "app.services.compliance.engine.CryptoPolicyRepository",
            return_value=policy_repo_mock,
        ),
    ):
        result = await engine._gather_inputs(db, resolved)

    assert result.resolved is resolved
    assert "user scope" in result.scope_description
    assert result.scan_ids == ["s1"]


def _make_engine_db(*, agg_rows, project_doc=None):
    """MagicMock db that drives _gather_inputs and captures the findings query and per-scan lookups."""
    db = MagicMock()

    async def scan_agg_iter():
        for r in agg_rows:
            yield r

    scan_aggregate = MagicMock()
    scan_aggregate.__aiter__ = lambda self: scan_agg_iter()
    db.scans.aggregate = MagicMock(return_value=scan_aggregate)
    # project_id comes from the aggregation, so find_one must not be called.
    db.scans.find_one = AsyncMock(return_value={"project_id": "should-not-be-used"})

    captured: dict = {}

    async def findings_iter():
        if False:
            yield None
        return

    findings_cursor = MagicMock()
    findings_cursor.__aiter__ = lambda self: findings_iter()

    def find(query, projection):
        captured["findings_query"] = query
        captured["findings_projection"] = projection
        return MagicMock(limit=MagicMock(return_value=findings_cursor))

    db.findings.find = MagicMock(side_effect=find)

    projects_mock = MagicMock()
    projects_mock.find_one = AsyncMock(return_value=project_doc)
    db.__getitem__ = MagicMock(side_effect=lambda k: projects_mock if k == "projects" else MagicMock())

    return db, captured, projects_mock


async def _run_gather(engine, db, resolved, framework, asset_repo_mock=None):
    asset_repo_mock = asset_repo_mock or MagicMock(list_by_scan=AsyncMock(return_value=[]))
    policy_repo_mock = MagicMock(get_system_policy=AsyncMock(return_value=None))
    with (
        patch("app.services.compliance.engine.CryptoAssetRepository", return_value=asset_repo_mock),
        patch("app.services.compliance.engine.CryptoPolicyRepository", return_value=policy_repo_mock),
    ):
        result = await engine._gather_inputs(db, resolved, framework)
    return result, asset_repo_mock


@pytest.mark.asyncio
async def test_gather_inputs_loads_vulnerability_findings_for_cve_sla():
    """The findings filter must select `vulnerability` for the CVE SLA framework."""
    db, captured, _ = _make_engine_db(agg_rows=[{"_id": "p1", "scan_id": "s1"}])
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    await _run_gather(engine, db, resolved, CveRemediationSlaFramework())

    assert captured["findings_query"]["type"] == "vulnerability"


@pytest.mark.asyncio
async def test_gather_inputs_loads_license_findings_for_license_audit():
    """The findings filter must select `license` for the License-Audit framework."""
    db, captured, _ = _make_engine_db(agg_rows=[{"_id": "p1", "scan_id": "s1"}])
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    await _run_gather(engine, db, resolved, LicenseAuditFramework())

    assert captured["findings_query"]["type"] == "license"


@pytest.mark.asyncio
async def test_gather_inputs_keeps_crypto_filter_for_crypto_framework():
    db, captured, _ = _make_engine_db(agg_rows=[{"_id": "p1", "scan_id": "s1"}])
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    await _run_gather(engine, db, resolved, NistSp800_131aFramework())

    assert captured["findings_query"]["type"] == {"$regex": "^crypto_"}


@pytest.mark.asyncio
async def test_gather_inputs_union_filter_when_framework_unknown():
    """Without a framework, the filter must load every consumed finding type."""
    db, captured, _ = _make_engine_db(agg_rows=[{"_id": "p1", "scan_id": "s1"}])
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    await _run_gather(engine, db, resolved, None)

    regex = captured["findings_query"]["type"]["$regex"]
    assert "crypto_" in regex and "vulnerability" in regex and "license" in regex


@pytest.mark.asyncio
async def test_gather_inputs_prepends_project_license_policy():
    """The resolved project license policy must be plumbed into policy_rules[0]."""
    license_policy = {"allow_strong_copyleft": True, "allow_network_copyleft": False}
    db, _, projects_mock = _make_engine_db(
        agg_rows=[{"_id": "p1", "scan_id": "s1"}],
        project_doc={"_id": "p1", "license_policy": license_policy},
    )
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    result, _ = await _run_gather(engine, db, resolved, LicenseAuditFramework())

    assert result.policy_rules[0] == license_policy
    projects_mock.find_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_gather_inputs_prefers_analyzer_settings_license_policy():
    """analyzer_settings.license_compliance takes precedence over top-level project.license_policy."""
    db, _, _ = _make_engine_db(
        agg_rows=[{"_id": "p1", "scan_id": "s1"}],
        project_doc={
            "_id": "p1",
            "license_policy": {"allow_strong_copyleft": False},
            "analyzer_settings": {"license_compliance": {"allow_strong_copyleft": True}},
        },
    )
    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    engine = ComplianceReportEngine()

    result, _ = await _run_gather(engine, db, resolved, LicenseAuditFramework())

    assert result.policy_rules[0] == {"allow_strong_copyleft": True}


@pytest.mark.asyncio
async def test_gather_inputs_no_license_policy_for_multi_project_scope():
    """A multi-project team/user scope must not prepend a single project policy."""
    db, _, projects_mock = _make_engine_db(
        agg_rows=[{"_id": "p1", "scan_id": "s1"}, {"_id": "p2", "scan_id": "s2"}],
    )
    resolved = ResolvedScope(scope="team", scope_id="t1", project_ids=["p1", "p2"])
    engine = ComplianceReportEngine()

    result, _ = await _run_gather(engine, db, resolved, LicenseAuditFramework())

    assert result.policy_rules == []
    projects_mock.find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_crypto_assets_avoids_per_scan_find_one():
    """The engine must reuse the project_id from _pick_scan_ids instead of a find_one per scan."""
    db, _, _ = _make_engine_db(
        agg_rows=[{"_id": "p1", "scan_id": "s1"}, {"_id": "p2", "scan_id": "s2"}],
    )
    resolved = ResolvedScope(scope="team", scope_id="t1", project_ids=["p1", "p2"])
    engine = ComplianceReportEngine()

    _, asset_repo_mock = await _run_gather(engine, db, resolved, NistSp800_131aFramework())

    db.scans.find_one.assert_not_called()
    calls = {(c.args[0], c.args[1]) for c in asset_repo_mock.list_by_scan.call_args_list}
    assert calls == {("p1", "s1"), ("p2", "s2")}

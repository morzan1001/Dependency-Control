"""Standalone async tool functions for crypto / CBOM / compliance / PQC migration.

External collaborators (``ScopeResolver``, ``ComplianceReportEngine``, …) are
resolved through the parent package namespace at call time so test patches on
``app.services.chat.tools.<NAME>`` keep working.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional, cast

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.user import User


def _pkg() -> Any:
    """Return the parent package module so collaborators resolve via the namespace
    that tests patch."""
    from app.services.chat import tools as _tools_pkg

    return _tools_pkg


async def list_crypto_assets(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
    asset_type: Optional[str] = None,
    primitive: Optional[str] = None,
    name_search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    from app.repositories.crypto_asset import CryptoAssetRepository
    from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

    at_enum: Optional[CryptoAssetType] = None
    if asset_type:
        try:
            at_enum = CryptoAssetType(asset_type)
        except ValueError:
            at_enum = None
    pr_enum: Optional[CryptoPrimitive] = None
    if primitive:
        try:
            pr_enum = CryptoPrimitive(primitive)
        except ValueError:
            pr_enum = None

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan(
        project_id,
        scan_id,
        limit=min(limit, 500),
        skip=skip,
        asset_type=at_enum,
        primitive=pr_enum,
        name_search=name_search,
    )
    total = await repo.count_by_scan(project_id, scan_id)
    return {
        "items": [i.model_dump(by_alias=True) for i in items],
        "total": total,
    }


async def get_crypto_asset_details(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    asset_id: str,
) -> Optional[Dict[str, Any]]:
    from app.repositories.crypto_asset import CryptoAssetRepository

    asset = await CryptoAssetRepository(db).get(project_id, asset_id)
    return asset.model_dump(by_alias=True) if asset else None


async def get_crypto_summary(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
) -> Dict[str, Any]:
    from app.repositories.crypto_asset import CryptoAssetRepository

    return await CryptoAssetRepository(db).summary_for_scan(project_id, scan_id)


async def get_project_crypto_policy(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
) -> Dict[str, Any]:
    from app.services.crypto_policy.resolver import CryptoPolicyResolver

    effective = await CryptoPolicyResolver(db).resolve(project_id)
    return {
        "system_version": effective.system_version,
        "override_version": effective.override_version,
        "rules": [r.model_dump() for r in effective.rules],
    }


async def suggest_crypto_policy_override(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
) -> Dict[str, Any]:
    """Advisory only — returns rule_ids producing the most findings; caller
    decides whether to craft an override (this function does not write)."""
    cursor = db.findings.aggregate(
        [
            {"$match": {"project_id": project_id, "scan_id": scan_id, "type": {"$regex": "^crypto_"}}},
            {"$group": {"_id": "$details.rule_id", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]
    )
    top = [{"rule_id": row["_id"], "findings": row["count"]} async for row in cursor]
    return {
        "top_noisy_rules": top,
        "advice": (
            "Rules producing many findings may be candidates for project-scoped "
            "overrides (disable or adjust severity) if the codebase has accepted "
            "legacy risk. Review each rule before disabling."
        ),
    }


async def get_crypto_hotspots(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    group_by: str = "name",
    limit: int = 20,
) -> Dict[str, Any]:
    from app.services.analytics.crypto_hotspots import CryptoHotspotService, GroupBy

    pkg = _pkg()
    resolved = pkg.ResolvedScope(scope="project", scope_id=project_id, project_ids=[project_id])
    group_by_lit = cast(GroupBy, group_by)
    resp = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by=group_by_lit,
        limit=limit,
    )
    return resp.model_dump()


async def get_crypto_trends(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    metric: str = "total_crypto_findings",
    days: int = 30,
) -> Dict[str, Any]:
    from app.services.analytics.crypto_trends import (
        Bucket,
        CryptoTrendService,
        Metric,
    )

    pkg = _pkg()
    resolved = pkg.ResolvedScope(scope="project", scope_id=project_id, project_ids=[project_id])
    now = datetime.now(timezone.utc)
    days = max(1, min(days, 365))
    bucket: Bucket = "day" if days <= 14 else "week" if days <= 90 else "month"
    series = await CryptoTrendService(db).trend(
        resolved=resolved,
        metric=cast(Metric, metric),
        bucket=bucket,
        range_start=now - timedelta(days=days),
        range_end=now,
    )
    return series.model_dump()


async def get_scan_delta(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan_id: str,
    to_scan_id: str,
) -> Dict[str, Any]:
    from app.services.analytics.crypto_delta import compute_scan_delta

    delta = await compute_scan_delta(
        db,
        project_id,
        from_scan=from_scan_id,
        to_scan=to_scan_id,
    )
    return {
        "from_scan_id": delta.from_scan_id,
        "to_scan_id": delta.to_scan_id,
        "added": [e.model_dump() for e in delta.added],
        "removed": [e.model_dump() for e in delta.removed],
        "unchanged_count": delta.unchanged_count,
    }


async def generate_pqc_migration_plan(
    db: AsyncIOMotorDatabase,
    *,
    user: User,
    project_id: str,
    limit: int = 500,
) -> Dict[str, Any]:
    """Generate the PQC migration plan for one project. ScopeResolver re-runs
    the project-member check so scope construction stays consistent with every
    other analytics path."""
    pkg = _pkg()
    resolved = await pkg.ScopeResolver(db, user).resolve(scope="project", scope_id=project_id)
    gen = pkg.PQCMigrationPlanGenerator(db)
    resp = await gen.generate(resolved=resolved, limit=limit)
    dumped: Dict[str, Any] = resp.model_dump()
    return dumped


async def list_compliance_reports(
    db: AsyncIOMotorDatabase,
    *,
    project_id: Optional[str] = None,
    framework: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Recent compliance reports (metadata only, no artifacts)."""
    pkg = _pkg()
    fw: Optional[Any] = None
    if framework:
        try:
            fw = pkg.ReportFramework(framework)
        except ValueError:
            fw = None
    reports = await pkg.ComplianceReportRepository(db).list(
        scope="project" if project_id else None,
        scope_id=project_id,
        framework=fw,
        limit=limit,
    )
    return {"reports": [r.model_dump(by_alias=True) for r in reports]}


async def list_policy_audit_entries(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: str,
    project_id: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    pkg = _pkg()
    entries = await pkg.PolicyAuditRepository(db).list(
        policy_scope=cast(Literal["system", "project"], policy_scope),
        project_id=project_id,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True) for e in entries]}


async def get_framework_evaluation_summary(
    db: AsyncIOMotorDatabase,
    *,
    user: User,
    scope: str,
    scope_id: Optional[str],
    framework: str,
) -> Dict[str, Any]:
    """Run compliance evaluation in-process and return summary counts."""
    pkg = _pkg()
    try:
        fw_enum = pkg.ReportFramework(framework)
    except ValueError:
        return {"error": f"Unknown framework: {framework}"}
    resolver = pkg.ScopeResolver(db, user)
    resolved = await resolver.resolve(
        scope=cast(Literal["project", "team", "global", "user"], scope),
        scope_id=scope_id,
    )

    engine = pkg.ComplianceReportEngine()
    inputs = await engine._gather_inputs(db, resolved)
    framework_obj = pkg.FRAMEWORK_REGISTRY[fw_enum]
    if hasattr(framework_obj, "evaluate_async"):
        eval_result = await framework_obj.evaluate_async(inputs)
    else:
        eval_result = framework_obj.evaluate(inputs)
    return {
        "framework": framework,
        "framework_name": eval_result.framework_name,
        "summary": eval_result.summary,
    }

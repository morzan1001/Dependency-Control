"""Standalone async tool functions for crypto / CBOM / compliance / PQC migration.

Collaborators are resolved through the parent package namespace at call time so
test patches on ``app.services.chat.tools.<NAME>`` keep working.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, cast

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import ScopeName
from app.models.finding import CRYPTO_FINDING_TYPES
from app.models.policy_audit_entry import PolicyType
from app.models.user import User
from app.schemas.finding_details import all_rule_ids
from app.services.compliance.renderers.base import coverage_statement
from app.services.crypto_policy.resolver import CryptoPolicyResolver

_NOISY_RULE_SAMPLE = 10


def _pkg() -> Any:
    """Return the parent package module so collaborators resolve via the namespace tests patch."""
    from app.services.chat import tools as _tools_pkg

    return _tools_pkg


async def list_crypto_assets(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
    asset_type: str | None = None,
    primitive: str | None = None,
    name_search: str | None = None,
    skip: int = 0,
    limit: int,
) -> dict[str, Any]:
    from app.repositories.crypto_asset import CryptoAssetRepository
    from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

    filters: dict[str, Any] = {
        "asset_type": CryptoAssetType(asset_type) if asset_type else None,
        "primitive": CryptoPrimitive(primitive) if primitive else None,
        "name_search": name_search,
    }
    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan(project_id, scan_id, limit=limit, skip=skip, **filters)
    return {
        "items": [i.model_dump(by_alias=True) for i in items],
        "items_total": await repo.count_by_scan(project_id, scan_id, **filters),
    }


async def get_crypto_asset_details(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    asset_id: str,
) -> dict[str, Any] | None:
    from app.repositories.crypto_asset import CryptoAssetRepository

    asset = await CryptoAssetRepository(db).get(project_id, asset_id)
    return asset.model_dump(by_alias=True) if asset else None


async def get_crypto_summary(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
) -> dict[str, Any]:
    from app.repositories.crypto_asset import CryptoAssetRepository

    return await CryptoAssetRepository(db).summary_for_scan(project_id, scan_id)


async def get_project_crypto_policy(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
) -> dict[str, Any]:
    effective = await CryptoPolicyResolver(db).resolve(project_id)
    return {
        "system_version": effective.system_version,
        "override_version": effective.override_version,
        "override_locked": effective.override_locked,
        "rules": [r.model_dump() for r in effective.rules],
    }


async def suggest_crypto_policy_override(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    scan_id: str,
) -> dict[str, Any]:
    """Advisory only — returns the enabled policy rules matching the most findings; does not write."""
    enabled = {rule.rule_id for rule in (await CryptoPolicyResolver(db).resolve(project_id)).active_rules}
    cursor = db.findings.find(
        {"project_id": project_id, "scan_id": scan_id, "type": {"$in": sorted(CRYPTO_FINDING_TYPES)}},
        {"_id": 0, "details.rule_id": 1, "details.matched_rules.rule_id": 1},
    )
    counts: Counter[str] = Counter()
    async for doc in cursor:
        counts.update(all_rule_ids(doc.get("details")) & enabled)
    # Counts tie often, so the rule id breaks them: without it the same scan names a different ten each call.
    top = sorted(counts.items(), key=lambda row: (-row[1], row[0]))[:_NOISY_RULE_SAMPLE]
    return {
        "top_noisy_rules": [{"rule_id": rule_id, "findings": count} for rule_id, count in top],
        "top_noisy_rules_total": len(counts),
        "advice": (
            "Rules producing many findings may be candidates for project-scoped "
            "overrides (disable or adjust severity) if the codebase has accepted "
            "legacy risk. A finding counts toward every rule it matched, so disabling "
            "one rule leaves the findings its co-matched rules still produce. "
            "Review each rule before disabling."
        ),
    }


async def get_crypto_hotspots(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    group_by: str,
    limit: int,
) -> dict[str, Any]:
    from app.schemas.analytics import GroupBy
    from app.services.analytics.crypto_hotspots import CryptoHotspotService

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
    metric: str,
    days: int,
) -> dict[str, Any]:
    from app.schemas.analytics import Metric
    from app.services.analytics.crypto_trends import CryptoTrendService, auto_bucket

    pkg = _pkg()
    resolved = pkg.ResolvedScope(scope="project", scope_id=project_id, project_ids=[project_id])
    # A range ending at the next UTC midnight keeps today's scans and repeats the cache key all day.
    range_end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    series = await CryptoTrendService(db).trend(
        resolved=resolved,
        metric=cast(Metric, metric),
        bucket=auto_bucket(timedelta(days=days)),
        range_start=range_end - timedelta(days=days),
        range_end=range_end,
    )
    return series.model_dump()


async def generate_pqc_migration_plan(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    limit: int,
) -> dict[str, Any]:
    """Generate the PQC migration plan for one project the caller already authorised."""
    pkg = _pkg()
    resolved = pkg.ResolvedScope(scope="project", scope_id=project_id, project_ids=[project_id])
    gen = pkg.PQCMigrationPlanGenerator(db)
    resp = await gen.generate(resolved=resolved, limit=limit)
    dumped: dict[str, Any] = resp.model_dump()
    return dumped


async def list_compliance_reports(
    db: AsyncIOMotorDatabase,
    *,
    visibility: dict[str, Any],
    framework: str | None,
    limit: int,
) -> dict[str, Any]:
    """Recent compliance reports among those ``visibility`` admits (metadata only, no artifacts)."""
    pkg = _pkg()
    fw = pkg.ReportFramework(framework) if framework else None
    reports = await pkg.ComplianceReportRepository(db).list(visibility=visibility, framework=fw, limit=limit)
    return {"reports": [r.model_dump(by_alias=True) for r in reports]}


async def list_policy_audit_entries(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: str,
    project_id: str | None,
    policy_type: PolicyType,
    limit: int,
) -> dict[str, Any]:
    pkg = _pkg()
    entries = await pkg.PolicyAuditRepository(db).list(
        policy_scope=cast(Literal["system", "project"], policy_scope),
        project_id=project_id,
        policy_type=policy_type,
        limit=limit,
    )
    return {"entries": [e.model_dump(by_alias=True, exclude={"snapshot"}) for e in entries]}


async def get_framework_evaluation_summary(
    db: AsyncIOMotorDatabase,
    *,
    user: User,
    scope: str,
    scope_id: str | None,
    framework: str,
) -> dict[str, Any]:
    """Run compliance evaluation in-process and return summary counts."""
    pkg = _pkg()
    fw_enum = pkg.ReportFramework(framework)
    resolver = pkg.ScopeResolver(db, user)
    resolved = await resolver.resolve(
        scope=cast(ScopeName, scope),
        scope_id=scope_id,
    )

    engine = pkg.ComplianceReportEngine()
    inputs = await engine._gather_inputs(db, resolved)
    framework_obj = pkg.FRAMEWORK_REGISTRY[fw_enum]
    if hasattr(framework_obj, "evaluate_async"):
        eval_result = await framework_obj.evaluate_async(inputs)
    else:
        eval_result = framework_obj.evaluate(inputs)
    coverage = coverage_statement(inputs.coverage)
    return {
        "framework": framework,
        "framework_name": eval_result.framework_name,
        "summary": eval_result.summary,
        **({"coverage": coverage} if coverage else {}),
    }

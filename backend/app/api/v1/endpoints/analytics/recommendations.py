"""Analytics recommendations endpoint: /projects/{project_id}/recommendations."""

from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    gather_cross_project_data,
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.core.permissions import Permissions
from app.repositories import (
    DependencyRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from app.schemas.analytics import (
    RecommendationResponse,
    RecommendationsResponse,
)
from app.services.recommendations import recommendation_engine

from ._shared import _MSG_ACCESS_DENIED

router = CustomAPIRouter()


@router.get("/projects/{project_id}/recommendations", responses=RESP_AUTH_404)
async def get_project_recommendations(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: Optional[str] = None,
) -> RecommendationsResponse:
    """Generate remediation recommendations for a project's findings,
    prioritized by impact and effort."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_project_ids = await get_user_project_ids(current_user, db)
    if project_id not in user_project_ids:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    if scan_id:
        scan = await scan_repo.get_by_id(scan_id)
        if scan and scan.project_id != project_id:
            scan = None
    else:
        scans = await scan_repo.find_many(
            {"project_id": project_id, "status": "completed"},
            limit=1,
            sort=[("created_at", -1)],
        )
        scan = scans[0] if scans else None

    if not scan:
        raise HTTPException(status_code=404, detail="No scan found for this project")

    scan_id = scan.id

    source_target = None

    findings = await finding_repo.find_by_scan(scan_id, limit=ANALYTICS_MAX_QUERY_LIMIT)

    dependencies = await dep_repo.find_by_scan(scan_id)

    for dep in dependencies:
        if dep.source_target:
            source_target = dep.source_target
            break

    previous_scan_findings = None
    scan_history = None

    previous_scans = await scan_repo.find_many(
        {"project_id": project_id, "_id": {"$ne": scan_id}},
        limit=1,
        sort=[("created_at", -1)],
    )
    previous_scan = previous_scans[0] if previous_scans else None

    if previous_scan:
        previous_scan_findings = await finding_repo.find_by_scan(previous_scan.id, limit=ANALYTICS_MAX_QUERY_LIMIT)

    recent_scans = await scan_repo.find_many(
        {"project_id": project_id},
        limit=10,
        sort=[("created_at", -1)],
    )

    if recent_scans:
        scan_history = [s.model_dump() for s in recent_scans]

    cross_project_data = await gather_cross_project_data(user_project_ids, project_id, db)

    recommendations = await recommendation_engine.generate_recommendations(
        findings=findings,
        dependencies=dependencies,
        source_target=source_target,
        previous_scan_findings=previous_scan_findings,
        scan_history=scan_history,
        cross_project_data=cross_project_data,
    )

    vuln_count = sum(1 for f in findings if f.type == "vulnerability")
    secret_count = sum(1 for f in findings if f.type == "secret")
    sast_count = sum(1 for f in findings if f.type == "sast")
    iac_count = sum(1 for f in findings if f.type == "iac")
    license_count = sum(1 for f in findings if f.type == "license")
    quality_count = sum(1 for f in findings if f.type == "quality")
    crypto_count = sum(1 for f in findings if isinstance(f.type, str) and f.type.startswith("crypto_"))

    summary: Dict[str, Any] = {
        "base_image_updates": 0,
        "direct_updates": 0,
        "transitive_updates": 0,
        "no_fix": 0,
        "total_fixable_vulns": 0,
        "total_unfixable_vulns": 0,
        "secrets_to_rotate": 0,
        "sast_issues": 0,
        "iac_issues": 0,
        "license_issues": 0,
        "quality_issues": 0,
        "crypto_issues": 0,
        "outdated_deps": 0,
        "fragmentation_issues": 0,
        "trend_alerts": 0,
        "cross_project_issues": 0,
        "finding_counts": {
            "vulnerabilities": vuln_count,
            "secrets": secret_count,
            "sast": sast_count,
            "iac": iac_count,
            "license": license_count,
            "quality": quality_count,
            "crypto": crypto_count,
        },
    }

    for rec in recommendations:
        rec_type = rec.type.value
        impact_total = rec.impact.get("total", 0)

        if rec_type == "base_image_update":
            summary["base_image_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "direct_dependency_update":
            summary["direct_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "transitive_fix_via_parent":
            summary["transitive_updates"] += 1
            summary["total_fixable_vulns"] += impact_total
        elif rec_type == "no_fix_available":
            summary["no_fix"] += 1
            summary["total_unfixable_vulns"] += impact_total
        elif rec_type in ("rotate_secrets", "remove_secrets"):
            summary["secrets_to_rotate"] += impact_total
        elif rec_type == "fix_code_security":
            summary["sast_issues"] += impact_total
        elif rec_type == "fix_infrastructure":
            summary["iac_issues"] += impact_total
        elif rec_type == "license_compliance":
            summary["license_issues"] += impact_total
        elif rec_type == "supply_chain_risk":
            summary["quality_issues"] += impact_total
        elif rec_type in ("outdated_dependency", "unmaintained_package"):
            summary["outdated_deps"] += impact_total
        elif rec_type in (
            "version_fragmentation",
            "dev_in_production",
            "duplicate_functionality",
            "deep_dependency_chain",
        ):
            summary["fragmentation_issues"] += impact_total
        elif rec_type in ("recurring_vulnerability", "regression_detected"):
            summary["trend_alerts"] += 1
        elif rec_type in ("cross_project_pattern", "shared_vulnerability"):
            summary["cross_project_issues"] += impact_total
        elif rec_type in (
            "replace_weak_algorithm",
            "increase_key_size",
            "upgrade_protocol",
            "pqc_migration",
            "rotate_certificate",
            "replace_weak_cipher_suite",
        ):
            summary["crypto_issues"] += impact_total

    return RecommendationsResponse(
        project_id=project_id,
        project_name=project.get("name", "Unknown"),
        scan_id=scan_id,
        total_findings=len(findings),
        total_vulnerabilities=vuln_count,
        recommendations=[RecommendationResponse(**r.to_dict()) for r in recommendations],
        summary=summary,
    )

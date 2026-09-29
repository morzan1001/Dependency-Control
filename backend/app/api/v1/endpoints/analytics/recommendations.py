"""Analytics recommendations endpoint: /projects/{project_id}/recommendations."""

import hashlib
import logging
from typing import Any

from fastapi import HTTPException

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    gather_cross_project_data,
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYTICS_MAX_QUERY_LIMIT,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    SCAN_DEPENDENCY_READ_LIMIT,
)
from app.core.permissions import Permissions
from app.models.finding_record import FindingRecord
from app.models.project import Scan
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
from app.schemas.recommendation import Recommendation, RecommendationType
from app.core.cve import canonical_cves
from app.services.enrichment import get_cve_enrichment
from app.services.recommendation import trends
from app.services.recommendation.common import get_attr
from app.services.recommendations import recommendation_engine

from ._shared import _MSG_ACCESS_DENIED

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

# Newest scans the recurrence count is taken over; the recommendation text names the window.
_RECURRENCE_WINDOW_SCANS = 10

# Recommendation type -> (summary key counted once per recommendation, summary key its impact total adds to).
_SUMMARY_BUCKETS: dict[RecommendationType, tuple[str | None, str | None]] = {
    RecommendationType.BASE_IMAGE_UPDATE: ("base_image_updates", "total_fixable_vulns"),
    RecommendationType.DIRECT_DEPENDENCY_UPDATE: ("direct_updates", "total_fixable_vulns"),
    RecommendationType.TRANSITIVE_FIX_VIA_PARENT: ("transitive_updates", "total_fixable_vulns"),
    RecommendationType.NO_FIX_AVAILABLE: ("no_fix", "total_unfixable_vulns"),
    RecommendationType.ROTATE_SECRETS: (None, "secrets_to_rotate"),
    RecommendationType.REMOVE_SECRETS: (None, "secrets_to_rotate"),
    RecommendationType.FIX_CODE_SECURITY: (None, "sast_issues"),
    RecommendationType.FIX_INFRASTRUCTURE: (None, "iac_issues"),
    RecommendationType.LICENSE_COMPLIANCE: (None, "license_issues"),
    RecommendationType.SUPPLY_CHAIN_RISK: (None, "quality_issues"),
    RecommendationType.OUTDATED_DEPENDENCY: (None, "outdated_deps"),
    RecommendationType.UNMAINTAINED_PACKAGE: (None, "outdated_deps"),
    RecommendationType.VERSION_FRAGMENTATION: (None, "fragmentation_issues"),
    RecommendationType.DEV_IN_PRODUCTION: (None, "fragmentation_issues"),
    RecommendationType.DUPLICATE_FUNCTIONALITY: (None, "fragmentation_issues"),
    RecommendationType.DEEP_DEPENDENCY_CHAIN: (None, "fragmentation_issues"),
    RecommendationType.RECURRING_VULNERABILITY: ("trend_alerts", None),
    RecommendationType.REGRESSION_DETECTED: ("trend_alerts", None),
    RecommendationType.CROSS_PROJECT_PATTERN: (None, "cross_project_issues"),
    RecommendationType.SHARED_VULNERABILITY: (None, "cross_project_issues"),
    RecommendationType.REPLACE_WEAK_ALGORITHM: (None, "crypto_issues"),
    RecommendationType.INCREASE_KEY_SIZE: (None, "crypto_issues"),
    RecommendationType.UPGRADE_PROTOCOL: (None, "crypto_issues"),
    RecommendationType.PQC_MIGRATION: (None, "crypto_issues"),
    RecommendationType.ROTATE_CERTIFICATE: (None, "crypto_issues"),
    RecommendationType.REPLACE_WEAK_CIPHER_SUITE: (None, "crypto_issues"),
}


async def _apply_live_threat_intel(findings: list[Any]) -> None:
    """Populate each vulnerability finding's details with current KEV/EPSS from the live threat-intel
    source. Ingest rarely writes KEV to findings (in_kev is set on ~0.2%), so the recommendation
    engine — which reads is_kev/epss/kev_ransomware off details — otherwise almost never raises the
    KEV/exploit recommendations. Uses the canonical CVEs of each finding's advisory list, and writes
    the finding-level worst case (any-KEV, max-EPSS) so the existing engine picks it up unchanged."""
    vuln_findings = [f for f in findings if get_attr(f, "type") == "vulnerability"]
    all_cves = list({c for f in vuln_findings for c in canonical_cves([get_attr(f, "details", {})])})
    if not all_cves:
        return
    try:
        enrichments = await get_cve_enrichment(all_cves)
    except Exception as e:
        logger.warning("Recommendations: live CVE enrichment failed, using stored data: %s", e)
        return

    for f in vuln_findings:
        details = get_attr(f, "details", {})
        if not isinstance(details, dict):
            continue
        infos = [enrichments[c] for c in canonical_cves([details]) if c in enrichments]
        if not infos:
            continue
        if any(e.is_kev for e in infos):
            details[DETAILS_KEY_IN_KEV] = True
        if any(e.kev_ransomware_use for e in infos):
            details[DETAILS_KEY_KEV_RANSOMWARE] = True
        epss_vals = [e.epss_score for e in infos if e.epss_score is not None]
        if epss_vals:
            max_epss = max(epss_vals)
            if details.get("epss_score") is None or max_epss > details["epss_score"]:
                details["epss_score"] = max_epss


@router.get("/projects/{project_id}/recommendations", responses=RESP_AUTH_404)
async def get_project_recommendations(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: str | None = None,
) -> RecommendationsResponse:
    """Generate remediation recommendations for a project's findings."""
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

    scan = await _resolve_scan(scan_repo, project, project_id, scan_id)
    scan_id = scan.id

    # Cache per scan + caller scope so users with different project access never
    # share an entry; cross-project signal isn't in the key and may be TTL-stale.
    scope_hash = hashlib.md5(",".join(sorted(user_project_ids)).encode(), usedforsecurity=False).hexdigest()[:16]
    cache_key = CacheKeys.recommendations(project_id, scan_id, scope_hash)
    cached = await cache_service.get(cache_key)
    if cached:
        return RecommendationsResponse(**cached)

    findings = await finding_repo.find_by_scan(scan_id, limit=ANALYTICS_MAX_QUERY_LIMIT)
    await _apply_live_threat_intel(findings)

    dependencies, dependencies_total = await dep_repo.find_by_scan(
        project_id, scan_id, limit=SCAN_DEPENDENCY_READ_LIMIT
    )
    source_target = next((dep.source_target for dep in dependencies if dep.source_target), None)

    previous_scan_findings = None
    previous_scan = await scan_repo.get_preceding_scan(scan_id)
    if previous_scan:
        previous_scan_findings = await finding_repo.find_by_scan(previous_scan.id, limit=ANALYTICS_MAX_QUERY_LIMIT)

    recent_scan_ids = [
        recent.id
        for recent in await scan_repo.find_many(
            {"project_id": project_id},
            limit=_RECURRENCE_WINDOW_SCANS,
            sort=[("created_at", -1)],
        )
    ]
    cve_recurrence = await trends.build_cve_recurrence(finding_repo.iter_vulnerability_identities(recent_scan_ids))

    cross_project_data = await gather_cross_project_data(user_project_ids, project_id, db)

    recommendations = await recommendation_engine.generate_recommendations(
        findings=findings,
        dependencies=dependencies,
        source_target=source_target,
        previous_scan_findings=previous_scan_findings,
        cve_recurrence=cve_recurrence,
        recurrence_window_scans=len(recent_scan_ids),
        cross_project_data=cross_project_data,
    )

    finding_counts = _finding_counts(findings)
    response = RecommendationsResponse(
        project_id=project_id,
        project_name=project.get("name", "Unknown"),
        scan_id=scan_id,
        total_findings=len(findings),
        total_vulnerabilities=finding_counts["vulnerabilities"],
        recommendations=[RecommendationResponse(**r.to_dict()) for r in recommendations],
        summary=_summarize(recommendations, finding_counts),
        dependencies_read=len(dependencies),
        dependencies_total=dependencies_total,
    )
    # mode="json" so a cache hit reconstructs the same shape as a miss (enums/datetimes).
    await cache_service.set(cache_key, response.model_dump(mode="json"), ttl_seconds=CacheTTL.RECOMMENDATIONS)
    return response


async def _resolve_scan(
    scan_repo: ScanRepository, project: dict[str, Any], project_id: str, scan_id: str | None
) -> Scan:
    if scan_id:
        scan = await scan_repo.get_by_id(scan_id)
        if scan and scan.project_id != project_id:
            scan = None
    else:
        scan = await scan_repo.get_latest_active_scan(project)

    if not scan:
        raise HTTPException(status_code=404, detail="No scan found for this project")
    return scan


def _finding_counts(findings: list[FindingRecord]) -> dict[str, int]:
    return {
        "vulnerabilities": sum(1 for f in findings if f.type == "vulnerability"),
        "secrets": sum(1 for f in findings if f.type == "secret"),
        "sast": sum(1 for f in findings if f.type == "sast"),
        "iac": sum(1 for f in findings if f.type == "iac"),
        "license": sum(1 for f in findings if f.type == "license"),
        "quality": sum(1 for f in findings if f.type == "quality"),
        "crypto": sum(1 for f in findings if isinstance(f.type, str) and f.type.startswith("crypto_")),
    }


def _summarize(recommendations: list[Recommendation], finding_counts: dict[str, int]) -> dict[str, Any]:
    summary: dict[str, Any] = {
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
        "finding_counts": finding_counts,
    }
    for rec in recommendations:
        count_key, impact_key = _SUMMARY_BUCKETS.get(rec.type, (None, None))
        if count_key:
            summary[count_key] += 1
        if impact_key:
            summary[impact_key] += rec.impact.get("total", 0)
    return summary

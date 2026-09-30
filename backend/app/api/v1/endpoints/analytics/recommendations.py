"""Analytics recommendations endpoint: /projects/{project_id}/recommendations."""

import asyncio
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
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.core.cache import CacheKeys, CacheTTL, cache_service, scope_digest
from app.core.constants import (
    ANALYTICS_MAX_QUERY_LIMIT,
    SCAN_DEPENDENCY_READ_LIMIT,
)
from app.core.cve import entry_cves
from app.core.permissions import Permissions
from app.models.finding_record import FindingRecord
from app.repositories.base import find_window
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.schemas.analytics import (
    RecommendationResponse,
    RecommendationsResponse,
)
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.recommendation import Recommendation, RecommendationType
from app.services.component_identity import component_name_candidates
from app.services.enrichment.service import apply_enrichments, vulnerability_enrichment_service
from app.services.recommendation import trends
from app.services.recommendation.common import live_cves
from app.services.recommendations import recommendation_engine

from ._shared import SCAN_NOT_IN_PROJECT, resolve_project_scan_id

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

# Newest scans the recurrence count is taken over; the recommendation text names the window.
_RECURRENCE_WINDOW_SCANS = 10

_LICENSE_DRIFT_PROJECTION = {"name": 1, "purl": 1, "license": 1, "license_category": 1}
_JOIN_PROJECTION = dict.fromkeys(
    ("name", "version", "purl", "type", "direct", "direct_inferred", "source_type", "source_target"), 1
)

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
}


async def _apply_live_threat_intel(findings: list[FindingRecord]) -> dict[str, VulnerabilityEnrichment]:
    """Mark each finding's advisories with KEV/EPSS as of now, not as of the scan; returns the per-CVE enrichment."""
    vuln_findings = [f for f in findings if f.type == "vulnerability"]
    all_cves = list({c for f in vuln_findings for c in live_cves([f.details])})
    if not all_cves:
        return {}
    try:
        enrichments = await vulnerability_enrichment_service.enrich_cves(all_cves)
    except Exception as e:
        logger.warning("Recommendations: live CVE enrichment failed, using stored data: %s", e)
        return {}

    # A CVE the live sources returned nothing for keeps the scores stored at scan time.
    live = {cve: e for cve, e in enrichments.items() if e.epss_score is not None or e.is_kev}
    for f in vuln_findings:
        refreshed = [v for v in f.details.get("vulnerabilities") or [] if any(c in live for c in entry_cves(v))]
        apply_enrichments({"vulnerabilities": refreshed}, live)
    return enrichments


@router.get("/projects/{project_id}/recommendations", responses=RESP_AUTH_404)
async def get_project_recommendations(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: str | None = None,
) -> RecommendationsResponse:
    """Generate remediation recommendations for a project's findings."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    project = await check_project_access(project_id, current_user, db)
    scan_id = await resolve_project_scan_id(db, project, scan_id)
    if not scan_id:
        raise HTTPException(status_code=404, detail=SCAN_NOT_IN_PROJECT)

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)
    user_project_ids = await get_user_project_ids(current_user, db)

    stamped = await scan_repo.find_many_raw({"_id": scan_id}, limit=1, projection={"completed_at": 1})
    completed_at = stamped[0].get("completed_at") if stamped else None
    # Per analysis + caller scope so users with different project access never share an
    # entry; cross-project signal isn't in the key and may be TTL-stale.
    cache_key = CacheKeys.recommendations(
        project_id, scan_id, completed_at.isoformat() if completed_at else "none", scope_digest(user_project_ids)
    )

    async def _compute() -> dict[str, Any]:
        findings, findings_total = await finding_repo.find_by_scan(scan_id, limit=ANALYTICS_MAX_QUERY_LIMIT)
        threat_intel = await _apply_live_threat_intel(findings)

        dependencies, dependencies_total = await dep_repo.find_by_scan(
            project_id, scan_id, limit=SCAN_DEPENDENCY_READ_LIMIT
        )
        source_target = next((dep.source_target for dep in dependencies if dep.source_target), None)
        # The window above can miss a finding's row; the join reads exactly the rows the findings name.
        names = list({n for f in findings if f.type == "vulnerability" for n in component_name_candidates(f.component)})
        join_query = {"project_id": project_id, "scan_id": scan_id, "name": {"$in": names}}
        join_dependencies = [dep async for dep in dep_repo.iterate_raw(join_query, _JOIN_PROJECTION)]

        previous = None
        previous_scan_dependencies = None
        previous_scan = await scan_repo.get_preceding_scan(scan_id)
        if previous_scan:
            previous = trends.PreviousScan()
            previous_query = {"scan_id": previous_scan.id, "waived": {"$ne": True}}
            async for doc in finding_repo.iterate_raw(previous_query, trends.PREVIOUS_SCAN_PROJECTION):
                previous.add(doc)
            previous_scan_dependencies, _ = await find_window(
                dep_repo.collection,
                {"project_id": project_id, "scan_id": previous_scan.id},
                SCAN_DEPENDENCY_READ_LIMIT,
                projection=_LICENSE_DRIFT_PROJECTION,
            )

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

        recommendations = await asyncio.to_thread(
            recommendation_engine.generate_recommendations,
            findings=findings,
            dependencies=dependencies,
            join_dependencies=join_dependencies,
            source_target=source_target,
            previous_scan=previous,
            previous_scan_dependencies=previous_scan_dependencies,
            cve_recurrence=cve_recurrence,
            recurrence_window_scans=len(recent_scan_ids),
            cross_project_data=cross_project_data,
            threat_intel=threat_intel,
        )

        finding_counts = _finding_counts(findings)
        response = RecommendationsResponse(
            project_id=project_id,
            project_name=project.name,
            scan_id=scan_id,
            total_findings=len(findings),
            findings_total=findings_total,
            total_vulnerabilities=finding_counts["vulnerabilities"],
            recommendations=[RecommendationResponse(**r.to_dict()) for r in recommendations],
            summary=_summarize(recommendations, finding_counts),
            dependencies_read=len(dependencies),
            dependencies_total=dependencies_total,
        )
        # mode="json" so a cache hit reconstructs the same shape as a miss (enums/datetimes).
        return response.model_dump(mode="json")

    # A waiter outlasts a slow miss instead of starting a second one.
    payload = await cache_service.get_or_fetch_with_lock(
        cache_key,
        _compute,
        ttl_seconds=CacheTTL.RECOMMENDATIONS,
        lock_ttl_seconds=30,
        max_wait_seconds=30,
        reraise_fetch_errors=True,
    )
    return RecommendationsResponse.model_validate(payload)


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

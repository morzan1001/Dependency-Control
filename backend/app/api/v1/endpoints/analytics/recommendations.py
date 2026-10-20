import asyncio
import logging
from collections import Counter
from typing import Any

from fastapi import HTTPException

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    gather_cross_project_data,
    get_user_projects,
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
from app.models.finding import CRYPTO_FINDING_TYPES
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
from app.services.enrichment.service import (
    THREAT_INTEL_SOURCES,
    apply_enrichments,
    vulnerability_enrichment_service,
)
from app.services.recommendation import trends
from app.services.recommendation.common import live_cves, live_fixed_version
from app.services.recommendation.crypto import CRYPTO_ISSUE_FINDING_TYPES, CRYPTO_RECOMMENDATION_TYPES
from app.services.recommendations import generate_recommendations

from ._shared import SCAN_NOT_IN_PROJECT, resolve_project_scan_id

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

# The viewed scan and its predecessors the recurrence count spans; the recommendation text names this window.
_RECURRENCE_WINDOW_SCANS = 10

# What the generators read of a dependency row, the license-drift comparison of the previous scan included.
_DEPENDENCY_PROJECTION = dict.fromkeys(
    ("name", "version", "purl", "type", "group", "scope", "direct", "parent_components", "license", "license_category"),
    1,
)
_JOIN_PROJECTION = dict.fromkeys(
    ("name", "version", "purl", "type", "direct", "direct_inferred", "source_type", "source_target"), 1
)

_SUMMARY_BUCKETS: dict[RecommendationType, tuple[str | None, str | None]] = {
    RecommendationType.BASE_IMAGE_UPDATE: ("base_image_updates", None),
    RecommendationType.DIRECT_DEPENDENCY_UPDATE: ("direct_updates", None),
    RecommendationType.TRANSITIVE_FIX_VIA_PARENT: ("transitive_updates", None),
    RecommendationType.NO_FIX_AVAILABLE: ("no_fix", None),
    RecommendationType.ROTATE_SECRETS: (None, "secrets_to_rotate"),
    RecommendationType.FIX_CODE_SECURITY: (None, "sast_issues"),
    RecommendationType.FIX_INFRASTRUCTURE: (None, "iac_issues"),
    RecommendationType.LICENSE_COMPLIANCE: (None, "license_issues"),
    RecommendationType.SUPPLY_CHAIN_RISK: (None, "quality_issues"),
    RecommendationType.OUTDATED_DEPENDENCY: (None, "outdated_deps"),
    RecommendationType.VERSION_FRAGMENTATION: (None, "fragmentation_issues"),
    RecommendationType.DEV_IN_PRODUCTION: (None, "fragmentation_issues"),
    RecommendationType.DUPLICATE_FUNCTIONALITY: (None, "fragmentation_issues"),
    RecommendationType.DEEP_DEPENDENCY_CHAIN: (None, "fragmentation_issues"),
    RecommendationType.RECURRING_VULNERABILITY: ("trend_alerts", None),
    RecommendationType.REGRESSION_DETECTED: ("trend_alerts", None),
    RecommendationType.CROSS_PROJECT_PATTERN: (None, "cross_project_issues"),
    RecommendationType.SHARED_VULNERABILITY: (None, "cross_project_issues"),
    **dict.fromkeys(CRYPTO_RECOMMENDATION_TYPES, (None, "crypto_issues")),
}
# Their cards restate findings the tallies above already count, or have no tile to fall under.
_NOT_SUMMARISED = frozenset(
    {
        RecommendationType.LICENSE_DRIFT,
        RecommendationType.CRITICAL_RISK,
        RecommendationType.CRITICAL_HOTSPOT,
        RecommendationType.KNOWN_EXPLOIT,
        RecommendationType.RANSOMWARE_RISK,
        RecommendationType.ACTIVELY_EXPLOITED,
        RecommendationType.MALWARE_DETECTED,
        RecommendationType.TYPOSQUAT_DETECTED,
        RecommendationType.HASH_MISMATCH,
        RecommendationType.EOL_DEPENDENCY,
        RecommendationType.QUICK_WIN,
        RecommendationType.SINGLE_UPDATE_MULTI_FIX,
        RecommendationType.TOXIC_DEPENDENCY,
        RecommendationType.ATTACK_SURFACE_REDUCTION,
    }
)
_SAST_FINDING_TYPES = {"sast"} | (CRYPTO_FINDING_TYPES - CRYPTO_ISSUE_FINDING_TYPES)


async def _apply_live_threat_intel(
    findings: list[dict[str, Any]],
) -> tuple[dict[str, VulnerabilityEnrichment], list[str]]:
    """Mark each finding's advisories with KEV/EPSS as of now, not as of the scan, unless a live source is down."""
    vuln_findings = [f for f in findings if f["type"] == "vulnerability"]
    all_cves = list({c for f in vuln_findings for c in live_cves([f["details"]])})
    if not all_cves:
        return {}, []
    try:
        enrichments, unavailable = await vulnerability_enrichment_service.enrich_cves(all_cves)
    except Exception as e:
        logger.warning("Recommendations: live CVE enrichment failed, using stored data: %s", e)
        return {}, list(THREAT_INTEL_SOURCES)
    if unavailable:
        # A partial refresh would clear stored KEV marks and the risk points they carry, so the scan's data stands.
        logger.warning("Recommendations: %s unavailable, using stored data", " and ".join(unavailable))
        return {}, unavailable

    # A CVE the live sources returned nothing for keeps the scores stored at scan time.
    live = {cve: e for cve, e in enrichments.items() if e.epss_score is not None or e.is_kev}
    for f in vuln_findings:
        refreshed = [v for v in f["details"].get("vulnerabilities") or [] if any(c in live for c in entry_cves(v))]
        apply_enrichments({"vulnerabilities": refreshed}, live)
    return enrichments, []


async def _dependency_window(
    dep_repo: DependencyRepository, project_id: str, scan_id: str
) -> tuple[list[dict[str, Any]], int]:
    query = {"project_id": project_id, "scan_id": scan_id}
    return await find_window(dep_repo.collection, query, SCAN_DEPENDENCY_READ_LIMIT, projection=_DEPENDENCY_PROJECTION)


async def _join_dependencies(
    dep_repo: DependencyRepository, project_id: str, scan_id: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The dependency window can miss a finding's row; this reads exactly the rows the findings name."""
    names = list(
        {
            n
            for f in findings
            if f["type"] in ("vulnerability", "outdated")
            for n in component_name_candidates(f["component"])
        }
    )
    query = {"project_id": project_id, "scan_id": scan_id, "name": {"$in": names}}
    return [dep async for dep in dep_repo.iterate_raw(query, _JOIN_PROJECTION)]


async def _previous_scan(finding_repo: FindingRepository, scan_id: str) -> trends.PreviousScan:
    previous = trends.PreviousScan()
    async for doc in finding_repo.iterate_raw(
        {"scan_id": scan_id, "waived": {"$ne": True}}, trends.PREVIOUS_SCAN_PROJECTION
    ):
        previous.add(doc)
    return previous


async def _history(
    scan_repo: ScanRepository,
    finding_repo: FindingRepository,
    dep_repo: DependencyRepository,
    project_id: str,
    scan_id: str,
) -> tuple[trends.PreviousScan | None, list[dict[str, Any]] | None, dict[str, trends.CveRecurrence], int]:
    """The previous scan's findings and dependencies, and CVE recurrence over the window the text names."""
    preceding = await scan_repo.get_preceding_scans(scan_id, _RECURRENCE_WINDOW_SCANS - 1)
    recent_scan_ids = [scan_id, *(scan.id for scan in preceding)]
    recurrence = trends.build_cve_recurrence(finding_repo.iter_vulnerability_identities(recent_scan_ids))
    if not preceding:
        return None, None, await recurrence, len(recent_scan_ids)
    previous, (previous_dependencies, _), cve_recurrence = await asyncio.gather(
        _previous_scan(finding_repo, preceding[0].id),
        _dependency_window(dep_repo, project_id, preceding[0].id),
        recurrence,
    )
    return previous, previous_dependencies, cve_recurrence, len(recent_scan_ids)


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
    user_projects = await get_user_projects(current_user, db)

    stamped = await scan_repo.find_many_raw(
        {"_id": scan_id}, limit=1, projection={"completed_at": 1, "waiver_fingerprint": 1}
    )
    stamp = stamped[0] if stamped else {}
    # Keyed by caller scope too, so differing project access never shares an entry; cross-project data may be stale.
    cache_key = CacheKeys.recommendations(
        project_id,
        scan_id,
        f"{stamp.get('completed_at')}|{stamp.get('waiver_fingerprint')}",
        scope_digest(p.id for p in user_projects),
    )

    async def _compute() -> dict[str, Any]:
        findings, findings_total = await finding_repo.find_raw_by_scan(scan_id, limit=ANALYTICS_MAX_QUERY_LIMIT)
        (
            (threat_intel, threat_intel_unavailable),
            (dependencies, dependencies_total),
            join_dependencies,
            (previous, previous_scan_dependencies, cve_recurrence, recurrence_window_scans),
            cross_project_data,
        ) = await asyncio.gather(
            _apply_live_threat_intel(findings),
            _dependency_window(dep_repo, project_id, scan_id),
            _join_dependencies(dep_repo, project_id, scan_id, findings),
            _history(scan_repo, finding_repo, dep_repo, project_id, scan_id),
            gather_cross_project_data(user_projects, project_id, db),
        )

        recommendations = await asyncio.to_thread(
            generate_recommendations,
            findings=findings,
            dependencies=dependencies,
            join_dependencies=join_dependencies,
            previous_scan=previous,
            previous_scan_dependencies=previous_scan_dependencies,
            cve_recurrence=cve_recurrence,
            recurrence_window_scans=recurrence_window_scans,
            cross_project_data=cross_project_data,
            threat_intel=threat_intel,
        )
        unfixable_vulns = await asyncio.to_thread(_unfixable_vulnerabilities, findings)

        finding_counts = _finding_counts(findings)
        response = RecommendationsResponse(
            project_id=project_id,
            project_name=project.name,
            scan_id=scan_id,
            total_findings=len(findings),
            findings_total=findings_total,
            total_vulnerabilities=finding_counts["vulnerabilities"],
            recommendations=[RecommendationResponse.model_validate(r) for r in recommendations],
            summary=_summarize(recommendations, finding_counts, unfixable_vulns),
            dependencies_read=len(dependencies),
            dependencies_total=dependencies_total,
            threat_intel_unavailable=threat_intel_unavailable,
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


def _finding_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    types = Counter(f["type"] for f in findings)
    return {
        "vulnerabilities": types["vulnerability"],
        "secrets": types["secret"],
        "sast": sum(types[t] for t in _SAST_FINDING_TYPES),
        "iac": types["iac"],
        "license": types["license"],
        "quality": types["quality"],
        "crypto": sum(types[t] for t in CRYPTO_ISSUE_FINDING_TYPES),
    }


def _unfixable_vulnerabilities(findings: list[dict[str, Any]]) -> int:
    """The engine's no-fix bucket in full, while its card lists only the Critical/High part."""
    return sum(1 for f in findings if f["type"] == "vulnerability" and not live_fixed_version(f))


def _summarize(
    recommendations: list[Recommendation], finding_counts: dict[str, int], unfixable_vulns: int
) -> dict[str, Any]:
    summary: dict[str, Any] = {key: 0 for keys in _SUMMARY_BUCKETS.values() for key in keys if key}
    summary["finding_counts"] = finding_counts
    summary["total_fixable_vulns"] = finding_counts["vulnerabilities"] - unfixable_vulns
    summary["total_unfixable_vulns"] = unfixable_vulns
    for rec in recommendations:
        if rec.type in _NOT_SUMMARISED:
            continue
        count_key, impact_key = _SUMMARY_BUCKETS[rec.type]
        if count_key:
            summary[count_key] += 1
        if impact_key:
            # Hygiene cards count no findings, so they tally the components they cover.
            summary[impact_key] += rec.impact.get("total") or rec.affected_components_total
    return summary

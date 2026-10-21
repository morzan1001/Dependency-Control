from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import build_user_project_query
from app.api.v1.helpers.sorting import case_insensitive_sort
from app.core.constants import (
    BLAST_RADIUS_THRESHOLD,
    CROSS_PROJECT_MIN_OCCURRENCES,
    EPSS_HIGH_BOOST,
    EPSS_HIGH_THRESHOLD,
    EPSS_MEDIUM_BOOST,
    EPSS_MEDIUM_THRESHOLD,
    EPSS_VERY_HIGH_BOOST,
    EPSS_VERY_HIGH_THRESHOLD,
    EXPLOIT_MATURITY_BOOST,
    IMPACT_AGE_BOOST,
    IMPACT_FIX_AVAILABLE_BOOST,
    IMPACT_MAX_SCORE_BOOST,
    IMPACT_REACH_MULTIPLIER_CAP,
    IMPACT_SEVERITY_WEIGHTS,
    KEV_DEFAULT_BOOST,
    KEV_DUE_SOON_BOOST,
    KEV_DUE_SOON_DAYS,
    KEV_OVERDUE_BOOST,
    KEV_RANSOMWARE_BOOST,
    RELEASE_ENVIRONMENT_PATTERN,
    REMEDIATION_SLA_DAYS,
    SEVERITY_ORDER,
    get_severity_value,
)
from app.core.cve import counted_cves
from app.core.permissions import Permissions, has_permission
from app.core.purl import package_identity_expr
from app.models.finding import Severity
from app.models.user import User
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.repositories.projections import ProjectWithScanId
from app.repositories.scans import ScanRepository
from app.repositories.teams import TeamRepository
from app.schemas.analytics import ThreatIntelFields
from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.aggregation.versions import (
    aggregate_fixed_version,
    normalize_version,
    split_fixed_versions,
    version_covered,
)
from app.services.analytics.scopes import ScopeResolver, read_scope_project_ids
from app.services.component_identity import build_component_index, finding_component_name, lookup_component
from app.services.enrichment.scoring import fold_enrichments
from app.services.enrichment.service import advisory_enrichment
from app.services.recommendation.common import live_advisories, live_cves
from app.services.releases import resolve_scan_ids

MONGO_MATCH = "$match"
MONGO_GROUP = "$group"

# Counts the project itself; each costs a scan resolution and a share of two aggregations.
_CROSS_PROJECT_COMPARISON_LIMIT = 20

ReleaseEnvironmentQuery = Annotated[
    str | None,
    Query(
        pattern=RELEASE_ENVIRONMENT_PATTERN,
        description="Report the release of this environment instead of the branch tip",
    ),
]


_ANALYTICS_FEATURE_PERMISSIONS = [
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    Permissions.ANALYTICS_DEPENDENCIES,
    Permissions.ANALYTICS_TREE,
    Permissions.ANALYTICS_IMPACT,
    Permissions.ANALYTICS_HOTSPOTS,
    Permissions.ANALYTICS_SEARCH,
    Permissions.ANALYTICS_RECOMMENDATIONS,
]


def require_any_analytics_permission(user: User) -> None:
    if not has_permission(user.permissions, _ANALYTICS_FEATURE_PERMISSIONS):
        raise HTTPException(
            status_code=403,
            detail=f"Analytics permission required: one of {', '.join(_ANALYTICS_FEATURE_PERMISSIONS)}",
        )


def require_analytics_permission(user: User, permission: str) -> None:
    if not has_permission(user.permissions, [Permissions.ANALYTICS_READ, permission]):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Analytics permission required: {permission}. "
                f"Grant '{Permissions.ANALYTICS_READ}' for full analytics access "
                f"or '{permission}' for this specific feature."
            ),
        )


async def get_user_project_ids(user: User, db: AsyncIOMotorDatabase) -> list[str]:
    return await read_scope_project_ids(db, await build_user_project_query(user, TeamRepository(db)))


async def get_user_projects(user: User, db: AsyncIOMotorDatabase) -> list[ProjectWithScanId]:
    return await ScopeResolver(db, user).list_user_projects()


async def get_latest_scan_ids(
    projects: list[ProjectWithScanId],
    db: AsyncIOMotorDatabase,
    *,
    release_environment: str | None = None,
) -> list[str]:
    resolved = await resolve_scan_ids(
        db, [p.id for p in projects], release_environment=release_environment, projects=projects
    )
    return list(resolved.values())


async def get_projects_with_scans(
    projects: list[ProjectWithScanId],
    db: AsyncIOMotorDatabase,
    *,
    release_environment: str | None = None,
) -> tuple[dict[str, str], list[str]]:
    scan_ids = await get_latest_scan_ids(projects, db, release_environment=release_environment)
    return {p.id: p.name for p in projects}, scan_ids


def scope_resolution_counts(project_ids: Sequence[str], scan_ids: Sequence[str]) -> tuple[int, int]:
    """One scan per resolved project, so the scan count is the contributor count; in head mode the rest have no scan."""
    resolved = len(scan_ids)
    return resolved, len(project_ids) - resolved


def calculate_days_until_due(kev_due_date: str | None) -> int | None:
    if not kev_due_date:
        return None
    try:
        due = datetime.strptime(kev_due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc).date()
        return (due - datetime.now(timezone.utc).date()).days
    except Exception:
        return None


def calculate_days_known(first_seen: datetime | None) -> int | None:
    return (datetime.now(timezone.utc) - first_seen).days if first_seen else None


def extract_fix_versions(details_list: list[Any], installed_version: str | None) -> set[str]:
    advisories = [vuln for details in details_list for vuln in live_advisories(details)]
    fixes_all = aggregate_fixed_version(advisories, installed_version)
    if fixes_all:
        return set(split_fixed_versions(fixes_all))
    return {part for vuln in advisories for part in split_fixed_versions(vuln.get("fixed_version"))}


def process_cve_enrichments(
    details_list: list[Any], enrichments: Mapping[str, VulnerabilityEnrichment]
) -> ThreatIntelFields:
    """The worst case across a group's live advisories, each scored on its own CVSS as at scan time."""
    advisories = [vuln for details in details_list for vuln in live_advisories(details)]
    worst = fold_enrichments(advisory_enrichment(vuln, enrichments) for vuln in advisories)
    if worst is None:
        return ThreatIntelFields()
    matched = [enrichments[cve] for cve in live_cves(details_list) if cve in enrichments]
    return ThreatIntelFields(
        max_epss_score=worst.epss_score,
        epss_percentile=worst.epss_percentile,
        max_risk_score=worst.risk_score,
        has_kev=worst.in_kev,
        kev_count=sum(1 for enr in matched if enr.in_kev),
        kev_ransomware_use=worst.kev_ransomware_use,
        kev_due_date=worst.kev_due_date,
        exploit_maturity=worst.exploit_maturity,
        days_until_due=calculate_days_until_due(worst.kev_due_date),
    )


def _calculate_kev_boost(enrichment_data: ThreatIntelFields) -> float:
    if not enrichment_data.has_kev:
        return 1.0

    if enrichment_data.kev_ransomware_use:
        return KEV_RANSOMWARE_BOOST

    days_until_due = enrichment_data.days_until_due
    if days_until_due is not None and days_until_due < 0:
        return KEV_OVERDUE_BOOST
    if days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        return KEV_DUE_SOON_BOOST

    return KEV_DEFAULT_BOOST


def _calculate_epss_boost(max_epss: float | None) -> float:
    if not max_epss:
        return 1.0

    if max_epss >= EPSS_VERY_HIGH_THRESHOLD:
        return EPSS_VERY_HIGH_BOOST
    if max_epss >= EPSS_HIGH_THRESHOLD:
        return EPSS_HIGH_BOOST
    if max_epss >= EPSS_MEDIUM_THRESHOLD:
        return EPSS_MEDIUM_BOOST

    return 1.0


def impact_pre_score(severity_counts: dict[str, int], affected_projects: int) -> float:
    """Every boost is >= 1.0, so this bounds the final score from below and, times IMPACT_MAX_SCORE_BOOST, above."""
    severity_score = sum(
        severity_counts.get(sev.lower(), 0) * weight for sev, weight in IMPACT_SEVERITY_WEIGHTS.items()
    )
    reach_multiplier = min(affected_projects, IMPACT_REACH_MULTIPLIER_CAP)
    return float(severity_score * reach_multiplier)


def impact_pre_score_expr(counts: str, project_ids: str) -> dict[str, Any]:
    """impact_pre_score as an aggregation expression over a severity-count document and a project-id array."""
    severity_score = [
        {"$multiply": [f"{counts}.{sev.lower()}", weight]} for sev, weight in IMPACT_SEVERITY_WEIGHTS.items()
    ]
    return {"$multiply": [{"$add": severity_score}, {"$min": [{"$size": project_ids}, IMPACT_REACH_MULTIPLIER_CAP]}]}


def select_impact_candidates[T](scored: list[tuple[float, T]], limit: int) -> list[T]:
    """Payloads whose enrichment-boosted ceiling can still beat the limit-th pre-score; only these need enriching."""
    ranked = sorted(scored, key=lambda t: t[0], reverse=True)
    if len(ranked) <= limit:
        return [payload for _, payload in ranked]
    threshold = ranked[limit - 1][0] / IMPACT_MAX_SCORE_BOOST
    return [payload for score, payload in ranked if score >= threshold]


def _missed_sla(severity_counts: dict[str, int], days_known: int | None) -> tuple[Severity, int] | None:
    """The deadline of the most severe live CVE, as the CVE-SLA report sets it, once days_known reaches it."""
    for severity, sla_days in REMEDIATION_SLA_DAYS.items():
        if severity_counts.get(severity.value.lower()):
            return (severity, sla_days) if days_known is not None and days_known >= sla_days else None
    return None


def calculate_impact_score(
    severity_counts: dict[str, int],
    affected_projects: int,
    enrichment_data: ThreatIntelFields,
    has_fix: bool,
    days_known: int | None,
) -> float:
    base_impact = impact_pre_score(severity_counts, affected_projects)

    base_impact *= _calculate_kev_boost(enrichment_data)
    base_impact *= _calculate_epss_boost(enrichment_data.max_epss_score)
    base_impact *= EXPLOIT_MATURITY_BOOST.get(enrichment_data.exploit_maturity, 1.0)

    if has_fix:
        base_impact *= IMPACT_FIX_AVAILABLE_BOOST

    if _missed_sla(severity_counts, days_known):
        base_impact *= IMPACT_AGE_BOOST

    return base_impact


def build_priority_reasons(
    severity_counts: dict[str, int],
    enrichment_data: ThreatIntelFields,
    affected_projects: int,
    has_fix: bool,
    days_known: int | None,
) -> list[str]:
    reasons = []
    days_until_due = enrichment_data.days_until_due
    max_epss = enrichment_data.max_epss_score

    if enrichment_data.kev_ransomware_use:
        reasons.append("ransomware:Used in ransomware campaigns - fix immediately")

    if days_until_due is not None and days_until_due < 0:
        reasons.append(f"deadline_overdue:CISA deadline overdue by {abs(days_until_due)} days")
    elif days_until_due is not None and days_until_due <= KEV_DUE_SOON_DAYS:
        reasons.append(f"deadline:CISA deadline in {days_until_due} days")

    # Within the first three reasons, the most the impact cards show, whatever else applies.
    if missed := _missed_sla(severity_counts, days_known):
        severity, sla_days = missed
        reasons.append(
            f"overdue:Known for {days_known} days - past the {sla_days}-day remediation SLA "
            f"for {severity.value.lower()} vulnerabilities"
        )

    if enrichment_data.has_kev and not enrichment_data.kev_ransomware_use:
        reasons.append("kev:Actively exploited in the wild (CISA KEV)")

    if max_epss and max_epss >= EPSS_HIGH_THRESHOLD:
        reasons.append(f"epss:High exploitation probability ({max_epss * 100:.1f}% EPSS)")

    if severity_counts.get("critical", 0) > 0:
        reasons.append(f"critical:{severity_counts['critical']} critical vulnerabilities")

    if affected_projects >= BLAST_RADIUS_THRESHOLD:
        reasons.append(f"blast_radius:Affects {affected_projects} projects (high blast radius)")

    if has_fix:
        reasons.append("fix_available:Fix available - easy to remediate")

    return reasons


# Slimmed before $group, so the group holds only the per-advisory fields read later, never the raw analyzer payload.
SLIM_DETAILS_EXPR: dict[str, Any] = {
    "vulnerabilities": {
        "$map": {
            "input": {"$ifNull": ["$details.vulnerabilities", []]},
            "as": "v",
            "in": {
                "id": "$$v.id",
                "resolved_cve": "$$v.resolved_cve",
                "aliases": "$$v.aliases",
                "severity": "$$v.severity",
                "cvss_score": "$$v.cvss_score",
                "fixed_version": "$$v.fixed_version",
                "waived": "$$v.waived",
            },
        }
    },
}


def severity_counts_from_details(details_list: list[Any]) -> dict[str, int]:
    """Distinct live CVEs per worst severity; the buckets are disjoint and sum to len(live_cves)."""
    worst: dict[str, str] = {}
    for details in details_list:
        for vuln in live_advisories(details):
            sev = str(vuln.get("severity") or "").upper()
            sev = sev if sev in SEVERITY_ORDER else "UNKNOWN"
            for cve in counted_cves(vuln):
                if cve not in worst or get_severity_value(sev) > get_severity_value(worst[cve]):
                    worst[cve] = sev
    counts = {sev.lower(): 0 for sev in SEVERITY_ORDER}
    for sev in worst.values():
        counts[sev.lower()] += 1
    return counts


async def vuln_details_by(
    finding_repo: Any, match: dict[str, Any], *fields: str, hint: dict[str, int] | None = None
) -> dict[tuple[Any, ...], list[Any]]:
    rows = await finding_repo.aggregate(
        [
            {MONGO_MATCH: {**match, "type": "vulnerability", "waived": {"$ne": True}}},
            {"$unwind": "$details.vulnerabilities"},
            {MONGO_MATCH: {"details.vulnerabilities.waived": {"$ne": True}}},
            {
                MONGO_GROUP: {
                    "_id": {field: f"${field}" for field in fields},
                    "advisories": {
                        "$addToSet": {
                            "id": "$details.vulnerabilities.id",
                            "resolved_cve": "$details.vulnerabilities.resolved_cve",
                            "aliases": "$details.vulnerabilities.aliases",
                            "severity": "$details.vulnerabilities.severity",
                        }
                    },
                }
            },
        ],
        hint=hint,
    )
    return {
        tuple(r["_id"].get(field) for field in fields): [{"vulnerabilities": r["advisories"]}]
        for r in rows
        if r["_id"].get(fields[0])
    }


def cross_project_package_pipeline(scan_ids: list[str], min_projects: int, viewed_scan_id: str) -> list[dict[str, Any]]:
    """Grouped in Mongo because a per-scan sample of the packages cannot produce a version count per package."""
    return [
        {MONGO_MATCH: {"scan_id": {"$in": scan_ids}}},
        {
            MONGO_GROUP: {
                "_id": {"package": package_identity_expr(), "version": "$version"},
                "scan_ids": {"$addToSet": "$scan_id"},
            }
        },
        {
            MONGO_GROUP: {
                "_id": "$_id.package",
                "versions": {"$push": "$_id.version"},
                "scan_ids": {"$push": "$scan_ids"},
                "least_shared": {"$min": {"$size": "$scan_ids"}},
            }
        },
        {
            "$project": {
                "name": "$_id.path",
                "type": "$_id.type",
                "versions": 1,
                "version_count": {"$size": "$versions"},
                "scan_ids": {
                    "$reduce": {"input": "$scan_ids", "initialValue": [], "in": {"$setUnion": ["$$value", "$$this"]}}
                },
                "least_shared": 1,
            }
        },
        # One head scan per compared project, so distinct scans count the projects.
        {"$addFields": {"project_count": {"$size": "$scan_ids"}}},
        # Projects holding the same version set (nested copies included) agree; a version some project lacks differs.
        {
            MONGO_MATCH: {
                "scan_ids": viewed_scan_id,
                "project_count": {"$gte": min_projects},
                "$expr": {"$lt": ["$least_shared", "$project_count"]},
            }
        },
        {"$unset": ["least_shared", "scan_ids"]},
        *case_insensitive_sort([("version_count", -1), ("name", 1), ("type", 1)], {"name"}),
    ]


async def gather_cross_project_data(
    user_projects: list[ProjectWithScanId],
    current_project_id: str,
    db: AsyncIOMotorDatabase,
) -> dict[str, Any] | None:
    if len(user_projects) <= 1:
        return None

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    dep_repo = DependencyRepository(db)

    cross_project_data: dict[str, Any] = {
        "current_project_id": current_project_id,
        "projects": [],
        "shared_packages": [],
        "total_projects": len(user_projects),
    }

    scanned = [p for p in user_projects if p.latest_scan_id]
    compared = sorted(
        scanned,
        key=lambda p: (p.id != current_project_id, -(p.last_scan_at.timestamp() if p.last_scan_at else 0)),
    )[:_CROSS_PROJECT_COMPARISON_LIMIT]
    head_scan_ids = await scan_repo.get_latest_active_scan_ids(compared)
    scan_ids = list(head_scan_ids.values())

    if not scan_ids:
        return cross_project_data

    scans = await scan_repo.find_many_with_stats({"_id": {"$in": scan_ids}}, limit=len(scan_ids))
    scan_stats_map = {s.id: s.stats for s in scans if s.stats}

    details_by_finding = await vuln_details_by(
        finding_repo, {"scan_id": {"$in": scan_ids}}, "scan_id", "component", "version"
    )
    details_by_scan: dict[str, list[Any]] = defaultdict(list)
    vulnerable_by_component: dict[str, set[str]] = defaultdict(set)
    for (scan_id, component, version), details in details_by_finding.items():
        details_by_scan[scan_id] += details
        vulnerable_by_component[component].add(normalize_version(version))
    scan_cves_map = {scan_id: live_cves(details) for scan_id, details in details_by_scan.items()}

    if viewed_scan_id := head_scan_ids.get(current_project_id):
        shared_packages = await dep_repo.aggregate(
            cross_project_package_pipeline(scan_ids, CROSS_PROJECT_MIN_OCCURRENCES, viewed_scan_id)
        )
        vulnerable_index = build_component_index(vulnerable_by_component)
        for package in shared_packages:
            name = finding_component_name(package["type"], package["name"])
            vulnerable = lookup_component(vulnerable_index, name) or set()
            package["vulnerable_versions"] = [v for v in package["versions"] if version_covered(vulnerable, v)]
        cross_project_data["shared_packages"] = shared_packages

    for project in compared:
        if not (scan_id := head_scan_ids.get(project.id)):
            continue
        stats = scan_stats_map.get(scan_id)

        cross_project_data["projects"].append(
            {
                "project_id": project.id,
                "project_name": project.name,
                "cves": scan_cves_map.get(scan_id, []),
                "total_critical": stats.critical if stats else 0,
                "total_high": stats.high if stats else 0,
            }
        )

    return cross_project_data

"""Private helpers shared by multiple analytics submodules."""

from typing import Any

from app.api.deps import DatabaseDep
from app.core.constants import SCAN_USABLE_STATUSES
from app.repositories import (
    DependencyEnrichmentRepository,
    ProjectRepository,
)

_MSG_ACCESS_DENIED = "Access denied to this project"


async def _resolve_scan_id(project_id: str, db: DatabaseDep) -> str | None:
    """Latest scan ID for a project, preferring branches that aren't deleted."""
    project_repo = ProjectRepository(db)
    project = await project_repo.get_by_id(project_id)
    if not project:
        return None

    deleted = project.deleted_branches or []
    if not deleted:
        return project.latest_scan_id

    scan_doc = await db.scans.find_one(
        {"project_id": project_id, "branch": {"$nin": deleted}, "status": {"$in": SCAN_USABLE_STATUSES}},
        sort=[("created_at", -1)],
        projection={"_id": 1},
    )
    return scan_doc["_id"] if scan_doc else None


async def _get_enrichment_info(enrichment_repo: DependencyEnrichmentRepository, purl: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "deps_dev_data": None,
        "enrichment_sources": [],
        "license_category": None,
        "license_risks": [],
        "license_obligations": [],
        "description": None,
        "homepage": None,
        "repository_url": None,
    }
    if not purl:
        return result

    enrichment = await enrichment_repo.get_by_purl(purl)
    if not enrichment:
        return result

    # Dependency docs only carry parser-declared metadata; deps.dev-derived
    # description/links live solely on the enrichment doc.
    result["description"] = enrichment.get("description")
    result["homepage"] = enrichment.get("homepage")
    result["repository_url"] = enrichment.get("repository_url")

    deps_dev_data = enrichment.get("deps_dev")
    if deps_dev_data:
        result["deps_dev_data"] = deps_dev_data
        result["enrichment_sources"].append("deps_dev")

    # DependencyEnrichment.to_mongo_dict() stores these top-level, not nested under license_compliance.
    license_category = enrichment.get("license_category")
    license_risks = enrichment.get("license_risks")
    license_obligations = enrichment.get("license_obligations")
    if license_category or license_risks or license_obligations:
        result["enrichment_sources"].append("license_compliance")
        result["license_category"] = license_category
        result["license_risks"] = license_risks or []
        result["license_obligations"] = license_obligations or []

    return result

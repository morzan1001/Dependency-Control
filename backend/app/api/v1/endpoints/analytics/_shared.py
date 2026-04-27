"""Private helpers shared by multiple analytics submodules."""

from typing import Any, Dict, Optional

from app.api.deps import DatabaseDep
from app.repositories import (
    DependencyEnrichmentRepository,
    ProjectRepository,
)

_MSG_ACCESS_DENIED = "Access denied to this project"


async def _resolve_scan_id(project_id: str, db: DatabaseDep) -> Optional[str]:
    """Resolve the latest scan ID for a project, preferring active branches."""
    project_repo = ProjectRepository(db)
    project = await project_repo.get_by_id(project_id)
    if not project:
        return None

    deleted = project.deleted_branches or []
    if not deleted:
        return project.latest_scan_id

    # Find latest scan not on a deleted branch
    scan_doc = await db.scans.find_one(
        {"project_id": project_id, "branch": {"$nin": deleted}, "status": "completed"},
        sort=[("created_at", -1)],
        projection={"_id": 1},
    )
    return scan_doc["_id"] if scan_doc else None


async def _get_enrichment_info(enrichment_repo: DependencyEnrichmentRepository, purl: Optional[str]) -> Dict[str, Any]:
    """Fetch and extract enrichment info for a dependency by PURL."""
    result: Dict[str, Any] = {
        "deps_dev_data": None,
        "enrichment_sources": [],
        "license_category": None,
        "license_risks": [],
        "license_obligations": [],
    }
    if not purl:
        return result

    enrichment = await enrichment_repo.get_by_purl(purl)
    if not enrichment:
        return result

    deps_dev_data = enrichment.get("deps_dev")
    if deps_dev_data:
        result["deps_dev_data"] = deps_dev_data
        result["enrichment_sources"].append("deps_dev")

    license_info = enrichment.get("license_compliance")
    if license_info:
        result["enrichment_sources"].append("license_compliance")
        result["license_category"] = license_info.get("category")
        result["license_risks"] = license_info.get("risks", [])
        result["license_obligations"] = license_info.get("obligations", [])

    return result

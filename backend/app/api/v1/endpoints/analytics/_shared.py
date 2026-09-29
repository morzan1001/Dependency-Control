"""Private helpers shared by multiple analytics submodules."""

from typing import Any

from app.repositories.dependency_enrichments import DependencyEnrichmentRepository

_MSG_ACCESS_DENIED = "Access denied to this project"


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

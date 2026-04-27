from typing import Any, Dict, List, Optional

from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

vulnerability_enrichment_service = VulnerabilityEnrichmentService()


async def enrich_vulnerability_findings(
    findings: List[Dict[str, Any]],
    github_token: Optional[str] = None,
) -> None:
    """Enrich findings in place. Closes the HTTP client after each run to keep
    the connection pool from growing — it's lazily recreated on next use."""
    if github_token:
        vulnerability_enrichment_service.set_github_token(github_token)
    try:
        await vulnerability_enrichment_service.enrich_findings(findings)
    finally:
        await vulnerability_enrichment_service.close()


async def get_cve_enrichment(cves: List[str]) -> Dict[str, VulnerabilityEnrichment]:
    return await vulnerability_enrichment_service.enrich_cves(cves)


async def resolve_ghsa_ids(ghsa_ids: List[str]) -> Dict[str, GHSAData]:
    return await vulnerability_enrichment_service.resolve_ghsa_to_cve(ghsa_ids)


def get_github_advisory_url(ghsa_id: str) -> str:
    return vulnerability_enrichment_service.get_ghsa_url(ghsa_id)

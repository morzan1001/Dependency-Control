from typing import Any, Dict, List, Optional

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

vulnerability_enrichment_service = VulnerabilityEnrichmentService()


async def enrich_vulnerability_findings(
    findings: List[Dict[str, Any]],
    github_token: Optional[str] = None,
) -> None:
    """Enrich findings in place; the shared HTTP client is process-lifetime and must not be closed here (concurrent runs share it)."""
    if github_token:
        vulnerability_enrichment_service.set_github_token(github_token)
    await vulnerability_enrichment_service.enrich_findings(findings)


async def get_cve_enrichment(cves: List[str]) -> Dict[str, VulnerabilityEnrichment]:
    return await vulnerability_enrichment_service.enrich_cves(cves)

from typing import Any, Dict, List, Optional

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

vulnerability_enrichment_service = VulnerabilityEnrichmentService()


async def enrich_vulnerability_findings(
    findings: List[Dict[str, Any]],
    github_token: Optional[str] = None,
) -> None:
    """Enrich findings in place using the shared enrichment service.

    The service's HTTP client is a process-lifetime singleton and is
    intentionally NOT closed here: this function runs concurrently (worker
    pool + request-time analytics both share ``vulnerability_enrichment_service``),
    so closing the client at the end of one run would tear it out from under
    other in-flight runs, causing "client has been closed" errors that the
    providers silently swallow into missing EPSS/KEV data.
    """
    if github_token:
        vulnerability_enrichment_service.set_github_token(github_token)
    await vulnerability_enrichment_service.enrich_findings(findings)


async def get_cve_enrichment(cves: List[str]) -> Dict[str, VulnerabilityEnrichment]:
    return await vulnerability_enrichment_service.enrich_cves(cves)

from typing import Any

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

vulnerability_enrichment_service = VulnerabilityEnrichmentService()


async def enrich_vulnerability_findings(
    findings: list[dict[str, Any]],
    github_token: str | None = None,
) -> None:
    """Enrich findings in place; the shared HTTP client is process-lifetime and must not be closed here (concurrent runs share it)."""
    if github_token:
        vulnerability_enrichment_service.set_github_token(github_token)
    await vulnerability_enrichment_service.enrich_findings(findings)


async def get_cve_enrichment(cves: list[str]) -> dict[str, VulnerabilityEnrichment]:
    return await vulnerability_enrichment_service.enrich_cves(cves)

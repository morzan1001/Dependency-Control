from typing import Any, Dict, List, Optional

from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

# Singleton instance
vulnerability_enrichment_service = VulnerabilityEnrichmentService()


async def enrich_vulnerability_findings(
    findings: List[Dict[str, Any]],
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Convenience function to enrich findings.

    Args:
        findings: List of finding dicts to enrich
        github_token: Optional GitHub Personal Access Token for authenticated API access
    """
    # Set the GitHub token on the service if provided
    if github_token:
        vulnerability_enrichment_service.set_github_token(github_token)
    return await vulnerability_enrichment_service.enrich_findings(findings)


async def get_cve_enrichment(cves: List[str]) -> Dict[str, VulnerabilityEnrichment]:
    """Convenience function to get enrichment for CVE list."""
    return await vulnerability_enrichment_service.enrich_cves(cves)


async def resolve_ghsa_ids(ghsa_ids: List[str]) -> Dict[str, GHSAData]:
    """Convenience function to resolve GHSA IDs to CVEs."""
    return await vulnerability_enrichment_service.resolve_ghsa_to_cve(ghsa_ids)


def get_github_advisory_url(ghsa_id: str) -> str:
    """Get the GitHub Advisory URL for a GHSA ID."""
    return vulnerability_enrichment_service.get_ghsa_url(ghsa_id)

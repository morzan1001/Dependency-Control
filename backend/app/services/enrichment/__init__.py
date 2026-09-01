from typing import Any

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import VulnerabilityEnrichmentService

vulnerability_enrichment_service = VulnerabilityEnrichmentService()


def canonical_cve(vuln: dict[str, Any]) -> str | None:
    """A vulnerability advisory's CVE identity. Findings carry one advisory list per
    (component, version) in details.vulnerabilities, and a vuln is listed as both its GHSA and its
    CVE alias. Collapse to the CVE (resolved_cve, a CVE id, or a CVE alias) so those count once;
    fall back to the raw id for GHSA-only advisories."""
    resolved = vuln.get("resolved_cve")
    if isinstance(resolved, str) and resolved.startswith("CVE-"):
        return resolved
    ident = vuln.get("id")
    if isinstance(ident, str) and ident.startswith("CVE-"):
        return ident
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return ident if isinstance(ident, str) and ident else None


def canonical_cves(details_list: list[Any]) -> list[str]:
    """Distinct canonical CVE ids across a group's advisory lists (details.vulnerabilities)."""
    seen: dict[str, None] = {}
    for details in details_list:
        if not isinstance(details, dict):
            continue
        for vuln in details.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                cve = canonical_cve(vuln)
                if cve:
                    seen.setdefault(cve, None)
    return list(seen)


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

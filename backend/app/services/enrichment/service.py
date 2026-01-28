import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.core.constants import ANALYZER_TIMEOUTS, EXPLOIT_MATURITY_ORDER
from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.epss import EPSSProvider
from app.services.enrichment.ghsa import GHSAProvider
from app.services.enrichment.kev import KEVProvider
from app.services.enrichment.scoring import (
    calculate_adjusted_risk_score,
    calculate_exploit_maturity,
    calculate_risk_score,
)

logger = logging.getLogger(__name__)


class VulnerabilityEnrichmentService:
    """
    Service to enrich vulnerability data with EPSS scores and CISA KEV information.

    Uses Redis for distributed caching across all pods:
    - KEV catalog is cached globally for 24 hours (updates daily)
    - EPSS scores are cached per-CVE for 24 hours
    - GHSA resolutions are cached per-ID for 7 days (rarely change)

    This dramatically reduces API calls when running multiple backend replicas.
    """

    def __init__(self):
        self._http_client: Optional[httpx.AsyncClient] = None
        self._client_lock = asyncio.Lock()  # Prevent race condition on client creation
        self._epss_provider = EPSSProvider()
        self._kev_provider = KEVProvider()
        self._ghsa_provider = GHSAProvider()

    def set_github_token(self, token: Optional[str]) -> None:
        """Set the GitHub Personal Access Token for authenticated API requests."""
        self._ghsa_provider.set_token(token)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with thread-safe initialization."""
        if self._http_client is not None and not self._http_client.is_closed:
            return self._http_client

        async with self._client_lock:
            # Double-check after acquiring lock
            if self._http_client is not None and not self._http_client.is_closed:
                return self._http_client
            timeout = ANALYZER_TIMEOUTS.get("default", 30.0)
            self._http_client = httpx.AsyncClient(timeout=timeout)
        return self._http_client

    async def close(self):
        """Close HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    async def resolve_ghsa_to_cve(self, ghsa_ids: List[str]) -> Dict[str, GHSAData]:
        """Resolve multiple GHSA IDs to CVEs."""
        client = await self._get_client()
        return await self._ghsa_provider.resolve_ghsa_to_cve(client, ghsa_ids)

    def get_ghsa_url(self, ghsa_id: str) -> str:
        """Get the GitHub Advisory URL for a GHSA ID."""
        return f"https://github.com/advisories/{ghsa_id}"

    async def enrich_cves(
        self,
        cves: List[str],
        cvss_scores: Optional[Dict[str, float]] = None,
    ) -> Dict[str, VulnerabilityEnrichment]:
        """
        Enrich a list of CVEs with EPSS and KEV data.

        Args:
            cves: List of CVE IDs to enrich
            cvss_scores: Optional dict of CVE -> CVSS score for risk calculation

        Returns:
            Dict mapping CVE ID to VulnerabilityEnrichment
        """
        if not cves:
            return {}

        # Deduplicate and filter valid CVE IDs
        unique_cves = list(set(cve for cve in cves if cve and cve.startswith("CVE-")))

        if not unique_cves:
            return {}

        cvss_scores = cvss_scores or {}
        client = await self._get_client()

        # Load data sources in parallel
        kev_task = self._kev_provider.load_kev_catalog(client)
        epss_task = self._epss_provider.load_epss_scores(client, unique_cves)

        kev_catalog, epss_data = await asyncio.gather(kev_task, epss_task)

        # Build enrichment for each CVE
        results = {}
        for cve in unique_cves:
            kev_entry = kev_catalog.get(cve)
            epss_entry = epss_data.get(cve)
            cvss = cvss_scores.get(cve)

            is_kev = kev_entry is not None
            kev_ransomware = kev_entry.known_ransomware_use if kev_entry else False
            epss_score = epss_entry.epss_score if epss_entry else None

            enrichment = VulnerabilityEnrichment(
                cve=cve,
                epss_score=epss_score,
                epss_percentile=epss_entry.percentile if epss_entry else None,
                epss_date=epss_entry.date if epss_entry else None,
                is_kev=is_kev,
                kev_date_added=kev_entry.date_added if kev_entry else None,
                kev_due_date=kev_entry.due_date if kev_entry else None,
                kev_required_action=kev_entry.required_action if kev_entry else None,
                kev_ransomware_use=kev_ransomware,
                exploit_maturity=calculate_exploit_maturity(
                    is_kev, kev_ransomware, epss_score
                ),
                risk_score=calculate_risk_score(
                    cvss, epss_score, is_kev, kev_ransomware
                ),
            )

            results[cve] = enrichment

        kev_count = sum(1 for e in results.values() if e.is_kev)
        epss_count = sum(1 for e in results.values() if e.epss_score is not None)
        logger.info(
            f"Enriched {len(results)} CVEs (KEV: {kev_count}, EPSS: {epss_count})"
        )

        return results

    async def enrich_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of vulnerability findings with EPSS and KEV data.
        Modifies findings in-place and returns them.

        Args:
            findings: List of finding dicts with vulnerabilities in details

        Returns:
            Same list with enrichment data added to each finding
        """
        if not findings:
            return findings

        # Extract CVE IDs and CVSS scores from all findings
        # Map: CVE -> List of (finding, vuln_index) tuples to update
        cve_to_findings: Dict[str, List[Dict[str, Any]]] = {}
        cvss_scores: Dict[str, float] = {}

        for finding in findings:
            details = finding.get("details", {})
            if not isinstance(details, dict):
                continue

            # Check if finding ID itself is a CVE
            finding_id = finding.get("finding_id") or finding.get("id", "")
            if finding_id and finding_id.startswith("CVE-"):
                if finding_id not in cve_to_findings:
                    cve_to_findings[finding_id] = []
                cve_to_findings[finding_id].append(finding)
                if details.get("cvss_score") is not None:
                    cvss_scores[finding_id] = details["cvss_score"]

            # Extract CVEs from vulnerabilities array (aggregated findings)
            vulns = details.get("vulnerabilities", [])
            for vuln in vulns:
                cve = vuln.get("id", "")
                if cve and (cve.startswith("CVE-") or cve.startswith("GHSA-")):
                    if cve not in cve_to_findings:
                        cve_to_findings[cve] = []
                    cve_to_findings[cve].append(finding)

                    # Extract CVSS score
                    if vuln.get("cvss_score") is not None and cve not in cvss_scores:
                        cvss_scores[cve] = vuln["cvss_score"]

                # Also check aliases within the vulnerability
                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        if alias not in cve_to_findings:
                            cve_to_findings[alias] = []
                        if finding not in cve_to_findings[alias]:
                            cve_to_findings[alias].append(finding)

            # Also check aliases at finding level
            for alias in finding.get("aliases", []):
                if alias.startswith("CVE-"):
                    if alias not in cve_to_findings:
                        cve_to_findings[alias] = []
                    if finding not in cve_to_findings[alias]:
                        cve_to_findings[alias].append(finding)

        if not cve_to_findings:
            return findings

        # =====================================================================
        # GHSA Resolution: Resolve GHSA IDs to CVEs and add GitHub URLs
        # =====================================================================
        ghsa_ids = [vid for vid in cve_to_findings.keys() if vid.startswith("GHSA-")]
        ghsa_resolutions: Dict[str, GHSAData] = {}

        if ghsa_ids:
            logger.info(f"Resolving {len(ghsa_ids)} GHSA IDs to CVEs")
            ghsa_resolutions = await self.resolve_ghsa_to_cve(ghsa_ids)

            # Process resolved GHSAs
            for ghsa_id, ghsa_data in ghsa_resolutions.items():
                affected_findings = cve_to_findings.get(ghsa_id, [])

                for finding in affected_findings:
                    if "details" not in finding:
                        finding["details"] = {}

                    # Add GitHub Advisory URL to finding
                    finding["details"]["github_advisory_url"] = ghsa_data.advisory_url

                    # Update vulnerabilities array with GHSA data
                    vulns = finding["details"].get("vulnerabilities", [])
                    for vuln in vulns:
                        if vuln.get("id") == ghsa_id:
                            vuln["github_advisory_url"] = ghsa_data.advisory_url

                            # If we resolved a CVE, add it as an alias and use for EPSS/KEV
                            if ghsa_data.cve_id:
                                if "aliases" not in vuln:
                                    vuln["aliases"] = []
                                if ghsa_data.cve_id not in vuln["aliases"]:
                                    vuln["aliases"].append(ghsa_data.cve_id)
                                vuln["resolved_cve"] = ghsa_data.cve_id

                                # Add this CVE to our enrichment list
                                if ghsa_data.cve_id not in cve_to_findings:
                                    cve_to_findings[ghsa_data.cve_id] = []
                                if finding not in cve_to_findings[ghsa_data.cve_id]:
                                    cve_to_findings[ghsa_data.cve_id].append(finding)

                            # Add other aliases from GHSA
                            for alias in ghsa_data.aliases:
                                if alias not in vuln.get("aliases", []):
                                    if "aliases" not in vuln:
                                        vuln["aliases"] = []
                                    vuln["aliases"].append(alias)

                    # Also update finding-level aliases
                    if ghsa_data.cve_id:
                        if "aliases" not in finding:
                            finding["aliases"] = []
                        if ghsa_data.cve_id not in finding["aliases"]:
                            finding["aliases"].append(ghsa_data.cve_id)

        # Enrich CVEs (only CVE- prefixed, not GHSA-)
        cves_to_enrich = [
            cve for cve in cve_to_findings.keys() if cve.startswith("CVE-")
        ]
        enrichments = await self.enrich_cves(cves_to_enrich, cvss_scores)

        # Apply enrichment to findings and their vulnerabilities
        for cve, enrichment in enrichments.items():
            for finding in cve_to_findings.get(cve, []):
                # Add enrichment data to finding details
                if "details" not in finding:
                    finding["details"] = {}

                # Enrich individual vulnerabilities in the array
                vulns = finding["details"].get("vulnerabilities", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "")
                    if vuln_id == cve or cve in vuln.get("aliases", []):
                        # Add enrichment to this specific vulnerability
                        if enrichment.epss_score is not None:
                            vuln["epss_score"] = enrichment.epss_score
                            vuln["epss_percentile"] = enrichment.epss_percentile
                        if enrichment.is_kev:
                            vuln["in_kev"] = True
                            vuln["kev_due_date"] = enrichment.kev_due_date
                            vuln["kev_ransomware_use"] = enrichment.kev_ransomware_use

                # Also add aggregated data to finding level for quick access
                # Use the highest EPSS score and any KEV status across all vulns
                max_epss = finding["details"].get("epss_score")
                if enrichment.epss_score is not None:
                    if max_epss is None or enrichment.epss_score > max_epss:
                        finding["details"]["epss_score"] = enrichment.epss_score
                        finding["details"][
                            "epss_percentile"
                        ] = enrichment.epss_percentile
                        finding["details"]["epss_date"] = enrichment.epss_date

                if enrichment.is_kev:
                    finding["details"]["in_kev"] = True
                    finding["details"]["kev_date_added"] = enrichment.kev_date_added
                    finding["details"]["kev_due_date"] = enrichment.kev_due_date
                    finding["details"][
                        "kev_required_action"
                    ] = enrichment.kev_required_action
                    finding["details"][
                        "kev_ransomware_use"
                    ] = enrichment.kev_ransomware_use

                if (
                    enrichment.exploit_maturity
                    and enrichment.exploit_maturity != "unknown"
                ):
                    current_maturity = finding["details"].get(
                        "exploit_maturity", "unknown"
                    )
                    # Keep the more severe maturity level
                    if EXPLOIT_MATURITY_ORDER.get(
                        enrichment.exploit_maturity, 0
                    ) > EXPLOIT_MATURITY_ORDER.get(current_maturity, 0):
                        finding["details"][
                            "exploit_maturity"
                        ] = enrichment.exploit_maturity

                if enrichment.risk_score is not None:
                    current_risk = finding["details"].get("risk_score")
                    if current_risk is None or enrichment.risk_score > current_risk:
                        finding["details"]["risk_score"] = enrichment.risk_score

        return findings

    # expose the scoring functions for external use if needed, e.g. reachability
    def calculate_adjusted_risk_score(
        self,
        base_risk_score: float,
        is_reachable: Optional[bool] = None,
        reachability_level: Optional[str] = None,
    ) -> float:
        """
        Calculate an adjusted risk score considering reachability.
        Delegates to scoring module.
        """
        return calculate_adjusted_risk_score(
            base_risk_score, is_reachable, reachability_level
        )

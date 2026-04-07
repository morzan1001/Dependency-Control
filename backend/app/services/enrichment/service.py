import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.core.constants import ANALYZER_TIMEOUTS, EXPLOIT_MATURITY_ORDER
from app.core.http_utils import InstrumentedAsyncClient
from app.schemas.enrichment import EPSSData, GHSAData, KEVEntry, VulnerabilityEnrichment
from app.services.enrichment.epss import EPSSProvider
from app.services.enrichment.ghsa import GHSAProvider
from app.services.enrichment.kev import KEVProvider
from app.services.enrichment.scoring import (
    calculate_adjusted_risk_score,
    calculate_exploit_maturity,
    calculate_risk_score,
)

logger = logging.getLogger(__name__)


def _build_enrichment(
    cve: str,
    kev_entry: Optional[KEVEntry],
    epss_entry: Optional[EPSSData],
    cvss: Optional[float],
) -> VulnerabilityEnrichment:
    """Build a VulnerabilityEnrichment for a single CVE from its data sources."""
    is_kev = kev_entry is not None
    kev_ransomware = kev_entry.known_ransomware_use if kev_entry else False
    epss_score = epss_entry.epss_score if epss_entry else None

    return VulnerabilityEnrichment(
        cve=cve,
        epss_score=epss_score,
        epss_percentile=epss_entry.percentile if epss_entry else None,
        epss_date=epss_entry.date if epss_entry else None,
        is_kev=is_kev,
        kev_date_added=kev_entry.date_added if kev_entry else None,
        kev_due_date=kev_entry.due_date if kev_entry else None,
        kev_required_action=kev_entry.required_action if kev_entry else None,
        kev_ransomware_use=kev_ransomware,
        exploit_maturity=calculate_exploit_maturity(is_kev, kev_ransomware, epss_score),
        risk_score=calculate_risk_score(cvss, epss_score, is_kev, kev_ransomware),
    )


def _add_finding_to_map(
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cve: str,
    finding: Dict[str, Any],
) -> None:
    """Add a finding to the CVE-to-findings map, avoiding duplicates."""
    if cve not in cve_to_findings:
        cve_to_findings[cve] = []
    if not any(f.get("_id") == finding.get("_id") for f in cve_to_findings[cve]):
        cve_to_findings[cve].append(finding)


def _extract_cves_from_finding(
    finding: Dict[str, Any],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cvss_scores: Dict[str, float],
) -> None:
    """Extract CVE/GHSA IDs from a single finding and its nested vulnerabilities."""
    details = finding.get("details", {})
    if not isinstance(details, dict):
        return

    # Check if finding ID itself is a CVE
    finding_id = finding.get("finding_id") or finding.get("id", "")
    if finding_id and finding_id.startswith("CVE-"):
        _add_finding_to_map(cve_to_findings, finding_id, finding)
        if details.get("cvss_score") is not None:
            cvss_scores[finding_id] = details["cvss_score"]

    # Extract CVEs from vulnerabilities array (aggregated findings)
    for vuln in details.get("vulnerabilities", []):
        cve = vuln.get("id", "")
        if cve and (cve.startswith("CVE-") or cve.startswith("GHSA-")):
            _add_finding_to_map(cve_to_findings, cve, finding)
            if vuln.get("cvss_score") is not None and cve not in cvss_scores:
                cvss_scores[cve] = vuln["cvss_score"]

        # Also check aliases within the vulnerability
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                _add_finding_to_map(cve_to_findings, alias, finding)

    # Also check aliases at finding level
    for alias in finding.get("aliases", []):
        if alias.startswith("CVE-"):
            _add_finding_to_map(cve_to_findings, alias, finding)


def _apply_ghsa_to_vuln(
    vuln: Dict[str, Any],
    ghsa_id: str,
    ghsa_data: GHSAData,
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    finding: Dict[str, Any],
) -> None:
    """Apply GHSA resolution data to a single vulnerability entry."""
    if vuln.get("id") != ghsa_id:
        return

    vuln["github_advisory_url"] = ghsa_data.advisory_url

    if ghsa_data.cve_id:
        if "aliases" not in vuln:
            vuln["aliases"] = []
        if ghsa_data.cve_id not in vuln["aliases"]:
            vuln["aliases"].append(ghsa_data.cve_id)
        vuln["resolved_cve"] = ghsa_data.cve_id
        _add_finding_to_map(cve_to_findings, ghsa_data.cve_id, finding)

    for alias in ghsa_data.aliases:
        if "aliases" not in vuln:
            vuln["aliases"] = []
        if alias not in vuln["aliases"]:
            vuln["aliases"].append(alias)


def _apply_ghsa_resolutions(
    ghsa_resolutions: Dict[str, GHSAData],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
) -> None:
    """Apply all GHSA resolutions to affected findings."""
    for ghsa_id, ghsa_data in ghsa_resolutions.items():
        for finding in cve_to_findings.get(ghsa_id, []):
            if "details" not in finding:
                finding["details"] = {}

            finding["details"]["github_advisory_url"] = ghsa_data.advisory_url

            for vuln in finding["details"].get("vulnerabilities", []):
                _apply_ghsa_to_vuln(vuln, ghsa_id, ghsa_data, cve_to_findings, finding)

            if ghsa_data.cve_id:
                if "aliases" not in finding:
                    finding["aliases"] = []
                if ghsa_data.cve_id not in finding["aliases"]:
                    finding["aliases"].append(ghsa_data.cve_id)


def _apply_enrichment_to_vuln(
    vuln: Dict[str, Any],
    cve: str,
    enrichment: VulnerabilityEnrichment,
) -> None:
    """Apply EPSS/KEV enrichment to a single vulnerability entry."""
    vuln_id = vuln.get("id", "")
    if vuln_id != cve and cve not in vuln.get("aliases", []):
        return

    if enrichment.epss_score is not None:
        vuln["epss_score"] = enrichment.epss_score
        vuln["epss_percentile"] = enrichment.epss_percentile
    if enrichment.is_kev:
        vuln["in_kev"] = True
        vuln["kev_due_date"] = enrichment.kev_due_date
        vuln["kev_ransomware_use"] = enrichment.kev_ransomware_use


def _apply_enrichment_to_finding(
    finding: Dict[str, Any],
    enrichment: VulnerabilityEnrichment,
) -> None:
    """Apply aggregated EPSS/KEV enrichment to finding-level details."""
    details = finding.setdefault("details", {})

    # Enrich individual vulnerabilities in the array
    for vuln in details.get("vulnerabilities", []):
        _apply_enrichment_to_vuln(vuln, enrichment.cve, enrichment)

    # Aggregate: use the highest EPSS score across all vulns
    if enrichment.epss_score is not None:
        max_epss = details.get("epss_score")
        if max_epss is None or enrichment.epss_score > max_epss:
            details["epss_score"] = enrichment.epss_score
            details["epss_percentile"] = enrichment.epss_percentile
            details["epss_date"] = enrichment.epss_date

    if enrichment.is_kev:
        details["in_kev"] = True
        details["kev_date_added"] = enrichment.kev_date_added
        details["kev_due_date"] = enrichment.kev_due_date
        details["kev_required_action"] = enrichment.kev_required_action
        details["kev_ransomware_use"] = enrichment.kev_ransomware_use

    if enrichment.exploit_maturity and enrichment.exploit_maturity != "unknown":
        current_maturity = details.get("exploit_maturity", "unknown")
        if EXPLOIT_MATURITY_ORDER.get(enrichment.exploit_maturity, 0) > EXPLOIT_MATURITY_ORDER.get(current_maturity, 0):
            details["exploit_maturity"] = enrichment.exploit_maturity

    if enrichment.risk_score is not None:
        current_risk = details.get("risk_score")
        if current_risk is None or enrichment.risk_score > current_risk:
            details["risk_score"] = enrichment.risk_score


class VulnerabilityEnrichmentService:
    """
    Service to enrich vulnerability data with EPSS scores and CISA KEV information.

    Uses Redis for distributed caching across all pods:
    - KEV catalog is cached globally for 24 hours (updates daily)
    - EPSS scores are cached per-CVE for 24 hours
    - GHSA resolutions are cached per-ID for 7 days (rarely change)

    This dramatically reduces API calls when running multiple backend replicas.
    """

    def __init__(self) -> None:
        self._http_client: Optional[InstrumentedAsyncClient] = None
        self._client_lock = asyncio.Lock()  # Prevent race condition on client creation
        self._epss_provider = EPSSProvider()
        self._kev_provider = KEVProvider()
        self._ghsa_provider = GHSAProvider()

    def set_github_token(self, token: Optional[str]) -> None:
        """Set the GitHub Personal Access Token for authenticated API requests."""
        self._ghsa_provider.set_token(token)

    async def _get_client(self) -> InstrumentedAsyncClient:
        """Get or create HTTP client with thread-safe initialization."""
        if self._http_client is not None and self._http_client._client is not None:
            return self._http_client

        async with self._client_lock:
            # Double-check after acquiring lock
            if self._http_client is not None and self._http_client._client is not None:
                return self._http_client
            timeout = ANALYZER_TIMEOUTS.get("default", 30.0)
            self._http_client = InstrumentedAsyncClient("Enrichment Service", timeout=timeout)
            await self._http_client.start()
        return self._http_client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.close()

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
        unique_cves = list({cve for cve in cves if cve and cve.startswith("CVE-")})

        if not unique_cves:
            return {}

        cvss_scores = cvss_scores or {}
        client = await self._get_client()

        # Load data sources in parallel
        kev_task = self._kev_provider.load_kev_catalog(client)
        epss_task = self._epss_provider.load_epss_scores(client, unique_cves)

        kev_catalog, epss_data = await asyncio.gather(kev_task, epss_task)

        # Build enrichment for each CVE
        results = {
            cve: _build_enrichment(
                cve,
                kev_catalog.get(cve),
                epss_data.get(cve),
                cvss_scores.get(cve),
            )
            for cve in unique_cves
        }

        kev_count = sum(1 for e in results.values() if e.is_kev)
        epss_count = sum(1 for e in results.values() if e.epss_score is not None)
        logger.info(f"Enriched {len(results)} CVEs (KEV: {kev_count}, EPSS: {epss_count})")

        return results

    async def enrich_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Enrich a list of vulnerability findings with EPSS and KEV data.
        Modifies findings in-place.

        Args:
            findings: List of finding dicts with vulnerabilities in details
        """
        if not findings:
            return

        # Phase 1: Extract CVE/GHSA IDs from all findings
        cve_to_findings: Dict[str, List[Dict[str, Any]]] = {}
        cvss_scores: Dict[str, float] = {}

        for finding in findings:
            _extract_cves_from_finding(finding, cve_to_findings, cvss_scores)

        if not cve_to_findings:
            return

        # Phase 2: Resolve GHSA IDs to CVEs
        ghsa_ids = [vid for vid in cve_to_findings.keys() if vid.startswith("GHSA-")]
        if ghsa_ids:
            logger.info(f"Resolving {len(ghsa_ids)} GHSA IDs to CVEs")
            ghsa_resolutions = await self.resolve_ghsa_to_cve(ghsa_ids)
            _apply_ghsa_resolutions(ghsa_resolutions, cve_to_findings)

        # Phase 3: Enrich CVEs with EPSS/KEV data
        cves_to_enrich = [cve for cve in cve_to_findings.keys() if cve.startswith("CVE-")]
        enrichments = await self.enrich_cves(cves_to_enrich, cvss_scores)

        # Phase 4: Apply enrichment to findings
        for cve, enrichment in enrichments.items():
            for finding in cve_to_findings.get(cve, []):
                _apply_enrichment_to_finding(finding, enrichment)

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
        return calculate_adjusted_risk_score(base_risk_score, is_reachable, reachability_level)

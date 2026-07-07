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
    if cve not in cve_to_findings:
        cve_to_findings[cve] = []
    if not any(f.get("_id") == finding.get("_id") for f in cve_to_findings[cve]):
        cve_to_findings[cve].append(finding)


def _extract_finding_id_cve(
    finding: Dict[str, Any],
    details: Dict[str, Any],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cvss_scores: Dict[str, float],
) -> None:
    finding_id = finding.get("finding_id") or finding.get("id", "")
    if not (finding_id and finding_id.startswith("CVE-")):
        return
    _add_finding_to_map(cve_to_findings, finding_id, finding)
    if details.get("cvss_score") is not None:
        cvss_scores[finding_id] = details["cvss_score"]


def _extract_aliases(
    aliases: List[str],
    finding: Dict[str, Any],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
) -> None:
    for alias in aliases:
        if alias.startswith("CVE-"):
            _add_finding_to_map(cve_to_findings, alias, finding)


def _extract_vuln_cves(
    vuln: Dict[str, Any],
    finding: Dict[str, Any],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cvss_scores: Dict[str, float],
) -> None:
    cve = vuln.get("id", "")
    if cve and (cve.startswith("CVE-") or cve.startswith("GHSA-")):
        _add_finding_to_map(cve_to_findings, cve, finding)
        if vuln.get("cvss_score") is not None and cve not in cvss_scores:
            cvss_scores[cve] = vuln["cvss_score"]
    _extract_aliases(vuln.get("aliases", []), finding, cve_to_findings)


def _extract_cves_from_finding(
    finding: Dict[str, Any],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cvss_scores: Dict[str, float],
) -> None:
    details = finding.get("details", {})
    if not isinstance(details, dict):
        return

    _extract_finding_id_cve(finding, details, cve_to_findings, cvss_scores)

    for vuln in details.get("vulnerabilities", []):
        _extract_vuln_cves(vuln, finding, cve_to_findings, cvss_scores)

    _extract_aliases(finding.get("aliases", []), finding, cve_to_findings)


def _apply_ghsa_to_vuln(
    vuln: Dict[str, Any],
    ghsa_id: str,
    ghsa_data: GHSAData,
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    finding: Dict[str, Any],
) -> None:
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


def _apply_ghsa_cve_alias_to_finding(
    finding: Dict[str, Any],
    cve_id: Optional[str],
) -> None:
    if not cve_id:
        return
    if "aliases" not in finding:
        finding["aliases"] = []
    if cve_id not in finding["aliases"]:
        finding["aliases"].append(cve_id)


def _apply_ghsa_to_finding(
    finding: Dict[str, Any],
    ghsa_id: str,
    ghsa_data: GHSAData,
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
) -> None:
    if "details" not in finding:
        finding["details"] = {}

    finding["details"]["github_advisory_url"] = ghsa_data.advisory_url

    for vuln in finding["details"].get("vulnerabilities", []):
        _apply_ghsa_to_vuln(vuln, ghsa_id, ghsa_data, cve_to_findings, finding)

    _apply_ghsa_cve_alias_to_finding(finding, ghsa_data.cve_id)


def _apply_ghsa_resolutions(
    ghsa_resolutions: Dict[str, GHSAData],
    cve_to_findings: Dict[str, List[Dict[str, Any]]],
    cvss_scores: Dict[str, float],
) -> None:
    for ghsa_id, ghsa_data in ghsa_resolutions.items():
        # GHSA-first ecosystems record cvss_score only under the GHSA id; carry it
        # to the resolved CVE key so risk scoring uses the real CVSS, not the base.
        if ghsa_data.cve_id and ghsa_id in cvss_scores:
            cvss_scores.setdefault(ghsa_data.cve_id, cvss_scores[ghsa_id])
        for finding in cve_to_findings.get(ghsa_id, []):
            _apply_ghsa_to_finding(finding, ghsa_id, ghsa_data, cve_to_findings)


def _apply_enrichment_to_vuln(
    vuln: Dict[str, Any],
    cve: str,
    enrichment: VulnerabilityEnrichment,
) -> None:
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
    details = finding.setdefault("details", {})

    for vuln in details.get("vulnerabilities", []):
        _apply_enrichment_to_vuln(vuln, enrichment.cve, enrichment)

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
        # Stay flagged if any KEV CVE is ransomware-linked; don't clobber to False.
        details["kev_ransomware_use"] = bool(details.get("kev_ransomware_use")) or enrichment.kev_ransomware_use

    if enrichment.exploit_maturity and enrichment.exploit_maturity != "unknown":
        current_maturity = details.get("exploit_maturity", "unknown")
        if EXPLOIT_MATURITY_ORDER.get(enrichment.exploit_maturity, 0) > EXPLOIT_MATURITY_ORDER.get(current_maturity, 0):
            details["exploit_maturity"] = enrichment.exploit_maturity

    if enrichment.risk_score is not None:
        current_risk = details.get("risk_score")
        if current_risk is None or enrichment.risk_score > current_risk:
            details["risk_score"] = enrichment.risk_score


class VulnerabilityEnrichmentService:
    """Enrich vulnerabilities with EPSS, KEV, and GHSA data, using Redis for cross-pod caching."""

    def __init__(self) -> None:
        self._http_client: Optional[InstrumentedAsyncClient] = None
        self._client_lock = asyncio.Lock()
        self._epss_provider = EPSSProvider()
        self._kev_provider = KEVProvider()
        self._ghsa_provider = GHSAProvider()

    def set_github_token(self, token: Optional[str]) -> None:
        self._ghsa_provider.set_token(token)

    async def _get_client(self) -> InstrumentedAsyncClient:
        if self._http_client is not None and self._http_client._client is not None:
            return self._http_client

        async with self._client_lock:
            # Double-checked locking: another coroutine may have created it.
            if self._http_client is not None and self._http_client._client is not None:
                return self._http_client
            timeout = ANALYZER_TIMEOUTS.get("default", 30.0)
            self._http_client = InstrumentedAsyncClient("Enrichment Service", timeout=timeout)
            await self._http_client.start()
        return self._http_client

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.close()

    async def resolve_ghsa_to_cve(self, ghsa_ids: List[str]) -> Dict[str, GHSAData]:
        client = await self._get_client()
        return await self._ghsa_provider.resolve_ghsa_to_cve(client, ghsa_ids)

    async def enrich_cves(
        self,
        cves: List[str],
        cvss_scores: Optional[Dict[str, float]] = None,
    ) -> Dict[str, VulnerabilityEnrichment]:
        """Enrich CVEs with EPSS and KEV data; returns {cve: VulnerabilityEnrichment}."""
        if not cves:
            return {}

        unique_cves = list({cve for cve in cves if cve and cve.startswith("CVE-")})

        if not unique_cves:
            return {}

        cvss_scores = cvss_scores or {}
        client = await self._get_client()

        kev_task = self._kev_provider.load_kev_catalog(client)
        epss_task = self._epss_provider.load_epss_scores(client, unique_cves)

        kev_catalog, epss_data = await asyncio.gather(kev_task, epss_task)

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
        """Enrich vulnerability findings in-place with EPSS and KEV data."""
        if not findings:
            return

        cve_to_findings: Dict[str, List[Dict[str, Any]]] = {}
        cvss_scores: Dict[str, float] = {}

        for finding in findings:
            _extract_cves_from_finding(finding, cve_to_findings, cvss_scores)

        if not cve_to_findings:
            return

        ghsa_ids = [vid for vid in cve_to_findings.keys() if vid.startswith("GHSA-")]
        if ghsa_ids:
            logger.info(f"Resolving {len(ghsa_ids)} GHSA IDs to CVEs")
            ghsa_resolutions = await self.resolve_ghsa_to_cve(ghsa_ids)
            _apply_ghsa_resolutions(ghsa_resolutions, cve_to_findings, cvss_scores)

        cves_to_enrich = [cve for cve in cve_to_findings.keys() if cve.startswith("CVE-")]
        enrichments = await self.enrich_cves(cves_to_enrich, cvss_scores)

        for cve, enrichment in enrichments.items():
            for finding in cve_to_findings.get(cve, []):
                _apply_enrichment_to_finding(finding, enrichment)

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

from app.core.constants import (
    CVSS_SEVERITY_SCORES,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    EPSS_API_URL,
    GHSA_API_URL,
    KEV_CATALOG_URL,
)
from app.core.cve import entry_cves
from app.core.risk_scoring import calculate_exploit_maturity
from app.schemas.enrichment import EPSSData, GHSAData, KEVEntry, VulnerabilityEnrichment
from app.services.aggregation.merging import dedupe_vulnerability_entries
from app.services.aggregation.versions import aggregate_fixed_version
from app.services.enrichment.epss import EPSSProvider
from app.services.enrichment.ghsa import GHSAProvider
from app.services.enrichment.kev import KEVProvider
from app.services.enrichment.scoring import calculate_risk_score, fold_enrichments

logger = logging.getLogger(__name__)

# Enrichment the document carries only as the roll-up over its advisories.
_ROLLUP_ONLY_KEYS = frozenset({"epss_date"})


def _build_enrichment(cve: str, kev_entry: KEVEntry | None, epss_entry: EPSSData | None) -> VulnerabilityEnrichment:
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
        risk_score=calculate_risk_score(None, epss_score, is_kev, kev_ransomware),
    )


def _vulnerabilities(finding: dict[str, Any]) -> list[dict[str, Any]]:
    return (finding.get("details") or {}).get("vulnerabilities") or []


def _ghsa_ids(findings: list[dict[str, Any]]) -> list[str]:
    return sorted({i for f in findings for v in _vulnerabilities(f) if (i := v.get("id") or "").startswith("GHSA-")})


def _cves(findings: list[dict[str, Any]]) -> list[str]:
    return sorted({cve for f in findings for v in _vulnerabilities(f) for cve in entry_cves(v)})


def sends_ids(findings: list[dict[str, Any]]) -> bool:
    """Whether enrich_findings puts any id of these findings on the wire."""
    return bool(_ghsa_ids(findings) or _cves(findings))


def _resolve_ghsa(vuln: dict[str, Any], ghsa_data: GHSAData) -> bool:
    """Record GitHub's CVE on a GHSA advisory; True when its identity grew."""
    vuln["github_advisory_url"] = ghsa_data.advisory_url
    aliases = vuln.setdefault("aliases", [])
    cve_id = ghsa_data.cve_id
    if cve_id is None or (cve_id in aliases and vuln.get("resolved_cve") == cve_id):
        return False
    if cve_id not in aliases:
        aliases.append(cve_id)
    vuln["resolved_cve"] = cve_id
    return True


def _apply_ghsa_resolutions(
    findings: list[dict[str, Any]], resolutions: Mapping[str, GHSAData]
) -> list[dict[str, Any]]:
    """Resolve every GHSA advisory; returns the findings whose advisories gained an id."""
    touched = []
    for finding in findings:
        changed = False
        for vuln in _vulnerabilities(finding):
            ghsa_data = resolutions.get(vuln.get("id") or "")
            if ghsa_data is None:
                continue
            changed = _resolve_ghsa(vuln, ghsa_data) or changed
            aliases = finding.setdefault("aliases", [])
            if ghsa_data.cve_id and ghsa_data.cve_id not in aliases:
                aliases.append(ghsa_data.cve_id)
        if changed:
            touched.append(finding)
    return touched


def _dedupe_finding_vulnerabilities(findings: list[dict[str, Any]]) -> None:
    """GHSA->CVE resolution can link entries that were distinct at aggregation time."""
    for finding in findings:
        vulns = _vulnerabilities(finding)
        before = len(vulns)
        dedupe_vulnerability_entries(vulns)
        if len(vulns) != before:
            finding["details"]["fixed_version"] = aggregate_fixed_version(vulns, finding.get("version"))


def _enrichment_fields(enrichment: VulnerabilityEnrichment) -> dict[str, Any]:
    fields: dict[str, Any] = {"risk_score": enrichment.risk_score}
    if enrichment.epss_score is not None:
        fields |= {
            "epss_score": enrichment.epss_score,
            "epss_percentile": enrichment.epss_percentile,
            "epss_date": enrichment.epss_date,
        }
    if enrichment.is_kev:
        fields |= {
            DETAILS_KEY_IN_KEV: True,
            "kev_date_added": enrichment.kev_date_added,
            "kev_due_date": enrichment.kev_due_date,
            "kev_required_action": enrichment.kev_required_action,
            DETAILS_KEY_KEV_RANSOMWARE: enrichment.kev_ransomware_use,
        }
    if enrichment.exploit_maturity != "unknown":
        fields["exploit_maturity"] = enrichment.exploit_maturity
    return fields


def advisory_enrichment(
    vuln: dict[str, Any], enrichments: Mapping[str, VulnerabilityEnrichment]
) -> VulnerabilityEnrichment:
    """The advisory's CVEs folded, each scored on the advisory's own CVSS, or on its severity without one."""
    cvss = vuln.get("cvss_score")
    if cvss is None:
        cvss = CVSS_SEVERITY_SCORES.get(vuln.get("severity") or "UNKNOWN")
    matched = [enrichments[cve] for cve in entry_cves(vuln) if cve in enrichments]
    folded = fold_enrichments(
        e.model_copy(update={"risk_score": calculate_risk_score(cvss, e.epss_score, e.is_kev, e.kev_ransomware_use)})
        for e in matched
    )
    return folded or VulnerabilityEnrichment(
        cve=str(vuln.get("id")), risk_score=calculate_risk_score(cvss, None, False, False)
    )


def apply_enrichments(details: dict[str, Any], enrichments: Mapping[str, VulnerabilityEnrichment]) -> None:
    """Mark each advisory with its own CVEs' enrichment, then roll the document up from its advisories."""
    folded = []
    for vuln in details.get("vulnerabilities") or []:
        advisory = advisory_enrichment(vuln, enrichments)
        vuln.update({k: v for k, v in _enrichment_fields(advisory).items() if k not in _ROLLUP_ONLY_KEYS})
        folded.append(advisory)
    rollup = fold_enrichments(folded)
    if rollup is not None:
        details.update(_enrichment_fields(rollup))


class VulnerabilityEnrichmentService:
    """Enrich vulnerabilities with EPSS, KEV, and GHSA data, using Redis for cross-pod caching."""

    SENDS_IDS_TO = (EPSS_API_URL, GHSA_API_URL)
    DOWNLOADS_FROM = (KEV_CATALOG_URL,)

    def __init__(self) -> None:
        self._epss_provider = EPSSProvider()
        self._kev_provider = KEVProvider()
        self._ghsa_provider = GHSAProvider()

    async def _enrich_cves(self, cves: list[str]) -> tuple[dict[str, VulnerabilityEnrichment], list[str]]:
        """Enrich CVEs with EPSS and KEV, scored without CVSS; also names the sources that could not be read."""
        unique_cves = list({cve for cve in cves if cve and cve.startswith("CVE-")})
        if not unique_cves:
            return {}, []

        kev_catalog, (epss_data, epss_complete) = await asyncio.gather(
            self._kev_provider.load_kev_catalog(), self._epss_provider.load_epss_scores(unique_cves)
        )
        unavailable = [name for name, missing in (("KEV", kev_catalog is None), ("EPSS", not epss_complete)) if missing]
        kev_catalog = kev_catalog or {}
        results = {cve: _build_enrichment(cve, kev_catalog.get(cve), epss_data.get(cve)) for cve in unique_cves}

        kev_count = sum(1 for e in results.values() if e.is_kev)
        logger.info(
            f"Enriched {len(results)} CVEs (KEV: {kev_count}, EPSS: {len(epss_data)}, unavailable: {unavailable})"
        )
        return results, unavailable

    async def enrich_cves(self, cves: list[str]) -> dict[str, VulnerabilityEnrichment]:
        return (await self._enrich_cves(cves))[0]

    async def enrich_findings(
        self, findings: list[dict[str, Any]], github_token: str | None = None
    ) -> tuple[dict[str, VulnerabilityEnrichment], list[str]]:
        """Fold GHSA, EPSS and KEV into the findings in place; returns per-CVE enrichment and the unreadable sources."""
        if ghsa_ids := _ghsa_ids(findings):
            logger.info(f"Resolving {len(ghsa_ids)} GHSA IDs to CVEs")
            resolutions = await self._ghsa_provider.resolve_ghsa_to_cve(ghsa_ids, github_token)
            _dedupe_finding_vulnerabilities(_apply_ghsa_resolutions(findings, resolutions))

        enrichments, unavailable = await self._enrich_cves(_cves(findings))
        for finding in findings:
            apply_enrichments(finding.setdefault("details", {}), enrichments)
        return enrichments, unavailable


vulnerability_enrichment_service = VulnerabilityEnrichmentService()

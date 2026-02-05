import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    OSV_BATCH_API_URL,
)
from app.models.finding import Severity

from .base import Analyzer

logger = logging.getLogger(__name__)

# OSV severity to our Severity enum mapping
OSV_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL.value,
    "HIGH": Severity.HIGH.value,
    "MODERATE": Severity.MEDIUM.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
}


class OSVAnalyzer(Analyzer):
    """
    Analyzer that checks packages for known vulnerabilities via the OSV API.

    Uses Redis cache to reduce API calls across all pods.
    """

    name = "osv"
    api_url = OSV_BATCH_API_URL

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []

        # Check cache first for all components
        cached_results, uncached_components = await self._get_cached_components(
            components
        )
        results.extend(cached_results)

        logger.debug(
            f"OSV: {len(cached_results)} from cache, {len(uncached_components)} to fetch"
        )

        if not uncached_components:
            return {"osv_vulnerabilities": results}

        timeout = ANALYZER_TIMEOUTS.get("osv", ANALYZER_TIMEOUTS["default"])
        batch_size = ANALYZER_BATCH_SIZES.get("osv", 500)

        async with InstrumentedAsyncClient("OSV API", timeout=timeout) as client:

            for chunk_start in range(0, len(uncached_components), batch_size):
                chunk = uncached_components[chunk_start : chunk_start + batch_size]

                batch_payload: Dict[str, List[Dict[str, Any]]] = {"queries": []}
                valid_components = []
                skipped_count = 0

                for component in chunk:
                    purl = component.get("purl")
                    if purl:
                        batch_payload["queries"].append({"package": {"purl": purl}})
                        valid_components.append(component)
                    else:
                        skipped_count += 1

                if skipped_count > 0:
                    logger.debug(
                        f"OSV: Skipped {skipped_count} components without PURL"
                    )

                if not batch_payload["queries"]:
                    continue

                try:
                    response = await client.post(self.api_url, json=batch_payload)
                    if response.status_code == 200:
                        data = response.json()
                        batch_results = data.get("results", [])

                        # Validate response length matches request
                        if len(batch_results) != len(valid_components):
                            logger.warning(
                                f"OSV API response count mismatch: "
                                f"sent {len(valid_components)}, received {len(batch_results)}"
                            )
                            # Only process matching pairs to avoid misalignment
                            batch_results = batch_results[: len(valid_components)]

                        # Cache results and add to output
                        cache_mapping = {}
                        for comp, res in zip(valid_components, batch_results):
                            vulns = res.get("vulns", [])
                            purl = comp.get("purl", "")
                            comp_name = comp.get("name", "")
                            comp_version = comp.get("version", "")

                            # Normalize vulnerabilities with severity and message
                            normalized_vulns = self._normalize_vulnerabilities(vulns)

                            # Cache even empty results (with shorter TTL)
                            cache_key = CacheKeys.osv(purl)
                            cache_data = {
                                "component": comp_name,
                                "version": comp_version,
                                "purl": purl,
                                "vulnerabilities": normalized_vulns,
                                "severity": self._get_highest_severity(
                                    normalized_vulns
                                ),
                                "message": self._create_summary_message(
                                    comp_name, comp_version, normalized_vulns
                                ),
                            }
                            cache_mapping[cache_key] = cache_data

                            if normalized_vulns:
                                results.append(cache_data)

                        # Batch cache all results
                        if cache_mapping:
                            await cache_service.mset(
                                cache_mapping, CacheTTL.OSV_VULNERABILITY
                            )

                    elif response.status_code == 429:
                        logger.warning("OSV API rate limit hit, waiting...")
                        await asyncio.sleep(5)
                    else:
                        logger.warning(f"OSV Batch API error: {response.status_code}")

                except httpx.TimeoutException:
                    logger.warning(
                        f"OSV API timeout for batch starting at {chunk_start}"
                    )
                except httpx.ConnectError:
                    logger.warning("OSV API connection error")
                except Exception as e:
                    logger.warning(f"OSV Analysis Exception: {type(e).__name__}: {e}")

                # Small delay between batches
                if chunk_start + batch_size < len(uncached_components):
                    await asyncio.sleep(0.2)

        return {"osv_vulnerabilities": results}

    async def _get_cached_components(
        self, components: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Check cache for components, return cached results and uncached components."""
        cached_results = []
        uncached_components = []

        # Build cache keys for components with PURLs
        cache_keys = []
        component_map = {}

        for component in components:
            purl = component.get("purl")
            if purl:
                cache_key = CacheKeys.osv(purl)
                cache_keys.append(cache_key)
                component_map[cache_key] = component

        if not cache_keys:
            return [], components

        # Batch get from Redis
        cached_data = await cache_service.mget(cache_keys)

        for cache_key, data in cached_data.items():
            component = component_map.get(cache_key)
            if not component:
                continue

            if data:
                # Only add to results if there are vulnerabilities
                if data.get("vulnerabilities"):
                    cached_results.append(data)
            else:
                uncached_components.append(component)

        return cached_results, uncached_components

    def _normalize_vulnerabilities(
        self, vulns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Normalize OSV vulnerabilities with severity and message."""
        normalized = []
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            aliases = vuln.get("aliases", [])

            # Extract severity from OSV data
            severity = self._extract_severity(vuln)

            normalized.append(
                {
                    "id": vuln_id,
                    "aliases": aliases,
                    "summary": summary,
                    "details": details,
                    "severity": severity,
                    "message": summary or f"Vulnerability {vuln_id} detected",
                    "references": [
                        ref.get("url")
                        for ref in vuln.get("references", [])
                        if ref.get("url")
                    ],
                    "affected": vuln.get("affected", []),
                }
            )
        return normalized

    def _extract_severity(self, vuln: Dict[str, Any]) -> str:
        """Extract severity from OSV vulnerability data."""
        # Check database_specific first (e.g., GitHub advisories)
        db_specific = vuln.get("database_specific", {})
        if db_specific.get("severity"):
            sev = db_specific["severity"].upper()
            if sev in OSV_SEVERITY_MAP:
                return OSV_SEVERITY_MAP[sev]

        # Check severity array (CVSS scores)
        for sev_info in vuln.get("severity", []):
            sev_type = sev_info.get("type", "")
            score = sev_info.get("score", "")

            # Parse CVSS score
            if "CVSS" in sev_type and score:
                cvss_score = self._parse_cvss_score(str(score))
                if cvss_score is not None:
                    if cvss_score >= 9.0:
                        return Severity.CRITICAL.value
                    elif cvss_score >= 7.0:
                        return Severity.HIGH.value
                    elif cvss_score >= 4.0:
                        return Severity.MEDIUM.value
                    else:
                        return Severity.LOW.value

        # Check affected entries for severity
        for affected in vuln.get("affected", []):
            ecosystem_specific = affected.get("ecosystem_specific", {})
            if ecosystem_specific.get("severity"):
                sev = ecosystem_specific["severity"].upper()
                if sev in OSV_SEVERITY_MAP:
                    return OSV_SEVERITY_MAP[sev]

        # Default to MEDIUM if no severity found
        return Severity.MEDIUM.value

    def _parse_cvss_score(self, score: str) -> Optional[float]:
        """Parse CVSS score from numeric value or vector string."""
        try:
            # Try direct numeric conversion first
            return float(score)
        except ValueError:
            pass

        # Try to extract base score from CVSS vector
        if "/" in score:
            parts = score.split("/")
            # Check last part for numeric score
            try:
                return float(parts[-1])
            except ValueError:
                pass

        return None

    def _get_highest_severity(self, vulns: List[Dict[str, Any]]) -> str:
        """Get the highest severity from a list of vulnerabilities."""
        if not vulns:
            return Severity.INFO.value

        severity_order = [
            Severity.CRITICAL.value,
            Severity.HIGH.value,
            Severity.MEDIUM.value,
            Severity.LOW.value,
            Severity.INFO.value,
        ]

        for sev in severity_order:
            for vuln in vulns:
                if vuln.get("severity") == sev:
                    return sev

        return Severity.MEDIUM.value

    def _create_summary_message(
        self, component: str, version: str, vulns: List[Dict[str, Any]]
    ) -> str:
        """Create a summary message for the component's vulnerabilities."""
        if not vulns:
            return ""

        count = len(vulns)
        critical = sum(1 for v in vulns if v.get("severity") == Severity.CRITICAL.value)
        high = sum(1 for v in vulns if v.get("severity") == Severity.HIGH.value)

        parts = [
            f"{component}@{version} has {count} known vulnerabilit{'y' if count == 1 else 'ies'}"
        ]

        severity_parts = []
        if critical:
            severity_parts.append(f"{critical} critical")
        if high:
            severity_parts.append(f"{high} high")

        if severity_parts:
            parts.append(f"({', '.join(severity_parts)})")

        return " ".join(parts)

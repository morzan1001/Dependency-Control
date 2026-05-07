import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    OSV_BATCH_API_URL,
)
from app.core.metrics import external_api_rate_limit_hits_total
from app.models.finding import Severity

from .base import Analyzer

logger = logging.getLogger(__name__)

OSV_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL.value,
    "HIGH": Severity.HIGH.value,
    "MODERATE": Severity.MEDIUM.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
}


def _build_batch_payload(
    chunk: List[Dict[str, Any]],
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """``(payload, valid_components)`` from a chunk; PURL-less components are skipped."""
    payload: Dict[str, List[Dict[str, Any]]] = {"queries": []}
    valid_components: List[Dict[str, Any]] = []
    skipped = 0
    for component in chunk:
        purl = component.get("purl")
        if purl:
            payload["queries"].append({"package": {"purl": purl}})
            valid_components.append(component)
        else:
            skipped += 1
    if skipped:
        logger.debug(f"OSV: Skipped {skipped} components without PURL")
    return payload, valid_components


class OSVAnalyzer(Analyzer):
    """Vulnerability lookup via the OSV batch API, cached across pods."""

    name = "osv"
    api_url = OSV_BATCH_API_URL

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results: List[Dict[str, Any]] = []

        cached_results, uncached_components = await self._get_cached_components(components)
        results.extend(cached_results)
        logger.debug(f"OSV: {len(cached_results)} from cache, {len(uncached_components)} to fetch")

        if not uncached_components:
            return {"osv_vulnerabilities": results}

        await self._fetch_uncached(uncached_components, results)
        return {"osv_vulnerabilities": results}

    async def _fetch_uncached(
        self,
        uncached_components: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
    ) -> None:
        """Drive the chunked batch loop, populating ``results`` in-place."""
        timeout = ANALYZER_TIMEOUTS.get("osv", ANALYZER_TIMEOUTS["default"])
        batch_size = ANALYZER_BATCH_SIZES.get("osv", 500)

        async with InstrumentedAsyncClient("OSV API", timeout=timeout) as client:
            for chunk_start in range(0, len(uncached_components), batch_size):
                chunk = uncached_components[chunk_start : chunk_start + batch_size]
                payload, valid_components = _build_batch_payload(chunk)
                if not payload["queries"]:
                    continue
                await self._post_and_handle(client, payload, valid_components, results, chunk_start)
                if chunk_start + batch_size < len(uncached_components):
                    await asyncio.sleep(0.2)

    async def _post_and_handle(
        self,
        client: InstrumentedAsyncClient,
        payload: Dict[str, List[Dict[str, Any]]],
        valid_components: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
        chunk_start: int,
    ) -> None:
        """POST one batch and dispatch on response status."""
        try:
            response = await client.post(self.api_url, json=payload)
        except httpx.TimeoutException:
            logger.warning(f"OSV API timeout for batch starting at {chunk_start}")
            return
        except httpx.ConnectError:
            logger.warning("OSV API connection error")
            return
        except Exception as e:
            logger.warning(f"OSV Analysis Exception: {type(e).__name__}: {e}")
            return

        if response.status_code == 200:
            await self._handle_success(response, valid_components, results)
        elif response.status_code == 429:
            external_api_rate_limit_hits_total.labels(service="OSV API").inc()
            logger.warning("OSV API rate limit hit, waiting...")
            await asyncio.sleep(5)
        else:
            logger.warning(f"OSV Batch API error: {response.status_code}")

    async def _handle_success(
        self,
        response: Any,
        valid_components: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
    ) -> None:
        """Parse a 200 response: align entries with components, cache, append."""
        data = response.json()
        batch_results = data.get("results", [])
        if len(batch_results) != len(valid_components):
            logger.warning(
                f"OSV API response count mismatch: "
                f"sent {len(valid_components)}, received {len(batch_results)}"
            )
            batch_results = batch_results[: len(valid_components)]

        cache_mapping: Dict[str, Dict[str, Any]] = {}
        for comp, res in zip(valid_components, batch_results):
            cache_data = self._build_cache_entry(comp, res.get("vulns", []))
            cache_mapping[CacheKeys.osv(comp.get("purl", ""))] = cache_data
            if cache_data["vulnerabilities"]:
                results.append(cache_data)

        if cache_mapping:
            await cache_service.mset(cache_mapping, CacheTTL.OSV_VULNERABILITY)

    def _build_cache_entry(
        self, component: Dict[str, Any], vulns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build the per-component dict that gets written to cache and to results."""
        comp_name = component.get("name", "")
        comp_version = component.get("version", "")
        normalized = self._normalize_vulnerabilities(vulns)
        return {
            "component": comp_name,
            "version": comp_version,
            "purl": component.get("purl", ""),
            "vulnerabilities": normalized,
            "severity": self._get_highest_severity(normalized),
            "message": self._create_summary_message(comp_name, comp_version, normalized),
        }

    async def _get_cached_components(
        self, components: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """``(cached_results, uncached_components)`` from a batch Redis lookup."""
        cached_results: List[Dict[str, Any]] = []
        uncached_components: List[Dict[str, Any]] = []

        cache_keys: List[str] = []
        component_map: Dict[str, Any] = {}
        for component in components:
            purl = component.get("purl")
            if purl:
                cache_key = CacheKeys.osv(purl)
                cache_keys.append(cache_key)
                component_map[cache_key] = component

        if not cache_keys:
            return [], components

        cached_data = await cache_service.mget(cache_keys)
        for cache_key, data in cached_data.items():
            cached_comp = component_map.get(cache_key)
            if not cached_comp:
                continue
            if data:
                if data.get("vulnerabilities"):
                    cached_results.append(data)
            else:
                uncached_components.append(cached_comp)

        return cached_results, uncached_components

    def _normalize_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize OSV vulnerabilities, dropping retracted entries (``withdrawn`` set)."""
        normalized = []
        for vuln in vulns:
            if vuln.get("withdrawn"):
                continue
            vuln_id = vuln.get("id", "")
            summary = vuln.get("summary", "")
            normalized.append(
                {
                    "id": vuln_id,
                    "aliases": vuln.get("aliases", []),
                    "summary": summary,
                    "details": vuln.get("details", ""),
                    "severity": self._extract_severity(vuln),
                    "message": summary or f"Vulnerability {vuln_id} detected",
                    "references": [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")],
                    "affected": vuln.get("affected", []),
                }
            )
        return normalized

    # CVSS-type preference order — newest standard wins.
    _CVSS_TYPE_PREFERENCE = ("CVSS_V4", "CVSS_V3", "CVSS_V3.1", "CVSS_V3.0", "CVSS_V2")

    @staticmethod
    def _cvss_to_severity(cvss_score: float, cvss_type: str = "CVSS_V3") -> str:
        """Map a CVSS score to a severity using version-specific cutoffs.

        v2 has no CRITICAL tier; v3/v4 use 9 / 7 / 4 / 0. Scores outside
        ``[0, 10]`` are clamped so malformed input can't land in CRITICAL.
        """
        score = max(0.0, min(10.0, cvss_score))
        if cvss_type == "CVSS_V2":
            if score >= 7.0:
                return Severity.HIGH.value
            if score >= 4.0:
                return Severity.MEDIUM.value
            return Severity.LOW.value
        if score >= 9.0:
            return Severity.CRITICAL.value
        if score >= 7.0:
            return Severity.HIGH.value
        if score >= 4.0:
            return Severity.MEDIUM.value
        return Severity.LOW.value

    def _severity_from_cvss_array(self, severity_array: List[Dict[str, Any]]) -> Optional[str]:
        """Pick the highest-ranked CVSS entry (newest standard wins) and map it."""
        entries_by_type: Dict[str, List[Dict[str, Any]]] = {}
        for sev_info in severity_array:
            sev_type = sev_info.get("type", "")
            if "CVSS" in sev_type and sev_info.get("score"):
                entries_by_type.setdefault(sev_type, []).append(sev_info)

        for preferred_type in self._CVSS_TYPE_PREFERENCE:
            for sev_info in entries_by_type.get(preferred_type, []):
                cvss_score = self._parse_cvss_score(str(sev_info["score"]))
                if cvss_score is not None:
                    return self._cvss_to_severity(cvss_score, preferred_type)

        # Fall through for unknown CVSS subtypes (e.g. a future v5).
        for sev_info in severity_array:
            sev_type = sev_info.get("type", "")
            if "CVSS" not in sev_type or not sev_info.get("score"):
                continue
            cvss_score = self._parse_cvss_score(str(sev_info["score"]))
            if cvss_score is not None:
                return self._cvss_to_severity(cvss_score, sev_type)
        return None

    @staticmethod
    def _severity_from_map(raw_severity: Optional[str]) -> Optional[str]:
        """Look up a raw severity string in the OSV severity map."""
        if not raw_severity:
            return None
        sev = raw_severity.upper()
        return OSV_SEVERITY_MAP.get(sev)

    def _extract_severity(self, vuln: Dict[str, Any]) -> str:
        """Extract severity from OSV vulnerability data."""
        # Check database_specific first (e.g., GitHub advisories)
        db_sev = self._severity_from_map(vuln.get("database_specific", {}).get("severity"))
        if db_sev:
            return db_sev

        # Check severity array (CVSS scores)
        cvss_sev = self._severity_from_cvss_array(vuln.get("severity", []))
        if cvss_sev:
            return cvss_sev

        # Check affected entries for severity
        for affected in vuln.get("affected", []):
            eco_sev = self._severity_from_map(affected.get("ecosystem_specific", {}).get("severity"))
            if eco_sev:
                return eco_sev

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

    def _create_summary_message(self, component: str, version: str, vulns: List[Dict[str, Any]]) -> str:
        """Create a summary message for the component's vulnerabilities."""
        if not vulns:
            return ""

        count = len(vulns)
        critical = sum(1 for v in vulns if v.get("severity") == Severity.CRITICAL.value)
        high = sum(1 for v in vulns if v.get("severity") == Severity.HIGH.value)

        parts = [f"{component}@{version} has {count} known vulnerabilit{'y' if count == 1 else 'ies'}"]

        severity_parts = []
        if critical:
            severity_parts.append(f"{critical} critical")
        if high:
            severity_parts.append(f"{high} high")

        if severity_parts:
            parts.append(f"({', '.join(severity_parts)})")

        return " ".join(parts)

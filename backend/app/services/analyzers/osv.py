import asyncio
import logging
from typing import Any

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    OSV_BATCH_API_URL,
    OSV_VULN_API_URL,
)
from app.core.http_utils import InstrumentedAsyncClient
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

# Parallel /v1/vulns fetches; OSV throttles aggressively and a scan can carry thousands of ids.
_HYDRATION_CONCURRENCY = 8


def _build_batch_payload(
    chunk: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """``(payload, valid_components)`` from a chunk; PURL-less components are skipped."""
    payload: dict[str, list[dict[str, Any]]] = {"queries": []}
    valid_components: list[dict[str, Any]] = []
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

    # Bounded retry on HTTP 429 so a throttled chunk isn't silently dropped.
    max_retries: int = 3
    retry_base_delay: float = 5.0  # seconds, doubles each attempt

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results: list[dict[str, Any]] = []

        cached_results, uncached_components = await self._get_cached_components(components)
        results.extend(cached_results)
        logger.debug(f"OSV: {len(cached_results)} from cache, {len(uncached_components)} to fetch")

        if not uncached_components:
            return {"osv_vulnerabilities": results}

        skipped, unhydrated = await self._fetch_uncached(uncached_components, results)
        result: dict[str, Any] = {"osv_vulnerabilities": results}
        # Surfaced by the engine as a partial scan; never silently report full coverage.
        if skipped:
            result["partial_components_skipped"] = skipped
        if unhydrated:
            result["partial_vulnerabilities_unhydrated"] = unhydrated
        return result

    async def _fetch_uncached(
        self,
        uncached_components: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> tuple[int, int]:
        """Drive the chunked batch loop, then hydrate, populating ``results`` in-place.

        Returns ``(components_never_scanned, vulnerability_records_not_fetched)``: dropped
        batches, persistent rate limiting and truncated responses for the first, OSV records
        that could not be resolved to their full form for the second.
        """
        timeout = ANALYZER_TIMEOUTS.get("osv", ANALYZER_TIMEOUTS["default"])
        batch_size = ANALYZER_BATCH_SIZES.get("osv", 500)
        total_skipped = 0
        # (component, [{id, modified}, ...]) pairs; hydrated together so one id is fetched once.
        pending: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []

        async with InstrumentedAsyncClient("OSV API", timeout=timeout) as client:
            for chunk_start in range(0, len(uncached_components), batch_size):
                chunk = uncached_components[chunk_start : chunk_start + batch_size]
                payload, valid_components = _build_batch_payload(chunk)
                if not payload["queries"]:
                    continue
                for attempt in range(1 + self.max_retries):
                    rate_limited, skipped = await self._post_and_handle(
                        client, payload, valid_components, pending, chunk_start
                    )
                    if not rate_limited:
                        total_skipped += skipped
                        break
                    if attempt < self.max_retries:
                        delay = self.retry_base_delay * (2**attempt)
                        logger.warning(
                            f"OSV API rate limit hit for batch starting at {chunk_start} "
                            f"(attempt {attempt + 1}/{1 + self.max_retries}), retrying in {delay:.1f}s"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"OSV API rate limit persisted after {1 + self.max_retries} attempts; "
                            f"dropping batch starting at {chunk_start} ({len(valid_components)} components)"
                        )
                        total_skipped += len(valid_components)
                if chunk_start + batch_size < len(uncached_components):
                    await asyncio.sleep(0.2)

            unhydrated = await self._hydrate_and_emit(client, pending, results)
        return total_skipped, unhydrated

    async def _hydrate_and_emit(
        self,
        client: InstrumentedAsyncClient,
        pending: list[tuple[dict[str, Any], list[dict[str, Any]]]],
        results: list[dict[str, Any]],
    ) -> int:
        """Replace the querybatch stubs with full OSV records, then build the result entries.

        Returns how many distinct ids stayed unresolved; their stubs are kept, so the
        vulnerability is still reported — as UNKNOWN severity rather than an invented one.
        """
        stubs: dict[str, str] = {}
        for _component, vulns in pending:
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if vuln_id:
                    stubs[vuln_id] = str(vuln.get("modified") or "")

        records, unresolved = await self._fetch_vuln_records(client, stubs)

        cache_mapping: dict[str, dict[str, Any]] = {}
        for component, vulns in pending:
            hydrated = [records.get(vuln.get("id", ""), vuln) for vuln in vulns]
            entry = self._build_cache_entry(component, hydrated)
            cache_mapping[CacheKeys.osv(component.get("purl", ""))] = entry
            if entry["vulnerabilities"]:
                results.append(entry)

        if cache_mapping:
            await cache_service.mset(cache_mapping, CacheTTL.OSV_VULNERABILITY)
        return unresolved

    async def _fetch_vuln_records(
        self,
        client: InstrumentedAsyncClient,
        stubs: dict[str, str],
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """``({id: record}, unresolved_count)`` for the given ids, Redis-cached per id+modified."""
        if not stubs:
            return {}, 0

        keys = {vuln_id: CacheKeys.osv_vuln(vuln_id, modified) for vuln_id, modified in stubs.items()}
        cached = await cache_service.mget(list(keys.values()))
        records: dict[str, dict[str, Any]] = {}
        missing: list[str] = []
        for vuln_id, key in keys.items():
            value = cached.get(key)
            if isinstance(value, dict):
                records[vuln_id] = value
            else:
                missing.append(vuln_id)

        if not missing:
            return records, 0

        semaphore = asyncio.Semaphore(_HYDRATION_CONCURRENCY)

        async def _one(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
            async with semaphore:
                return vuln_id, await self._get_vuln_record(client, vuln_id)

        fetched = await asyncio.gather(*(_one(vuln_id) for vuln_id in missing))

        to_cache: dict[str, dict[str, Any]] = {}
        unresolved = 0
        for vuln_id, record in fetched:
            if record is None:
                unresolved += 1
                continue
            records[vuln_id] = record
            to_cache[keys[vuln_id]] = record

        if to_cache:
            await cache_service.mset(to_cache, CacheTTL.OSV_VULN_RECORD)
        if unresolved:
            logger.warning(f"OSV: {unresolved} of {len(missing)} vulnerability records could not be fetched")
        return records, unresolved

    async def _get_vuln_record(
        self,
        client: InstrumentedAsyncClient,
        vuln_id: str,
    ) -> dict[str, Any] | None:
        """One full OSV record, retrying only on 429. None when it stays unresolved."""
        for attempt in range(1 + self.max_retries):
            try:
                response = await client.get(f"{OSV_VULN_API_URL}/{vuln_id}")
            except Exception as exc:
                logger.warning(f"OSV vuln fetch failed for {vuln_id}: {type(exc).__name__}: {exc}")
                return None

            if response.status_code == 200:
                record = response.json()
                return record if isinstance(record, dict) else None
            if response.status_code != 429:
                logger.warning(f"OSV vuln fetch for {vuln_id} returned {response.status_code}")
                return None

            external_api_rate_limit_hits_total.labels(service="OSV API").inc()
            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_base_delay * (2**attempt))
        logger.error(f"OSV vuln fetch for {vuln_id} rate limited after {1 + self.max_retries} attempts")
        return None

    async def _post_and_handle(
        self,
        client: InstrumentedAsyncClient,
        payload: dict[str, list[dict[str, Any]]],
        valid_components: list[dict[str, Any]],
        pending: list[tuple[dict[str, Any], list[dict[str, Any]]]],
        chunk_start: int,
    ) -> tuple[bool, int]:
        """POST one batch and dispatch on response status.

        Returns ``(rate_limited, skipped)``: ``rate_limited`` asks the caller to
        retry the same chunk, ``skipped`` counts components this batch lost.
        """
        try:
            response = await client.post(self.api_url, json=payload)
        except httpx.TimeoutException:
            logger.warning(f"OSV API timeout for batch starting at {chunk_start}")
            return False, len(valid_components)
        except httpx.ConnectError:
            logger.warning("OSV API connection error")
            return False, len(valid_components)
        except Exception as e:
            logger.warning(f"OSV Analysis Exception: {type(e).__name__}: {e}")
            return False, len(valid_components)

        if response.status_code == 200:
            skipped = self._handle_success(response, valid_components, pending)
            return False, skipped
        if response.status_code == 429:
            external_api_rate_limit_hits_total.labels(service="OSV API").inc()
            return True, 0
        logger.warning(f"OSV Batch API error: {response.status_code}")
        return False, len(valid_components)

    def _handle_success(
        self,
        response: Any,
        valid_components: list[dict[str, Any]],
        pending: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    ) -> int:
        """Parse a 200 response and align its ``{id, modified}`` stubs with their components.

        Returns the number of components whose result was missing from the response.
        """
        data = response.json()
        batch_results = data.get("results", [])
        skipped = 0
        if len(batch_results) != len(valid_components):
            logger.warning(
                f"OSV API response count mismatch: sent {len(valid_components)}, received {len(batch_results)}"
            )
            skipped = max(0, len(valid_components) - len(batch_results))
            batch_results = batch_results[: len(valid_components)]

        for comp, res in zip(valid_components, batch_results):
            pending.append((comp, res.get("vulns") or []))
        return skipped

    def _build_cache_entry(self, component: dict[str, Any], vulns: list[dict[str, Any]]) -> dict[str, Any]:
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
        self, components: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """``(cached_results, uncached_components)`` from a batch Redis lookup."""
        cached_results: list[dict[str, Any]] = []
        uncached_components: list[dict[str, Any]] = []

        cache_keys: list[str] = []
        component_map: dict[str, Any] = {}
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

    def _normalize_vulnerabilities(self, vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    def _severity_from_cvss_array(self, severity_array: list[dict[str, Any]]) -> str | None:
        """Pick the highest-ranked CVSS entry (newest standard wins) and map it."""
        entries_by_type: dict[str, list[dict[str, Any]]] = {}
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
    def _severity_from_map(raw_severity: str | None) -> str | None:
        """Look up a raw severity string in the OSV severity map."""
        if not raw_severity:
            return None
        sev = raw_severity.upper()
        return OSV_SEVERITY_MAP.get(sev)

    def _extract_severity(self, vuln: dict[str, Any]) -> str:
        """Extract severity from OSV vulnerability data."""
        db_sev = self._severity_from_map(vuln.get("database_specific", {}).get("severity"))
        if db_sev:
            return db_sev

        cvss_sev = self._severity_from_cvss_array(vuln.get("severity", []))
        if cvss_sev:
            return cvss_sev

        for affected in vuln.get("affected", []):
            eco_sev = self._severity_from_map(affected.get("ecosystem_specific", {}).get("severity"))
            if eco_sev:
                return eco_sev

        # A record OSV does not rate stays unrated. Any placeholder here would be max-merged
        # against the other scanners and could only ever inflate a real severity.
        return Severity.UNKNOWN.value

    def _parse_cvss_score(self, score: str) -> float | None:
        """Parse CVSS score from numeric value or vector string."""
        try:
            return float(score)
        except ValueError:
            pass

        if "/" in score:
            parts = score.split("/")
            try:
                return float(parts[-1])
            except ValueError:
                pass

        return None

    def _get_highest_severity(self, vulns: list[dict[str, Any]]) -> str:
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

        return Severity.UNKNOWN.value

    def _create_summary_message(self, component: str, version: str, vulns: list[dict[str, Any]]) -> str:
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

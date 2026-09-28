import asyncio
import logging
import math
import re
from typing import Any
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    OSV_BATCH_API_URL,
    OSV_VULN_API_URL,
)
from app.core.cvss import cvss_base_score
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import external_api_rate_limit_hits_total
from app.models.finding import Severity
from app.services.purl_utils import canonical_purl, parse_purl

from .base import Analyzer

logger = logging.getLogger(__name__)

OSV_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL.value,
    "HIGH": Severity.HIGH.value,
    "MODERATE": Severity.MEDIUM.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
}

_OSV_SERVICE_LABEL = "OSV API"

# Parallel /v1/vulns fetches; OSV throttles aggressively and a scan can carry thousands of ids.
_HYDRATION_CONCURRENCY = 8
# Wall-clock budget for the whole hydration phase. Without it a slow-at-timeout OSV would add
# hours to a cold-cache scan (per-request 60s x thousands of new ids / 8 in flight).
_HYDRATION_BUDGET_SECONDS = 300.0
# Stop early when OSV is clearly down or throttling everything, rather than amplifying a storm.
_HYDRATION_FAILURE_STREAK = 10


class _HydrationBudget:
    """Stops the hydration phase on a wall-clock deadline or a run of consecutive failures."""

    def __init__(self, deadline: float) -> None:
        self._deadline = deadline
        self._failures = 0
        self._tripped = False

    def exhausted(self) -> bool:
        if self._tripped:
            return True
        if asyncio.get_running_loop().time() >= self._deadline:
            logger.error("OSV hydration budget exhausted; remaining records are left unresolved")
            self._tripped = True
        return self._tripped

    def record(self, success: bool) -> None:
        if success:
            self._failures = 0
            return
        self._failures += 1
        if self._failures >= _HYDRATION_FAILURE_STREAK and not self._tripped:
            logger.error(
                f"OSV hydration stopped after {self._failures} consecutive failures; "
                "remaining records are left unresolved"
            )
            self._tripped = True


# OSV answers HTTP 400 for the whole batch when one query holds a malformed percent escape.
_INVALID_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
# OSV resolves Debian and Alpine packages only by release-scoped ecosystem and source package name.
_OS_ECOSYSTEMS = {
    ("deb", "debian"): (re.compile(r"^(?:debian-)?(\d+)"), "Debian:{}"),
    ("apk", "alpine"): (re.compile(r"^(?:alpine-)?(\d+\.\d+)"), "Alpine:v{}"),
}
_TRIVY_SOURCE_NAME = "aquasecurity:trivy:SrcName"
_TRIVY_SOURCE_VERSION = "aquasecurity:trivy:SrcVersion"

# (component, versioned purl, querybatch query)
_Target = tuple[dict[str, Any], str, dict[str, Any]]


def _versioned_purl(component: dict[str, Any]) -> str | None:
    """The component's purl carrying a version, or None when there is no version to ask about.

    Without a version OSV answers with every advisory ever published for the package.
    """
    purl = str(component.get("purl") or "")
    if not purl:
        return None
    parsed = parse_purl(purl)
    # A malformed purl passes through unchanged, so the query step reports it as unscanned.
    if parsed is None or not parsed.name or parsed.version:
        return purl
    version = str(component.get("version") or "")
    if version.lower() in ("", "unknown"):
        return None
    coordinates = canonical_purl(purl)
    return f"{coordinates.rstrip('@')}@{quote(version, safe='')}{purl[len(coordinates) :]}"


def _osv_query(purl: str, component: dict[str, Any]) -> dict[str, Any] | None:
    """The querybatch query for a versioned purl, or None when OSV would reject or cannot resolve it."""
    parsed = parse_purl(purl)
    if parsed is None or not parsed.name or _INVALID_ESCAPE.search(purl):
        return None
    rule = _OS_ECOSYSTEMS.get((parsed.type, parsed.namespace or ""))
    if rule is None:
        return {"package": {"purl": purl}}
    release_pattern, ecosystem = rule
    release = release_pattern.match(parsed.qualifiers.get("distro", ""))
    if release is None:
        return None
    properties = component.get("properties") or {}
    # Syft writes the source package as ``upstream=name[@version]``; Trivy keeps it in properties.
    source, _, source_version = parsed.qualifiers.get("upstream", "").partition("@")
    return {
        "package": {
            "ecosystem": ecosystem.format(release[1]),
            "name": source or properties.get(_TRIVY_SOURCE_NAME) or parsed.name,
        },
        "version": source_version or properties.get(_TRIVY_SOURCE_VERSION) or parsed.version,
    }


def _query_targets(components: list[dict[str, Any]]) -> tuple[list[_Target], int]:
    """Every component OSV can be asked about, and how many it cannot although they are pinned."""
    targets: list[_Target] = []
    unqueryable: list[str] = []
    unpinned = 0
    for component in components:
        purl = _versioned_purl(component)
        if purl is None:
            unpinned += 1
            continue
        query = _osv_query(purl, component)
        if query is None:
            unqueryable.append(purl)
            continue
        targets.append((component, purl, query))
    if unpinned:
        logger.debug(f"OSV: Skipped {unpinned} components without a purl or version")
    if unqueryable:
        logger.warning(f"OSV: {len(unqueryable)} components cannot be queried, e.g. {unqueryable[:3]}")
    return targets, len(unqueryable)


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
        targets, unqueryable = _query_targets(self._get_components(sbom, parsed_components))

        results, uncached = await self._get_cached_components(targets)
        logger.debug(f"OSV: {len(results)} from cache, {len(uncached)} to fetch")

        skipped, unhydrated = await self._fetch_uncached(uncached, results) if uncached else (0, 0)
        skipped += unqueryable
        result: dict[str, Any] = {"osv_vulnerabilities": results}
        # Surfaced by the engine as a partial scan; never silently report full coverage.
        if skipped:
            result["partial_components_skipped"] = skipped
        if unhydrated:
            result["partial_vulnerabilities_unhydrated"] = unhydrated
        return result

    async def _fetch_uncached(
        self,
        uncached: list[_Target],
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
        # (target, [{id, modified}, ...]) pairs; hydrated together so one id is fetched once.
        pending: list[tuple[_Target, list[dict[str, Any]]]] = []

        async with InstrumentedAsyncClient(_OSV_SERVICE_LABEL, timeout=timeout) as client:
            for chunk_start in range(0, len(uncached), batch_size):
                chunk = uncached[chunk_start : chunk_start + batch_size]
                payload = {"queries": [query for _, _, query in chunk]}
                for attempt in range(1 + self.max_retries):
                    rate_limited, skipped = await self._post_and_handle(client, payload, chunk, pending, chunk_start)
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
                            f"dropping batch starting at {chunk_start} ({len(chunk)} components)"
                        )
                        total_skipped += len(chunk)
                if chunk_start + batch_size < len(uncached):
                    await asyncio.sleep(0.2)

            unhydrated = await self._hydrate_and_emit(client, pending, results)
        return total_skipped, unhydrated

    async def _hydrate_and_emit(
        self,
        client: InstrumentedAsyncClient,
        pending: list[tuple[_Target, list[dict[str, Any]]]],
        results: list[dict[str, Any]],
    ) -> int:
        """Replace the querybatch stubs with full OSV records, then build the result entries.

        Returns how many distinct ids stayed unresolved; their stubs are kept, so the
        vulnerability is still reported — as UNKNOWN severity rather than an invented one.
        """
        stubs: dict[str, str] = {}
        for _target, vulns in pending:
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if vuln_id:
                    stubs[vuln_id] = str(vuln.get("modified") or "")

        records, unresolved = await self._fetch_vuln_records(client, stubs)

        cache_mapping: dict[str, dict[str, Any]] = {}
        for (component, purl, _query), vulns in pending:
            ids = [vuln.get("id", "") for vuln in vulns]
            hydrated = [records.get(vuln_id, vuln) for vuln_id, vuln in zip(ids, vulns, strict=True)]
            normalized = self._normalize_vulnerabilities(hydrated)
            # Caching an entry built from unresolved stubs would serve UNKNOWN for the next
            # six hours with no partial flag, making the failure invisible on the next scan.
            if not any(vuln_id in unresolved for vuln_id in ids):
                cache_mapping[CacheKeys.osv(purl)] = {"vulnerabilities": normalized}
            if normalized:
                results.append(self._result_entry(component, normalized))

        if cache_mapping:
            await cache_service.mset(cache_mapping, CacheTTL.OSV_VULNERABILITY)
        return len(unresolved)

    async def _fetch_vuln_records(
        self,
        client: InstrumentedAsyncClient,
        stubs: dict[str, str],
    ) -> tuple[dict[str, dict[str, Any]], set[str]]:
        """``({id: record}, unresolved_ids)`` for the given ids, Redis-cached per id+modified."""
        if not stubs:
            return {}, set()

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
            return records, set()

        semaphore = asyncio.Semaphore(_HYDRATION_CONCURRENCY)
        deadline = asyncio.get_running_loop().time() + _HYDRATION_BUDGET_SECONDS
        budget = _HydrationBudget(deadline=deadline)

        async def _one(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
            if budget.exhausted():
                return vuln_id, None
            async with semaphore:
                if budget.exhausted():
                    return vuln_id, None
                record = await self._get_vuln_record(client, vuln_id, budget)
                budget.record(success=record is not None)
                return vuln_id, record

        fetched = await asyncio.gather(*(_one(vuln_id) for vuln_id in missing))

        to_cache: dict[str, dict[str, Any]] = {}
        unresolved: set[str] = set()
        for vuln_id, record in fetched:
            if record is None:
                unresolved.add(vuln_id)
                continue
            records[vuln_id] = record
            to_cache[keys[vuln_id]] = record

        if to_cache:
            await cache_service.mset(to_cache, CacheTTL.OSV_VULN_RECORD)
        if unresolved:
            logger.warning(f"OSV: {len(unresolved)} of {len(missing)} vulnerability records could not be fetched")
        return records, unresolved

    async def _get_vuln_record(
        self,
        client: InstrumentedAsyncClient,
        vuln_id: str,
        budget: "_HydrationBudget | None" = None,
    ) -> dict[str, Any] | None:
        """One full OSV record, retrying only on 429. None when it stays unresolved.

        The deadline is rechecked between attempts: it cannot cancel a request already in
        flight, so without this the tail past the budget would be the whole retry ladder
        (4 x 60s timeout + 35s of backoff). The residual tail is one request timeout plus one
        backoff sleep, because the sleep below runs before the next iteration rechecks.
        """
        for attempt in range(1 + self.max_retries):
            if budget is not None and attempt and budget.exhausted():
                return None
            try:
                response = await client.get(f"{OSV_VULN_API_URL}/{vuln_id}")
            except Exception as exc:
                logger.warning(f"OSV vuln fetch failed for {vuln_id}: {type(exc).__name__}: {exc}")
                return None

            if response.status_code == 200:
                try:
                    record = response.json()
                except ValueError as exc:
                    # A proxy or CDN error page answering 200 must cost one id, not the analyzer.
                    logger.warning(f"OSV vuln fetch for {vuln_id} returned an unparseable body: {exc}")
                    return None
                return record if isinstance(record, dict) else None
            if response.status_code != 429:
                logger.warning(f"OSV vuln fetch for {vuln_id} returned {response.status_code}")
                return None

            external_api_rate_limit_hits_total.labels(service=_OSV_SERVICE_LABEL).inc()
            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_base_delay * (2**attempt))
        logger.error(f"OSV vuln fetch for {vuln_id} rate limited after {1 + self.max_retries} attempts")
        return None

    async def _post_and_handle(
        self,
        client: InstrumentedAsyncClient,
        payload: dict[str, list[dict[str, Any]]],
        chunk: list[_Target],
        pending: list[tuple[_Target, list[dict[str, Any]]]],
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
            return False, len(chunk)
        except httpx.ConnectError:
            logger.warning("OSV API connection error")
            return False, len(chunk)
        except Exception as e:
            logger.warning(f"OSV Analysis Exception: {type(e).__name__}: {e}")
            return False, len(chunk)

        if response.status_code == 200:
            skipped = self._handle_success(response, chunk, pending)
            return False, skipped
        if response.status_code == 429:
            external_api_rate_limit_hits_total.labels(service=_OSV_SERVICE_LABEL).inc()
            return True, 0
        # The body names the rejected query ("error in query at index N") within this batch.
        logger.warning(
            f"OSV Batch API error for batch starting at {chunk_start}: {response.status_code} {response.text[:200]}"
        )
        return False, len(chunk)

    def _handle_success(
        self,
        response: Any,
        chunk: list[_Target],
        pending: list[tuple[_Target, list[dict[str, Any]]]],
    ) -> int:
        """Parse a 200 response and align its ``{id, modified}`` stubs with their components.

        Returns the number of components whose result was missing from the response.
        """
        try:
            data = response.json()
        except ValueError as exc:
            # A proxy or CDN error page answering 200 must not abort the analyzer.
            logger.warning(f"OSV Batch API returned an unparseable body: {exc}")
            return len(chunk)
        batch_results = data.get("results", [])
        skipped = 0
        if len(batch_results) != len(chunk):
            logger.warning(f"OSV API response count mismatch: sent {len(chunk)}, received {len(batch_results)}")
            skipped = max(0, len(chunk) - len(batch_results))
            batch_results = batch_results[: len(chunk)]

        for target, res in zip(chunk, batch_results, strict=False):
            pending.append((target, res.get("vulns") or []))
        return skipped

    def _result_entry(self, component: dict[str, Any], vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        """The analyzer result for one component from its normalized vulnerabilities."""
        name = component.get("name", "")
        version = component.get("version", "")
        return {
            "component": name,
            "version": version,
            "purl": component.get("purl", ""),
            "vulnerabilities": vulnerabilities,
            "severity": self._get_highest_severity(vulnerabilities),
            "message": self._create_summary_message(name, version, vulnerabilities),
        }

    async def _get_cached_components(self, targets: list[_Target]) -> tuple[list[dict[str, Any]], list[_Target]]:
        """``(cached result entries, uncached targets)`` from a batch Redis lookup.

        A cached answer is per package version; the scanning component names the result.
        """
        keys = [CacheKeys.osv(purl) for _, purl, _ in targets]
        cached_data = await cache_service.mget(list(dict.fromkeys(keys)))
        cached_results: list[dict[str, Any]] = []
        uncached: list[_Target] = []
        for target, key in zip(targets, keys, strict=True):
            data = cached_data.get(key)
            if not data:
                uncached.append(target)
            elif data.get("vulnerabilities"):
                cached_results.append(self._result_entry(target[0], data["vulnerabilities"]))
        return cached_results, uncached

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
                    "published": vuln.get("published"),
                    "modified": vuln.get("modified"),
                    "affected": vuln.get("affected", []),
                }
            )
        return normalized

    # CVSS-type preference order — newest standard wins.
    _CVSS_TYPE_PREFERENCE = ("CVSS_V4", "CVSS_V3", "CVSS_V3.1", "CVSS_V3.0", "CVSS_V2")

    @staticmethod
    def _cvss_to_severity(cvss_score: float, cvss_type: str = "CVSS_V3") -> str:
        """Map a CVSS score to a severity using version-specific cutoffs.

        v2 has no CRITICAL tier; v3/v4 use 9 / 7 / 4 / 0. Scores outside ``[0, 10]`` are
        clamped so malformed input can't land in CRITICAL; non-finite input never reaches
        here (see _parse_cvss_score), because NaN would survive the clamp as 10.0.

        A computed 0.0 maps to LOW: Severity has no NONE band, and a rating of 0.0 does not
        occur in practice (0 of 3,920 NVD CVEs, and OSV only rates actual vulnerabilities).
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
        """A numeric score, else the base score computed from a CVSS v3.x vector."""
        try:
            value = float(score)
        except ValueError:
            return cvss_base_score(score)
        # float() accepts "nan"/"inf"; NaN survives the clamp in _cvss_to_severity as 10.0
        # (no comparison against it is true) and would land in CRITICAL.
        return value if math.isfinite(value) else None

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

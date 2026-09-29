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
from app.core.purl import PURL_TYPE_TO_SYSTEM, ParsedPURL, canonical_purl, package_identity, parse_purl
from app.models.finding import Severity
from app.services.aggregation.versions import parse_version_key

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
_PURL_TYPE = re.compile(r"[a-z][a-z0-9.+-]*")
_REJECTED_QUERY = re.compile(r"error in query at index (\d+)")
# Resends after OSV rejected a query; bisection doubles the requests at each of these levels.
_MAX_REJECTION_RESENDS = 4
# OSV resolves Debian and Alpine packages only by release-scoped ecosystem and source package name.
_OS_ECOSYSTEMS = {
    ("deb", "debian"): (re.compile(r"^(?:debian-)?(\d+)"), "Debian:{}"),
    ("apk", "alpine"): (re.compile(r"^(?:alpine-)?(\d+\.\d+)"), "Alpine:v{}"),
}
_TRIVY = "aquasecurity:trivy:"

# (component, versioned purl, querybatch query)
_Target = tuple[dict[str, Any], str, dict[str, Any]]
# Each target with the querybatch ``{id, modified}`` stubs naming its vulnerabilities.
_Pending = list[tuple[_Target, list[dict[str, Any]]]]


def _versioned_purl(component: dict[str, Any]) -> str | None:
    """The component's purl with its version, or None: unversioned, OSV answers with every advisory of the package."""
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
    if parsed is None or not parsed.name or not _PURL_TYPE.fullmatch(parsed.type) or _INVALID_ESCAPE.search(purl):
        return None
    rule = _OS_ECOSYSTEMS.get((parsed.type, (parsed.namespace or "").lower()))
    if rule is None:
        return {"package": {"purl": purl}}
    release_pattern, ecosystem = rule
    release = release_pattern.match(parsed.qualifiers.get("distro", ""))
    source = _os_source_package(parsed, component)
    if release is None or source is None:
        return None
    return {"package": {"ecosystem": ecosystem.format(release[1]), "name": source[0]}, "version": source[1]}


def _os_source_package(parsed: ParsedPURL, component: dict[str, Any]) -> tuple[str, str | None] | None:
    """``(name, version)`` of the source package an OS binary was built from, or None when unknown."""
    upstream = parsed.qualifiers.get("upstream")
    if upstream:
        name, _, version = upstream.partition("@")
        return name, version or parsed.version
    properties = component.get("properties") or {}
    source = properties.get(f"{_TRIVY}SrcName")
    if source:
        # Trivy splits the Debian source version into epoch, upstream version and revision.
        source_version = properties.get(f"{_TRIVY}SrcVersion")
        if source_version and properties.get(f"{_TRIVY}SrcRelease"):
            source_version = f"{source_version}-{properties[f'{_TRIVY}SrcRelease']}"
        if source_version and properties.get(f"{_TRIVY}SrcEpoch"):
            source_version = f"{properties[f'{_TRIVY}SrcEpoch']}:{source_version}"
        return source, source_version or parsed.version
    # Syft, the one generator naming its cataloger, leaves out ``upstream`` when the source is the binary.
    if component.get("found_by"):
        return parsed.name, parsed.version
    return None


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


def _package_key(package: dict[str, Any], purl_type: str | None) -> tuple[str, str] | None:
    ecosystem, name = str(package.get("ecosystem") or ""), str(package.get("name") or "")
    if purl_type is None:
        return ecosystem, name.casefold()
    purl = package.get("purl")
    # OSV makes ``purl`` optional; Maven names are group:artifact.
    if not purl and name and PURL_TYPE_TO_SYSTEM.get(purl_type) == ecosystem.casefold():
        purl = f"pkg:{purl_type}/{name.replace(':', '/')}"
    return package_identity(purl, "", None, None) if purl else None


def _affected_entries(record: dict[str, Any], query: dict[str, Any]) -> list[dict[str, Any]]:
    """The record's ``affected`` entries for the queried package; OS releases share a purl and match by ecosystem."""
    parsed = parse_purl(query["package"].get("purl") or "")
    purl_type = parsed.type if parsed else None
    key = _package_key(query["package"], purl_type)
    return [
        entry for entry in record.get("affected") or [] if _package_key(entry.get("package") or {}, purl_type) == key
    ]


def _installed_version(query: dict[str, Any]) -> str:
    if "purl" in query["package"]:
        parsed = parse_purl(query["package"]["purl"])
        return (parsed.version if parsed else None) or ""
    return query.get("version") or ""


def _fixed_version(entries: list[dict[str, Any]], installed: str) -> str | None:
    """The ``fixed`` event closing the affected interval the installed version is in; GIT ranges fix by commit."""
    current = parse_version_key(installed)
    if not current:
        return None
    for entry in entries:
        for version_range in entry.get("ranges") or []:
            if version_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced = None
            for event in version_range.get("events") or []:
                if "introduced" in event:
                    introduced = parse_version_key(str(event["introduced"]))
                elif (
                    "fixed" in event
                    and introduced is not None
                    and introduced <= current < parse_version_key(str(event["fixed"]))
                ):
                    return str(event["fixed"])
                else:
                    introduced = None
    return None


def _vulnerable_symbols(entries: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """The entries' ``ecosystem_specific`` symbol data, which symbol-level reachability matches."""
    merged: dict[str, list[Any]] = {}
    for entry in entries:
        eco = entry.get("ecosystem_specific")
        if not isinstance(eco, dict):
            continue
        for key in ("symbols", "imports"):
            if isinstance(eco.get(key), list):
                merged.setdefault(key, []).extend(eco[key])
    return merged


class OSVAnalyzer(Analyzer):
    """Vulnerability lookup via the OSV batch API, cached across pods."""

    name = "osv"
    api_url = OSV_BATCH_API_URL

    # Retries per request on 429, 5xx and non-timeout transport errors, so a throttled chunk isn't silently dropped.
    max_retries: int = 3
    retry_base_delay: float = 5.0  # seconds, doubles each attempt

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        targets, unqueryable = _query_targets(self._get_components(sbom, parsed_components))

        pending, uncached = await self._get_cached_stubs(targets)
        logger.debug(f"OSV: {len(pending)} from cache, {len(uncached)} to fetch")

        timeout = ANALYZER_TIMEOUTS.get("osv", ANALYZER_TIMEOUTS["default"])
        async with InstrumentedAsyncClient(_OSV_SERVICE_LABEL, timeout=timeout) as client:
            skipped = await self._fetch_uncached(client, uncached, pending)
            results, unhydrated = await self._hydrate_and_emit(client, pending)
        skipped += unqueryable
        result: dict[str, Any] = {"osv_vulnerabilities": results}
        # Surfaced by the engine as a partial scan; never silently report full coverage.
        if skipped:
            result["partial_components_skipped"] = skipped
        if unhydrated:
            result["partial_vulnerabilities_unhydrated"] = unhydrated
        return result

    async def _get_cached_stubs(self, targets: list[_Target]) -> tuple[_Pending, list[_Target]]:
        """``(pending, uncached)``: the targets with their cached querybatch stubs, and the targets without."""
        keys = [CacheKeys.osv(purl) for _, purl, _ in targets]
        cached = await cache_service.mget(list(dict.fromkeys(keys)))
        pending: _Pending = []
        uncached: list[_Target] = []
        for target, key in zip(targets, keys, strict=True):
            stubs = cached.get(key)
            if stubs is None:
                uncached.append(target)
            else:
                pending.append((target, stubs))
        return pending, uncached

    async def _fetch_uncached(self, client: InstrumentedAsyncClient, uncached: list[_Target], pending: _Pending) -> int:
        """Ask querybatch about ``uncached``, caching each answer's stubs and adding them to ``pending``.

        Returns how many components were never scanned: dropped batches, rejected queries,
        persistent rate limiting and truncated responses.
        """
        batch_size = ANALYZER_BATCH_SIZES.get("osv", 500)
        skipped = 0
        fetched: _Pending = []
        for chunk_start in range(0, len(uncached), batch_size):
            chunk = uncached[chunk_start : chunk_start + batch_size]
            skipped += await self._send_chunk(client, chunk, fetched, chunk_start, _MAX_REJECTION_RESENDS)
            if chunk_start + batch_size < len(uncached):
                await asyncio.sleep(0.2)
        if fetched:
            stubs_by_key = {CacheKeys.osv(purl): stubs for (_, purl, _), stubs in fetched}
            await cache_service.mset(stubs_by_key, CacheTTL.OSV_VULNERABILITY)
        pending.extend(fetched)
        return skipped

    async def _hydrate_and_emit(
        self, client: InstrumentedAsyncClient, pending: _Pending
    ) -> tuple[list[dict[str, Any]], int]:
        """The result entries built from the full OSV records behind ``pending``'s stubs, all hydrated together.

        Also returns how many distinct ids stayed unresolved; their stubs are kept, so the
        vulnerability is still reported — as UNKNOWN severity rather than an invented one.
        """
        stubs: dict[str, str] = {}
        for _target, vulns in pending:
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if vuln_id:
                    stubs[vuln_id] = str(vuln.get("modified") or "")

        records, unresolved = await self._fetch_vuln_records(client, stubs)

        results: list[dict[str, Any]] = []
        for (component, _, query), vulns in pending:
            hydrated = [records.get(vuln.get("id", ""), vuln) for vuln in vulns]
            normalized = self._normalize_vulnerabilities(hydrated, query)
            if normalized:
                results.append(self._result_entry(component, normalized))
        return results, len(unresolved)

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
                record = await self._get_vuln_record(client, vuln_id, deadline)
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
        deadline: float,
    ) -> dict[str, Any] | None:
        """One full OSV record, or None when it stays unresolved."""
        try:
            response = await client.send_with_backoff(
                "GET",
                f"{OSV_VULN_API_URL}/{vuln_id}",
                attempts=1 + self.max_retries,
                base_delay=self.retry_base_delay,
                deadline=deadline,
            )
        except httpx.HTTPError as exc:
            logger.warning(f"OSV vuln fetch failed for {vuln_id}: {type(exc).__name__}: {exc}")
            return None
        if response.status_code != 200:
            logger.warning(f"OSV vuln fetch for {vuln_id} returned {response.status_code}")
            return None
        try:
            record = response.json()
        except ValueError as exc:
            # A proxy or CDN error page answering 200 must cost one id, not the analyzer.
            logger.warning(f"OSV vuln fetch for {vuln_id} returned an unparseable body: {exc}")
            return None
        return record if isinstance(record, dict) else None

    async def _send_chunk(
        self,
        client: InstrumentedAsyncClient,
        chunk: list[_Target],
        pending: _Pending,
        chunk_start: int,
        resends: int,
    ) -> int:
        """POST one chunk and collect its stubs in ``pending``; returns how many of its components were lost."""
        try:
            response = await client.send_with_backoff(
                "POST",
                self.api_url,
                attempts=1 + self.max_retries,
                base_delay=self.retry_base_delay,
                json={"queries": [query for _, _, query in chunk]},
            )
        except httpx.HTTPError as exc:
            logger.warning(f"OSV batch starting at {chunk_start} failed: {type(exc).__name__}: {exc}")
            return len(chunk)
        if response.status_code == 200:
            return self._handle_success(response, chunk, pending)
        if response.status_code == 400 and resends:
            return await self._resend_accepted(client, chunk, pending, chunk_start, response.text, resends - 1)
        logger.warning(
            f"OSV Batch API error for batch starting at {chunk_start}: {response.status_code} {response.text[:200]}"
        )
        return len(chunk)

    async def _resend_accepted(
        self,
        client: InstrumentedAsyncClient,
        chunk: list[_Target],
        pending: _Pending,
        chunk_start: int,
        rejection: str,
        resends: int,
    ) -> int:
        """Resend a rejected chunk minus the named query, else bisected; returns how many components stay lost."""
        named = _REJECTED_QUERY.search(rejection)
        index = int(named[1]) if named and int(named[1]) < len(chunk) else None
        if index is None and len(chunk) > 1:
            middle = len(chunk) // 2
            lost = await self._send_chunk(client, chunk[:middle], pending, chunk_start, resends)
            return lost + await self._send_chunk(client, chunk[middle:], pending, chunk_start + middle, resends)
        index = index or 0
        logger.warning(f"OSV rejected {chunk[index][1]}: {rejection[:200]}")
        rest = chunk[:index] + chunk[index + 1 :]
        return 1 + (await self._send_chunk(client, rest, pending, chunk_start, resends) if rest else 0)

    def _handle_success(
        self,
        response: Any,
        chunk: list[_Target],
        pending: _Pending,
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
        return {
            "component": component.get("name", ""),
            "version": component.get("version", ""),
            "purl": component.get("purl", ""),
            "vulnerabilities": vulnerabilities,
        }

    def _normalize_vulnerabilities(self, vulns: list[dict[str, Any]], query: dict[str, Any]) -> list[dict[str, Any]]:
        """The fields normalize_osv reads, resolved for the queried package; retracted records (``withdrawn``) drop."""
        installed = _installed_version(query)
        normalized = []
        for vuln in vulns:
            if vuln.get("withdrawn"):
                continue
            entries = _affected_entries(vuln, query)
            cvss = self._select_cvss(vuln.get("severity") or [])
            entry: dict[str, Any] = {
                "id": vuln.get("id", ""),
                "aliases": vuln.get("aliases", []),
                "summary": vuln.get("summary", ""),
                "severity": self._extract_severity(vuln),
                "cvss_score": cvss[0] if cvss else None,
                "cvss_vector": cvss[1] if cvss else None,
                "fixed_version": _fixed_version(entries, installed),
                "references": [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")],
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
            }
            if not entry["summary"]:
                entry["details"] = vuln.get("details", "")
            symbols = _vulnerable_symbols(entries)
            if symbols:
                entry["ecosystem_specific"] = symbols
            if entry["id"].startswith("MAL-"):
                versions = [
                    version for affected in vuln.get("affected") or [] for version in affected.get("versions") or []
                ]
                entry["affected_versions"] = versions[:10]
            normalized.append(entry)
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

    def _select_cvss(self, severity_array: list[dict[str, Any]]) -> tuple[float, str | None, str] | None:
        """``(score, vector or None for a bare number, type)`` of the newest-standard rating that parses."""
        rank = {cvss_type: index for index, cvss_type in enumerate(self._CVSS_TYPE_PREFERENCE)}
        ratings = [rating for rating in severity_array if "CVSS" in rating.get("type", "") and rating.get("score")]
        # Unknown subtypes (e.g. a future v5) rank last, in their given order.
        for rating in sorted(ratings, key=lambda rating: rank.get(rating["type"], len(rank))):
            raw = str(rating["score"])
            score = self._parse_cvss_score(raw)
            if score is not None:
                return score, raw if raw.startswith("CVSS:") else None, rating["type"]
        return None

    def _severity_from_cvss_array(self, severity_array: list[dict[str, Any]]) -> str | None:
        selected = self._select_cvss(severity_array)
        return self._cvss_to_severity(selected[0], selected[2]) if selected else None

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

import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    DEPS_DEV_API_URL,
    SCORECARD_UNMAINTAINED_THRESHOLD,
)
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import parse_purl

logger = logging.getLogger(__name__)


def _validated_threshold(
    settings: Optional[Dict[str, Any]], key: str, default: float, min_value: float = 0.0, max_value: float = 10.0
) -> float:
    """Extract and validate a numeric threshold from settings, falling back to default."""
    if not settings or key not in settings:
        return default
    try:
        value = float(settings[key])
        if min_value <= value <= max_value:
            return value
    except (ValueError, TypeError):
        pass
    return default


class DepsDevAnalyzer(Analyzer):
    """
    Analyzer that fetches package metadata and OpenSSF Scorecard data from deps.dev API.

    This provides:
    1. Package metadata (links, description, publish date, deprecation status)
    2. Project info (stars, forks, open issues)
    3. Dependent count (how many packages depend on this)
    4. Supply chain security insights via OpenSSF Scorecard

    Uses Redis cache to reduce API calls across all pods.
    """

    name = "deps_dev"
    base_url = DEPS_DEV_API_URL

    # Maximum concurrent requests to avoid rate limiting
    MAX_CONCURRENT = ANALYZER_BATCH_SIZES.get("deps_dev", 10)

    def _resolve_scorecard_threshold(self, settings: Optional[Dict[str, Any]]) -> float:
        """Resolve the configured scorecard threshold, validating range."""
        threshold = SCORECARD_UNMAINTAINED_THRESHOLD
        if not settings or "scorecard_threshold" not in settings:
            return threshold
        try:
            custom_threshold = float(settings["scorecard_threshold"])
            if 0 <= custom_threshold <= 10:
                return custom_threshold
        except (ValueError, TypeError):
            pass
        return threshold

    def _collect_cached(
        self,
        cached_results: Dict[str, Any],
        threshold: float,
        package_metadata: Dict[str, Any],
        scorecard_issues: List[Any],
    ) -> None:
        """Apply cached deps.dev results to outputs, re-checking the threshold."""
        for key, data in cached_results.items():
            if not data:
                continue
            package_metadata[key] = data.get("metadata")
            scorecard_issue = data.get("scorecard_issue")
            if not scorecard_issue:
                continue
            score = scorecard_issue.get("scorecard", {}).get("overallScore", 10)
            if score < threshold:
                scorecard_issues.append(scorecard_issue)

    def _collect_live_result(self, result: Any, package_metadata: Dict[str, Any], scorecard_issues: List[Any]) -> None:
        """Apply a single live fetch result to outputs."""
        if isinstance(result, Exception):
            logger.warning(f"deps_dev check failed: {result}")
            return
        if not result:
            return
        if result.get("scorecard_issue"):
            scorecard_issues.append(result["scorecard_issue"])
        if result.get("metadata"):
            key = f"{result['metadata']['name']}@{result['metadata']['version']}"
            package_metadata[key] = result["metadata"]

    async def _fetch_uncached(self, uncached_components: List[Dict[str, Any]], threshold: float) -> List[Any]:
        """Fetch deps.dev data for uncached components with bounded concurrency."""
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        timeout = ANALYZER_TIMEOUTS.get("deps_dev", ANALYZER_TIMEOUTS["default"])

        async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:
            tasks = [self._check_component_with_limit(semaphore, client, c, threshold) for c in uncached_components]
            results: List[Any] = await asyncio.gather(*tasks, return_exceptions=True)
            return results

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        scorecard_issues: List[Any] = []
        package_metadata: Dict[str, Any] = {}

        threshold = self._resolve_scorecard_threshold(settings)
        self._severity_thresholds = {
            "high": _validated_threshold(settings, "scorecard_high_threshold", 2.0),
            "medium": _validated_threshold(settings, "scorecard_medium_threshold", 4.0),
            "low": _validated_threshold(settings, "scorecard_low_threshold", 5.0),
        }

        cached_results, uncached_components = await self._get_cached_components(components)
        self._collect_cached(cached_results, threshold, package_metadata, scorecard_issues)

        logger.debug(f"deps_dev: {len(cached_results)} from cache, {len(uncached_components)} to fetch")

        if uncached_components:
            component_results = await self._fetch_uncached(uncached_components, threshold)
            for result in component_results:
                self._collect_live_result(result, package_metadata, scorecard_issues)

        return {
            "scorecard_issues": scorecard_issues,
            "package_metadata": package_metadata,
        }

    def _get_cache_key_for_component(self, component: Dict[str, Any]) -> Optional[str]:
        """Get cache key for a component."""
        purl = component.get("purl", "")
        version = component.get("version", "")

        parsed = parse_purl(purl)
        if not parsed or not parsed.registry_system or not version:
            return None

        return CacheKeys.deps_dev(parsed.registry_system, parsed.deps_dev_name, version)

    async def _get_cached_components(
        self, components: List[Dict[str, Any]]
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Check cache for components, return cached data and uncached components."""
        cached_results = {}
        uncached_components = []

        # Build cache keys for all components
        cache_keys = []
        component_map: Dict[str, Any] = {}

        for component in components:
            purl = component.get("purl", "")
            version = component.get("version", "")

            parsed = parse_purl(purl)
            if not parsed or not parsed.registry_system or not version:
                continue

            cache_key = CacheKeys.deps_dev(parsed.registry_system, parsed.deps_dev_name, version)
            cache_keys.append(cache_key)
            component_map[cache_key] = component

        if not cache_keys:
            return {}, components

        # Batch get from Redis
        cached_data: Dict[str, Any] = await cache_service.mget(cache_keys)

        for cache_key, data in cached_data.items():
            cached_comp = component_map.get(cache_key)
            if not cached_comp:
                continue

            if data:
                key = f"{cached_comp.get('name')}@{cached_comp.get('version')}"
                cached_results[key] = data
            else:
                uncached_components.append(cached_comp)

        return cached_results, uncached_components

    async def _check_component_with_limit(
        self,
        semaphore: asyncio.Semaphore,
        client: InstrumentedAsyncClient,
        component: Dict[str, Any],
        threshold: float,
    ) -> Optional[Dict[str, Any]]:
        """Fetch component data with concurrency limit and distributed lock."""
        cache_key = self._get_cache_key_for_component(component)
        if not cache_key:
            return None

        async def fetch_component() -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await self._check_component(client, component, threshold)

        # Use distributed lock to prevent multiple pods fetching same package
        return await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_component,
            ttl_seconds=CacheTTL.DEPS_DEV_METADATA,
        )

    @staticmethod
    def _select_project_id(related_projects: List[Dict[str, Any]]) -> Optional[str]:
        """Pick the best project id: prefer SOURCE_REPO, fall back to any GitHub project."""
        project_id: Optional[str] = None
        for project in related_projects:
            project_key = project.get("projectKey", {})
            pid = str(project_key.get("id", ""))
            relation_type = project.get("relationType", "")
            if relation_type == "SOURCE_REPO":
                return pid
            if pid.startswith("github.com/") and project_id is None:
                project_id = pid
        return project_id

    async def _enrich_with_project(
        self,
        client: InstrumentedAsyncClient,
        project_id: str,
        metadata: Dict[str, Any],
        result: Dict[str, Any],
        name: str,
        version: str,
        purl: str,
        threshold: float,
    ) -> None:
        """Fetch project info and scorecard for the resolved project_id."""
        encoded_project_id = quote(project_id, safe="")
        project_url = f"{self.base_url}/projects/{encoded_project_id}"

        proj_response = await client.get(project_url)
        if proj_response.status_code != 200:
            return

        proj_data = proj_response.json()
        metadata["project"] = {
            "id": project_id,
            "url": f"https://{project_id}",
            "stars": proj_data.get("starsCount"),
            "forks": proj_data.get("forksCount"),
            "open_issues": proj_data.get("openIssuesCount"),
            "description": proj_data.get("description"),
            "homepage": proj_data.get("homepage"),
            "license": proj_data.get("license"),
        }

        scorecard = proj_data.get("scorecard")
        if not scorecard:
            return

        overall_score = scorecard.get("overallScore", 0)
        metadata["scorecard"] = {
            "overall_score": overall_score,
            "date": scorecard.get("date"),
            "checks_count": len(scorecard.get("checks", [])),
        }

        if overall_score < threshold:
            result["scorecard_issue"] = self._create_scorecard_issue(name, version, purl, project_id, scorecard)

    async def _enrich_with_dependents(
        self,
        client: InstrumentedAsyncClient,
        metadata: Dict[str, Any],
        system: str,
        encoded_name: str,
        encoded_version: str,
        name: str,
        version: str,
    ) -> None:
        """Fetch dependent counts and add them to metadata."""
        try:
            dependents_url = (
                f"{self.base_url}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}:dependents"
            )
            dep_response = await client.get(dependents_url)
            if dep_response.status_code == 200:
                dep_data = dep_response.json()
                metadata["dependents"] = {
                    "total": dep_data.get("dependentCount", 0),
                    "direct": dep_data.get("directDependentCount", 0),
                    "indirect": dep_data.get("indirectDependentCount", 0),
                }
        except Exception as e:
            logger.debug(f"Could not fetch dependents for {name}@{version}: {e}")

    async def _check_component(
        self, client: InstrumentedAsyncClient, component: Dict[str, Any], threshold: float
    ) -> Optional[Dict[str, Any]]:
        """Check a component for Scorecard data and package metadata via deps.dev API."""
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "")

        parsed = parse_purl(purl)
        if not parsed:
            return None

        system = parsed.registry_system
        lookup_name = parsed.deps_dev_name
        if not system or not lookup_name or not version:
            return None

        encoded_name = quote(lookup_name, safe="")
        encoded_version = quote(version, safe="")
        version_url = f"{self.base_url}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"

        result: Dict[str, Any | None] = {"metadata": None, "scorecard_issue": None}

        try:
            response = await client.get(version_url)
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                logger.debug(f"deps.dev API returned {response.status_code} for {name}@{version}")
                return None

            data = response.json()
            metadata = self._extract_metadata(data, name, version, system, purl)

            project_id = self._select_project_id(data.get("relatedProjects", []))
            if project_id:
                await self._enrich_with_project(client, project_id, metadata, result, name, version, purl, threshold)

            await self._enrich_with_dependents(client, metadata, system, encoded_name, encoded_version, name, version)

            result["metadata"] = metadata
            return result

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking {name}@{version} on deps.dev")
            return None
        except httpx.ConnectError:
            logger.debug(f"Connection error checking {name}@{version} on deps.dev")
            return None
        except Exception as e:
            logger.debug(f"Error checking {name}@{version} on deps.dev: {e}")
            return None

    @staticmethod
    def _classify_link_label(label: str) -> str:
        """Classify a link label into a normalized category name."""
        if "home" in label or label == "homepage":
            return "homepage"
        if "repo" in label or "source" in label or "github" in label or "gitlab" in label:
            return "repository"
        if "doc" in label:
            return "documentation"
        if "bug" in label or "issue" in label:
            return "issues"
        if "changelog" in label or "change" in label:
            return "changelog"
        return label

    def _extract_metadata(
        self, data: Dict[str, Any], name: str, version: str, system: str, purl: str
    ) -> Dict[str, Any]:
        """Extract useful metadata from version response."""
        # Extract links
        links = {}
        for link in data.get("links", []):
            label = link.get("label", "").lower()
            url = link.get("url", "")
            if url:
                links[self._classify_link_label(label)] = url

        # Build metadata object
        metadata = {
            "name": name,
            "version": version,
            "system": system,
            "purl": purl,
            "published_at": data.get("publishedAt"),
            "is_default": data.get("isDefault", False),
            "is_deprecated": data.get("isDeprecated", False),
            "licenses": data.get("licenses", []),
            "links": links,
            "registries": data.get("registries", []),
            "has_attestations": len(data.get("attestations", [])) > 0,
            "has_slsa_provenance": len(data.get("slsaProvenances", [])) > 0,
        }

        # Add advisory keys if any
        advisory_keys = data.get("advisoryKeys", [])
        if advisory_keys:
            metadata["known_advisories"] = [a.get("id") for a in advisory_keys]

        return metadata

    def _create_scorecard_issue(
        self,
        name: str,
        version: str,
        purl: str,
        project_id: str,
        scorecard: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a scorecard issue from scorecard data."""
        overall_score = scorecard.get("overallScore", 0)
        checks = scorecard.get("checks", [])

        failed_checks = []
        critical_issues = []

        for check in checks:
            check_name = check.get("name", "")
            check_score = check.get("score", 10)
            check_reason = check.get("reason", "")

            # Skip checks that returned -1 (not applicable)
            if check_score == -1:
                continue

            if check_score < 5:
                failed_checks.append({"name": check_name, "score": check_score, "reason": check_reason})

                # Identify critical security issues
                if check_name in [
                    "Maintained",
                    "Vulnerabilities",
                    "Dangerous-Workflow",
                ]:
                    critical_issues.append(check_name)

        # Determine severity based on score and critical issues
        thresholds = getattr(self, "_severity_thresholds", {"high": 2.0, "medium": 4.0, "low": 5.0})
        severity = self._calculate_scorecard_severity(
            overall_score,
            critical_issues,
            high_threshold=thresholds["high"],
            medium_threshold=thresholds["medium"],
            low_threshold=thresholds["low"],
        )

        # Build warning message
        warning_parts = [f"Low OpenSSF Scorecard score: {overall_score:.1f}/10"]

        if critical_issues:
            warning_parts.append(f"Critical issues: {', '.join(critical_issues)}")

        if failed_checks:
            failed_names = [f"{c['name']}({c['score']})" for c in failed_checks[:3]]
            warning_parts.append(f"Failed checks: {', '.join(failed_names)}")
            if len(failed_checks) > 3:
                warning_parts[-1] += f" (+{len(failed_checks) - 3} more)"

        message = ". ".join(warning_parts)

        return {
            "component": name,
            "version": version,
            "purl": purl,
            "severity": severity,
            "message": message,
            "project_url": f"https://{project_id}",
            "scorecard": {
                "overallScore": overall_score,
                "date": scorecard.get("date"),
                "checks": checks,
                "repository": scorecard.get("repository", {}).get("name"),
            },
            "failed_checks": failed_checks,
            "critical_issues": critical_issues,
            "warning": message,  # Keep for backward compatibility
        }

    def _calculate_scorecard_severity(
        self,
        overall_score: float,
        critical_issues: List[str],
        high_threshold: float = 2.0,
        medium_threshold: float = 4.0,
        low_threshold: float = 5.0,
    ) -> str:
        """Calculate severity based on scorecard score and critical issues."""
        # Critical issues always elevate severity
        if "Vulnerabilities" in critical_issues or "Dangerous-Workflow" in critical_issues:
            return Severity.HIGH.value
        if critical_issues:
            return Severity.MEDIUM.value

        # Score-based severity (configurable thresholds)
        if overall_score < high_threshold:
            return Severity.HIGH.value
        if overall_score < medium_threshold:
            return Severity.MEDIUM.value
        if overall_score < low_threshold:
            return Severity.LOW.value
        return Severity.INFO.value

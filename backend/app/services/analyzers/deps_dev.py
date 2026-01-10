import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service

from .base import Analyzer
from .purl_utils import parse_purl

logger = logging.getLogger(__name__)


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
    base_url = "https://api.deps.dev/v3alpha"

    # Scorecard threshold - packages with score below this are flagged
    SCORECARD_THRESHOLD = 5.0

    # Maximum concurrent requests to avoid rate limiting
    MAX_CONCURRENT = 10

    # Timeout for API requests
    REQUEST_TIMEOUT = 10.0

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        scorecard_issues = []
        package_metadata = {}  # component@version -> metadata

        # Apply custom threshold from settings if provided
        threshold = self.SCORECARD_THRESHOLD
        if settings and "scorecard_threshold" in settings:
            threshold = float(settings["scorecard_threshold"])

        # First, check Redis cache for all components
        cached_results, uncached_components = await self._get_cached_components(
            components
        )

        # Add cached results to metadata
        for key, data in cached_results.items():
            if data:
                package_metadata[key] = data.get("metadata")
                if data.get("scorecard_issue"):
                    # Re-check threshold in case settings changed
                    score = (
                        data["scorecard_issue"]
                        .get("scorecard", {})
                        .get("overallScore", 10)
                    )
                    if score < threshold:
                        scorecard_issues.append(data["scorecard_issue"])

        logger.debug(
            f"deps_dev: {len(cached_results)} from cache, {len(uncached_components)} to fetch"
        )

        # Use semaphore to limit concurrent requests for uncached components
        if uncached_components:
            semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
            results_to_cache = {}  # Collect results for batch caching

            async with httpx.AsyncClient(timeout=self.REQUEST_TIMEOUT) as client:
                tasks = []
                for component in uncached_components:
                    tasks.append(
                        self._check_component_with_limit(
                            semaphore, client, component, threshold
                        )
                    )

                component_results = await asyncio.gather(*tasks, return_exceptions=True)

                for component, result in zip(uncached_components, component_results):
                    if isinstance(result, Exception):
                        logger.warning(f"deps_dev check failed: {result}")
                        continue
                    if result:
                        # Collect for batch caching
                        cache_key = self._get_cache_key_for_component(component)
                        if cache_key:
                            results_to_cache[cache_key] = result

                        # Separate scorecard issues from package metadata
                        if result.get("scorecard_issue"):
                            scorecard_issues.append(result["scorecard_issue"])
                        if result.get("metadata"):
                            key = f"{result['metadata']['name']}@{result['metadata']['version']}"
                            package_metadata[key] = result["metadata"]

            # Batch cache all results at once
            if results_to_cache:
                await cache_service.mset(results_to_cache, CacheTTL.DEPS_DEV_METADATA)

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
        component_map = {}

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
        cached_data = await cache_service.mget(cache_keys)

        for cache_key, data in cached_data.items():
            component = component_map.get(cache_key)
            if not component:
                continue

            if data:
                key = f"{component.get('name')}@{component.get('version')}"
                cached_results[key] = data
            else:
                uncached_components.append(component)

        return cached_results, uncached_components

    async def _check_component_with_limit(
        self,
        semaphore: asyncio.Semaphore,
        client: httpx.AsyncClient,
        component: Dict[str, Any],
        threshold: float,
    ) -> Optional[Dict[str, Any]]:
        async with semaphore:
            return await self._check_component(client, component, threshold)

    async def _check_component(
        self, client: httpx.AsyncClient, component: Dict[str, Any], threshold: float
    ) -> Optional[Dict[str, Any]]:
        """Check a component for Scorecard data and package metadata via deps.dev API."""
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "")

        parsed = parse_purl(purl)
        if not parsed:
            return None

        system = parsed.registry_system
        # Use specific name format for lookup
        lookup_name = parsed.deps_dev_name

        if not system or not lookup_name or not version:
            return None

        # URL-encode the package name (handles scoped packages like @scope/pkg)
        encoded_name = quote(lookup_name, safe="")
        encoded_version = quote(version, safe="")

        version_url = f"{self.base_url}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"

        result = {"metadata": None, "scorecard_issue": None}

        try:
            # Step 1: Get version info
            response = await client.get(version_url)

            if response.status_code == 404:
                # Package not found in deps.dev - this is normal for many packages
                return None

            if response.status_code != 200:
                logger.debug(
                    f"deps.dev API returned {response.status_code} for {name}@{version}"
                )
                return None

            data = response.json()

            # Extract package metadata
            metadata = self._extract_metadata(data, name, version, system, purl)

            # Step 2: Find related project (source repository)
            related_projects = data.get("relatedProjects", [])
            project_id = None

            for project in related_projects:
                project_key = project.get("projectKey", {})
                pid = project_key.get("id", "")
                relation_type = project.get("relationType", "")

                # Prefer SOURCE_REPO, fall back to any GitHub project
                if relation_type == "SOURCE_REPO" or pid.startswith("github.com/"):
                    project_id = pid
                    if relation_type == "SOURCE_REPO":
                        break  # Found the preferred one

            # Step 3: Fetch project details including Scorecard
            if project_id:
                encoded_project_id = quote(project_id, safe="")
                project_url = f"{self.base_url}/projects/{encoded_project_id}"

                proj_response = await client.get(project_url)
                if proj_response.status_code == 200:
                    proj_data = proj_response.json()

                    # Add project info to metadata
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

                    # Check scorecard
                    scorecard = proj_data.get("scorecard")
                    if scorecard:
                        overall_score = scorecard.get("overallScore", 0)

                        # Add scorecard summary to metadata (always)
                        metadata["scorecard"] = {
                            "overall_score": overall_score,
                            "date": scorecard.get("date"),
                            "checks_count": len(scorecard.get("checks", [])),
                        }

                        # Only create a scorecard issue if score is below threshold
                        if overall_score < threshold:
                            result["scorecard_issue"] = self._create_scorecard_issue(
                                name, version, purl, project_id, scorecard
                            )

            # Step 4: Fetch dependent count (popularity indicator)
            try:
                dependents_url = f"{self.base_url}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}:dependents"
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

            result["metadata"] = metadata
            return result

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking {name}@{version} on deps.dev")
            return None
        except Exception as e:
            logger.debug(f"Error checking {name}@{version} on deps.dev: {e}")
            return None

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
                # Normalize common label names
                if "home" in label or label == "homepage":
                    links["homepage"] = url
                elif (
                    "repo" in label
                    or "source" in label
                    or "github" in label
                    or "gitlab" in label
                ):
                    links["repository"] = url
                elif "doc" in label:
                    links["documentation"] = url
                elif "bug" in label or "issue" in label:
                    links["issues"] = url
                elif "changelog" in label or "change" in label:
                    links["changelog"] = url
                else:
                    links[label] = url

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
                failed_checks.append(
                    {"name": check_name, "score": check_score, "reason": check_reason}
                )

                # Identify critical security issues
                if check_name in [
                    "Maintained",
                    "Vulnerabilities",
                    "Dangerous-Workflow",
                ]:
                    critical_issues.append(check_name)

        # Build warning message
        warning_parts = [f"Low OpenSSF Scorecard score: {overall_score:.1f}/10"]

        if critical_issues:
            warning_parts.append(f"Critical issues: {', '.join(critical_issues)}")

        if failed_checks:
            failed_names = [f"{c['name']}({c['score']})" for c in failed_checks[:3]]
            warning_parts.append(f"Failed checks: {', '.join(failed_names)}")
            if len(failed_checks) > 3:
                warning_parts[-1] += f" (+{len(failed_checks) - 3} more)"

        return {
            "component": name,
            "version": version,
            "purl": purl,
            "project_url": f"https://{project_id}",
            "scorecard": {
                "overallScore": overall_score,
                "date": scorecard.get("date"),
                "checks": checks,
                "repository": scorecard.get("repository", {}).get("name"),
            },
            "failed_checks": failed_checks,
            "critical_issues": critical_issues,
            "warning": ". ".join(warning_parts),
        }



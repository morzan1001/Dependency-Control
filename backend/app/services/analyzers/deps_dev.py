import asyncio
import logging
from typing import Any
from urllib.parse import quote

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    DEPS_DEV_API_URL,
    SCORECARD_FLAG_THRESHOLD,
)
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.schemas.sbom import has_known_version

from .base import Analyzer
from app.core.purl import parse_purl

logger = logging.getLogger(__name__)


async def fetch_deps_dev_json(client: InstrumentedAsyncClient, url: str) -> dict[str, Any] | None:
    """A deps.dev document, or None when deps.dev does not know it; any other failure raises so nothing is cached."""
    response = await client.get(url, follow_redirects=True)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    document: dict[str, Any] = response.json()
    return document


def _lookup_target(component: dict[str, Any]) -> tuple[str, str, str] | None:
    """``(cache key, deps.dev system, deps.dev name)`` of a component deps.dev can look up at its version."""
    parsed = parse_purl(component.get("purl", ""))
    version = component.get("version", "")
    if not parsed or not parsed.deps_dev_system or not parsed.deps_dev_name or not has_known_version(version):
        return None
    system, name = parsed.deps_dev_system, parsed.deps_dev_name
    return CacheKeys.deps_dev(system, name, version), system, name


class DepsDevAnalyzer(Analyzer):
    """Fetches package metadata and OpenSSF Scorecard data from the deps.dev API (Redis-cached)."""

    name = "deps_dev"
    base_url = DEPS_DEV_API_URL

    @staticmethod
    def _collect(
        component: dict[str, Any],
        key: str,
        payload: Any,
        threshold: float,
        package_metadata: dict[str, Any],
        scorecard_issues: list[Any],
    ) -> None:
        """Apply a payload under this scan's component (a cached one names its fetcher), re-checking the threshold."""
        if not payload:
            return
        name, version, purl = component.get("name", ""), component.get("version", ""), component.get("purl", "")
        if payload.get("metadata"):
            package_metadata[key] = {**payload["metadata"], "name": name, "version": version, "purl": purl}
        issue = payload.get("scorecard_issue")
        if issue and issue.get("scorecard", {}).get("overallScore", 10) < threshold:
            scorecard_issues.append({**issue, "component": name, "version": version, "purl": purl})

    async def _fetch_uncached(self, keys: list[str], targets: dict[str, tuple[dict[str, Any], str, str]]) -> list[Any]:
        """Fetch deps.dev data for uncached packages with bounded concurrency."""
        timeout = ANALYZER_TIMEOUTS["deps_dev"]
        async with InstrumentedAsyncClient("deps.dev API", timeout=timeout) as client:

            async def fetch(key: str) -> dict[str, Any] | None:
                component, system, lookup_name = targets[key]
                # Distributed lock prevents multiple pods fetching the same package.
                return await cache_service.get_or_fetch_with_lock(
                    key=key,
                    fetch_fn=lambda: self._check_component(client, component, system, lookup_name),
                    ttl_seconds=CacheTTL.DEPS_DEV_METADATA,
                    reraise_fetch_errors=True,
                )

            return await gather_bounded(keys, fetch, ANALYZER_BATCH_SIZES["deps_dev"])

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        components = parsed_components or []
        scorecard_issues: list[Any] = []
        package_metadata: dict[str, Any] = {}

        # The cache is shared across projects, so it holds every scorecard and each project filters its own.
        threshold = (settings or {}).get("scorecard_threshold", SCORECARD_FLAG_THRESHOLD)

        targets: dict[str, tuple[dict[str, Any], str, str]] = {}
        for component in components:
            target = _lookup_target(component)
            if target is not None:
                targets.setdefault(target[0], (component, target[1], target[2]))

        cached: dict[str, Any] = await cache_service.mget(list(targets))
        payloads = {key: data for key, data in cached.items() if data is not None}
        uncached = [key for key in targets if key not in payloads]
        logger.debug(f"deps_dev: {len(payloads)} from cache, {len(uncached)} to fetch")

        if uncached:
            fetched = await self._fetch_uncached(uncached, targets)
            payloads.update(zip(uncached, fetched, strict=True))

        skipped = 0
        for key, payload in payloads.items():
            if isinstance(payload, BaseException):
                logger.warning(f"deps_dev lookup failed for {key}: {payload!r}")
                skipped += 1
            else:
                self._collect(targets[key][0], key, payload, threshold, package_metadata, scorecard_issues)

        result: dict[str, Any] = {"scorecard_issues": scorecard_issues, "package_metadata": package_metadata}
        if skipped:
            result["partial_components_skipped"] = skipped
        return result

    @staticmethod
    def _select_project_id(related_projects: list[dict[str, Any]]) -> str | None:
        """Pick the best project id: prefer SOURCE_REPO, fall back to any GitHub project."""
        project_id: str | None = None
        for project in related_projects:
            project_key = project.get("projectKey", {})
            pid = str(project_key.get("id", ""))
            relation_type = project.get("relationType", "")
            if relation_type == "SOURCE_REPO":
                return pid
            if pid.startswith("github.com/") and project_id is None:
                project_id = pid
        return project_id

    async def _cached_project(self, client: InstrumentedAsyncClient, project_id: str | None) -> dict[str, Any] | None:
        """The project summary and trimmed scorecard, cached once for every version that links the project."""
        if not project_id:
            return None
        project: dict[str, Any] | None = await cache_service.get_or_fetch_with_lock(
            key=CacheKeys.deps_dev_project(project_id),
            fetch_fn=lambda: self._fetch_project(client, project_id),
            ttl_seconds=CacheTTL.DEPS_DEV_METADATA,
            reraise_fetch_errors=True,
        )
        return project

    async def _fetch_project(self, client: InstrumentedAsyncClient, project_id: str) -> dict[str, Any] | None:
        data = await fetch_deps_dev_json(client, f"{self.base_url}/projects/{quote(project_id, safe='')}")
        if data is None:
            return None
        scorecard = data.get("scorecard")
        return {
            "project": {
                "id": project_id,
                "url": f"https://{project_id}",
                "stars": data.get("starsCount"),
                "forks": data.get("forksCount"),
                "open_issues": data.get("openIssuesCount"),
                "description": data.get("description"),
                "homepage": data.get("homepage"),
                "license": data.get("license"),
            },
            "scorecard": {
                "overallScore": scorecard.get("overallScore", 0),
                "date": scorecard.get("date"),
                "repository": scorecard.get("repository", {}).get("name"),
                "checks": [
                    {"name": c.get("name", ""), "score": c.get("score", -1)} for c in scorecard.get("checks", [])
                ],
            }
            if scorecard
            else None,
        }

    @staticmethod
    async def _fetch_dependents(client: InstrumentedAsyncClient, version_url: str) -> dict[str, Any] | None:
        """Dependent counts only enrich the metadata, so their failure never costs the component."""
        try:
            return await fetch_deps_dev_json(client, f"{version_url}:dependents")
        except (httpx.HTTPError, ValueError) as e:
            logger.debug(f"deps.dev dependents unavailable at {version_url}: {e!r}")
            return None

    async def _check_component(
        self,
        client: InstrumentedAsyncClient,
        component: dict[str, Any],
        system: str,
        lookup_name: str,
    ) -> dict[str, Any] | None:
        """Package metadata and scorecard issue for a component, or None when deps.dev does not know its version."""
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "")

        encoded_name = quote(lookup_name, safe="")
        encoded_version = quote(version, safe="")
        version_url = f"{self.base_url}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"

        data = await fetch_deps_dev_json(client, version_url)
        if data is None:
            return None

        metadata = self._extract_metadata(data, name, version, system, purl)
        project_id = self._select_project_id(data.get("relatedProjects", []))
        project, dependents = await asyncio.gather(
            self._cached_project(client, project_id),
            self._fetch_dependents(client, version_url),
        )

        if dependents:
            metadata["dependents"] = {
                "total": dependents.get("dependentCount", 0),
                "direct": dependents.get("directDependentCount", 0),
                "indirect": dependents.get("indirectDependentCount", 0),
            }

        scorecard_issue = None
        if project:
            metadata["project"] = project["project"]
            scorecard = project["scorecard"]
            if scorecard:
                metadata["scorecard"] = {
                    "overall_score": scorecard["overallScore"],
                    "date": scorecard["date"],
                    "checks_count": len(scorecard["checks"]),
                }
                scorecard_issue = self._create_scorecard_issue(project["project"]["url"], scorecard)

        return {"metadata": metadata, "scorecard_issue": scorecard_issue}

    @staticmethod
    def _classify_link_label(label: str) -> str:
        """Classify a link label into a normalized category name."""
        if "home" in label:
            return "homepage"
        if "repo" in label or "source" in label or "github" in label or "gitlab" in label:
            return "repository"
        if "doc" in label:
            return "documentation"
        if "bug" in label or "issue" in label:
            return "issues"
        if "change" in label:
            return "changelog"
        return label

    def _extract_metadata(
        self, data: dict[str, Any], name: str, version: str, system: str, purl: str
    ) -> dict[str, Any]:
        """Extract useful metadata from version response."""
        links = {}
        for link in data.get("links", []):
            label = link.get("label", "").lower()
            url = link.get("url", "")
            if url:
                links[self._classify_link_label(label)] = url

        metadata = {
            "name": name,
            "version": version,
            "system": system,
            "purl": purl,
            "published_at": data.get("publishedAt"),
            "is_deprecated": data.get("isDeprecated", False),
            "licenses": data.get("licenses", []),
            "links": links,
            "has_attestations": len(data.get("attestations", [])) > 0,
            "has_slsa_provenance": len(data.get("slsaProvenances", [])) > 0,
        }

        advisory_keys = data.get("advisoryKeys", [])
        if advisory_keys:
            metadata["known_advisories"] = [a.get("id") for a in advisory_keys]

        return metadata

    @staticmethod
    def _create_scorecard_issue(project_url: str, scorecard: dict[str, Any]) -> dict[str, Any]:
        """The fields normalize_scorecard reads; it grades the severity and writes the text."""
        # Score -1 means the check is not applicable.
        failed_checks = [check for check in scorecard["checks"] if 0 <= check["score"] < 5]
        return {
            "project_url": project_url,
            "scorecard": scorecard,
            "failed_checks": failed_checks,
            "critical_issues": [
                check["name"]
                for check in failed_checks
                if check["name"] in ("Maintained", "Vulnerabilities", "Dangerous-Workflow")
            ],
        }

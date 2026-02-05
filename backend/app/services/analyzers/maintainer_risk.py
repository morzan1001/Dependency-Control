"""
Maintainer Risk Analyzer

Analyzes package maintainer activity and health indicators to identify
potential supply chain risks from abandoned or under-maintained packages.

Risk Indicators:
- No recent releases (stale packages)
- Single maintainer (bus factor)
- Maintainer email from free providers (less accountability)
- Recent maintainer changes (potential account takeover)
- Low GitHub/GitLab activity
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    GITHUB_API_URL,
    NPM_REGISTRY_URL,
    PYPI_API_URL,
    STALE_PACKAGE_THRESHOLD_DAYS,
    STALE_PACKAGE_WARNING_DAYS,
)
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import is_npm, is_pypi, parse_purl

logger = logging.getLogger(__name__)


class MaintainerRiskAnalyzer(Analyzer):
    name = "maintainer_risk"

    @staticmethod
    def _parse_iso_datetime(dt_string: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string, handling Z suffix."""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    # Free email providers (lower accountability)
    FREE_EMAIL_PROVIDERS = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com",
        "mail.com",
        "aol.com",
        "icloud.com",
    }

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze maintainer health for packages in the SBOM.
        """
        components = self._get_components(sbom, parsed_components)
        issues = []
        checked_count = 0

        # Extract GitHub token from settings for authenticated API access
        github_token = settings.get("github_token") if settings else None
        timeout = ANALYZER_TIMEOUTS.get("maintainer_risk", ANALYZER_TIMEOUTS["default"])
        batch_size = ANALYZER_BATCH_SIZES.get("maintainer_risk", 10)

        async with InstrumentedAsyncClient("Maintainer Risk API", timeout=timeout) as client:

            for i in range(0, len(components), batch_size):
                batch = components[i : i + batch_size]
                tasks = [
                    self._check_component(client, comp, github_token) for comp in batch
                ]
                results = await asyncio.gather(*tasks)

                for result in results:
                    if result:
                        checked_count += 1
                        if result.get("risks"):
                            issues.append(result)

                # Small delay between batches to respect rate limits
                if i + batch_size < len(components):
                    await asyncio.sleep(0.5)

        return {
            "maintainer_issues": issues,
            "summary": {"checked_count": checked_count, "issues_count": len(issues)},
        }

    async def _check_component(
        self,
        client: httpx.AsyncClient,
        component: Dict[str, Any],
        github_token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Check maintainer health for a single component."""

        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        # Extract repository URL from SBOM if available
        repo_url = component.get("_repository_url") or component.get("repository_url")

        # Determine registry and get cache key
        parsed = parse_purl(purl)
        registry = parsed.registry_system if parsed else None
        cache_key = CacheKeys.maintainer(registry, name) if registry else None

        if not cache_key:
            return None

        async def fetch_maintainer_data() -> Optional[Dict[str, Any]]:
            """Fetch maintainer data from APIs."""
            cache_data: Dict[str, Any] = {"maintainer_info": {}, "github_info": None}

            if is_pypi(purl):
                info = await self._check_pypi(client, name)
                if info:
                    cache_data["maintainer_info"] = info

            elif is_npm(purl):
                info = await self._check_npm(client, name)
                if info:
                    cache_data["maintainer_info"] = info

            # Check GitHub repository if available
            github_repo = self._extract_github_repo(repo_url)
            if github_repo:
                gh_info = await self._check_github(client, github_repo, github_token)
                if gh_info:
                    cache_data["github_info"] = gh_info

            # Return None for negative cache if no data found
            if not cache_data["maintainer_info"] and not cache_data["github_info"]:
                return {}  # Empty dict for negative cache

            return cache_data

        # Use distributed lock to prevent multiple pods fetching same package
        cached_info = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_maintainer_data,
            ttl_seconds=CacheTTL.MAINTAINER_INFO,
        )

        if not cached_info:
            return None

        # Process the cached/fetched data
        risks = []
        maintainer_info = cached_info.get("maintainer_info", {})

        if maintainer_info:
            if registry == "pypi":
                risks.extend(self._assess_risks(maintainer_info, "pypi"))
            elif registry == "npm":
                risks.extend(self._assess_risks(maintainer_info, "npm"))

        # Check GitHub info
        github_info = cached_info.get("github_info")
        if github_info:
            maintainer_info["github"] = github_info
            risks.extend(self._assess_github_risks(github_info))

        if not risks:
            return None

        overall_severity = self._calculate_overall_severity(risks)
        message = self._create_summary_message(name, version, risks)

        return {
            "component": name,
            "version": version,
            "purl": purl,
            "risks": risks,
            "severity": overall_severity,
            "message": message,
            "maintainer_info": maintainer_info,
        }

    def _calculate_overall_severity(self, risks: List[Dict[str, Any]]) -> str:
        """Calculate overall severity from individual risk scores."""
        if not risks:
            return Severity.LOW.value
        max_severity = max(r.get("severity_score", 1) for r in risks)
        if max_severity >= 4:
            return Severity.CRITICAL.value
        elif max_severity >= 3:
            return Severity.HIGH.value
        elif max_severity >= 2:
            return Severity.MEDIUM.value
        return Severity.LOW.value

    def _create_summary_message(
        self, name: str, version: str, risks: List[Dict[str, Any]]
    ) -> str:
        """Create a human-readable summary message for maintainer risks."""
        if not risks:
            return ""

        risk_types = [r.get("type", "") for r in risks]
        risk_count = len(risks)

        # Prioritize most critical risk types in message
        if "archived_repo" in risk_types:
            return f"{name}@{version}: Repository is archived - no longer maintained"
        if "stale_package" in risk_types:
            return f"{name}@{version}: Package appears abandoned (no recent releases)"
        if "inactive_repo" in risk_types:
            return f"{name}@{version}: Repository has no recent activity"
        if "single_maintainer" in risk_types:
            return f"{name}@{version}: Single maintainer (bus factor risk)"

        # Generic message for other risks
        return f"{name}@{version} has {risk_count} maintainer risk{'s' if risk_count > 1 else ''}"

    async def _check_pypi(
        self, client: httpx.AsyncClient, name: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch maintainer info from PyPI."""
        try:
            response = await client.get(f"{PYPI_API_URL}/{name}/json")
            if response.status_code != 200:
                return None

            data = response.json()
            info = data.get("info", {})
            releases = data.get("releases", {})

            # Find latest release date
            latest_release_date = None
            for ver, files in releases.items():
                for f in files:
                    upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                    dt = self._parse_iso_datetime(upload_time)
                    if dt and (latest_release_date is None or dt > latest_release_date):
                        latest_release_date = dt

            return {
                "author": info.get("author"),
                "author_email": info.get("author_email"),
                "maintainer": info.get("maintainer"),
                "maintainer_email": info.get("maintainer_email"),
                "latest_release_date": (
                    latest_release_date.isoformat() if latest_release_date else None
                ),
                "days_since_release": (
                    (datetime.now(timezone.utc) - latest_release_date).days
                    if latest_release_date
                    else None
                ),
                "release_count": len(releases),
                "home_page": info.get("home_page"),
                "project_urls": info.get("project_urls", {}),
            }
        except httpx.TimeoutException:
            logger.debug(f"PyPI API timeout for {name}")
            return None
        except httpx.ConnectError:
            logger.debug(f"PyPI API connection error for {name}")
            return None
        except Exception as e:
            logger.debug(f"PyPI check failed for {name}: {e}")
            return None

    async def _check_npm(
        self, client: httpx.AsyncClient, name: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch maintainer info from npm."""
        try:
            encoded_name = name.replace("/", "%2F") if "/" in name else name
            response = await client.get(f"{NPM_REGISTRY_URL}/{encoded_name}")
            if response.status_code != 200:
                return None

            data = response.json()

            # Get maintainers
            maintainers = data.get("maintainers", [])

            # Find latest release date
            time_info = data.get("time", {})
            latest_release_date = self._parse_iso_datetime(time_info.get("modified"))

            return {
                "maintainers": maintainers,
                "maintainer_count": len(maintainers),
                "latest_release_date": (
                    latest_release_date.isoformat() if latest_release_date else None
                ),
                "days_since_release": (
                    (datetime.now(timezone.utc) - latest_release_date).days
                    if latest_release_date
                    else None
                ),
                "version_count": len(data.get("versions", {})),
                "homepage": data.get("homepage"),
                "repository": data.get("repository", {}).get("url"),
            }
        except httpx.TimeoutException:
            logger.debug(f"npm API timeout for {name}")
            return None
        except httpx.ConnectError:
            logger.debug(f"npm API connection error for {name}")
            return None
        except Exception as e:
            logger.debug(f"npm check failed for {name}: {e}")
            return None

    async def _check_github(
        self, client: httpx.AsyncClient, repo: str, github_token: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch repository health from GitHub API.

        If a GitHub token is provided, uses authenticated requests for higher rate limits.
        """
        try:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if github_token:
                headers["Authorization"] = f"Bearer {github_token}"

            response = await client.get(
                f"{GITHUB_API_URL}/repos/{repo}",
                headers=headers,
            )
            if response.status_code != 200:
                return None

            data = response.json()

            # Parse dates
            pushed_at = self._parse_iso_datetime(data.get("pushed_at"))

            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "archived": data.get("archived", False),
                "pushed_at": pushed_at.isoformat() if pushed_at else None,
                "days_since_push": (
                    (datetime.now(timezone.utc) - pushed_at).days if pushed_at else None
                ),
            }
        except httpx.TimeoutException:
            logger.debug(f"GitHub API timeout for {repo}")
            return None
        except httpx.ConnectError:
            logger.debug(f"GitHub API connection error for {repo}")
            return None
        except Exception as e:
            logger.debug(f"GitHub check failed for {repo}: {e}")
            return None

    def _assess_risks(
        self, info: Dict[str, Any], registry: str
    ) -> List[Dict[str, Any]]:
        """Assess maintainer risks based on registry info."""
        risks = []

        # Check for stale packages
        days_since_release = info.get("days_since_release")
        if days_since_release:
            if days_since_release > STALE_PACKAGE_THRESHOLD_DAYS:
                risks.append(
                    {
                        "type": "stale_package",
                        "severity_score": 3,
                        "message": f"No releases in {days_since_release} days - potentially abandoned",
                        "detail": f"Last release: {info.get('latest_release_date')}",
                    }
                )
            elif days_since_release > STALE_PACKAGE_WARNING_DAYS:
                risks.append(
                    {
                        "type": "infrequent_updates",
                        "severity_score": 2,
                        "message": f"No releases in {days_since_release} days",
                        "detail": f"Last release: {info.get('latest_release_date')}",
                    }
                )

        # Check maintainer email (PyPI)
        email = info.get("maintainer_email") or info.get("author_email")
        if email:
            domain = email.split("@")[-1].lower() if "@" in email else ""
            if domain and domain in self.FREE_EMAIL_PROVIDERS:
                risks.append(
                    {
                        "type": "free_email_maintainer",
                        "severity_score": 1,
                        "message": "Maintainer uses free email provider",
                        "detail": "Lower accountability compared to organizational emails",
                    }
                )

        # Check single maintainer (npm)
        if registry == "npm" and info.get("maintainer_count", 0) == 1:
            risks.append(
                {
                    "type": "single_maintainer",
                    "severity_score": 2,
                    "message": "Package has only one maintainer (bus factor = 1)",
                    "detail": "If maintainer becomes unavailable, package may become unmaintained",
                }
            )

        return risks

    def _assess_github_risks(self, gh_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess risks from GitHub repository info."""
        risks = []

        # Archived repository
        if gh_info.get("archived"):
            risks.append(
                {
                    "type": "archived_repo",
                    "severity_score": 4,
                    "message": "Repository is archived - no longer maintained",
                    "detail": "The source repository has been archived by its owner",
                }
            )

        # No recent activity
        days_since_push = gh_info.get("days_since_push")
        if days_since_push and days_since_push > STALE_PACKAGE_THRESHOLD_DAYS:
            risks.append(
                {
                    "type": "inactive_repo",
                    "severity_score": 3,
                    "message": f"No repository activity in {days_since_push} days",
                    "detail": f"Last push: {gh_info.get('pushed_at')}",
                }
            )

        # High open issues with no activity
        if (
            gh_info.get("open_issues", 0) > 100
            and days_since_push
            and days_since_push > 180
        ):
            risks.append(
                {
                    "type": "unaddressed_issues",
                    "severity_score": 2,
                    "message": f"High number of open issues ({gh_info['open_issues']}) with no recent activity",
                    "detail": "May indicate overwhelmed or absent maintainers",
                }
            )

        return risks

    def _extract_github_repo(self, url: Optional[str]) -> Optional[str]:
        """Extract owner/repo from GitHub URL."""
        if not url:
            return None

        # Handle various GitHub URL formats
        patterns = [
            r"github\.com[/:]([^/]+)/([^/\.]+)",
            r"github\.com[/:]([^/]+)/([^/]+)\.git",
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return f"{match.group(1)}/{match.group(2)}"

        return None

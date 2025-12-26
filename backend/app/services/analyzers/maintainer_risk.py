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

from .base import Analyzer
from .purl_utils import get_registry_system, is_npm, is_pypi

logger = logging.getLogger(__name__)


class MaintainerRiskAnalyzer(Analyzer):
    name = "maintainer_risk"

    # Thresholds for risk assessment
    STALE_THRESHOLD_DAYS = 730  # 2 years without release = potentially abandoned
    WARNING_THRESHOLD_DAYS = 365  # 1 year = warning

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
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze maintainer health for packages in the SBOM.
        """
        components = self._get_components(sbom, parsed_components)
        issues = []
        checked_count = 0

        # Extract GitHub token from settings for authenticated API access
        github_token = settings.get("github_token") if settings else None

        async with httpx.AsyncClient(timeout=15.0) as client:
            # Process in batches to avoid rate limiting
            batch_size = 10

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

        risks = []
        maintainer_info = {}

        # Determine registry and get cache key
        registry = get_registry_system(purl)
        cache_key = CacheKeys.maintainer(registry, name) if registry else None

        # Check cache first
        if cache_key:
            cached_info = await cache_service.get(cache_key)
            if cached_info is not None:
                if cached_info:  # Not a negative cache entry
                    maintainer_info = cached_info.get("maintainer_info", {})
                    if registry == "pypi":
                        risks.extend(self._assess_risks(maintainer_info, "pypi"))
                    elif registry == "npm":
                        risks.extend(self._assess_risks(maintainer_info, "npm"))

                    # Check GitHub if available
                    github_info = cached_info.get("github_info")
                    if github_info:
                        maintainer_info["github"] = github_info
                        risks.extend(self._assess_github_risks(github_info))
                else:
                    # Negative cache - no info available
                    return None

                if not risks:
                    return None

                max_severity = max(r.get("severity_score", 1) for r in risks)
                overall_severity = (
                    "CRITICAL"
                    if max_severity >= 4
                    else (
                        "HIGH"
                        if max_severity >= 3
                        else "MEDIUM" if max_severity >= 2 else "LOW"
                    )
                )
                return {
                    "component": name,
                    "version": version,
                    "purl": purl,
                    "risks": risks,
                    "severity": overall_severity,
                    "maintainer_info": maintainer_info,
                }

        # Fetch from APIs if not cached
        cache_data = {"maintainer_info": {}, "github_info": None}

        if is_pypi(purl):
            info = await self._check_pypi(client, name)
            if info:
                maintainer_info = info
                cache_data["maintainer_info"] = info
                risks.extend(self._assess_risks(info, "pypi"))

        elif is_npm(purl):
            info = await self._check_npm(client, name)
            if info:
                maintainer_info = info
                cache_data["maintainer_info"] = info
                risks.extend(self._assess_risks(info, "npm"))

        # Check GitHub repository if available
        github_repo = self._extract_github_repo(repo_url)
        if github_repo:
            gh_info = await self._check_github(client, github_repo, github_token)
            if gh_info:
                maintainer_info["github"] = gh_info
                cache_data["github_info"] = gh_info
                risks.extend(self._assess_github_risks(gh_info))

        # Cache the result
        if cache_key:
            if cache_data["maintainer_info"] or cache_data["github_info"]:
                await cache_service.set(cache_key, cache_data, CacheTTL.MAINTAINER_INFO)
            else:
                # Cache negative result
                await cache_service.set(cache_key, {}, CacheTTL.NEGATIVE_RESULT)

        if not risks:
            return None

        # Determine overall severity
        max_severity = max(r.get("severity_score", 1) for r in risks)
        overall_severity = (
            "CRITICAL"
            if max_severity >= 4
            else (
                "HIGH"
                if max_severity >= 3
                else "MEDIUM" if max_severity >= 2 else "LOW"
            )
        )

        return {
            "component": name,
            "version": version,
            "purl": purl,
            "risks": risks,
            "severity": overall_severity,
            "maintainer_info": maintainer_info,
        }

    async def _check_pypi(
        self, client: httpx.AsyncClient, name: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch maintainer info from PyPI."""
        try:
            response = await client.get(f"https://pypi.org/pypi/{name}/json")
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
                    if upload_time:
                        try:
                            dt = datetime.fromisoformat(
                                upload_time.replace("Z", "+00:00")
                            )
                            if latest_release_date is None or dt > latest_release_date:
                                latest_release_date = dt
                        except (ValueError, TypeError):
                            pass

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
        except Exception as e:
            logger.debug(f"PyPI check failed for {name}: {e}")
            return None

    async def _check_npm(
        self, client: httpx.AsyncClient, name: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch maintainer info from npm."""
        try:
            encoded_name = name.replace("/", "%2F") if "/" in name else name
            response = await client.get(f"https://registry.npmjs.org/{encoded_name}")
            if response.status_code != 200:
                return None

            data = response.json()

            # Get maintainers
            maintainers = data.get("maintainers", [])

            # Find latest release date
            time_info = data.get("time", {})
            latest_release_date = None
            if time_info.get("modified"):
                try:
                    latest_release_date = datetime.fromisoformat(
                        time_info["modified"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

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
                f"https://api.github.com/repos/{repo}",
                headers=headers,
            )
            if response.status_code != 200:
                return None

            data = response.json()

            # Parse dates
            pushed_at = None
            if data.get("pushed_at"):
                try:
                    pushed_at = datetime.fromisoformat(
                        data["pushed_at"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

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
            if days_since_release > self.STALE_THRESHOLD_DAYS:
                risks.append(
                    {
                        "type": "stale_package",
                        "severity_score": 3,
                        "message": f"No releases in {days_since_release} days - potentially abandoned",
                        "detail": f"Last release: {info.get('latest_release_date')}",
                    }
                )
            elif days_since_release > self.WARNING_THRESHOLD_DAYS:
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
            if domain in self.FREE_EMAIL_PROVIDERS:
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
        if days_since_push and days_since_push > self.STALE_THRESHOLD_DAYS:
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

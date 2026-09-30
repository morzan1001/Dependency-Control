"""Analyzes package maintainer activity to flag supply-chain risk from abandoned or under-maintained packages."""

import logging
import re
from datetime import datetime, timezone
from email.utils import getaddresses
from typing import Any, ClassVar

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import (
    ANALYZER_BATCH_SIZES,
    ANALYZER_TIMEOUTS,
    GITHUB_API_URL,
    NPM_REGISTRY_URL,
    PYPI_API_URL,
    STALE_PACKAGE_THRESHOLD_DAYS,
    STALE_PACKAGE_WARNING_DAYS,
)
from app.core.http_utils import InstrumentedAsyncClient, gather_bounded
from app.models.finding import Severity
from app.services.github import github_api_headers

from .base import Analyzer
from .outdated import fetch_package_info
from app.core.purl import parse_purl

logger = logging.getLogger(__name__)


_STALENESS_TYPES = ("stale_package", "infrequent_updates")
_UNADDRESSED_ISSUES_MIN = 100
# PyPI project_urls labels that name the source repository, most specific first.
_REPOSITORY_LABELS = ("source", "source code", "repository", "github", "homepage")
# GitHub's owner and repo charsets, so registry metadata cannot steer the token-bearing request off /repos/.
_GITHUB_REPO = re.compile(r"(?:github\.com[/:]|^github:)([\w-]+)/(\.?[\w-][\w.-]*?)(?:\.git)?(?:[/#?]|$)")


def correlate_maintainer_risks(risks: list[dict[str, Any]], github_active: bool | None) -> list[dict[str, Any]]:
    """Drop staleness signals when the source repository is still active."""
    if github_active is not True:
        return risks
    return [r for r in risks if r.get("type") not in _STALENESS_TYPES]


class MaintainerRiskAnalyzer(Analyzer):
    name = "maintainer_risk"
    _stale_after_days = STALE_PACKAGE_THRESHOLD_DAYS
    _warn_after_days = STALE_PACKAGE_WARNING_DAYS

    @staticmethod
    def _parse_iso_datetime(dt_string: str | None) -> datetime | None:
        """Parse ISO datetime string, handling Z suffix."""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    FREE_EMAIL_PROVIDERS: ClassVar[set[str]] = {
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
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze maintainer health for packages in the SBOM."""
        settings = settings or {}
        github_token = settings.get("github_token")
        self._stale_after_days = settings.get("stale_after_days", STALE_PACKAGE_THRESHOLD_DAYS)
        self._warn_after_days = settings.get("warn_after_days", STALE_PACKAGE_WARNING_DAYS)
        timeout = ANALYZER_TIMEOUTS["maintainer_risk"]

        async with InstrumentedAsyncClient("Maintainer Risk API", timeout=timeout) as client:
            results = await gather_bounded(
                parsed_components or [],
                lambda component: self._check_component(client, component, github_token),
                ANALYZER_BATCH_SIZES["maintainer_risk"],
            )

        issues = []
        skipped = 0
        for result in results:
            if isinstance(result, BaseException):
                logger.warning(f"maintainer_risk component check failed: {result!r}")
                skipped += 1
            elif result:
                issues.append(result)
        output: dict[str, Any] = {"maintainer_issues": issues}
        if skipped:
            output["partial_components_skipped"] = skipped
        return output

    async def _check_component(
        self,
        client: InstrumentedAsyncClient,
        component: dict[str, Any],
        github_token: str | None,
    ) -> dict[str, Any] | None:
        """One package's risks from its registry facts and the facts of its GitHub repository."""
        name = component.get("name", "")
        purl = component.get("purl", "")
        parsed = parse_purl(purl)
        if not parsed or not parsed.registry_system:
            return None
        registry = parsed.registry_system

        maintainer_info: dict[str, Any] = {}
        if registry in ("pypi", "npm"):
            maintainer_info = dict(
                await cache_service.get_or_fetch_with_lock(
                    key=CacheKeys.maintainer(registry, name),
                    fetch_fn=lambda: (
                        self._check_pypi(client, name) if registry == "pypi" else self._check_npm(client, name)
                    ),
                    ttl_seconds=CacheTTL.MAINTAINER_INFO,
                )
                or {}
            )
        if registry == "npm":
            try:
                package = await fetch_package_info(client, "npm", parsed.deps_dev_name) or {}
            except (httpx.HTTPError, ValueError) as e:
                logger.debug(f"deps.dev release lookup failed for {name}: {e}")
                package = {}
            released = self._parse_iso_datetime(package.get("published_at"))
            if released:
                maintainer_info["latest_release_date"] = released.isoformat()
                maintainer_info["days_since_release"] = (datetime.now(timezone.utc) - released).days

        github_info = None
        repo = self._resolve_github_repo(component, maintainer_info)
        if repo:
            try:
                github_info = await cache_service.get_or_fetch_with_lock(
                    key=CacheKeys.maintainer_github(repo),
                    fetch_fn=lambda: self._check_github(client, repo, github_token),
                    ttl_seconds=CacheTTL.MAINTAINER_INFO,
                    reraise_fetch_errors=True,
                )
            except (httpx.HTTPError, ValueError) as e:
                logger.debug(f"GitHub check failed for {repo}: {e}")

        risks = self._assess_risks(maintainer_info)
        if github_info:
            maintainer_info["github"] = github_info
            risks.extend(self._assess_github_risks(github_info))
        risks = correlate_maintainer_risks(risks, github_active=self._infer_github_active(github_info))
        if not risks:
            return None

        return {
            "component": name,
            "version": component.get("version", ""),
            "purl": purl,
            "risks": risks,
            "severity": self._calculate_overall_severity(risks),
            "maintainer_info": maintainer_info,
        }

    @staticmethod
    def _resolve_github_repo(component: dict[str, Any], registry_info: dict[str, Any]) -> str | None:
        """owner/repo from the SBOM, then npm's repository, then PyPI's project URLs and home page."""
        project_urls = {label.lower(): url for label, url in (registry_info.get("project_urls") or {}).items()}
        candidates = [
            component.get("repository_url"),
            registry_info.get("repository"),
            *(project_urls.get(label) for label in _REPOSITORY_LABELS),
            registry_info.get("home_page"),
        ]
        for url in candidates:
            match = _GITHUB_REPO.search(url) if isinstance(url, str) else None
            if match:
                return f"{match.group(1)}/{match.group(2)}"
        return None

    def _calculate_overall_severity(self, risks: list[dict[str, Any]]) -> str:
        """Calculate overall severity from individual risk scores."""
        if not risks:
            return Severity.LOW.value
        max_severity = max(r.get("severity_score", 1) for r in risks)
        if max_severity >= 4:
            return Severity.CRITICAL.value
        if max_severity >= 3:
            return Severity.HIGH.value
        if max_severity >= 2:
            return Severity.MEDIUM.value
        return Severity.LOW.value

    async def _check_pypi(self, client: InstrumentedAsyncClient, name: str) -> dict[str, Any] | None:
        """Fetch maintainer info from PyPI."""
        try:
            response = await client.get(f"{PYPI_API_URL}/{name}/json")
            if response.status_code != 200:
                return None

            data = response.json()
            info = data.get("info", {})
            releases = data.get("releases", {})

            latest_release_date = None
            for files in releases.values():
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
                "latest_release_date": (latest_release_date.isoformat() if latest_release_date else None),
                "days_since_release": (
                    (datetime.now(timezone.utc) - latest_release_date).days if latest_release_date else None
                ),
                "release_count": len(releases),
                "home_page": info.get("home_page"),
                "project_urls": info.get("project_urls", {}),
            }
        except Exception as e:
            logger.debug(f"PyPI check failed for {name}: {e}")
            return None

    async def _check_npm(self, client: InstrumentedAsyncClient, name: str) -> dict[str, Any] | None:
        """Maintainers and repository of the latest npm release."""
        try:
            response = await client.get(f"{NPM_REGISTRY_URL}/{name.replace('/', '%2F')}/latest")
            if response.status_code != 200:
                return None

            data = response.json()
            maintainers = data.get("maintainers") or []
            repository = data.get("repository")
            return {
                "maintainer": ", ".join(m.get("name", "") for m in maintainers),
                "maintainer_email": ", ".join(m["email"] for m in maintainers if m.get("email")),
                "maintainer_count": len(maintainers),
                "repository": repository.get("url") if isinstance(repository, dict) else repository,
            }
        except Exception as e:
            logger.debug(f"npm check failed for {name}: {e}")
            return None

    async def _check_github(
        self, client: InstrumentedAsyncClient, repo: str, github_token: str | None
    ) -> dict[str, Any] | None:
        """Repository health from the GitHub API; None when the repository is gone, any other failure raises."""
        response = await client.get(
            f"{GITHUB_API_URL}/repos/{repo}", headers=github_api_headers(github_token), follow_redirects=True
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()

        data = response.json()
        pushed_at = self._parse_iso_datetime(data.get("pushed_at"))
        return {
            "stars": data.get("stargazers_count", 0),
            "forks": data.get("forks_count", 0),
            "open_issues": data.get("open_issues_count", 0),
            "archived": data.get("archived", False),
            "pushed_at": pushed_at.isoformat() if pushed_at else None,
            "days_since_push": ((datetime.now(timezone.utc) - pushed_at).days if pushed_at else None),
        }

    def _assess_risks(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        """Assess maintainer risks based on registry info."""
        risks = []

        days_since_release = info.get("days_since_release")
        stale_after = self._stale_after_days
        warn_after = self._warn_after_days
        if days_since_release:
            if days_since_release > stale_after:
                risks.append(
                    {
                        "type": "stale_package",
                        "severity_score": 3,
                        "message": f"No releases in {days_since_release} days - potentially abandoned",
                        "detail": f"Last release: {info.get('latest_release_date')}",
                    }
                )
            elif days_since_release > warn_after:
                risks.append(
                    {
                        "type": "infrequent_updates",
                        "severity_score": 2,
                        "message": f"No releases in {days_since_release} days",
                        "detail": f"Last release: {info.get('latest_release_date')}",
                    }
                )

        # Both registries give several maintainers as one "Name <addr>, Name2 <addr2>" string.
        addresses = [
            addr
            for _, addr in getaddresses([info.get("maintainer_email") or info.get("author_email") or ""])
            if "@" in addr
        ]
        if addresses and all(addr.rsplit("@", 1)[1].lower() in self.FREE_EMAIL_PROVIDERS for addr in addresses):
            risks.append(
                {
                    "type": "free_email_maintainer",
                    "severity_score": 1,
                    "message": "Maintainer uses free email provider",
                    "detail": "Lower accountability compared to organizational emails",
                }
            )

        if info.get("maintainer_count") == 1:
            risks.append(
                {
                    "type": "single_maintainer",
                    "severity_score": 2,
                    "message": "Package has only one maintainer (bus factor = 1)",
                    "detail": "If maintainer becomes unavailable, package may become unmaintained",
                }
            )

        return risks

    def _infer_github_active(self, gh_info: dict[str, Any] | None) -> bool | None:
        """True if the repo shows recent activity, False if archived/stale, None if data is unavailable."""
        if not gh_info:
            return None
        if gh_info.get("archived"):
            return False
        days_since_push = gh_info.get("days_since_push")
        if days_since_push is None:
            return None
        return bool(days_since_push <= self._warn_after_days)

    def _assess_github_risks(self, gh_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Assess risks from GitHub repository info."""
        risks = []

        if gh_info.get("archived"):
            risks.append(
                {
                    "type": "archived_repo",
                    "severity_score": 4,
                    "message": "Repository is archived - no longer maintained",
                    "detail": "The source repository has been archived by its owner",
                }
            )

        days_since_push = gh_info.get("days_since_push")
        if days_since_push and days_since_push > self._stale_after_days:
            risks.append(
                {
                    "type": "inactive_repo",
                    "severity_score": 3,
                    "message": f"No repository activity in {days_since_push} days",
                    "detail": f"Last push: {gh_info.get('pushed_at')}",
                }
            )

        idle = days_since_push is not None and days_since_push > self._warn_after_days
        if gh_info.get("open_issues", 0) > _UNADDRESSED_ISSUES_MIN and idle:
            risks.append(
                {
                    "type": "unaddressed_issues",
                    "severity_score": 2,
                    "message": f"High number of open issues ({gh_info['open_issues']}) with no recent activity",
                    "detail": "May indicate overwhelmed or absent maintainers",
                }
            )

        return risks

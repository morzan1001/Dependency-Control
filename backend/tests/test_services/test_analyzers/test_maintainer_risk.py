"""Maintainer risk: signal correlation, and analyze() on the npm, PyPI, deps.dev and GitHub answers it reads."""

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from app.core.constants import DEPS_DEV_API_URL, GITHUB_API_URL, NPM_REGISTRY_URL, PYPI_API_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.services.analyzers import maintainer_risk as maintainer_mod
from app.services.analyzers import outdated as outdated_mod
from app.services.analyzers.maintainer_risk import MaintainerRiskAnalyzer, correlate_maintainer_risks
from tests.helpers.analyzers import analyze_cyclonedx


def _stale() -> dict[str, Any]:
    return {"type": "stale_package", "severity_score": 3, "message": "stale"}


def _infrequent() -> dict[str, Any]:
    return {"type": "infrequent_updates", "severity_score": 2, "message": "infrequent"}


def _inactive() -> dict[str, Any]:
    return {"type": "inactive_repo", "severity_score": 3, "message": "inactive"}


def _archived() -> dict[str, Any]:
    return {"type": "archived_repo", "severity_score": 4, "message": "archived"}


def _free_email() -> dict[str, Any]:
    return {"type": "free_email_maintainer", "severity_score": 1, "message": "gmail"}


def _single_maintainer() -> dict[str, Any]:
    return {"type": "single_maintainer", "severity_score": 2, "message": "solo"}


def _types(risks: list[dict[str, Any]]) -> list[str]:
    return [r["type"] for r in risks]


class TestCorrelateMaintainerRisks:
    def test_stale_kept_when_repo_also_inactive(self):
        # Both registry and GitHub agree: real abandonment.
        risks = [_stale(), _inactive()]
        result = correlate_maintainer_risks(risks, github_active=False)
        assert "stale_package" in _types(result)
        assert "inactive_repo" in _types(result)

    def test_stale_suppressed_when_repo_active(self):
        # Registry says "no release in 2 years" but the repo is still getting
        # commits — a mature/finished package, not abandoned. Drop the stale signal.
        risks = [_stale()]
        result = correlate_maintainer_risks(risks, github_active=True)
        assert "stale_package" not in _types(result)

    def test_infrequent_updates_suppressed_when_repo_active(self):
        # Same rule applies to the lower-severity sibling signal.
        risks = [_infrequent()]
        result = correlate_maintainer_risks(risks, github_active=True)
        assert "infrequent_updates" not in _types(result)

    def test_stale_kept_when_no_github_data(self):
        # No corroborating evidence either way -> keep the registry signal.
        risks = [_stale()]
        result = correlate_maintainer_risks(risks, github_active=None)
        assert "stale_package" in _types(result)

    def test_archived_overrides_active_repo_check(self):
        # Archived repos are unmaintained by definition; even if commits
        # were "recent" before archiving, the package is dead.
        risks = [_stale(), _archived()]
        result = correlate_maintainer_risks(risks, github_active=False)
        assert "archived_repo" in _types(result)
        assert "stale_package" in _types(result)

    def test_free_email_kept_when_single_maintainer(self):
        # Free email + single maintainer is a real bus-factor concern:
        # if the maintainer disappears, there's no organizational fallback.
        risks = [_free_email(), _single_maintainer()]
        result = correlate_maintainer_risks(risks, github_active=None)
        assert "free_email_maintainer" in _types(result)
        assert "single_maintainer" in _types(result)

    def test_unrelated_risks_pass_through(self):
        # Correlation should never invent new risks or drop unrelated ones.
        custom = {"type": "unaddressed_issues", "severity_score": 2, "message": "x"}
        result = correlate_maintainer_risks([custom], github_active=True)
        assert result == [custom]

    def test_empty_list_returns_empty(self):
        assert correlate_maintainer_risks([], github_active=None) == []

    def test_active_repo_does_not_drop_unrelated_signals(self):
        # github_active=True should only affect stale-related signals, not
        # other registry findings.
        risks = [_single_maintainer(), _stale()]
        result = correlate_maintainer_risks(risks, github_active=True)
        types = _types(result)
        assert "single_maintainer" in types
        assert "stale_package" not in types


class TestOverallSeverity:
    @pytest.mark.parametrize(
        ("scores", "expected"),
        [([], "LOW"), ([1], "LOW"), ([2, 1], "MEDIUM"), ([3], "HIGH"), ([1, 4], "CRITICAL"), ([5], "CRITICAL")],
    )
    def test_the_worst_signal_sets_the_package_severity(self, scores, expected):
        risks = [{"severity_score": score} for score in scores]
        assert MaintainerRiskAnalyzer()._calculate_overall_severity(risks) == expected


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serve(monkeypatch: pytest.MonkeyPatch, cache: Any, routes: dict[str, Any]) -> list[httpx.Request]:
    """Answer each URL from ``routes`` (a JSON body, a status code or a Response), anything else 404."""
    seen: list[httpx.Request] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = routes.get(str(request.url), 404)
        if isinstance(answer, httpx.Response):
            return answer
        if isinstance(answer, int):
            return httpx.Response(answer)
        return httpx.Response(200, json=answer)

    transport = httpx.MockTransport(_answer)
    monkeypatch.setattr(
        maintainer_mod,
        "InstrumentedAsyncClient",
        lambda service, **kwargs: InstrumentedAsyncClient(service, transport=transport, **kwargs),
    )
    monkeypatch.setattr(maintainer_mod, "cache_service", cache)
    monkeypatch.setattr(outdated_mod, "cache_service", cache)
    return seen


def _npm_latest(repository: Any, maintainers: list[dict[str, str]]) -> dict[str, Any]:
    """GET /{name}/latest, trimmed to the fields the analyzer reads."""
    return {"version": "1.0.0", "maintainers": maintainers, "repository": repository}


def _deps_dev_package(default_published_days_ago: int) -> dict[str, Any]:
    return {
        "versions": [
            {"versionKey": {"version": "0.9.0"}, "publishedAt": _days_ago(2000), "isDefault": False},
            {
                "versionKey": {"version": "1.0.0"},
                "publishedAt": _days_ago(default_published_days_ago),
                "isDefault": True,
            },
        ]
    }


def _pypi_project(
    *, author_email: str | None = None, project_urls: dict[str, str] | None = None, uploaded_days_ago: int = 10
) -> dict[str, Any]:
    return {
        "info": {
            "author": None,
            "author_email": author_email,
            "maintainer": None,
            "maintainer_email": None,
            "home_page": None,
            "project_urls": project_urls,
        },
        "releases": {"1.0.0": [{"upload_time_iso_8601": _days_ago(uploaded_days_ago)}]},
    }


def _github_repo(*, archived: bool = False, pushed_days_ago: int | None = 3, open_issues: int = 10) -> dict[str, Any]:
    return {
        "archived": archived,
        "pushed_at": _days_ago(pushed_days_ago) if pushed_days_ago is not None else None,
        "open_issues_count": open_issues,
        "stargazers_count": 1,
        "forks_count": 1,
    }


def _component(purl_type: str, name: str, repository_url: str | None = None) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:{purl_type}/{name}@1.0.0",
    }
    if repository_url:
        component["externalReferences"] = [{"type": "vcs", "url": repository_url}]
    return component


def _risk_types(result: dict[str, Any]) -> list[str]:
    return [risk["type"] for issue in result["maintainer_issues"] for risk in issue["risks"]]


_ORG_MAINTAINERS = [{"name": "release-bot", "email": "release@vercel.com"}, {"name": "dev", "email": "dev@vercel.com"}]


class TestAnalyze:
    @pytest.mark.parametrize(
        ("name", "repository", "repo"),
        [
            ("next", {"type": "git", "url": "git+https://github.com/vercel/next.js.git"}, "vercel/next.js"),
            ("socket.io", "github:socketio/socket.io", "socketio/socket.io"),
        ],
        ids=["object", "shorthand-string"],
    )
    @pytest.mark.asyncio
    async def test_an_npm_package_finds_its_repository_through_the_registry(
        self, fake_cache, monkeypatch, name, repository, repo
    ):
        requests = _serve(
            monkeypatch,
            fake_cache,
            {
                f"{NPM_REGISTRY_URL}/{name}/latest": _npm_latest(repository, _ORG_MAINTAINERS),
                f"{DEPS_DEV_API_URL}/systems/npm/packages/{name}": _deps_dev_package(800),
                f"{GITHUB_API_URL}/repos/{repo}": _github_repo(archived=True),
            },
        )

        result = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [_component("npm", name)])

        [issue] = result["maintainer_issues"]
        assert set(result) == {"maintainer_issues"}
        assert "message" not in issue
        assert [risk["type"] for risk in issue["risks"]] == ["stale_package", "archived_repo"]
        assert issue["severity"] == "CRITICAL"
        assert issue["maintainer_info"]["days_since_release"] == 800
        assert f"{NPM_REGISTRY_URL}/{name}" not in [str(request.url) for request in requests]

    @pytest.mark.asyncio
    async def test_a_later_sbom_naming_the_repository_gets_the_github_facts(self, fake_cache, monkeypatch):
        _serve(
            monkeypatch,
            fake_cache,
            {
                f"{PYPI_API_URL}/oldlib/json": _pypi_project(uploaded_days_ago=800),
                f"{GITHUB_API_URL}/repos/acme/oldlib": _github_repo(archived=True),
            },
        )

        first = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [_component("pypi", "oldlib")])
        second = await analyze_cyclonedx(
            MaintainerRiskAnalyzer(), [_component("pypi", "oldlib", "https://github.com/acme/oldlib")]
        )

        assert _risk_types(first) == ["stale_package"]
        assert _risk_types(second) == ["stale_package", "archived_repo"]

    @pytest.mark.asyncio
    async def test_a_moved_repository_is_followed_with_the_token(self, fake_cache, monkeypatch):
        moved_to = f"{GITHUB_API_URL}/repositories/3655872"
        requests = _serve(
            monkeypatch,
            fake_cache,
            {
                f"{GITHUB_API_URL}/repos/zeit/ms": httpx.Response(301, headers={"Location": moved_to}),
                moved_to: _github_repo(archived=True),
            },
        )

        result = await analyze_cyclonedx(
            MaintainerRiskAnalyzer(), [_component("npm", "ms", "https://github.com/zeit/ms")], {"github_token": "tok"}
        )

        assert _risk_types(result) == ["archived_repo"]
        [followed] = [request for request in requests if str(request.url) == moved_to]
        assert followed.headers["Authorization"] == "Bearer tok"
        assert followed.headers["X-GitHub-Api-Version"] == "2022-11-28"

    @pytest.mark.parametrize("status", [403, 429])
    @pytest.mark.asyncio
    async def test_a_rate_limited_github_answer_is_asked_again_next_scan(self, fake_cache, monkeypatch, status):
        routes: dict[str, Any] = {f"{GITHUB_API_URL}/repos/acme/oldlib": status}
        _serve(monkeypatch, fake_cache, routes)
        component = _component("pypi", "oldlib", "https://github.com/acme/oldlib")

        throttled = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [component])
        routes[f"{GITHUB_API_URL}/repos/acme/oldlib"] = _github_repo(archived=True)
        answered = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [component])

        assert _risk_types(throttled) == []
        assert _risk_types(answered) == ["archived_repo"]

    @pytest.mark.asyncio
    async def test_pypi_project_urls_name_the_repository(self, fake_cache, monkeypatch):
        project_urls = {
            "Funding": "https://github.com/sponsors/acme",
            "Documentation": "https://docs.acme.dev",
            "Source": "https://github.com/acme/oldlib",
        }
        _serve(
            monkeypatch,
            fake_cache,
            {
                f"{PYPI_API_URL}/oldlib/json": _pypi_project(project_urls=project_urls),
                f"{GITHUB_API_URL}/repos/acme/oldlib": _github_repo(archived=True),
            },
        )

        result = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [_component("pypi", "oldlib")])

        assert _risk_types(result) == ["archived_repo"]

    @pytest.mark.parametrize(
        ("author_email", "expected"),
        [("Tom Christie <tom@gmail.com>", ["free_email_maintainer"]), ("Tom Christie <tom@encode.io>", [])],
    )
    @pytest.mark.asyncio
    async def test_a_named_pypi_address_is_checked_by_its_domain(self, fake_cache, monkeypatch, author_email, expected):
        _serve(monkeypatch, fake_cache, {f"{PYPI_API_URL}/httpx/json": _pypi_project(author_email=author_email)})

        result = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [_component("pypi", "httpx")])

        assert _risk_types(result) == expected

    @pytest.mark.parametrize(
        ("maintainers", "expected"),
        [
            ([{"name": "solo", "email": "solo@gmail.com"}], ["free_email_maintainer", "single_maintainer"]),
            ([{"name": "solo", "email": "solo@gmail.com"}, {"name": "org", "email": "dev@acme.dev"}], []),
        ],
        ids=["only-free", "one-organisational"],
    )
    @pytest.mark.asyncio
    async def test_npm_maintainer_emails_feed_the_free_email_check(
        self, fake_cache, monkeypatch, maintainers, expected
    ):
        _serve(
            monkeypatch,
            fake_cache,
            {
                f"{NPM_REGISTRY_URL}/left-pad/latest": _npm_latest(None, maintainers),
                f"{DEPS_DEV_API_URL}/systems/npm/packages/left-pad": _deps_dev_package(10),
            },
        )

        result = await analyze_cyclonedx(MaintainerRiskAnalyzer(), [_component("npm", "left-pad")])

        assert _risk_types(result) == expected

    @pytest.mark.parametrize(
        ("settings", "pushed_days_ago", "fires"),
        [({"warn_after_days": 30}, 100, True), ({}, 200, False), ({}, None, False)],
        ids=["idle-past-a-short-window", "active-within-the-default-window", "push-date-unknown"],
    )
    @pytest.mark.asyncio
    async def test_unaddressed_issues_follow_the_warn_window(
        self, fake_cache, monkeypatch, settings, pushed_days_ago, fires
    ):
        _serve(
            monkeypatch,
            fake_cache,
            {f"{GITHUB_API_URL}/repos/acme/busy": _github_repo(pushed_days_ago=pushed_days_ago, open_issues=150)},
        )

        result = await analyze_cyclonedx(
            MaintainerRiskAnalyzer(), [_component("pypi", "busy", "https://github.com/acme/busy")], settings
        )

        assert ("unaddressed_issues" in _risk_types(result)) is fires

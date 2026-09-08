"""GitHubService pull-request and comment API methods."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.github import GitHubService
from tests.mocks.github import make_github_instance

_MERGE_SHA = "1f0e9c2a3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"
_BASE_SHA = "9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"
_HEAD_SHA = "3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"
_THIRD_SHA = "7b6a5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"

# Shape of one item in GET /repos/{owner}/{repo}/commits/{sha}/pulls.
_PULL_REQUEST = {
    "url": "https://api.github.com/repos/acme/widget/pulls/42",
    "id": 1296269,
    "node_id": "PR_kwDOABCDEF",
    "html_url": "https://github.com/acme/widget/pull/42",
    "issue_url": "https://api.github.com/repos/acme/widget/issues/42",
    "number": 42,
    "state": "open",
    "locked": False,
    "title": "Bump libfoo to 2.4.1",
    "user": {"login": "octocat", "id": 1, "type": "User"},
    "draft": False,
    "merged_at": None,
    "head": {"label": "acme:feature", "ref": "feature", "sha": _HEAD_SHA},
    "base": {"label": "acme:main", "ref": "main", "sha": _BASE_SHA},
}


def _json_response(payload, status_code=200):
    response = MagicMock(status_code=status_code)
    response.json.return_value = payload
    return response


def _commit_payload(*parent_shas):
    """Shape of GET /repos/{owner}/{repo}/commits/{sha} (fields we read)."""
    return {
        "sha": _MERGE_SHA,
        "node_id": "C_kwDOABCDEF",
        # GitHub spells both SHAs out in full in a test-merge message.
        "commit": {"message": f"Merge {_HEAD_SHA} into {_BASE_SHA}"},
        "parents": [
            {
                "sha": sha,
                "url": f"https://api.github.com/repos/acme/widget/commits/{sha}",
                "html_url": f"https://github.com/acme/widget/commit/{sha}",
            }
            for sha in parent_shas
        ],
    }


def _error_body(message):
    """Shape of a GitHub REST error response."""
    return {"message": message, "documentation_url": "https://docs.github.com/rest"}


def _routed_api_get(routes):
    """An _api_get double keyed by endpoint; an unrouted endpoint behaves as a transport failure."""
    return AsyncMock(side_effect=lambda endpoint, params=None: routes.get(endpoint))


def _requested(api_get):
    return [call.args[0] for call in api_get.await_args_list]


class TestGetPullRequestsForCommit:
    def test_calls_the_documented_endpoint_and_parses(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        response = _json_response(
            [
                {"number": 7, "state": "open", "draft": False, "title": "Add thing"},
                {"number": 5, "state": "closed", "draft": False, "title": "Old"},
            ]
        )
        with patch.object(service, "_api_get", new_callable=AsyncMock, return_value=response) as api_get:
            prs = asyncio.run(service.get_pull_requests_for_commit("acme", "widget", "deadbeef"))

        api_get.assert_awaited_once_with("/repos/acme/widget/commits/deadbeef/pulls")
        assert [(p.number, p.state, p.draft) for p in prs] == [(7, "open", False), (5, "closed", False)]

    def test_returns_empty_list_on_api_failure(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_get", new_callable=AsyncMock, return_value=None):
            assert asyncio.run(service.get_pull_requests_for_commit("acme", "widget", "deadbeef")) == []

    def test_draft_defaults_false_when_github_omits_it(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        response = _json_response([{"number": 7, "state": "open"}])
        with patch.object(service, "_api_get", new_callable=AsyncMock, return_value=response):
            prs = asyncio.run(service.get_pull_requests_for_commit("acme", "widget", "deadbeef"))
        assert prs[0].draft is False


class TestMergeCommitFallback:
    """A `pull_request` workflow checks out an ephemeral test-merge commit that GitHub associates with no
    pull request — it answers 200 with [], never 404. Its parents[1] is the PR head and does resolve."""

    def test_empty_result_retries_the_merge_commits_second_parent(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        routes = {
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls": _json_response([]),
            f"/repos/acme/widget/commits/{_MERGE_SHA}": _json_response(_commit_payload(_BASE_SHA, _HEAD_SHA)),
            f"/repos/acme/widget/commits/{_HEAD_SHA}/pulls": _json_response([_PULL_REQUEST]),
        }
        with patch.object(service, "_api_get", _routed_api_get(routes)) as api_get:
            prs = asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA))

        assert [(p.number, p.state, p.draft) for p in prs] == [(42, "open", False)]
        assert _requested(api_get) == [
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls",
            f"/repos/acme/widget/commits/{_MERGE_SHA}",
            f"/repos/acme/widget/commits/{_HEAD_SHA}/pulls",
        ]

    @pytest.mark.parametrize(
        "parents",
        [
            pytest.param([_BASE_SHA], id="single-parent"),
            pytest.param([_BASE_SHA, _HEAD_SHA, _THIRD_SHA], id="octopus"),
        ],
    )
    def test_fallback_only_fires_for_an_exactly_two_parent_commit(self, parents):
        """On an ordinary commit parents[0] is just its ancestor; asking it would decorate a foreign pull request."""
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        routes = {
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls": _json_response([]),
            f"/repos/acme/widget/commits/{_MERGE_SHA}": _json_response(_commit_payload(*parents)),
        }
        for sha in parents:
            routes[f"/repos/acme/widget/commits/{sha}/pulls"] = _json_response([_PULL_REQUEST])

        with patch.object(service, "_api_get", _routed_api_get(routes)) as api_get:
            prs = asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA))

        assert prs == []
        assert _requested(api_get) == [
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls",
            f"/repos/acme/widget/commits/{_MERGE_SHA}",
        ]

    def test_logs_the_fallback_hit_at_info_naming_both_shas(self, caplog):
        """A decoration that came from the heuristic must be tellable from one the direct lookup found."""
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        routes = {
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls": _json_response([]),
            f"/repos/acme/widget/commits/{_MERGE_SHA}": _json_response(_commit_payload(_BASE_SHA, _HEAD_SHA)),
            f"/repos/acme/widget/commits/{_HEAD_SHA}/pulls": _json_response([_PULL_REQUEST]),
        }
        with patch.object(service, "_api_get", _routed_api_get(routes)):
            with caplog.at_level("INFO", logger="app.services.github"):
                prs = asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA))

        assert [p.number for p in prs] == [42]
        messages = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
        assert len(messages) == 1, messages
        assert _MERGE_SHA in messages[0]
        assert _HEAD_SHA in messages[0]

    def test_logs_the_two_step_miss_at_info_naming_both_shas(self, caplog):
        """Decorating nothing must never be silent: both the stored SHA and the head parent belong in the log."""
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        routes = {
            f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls": _json_response([]),
            f"/repos/acme/widget/commits/{_MERGE_SHA}": _json_response(_commit_payload(_BASE_SHA, _HEAD_SHA)),
            f"/repos/acme/widget/commits/{_HEAD_SHA}/pulls": _json_response([]),
        }
        with patch.object(service, "_api_get", _routed_api_get(routes)):
            with caplog.at_level("INFO", logger="app.services.github"):
                assert asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA)) == []

        messages = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
        assert len(messages) == 1, messages
        assert _MERGE_SHA in messages[0]
        assert _HEAD_SHA in messages[0]


class TestRejectedLookupsAreLoud:
    """A rejected lookup must not read like "this commit has no pull request": _api_get logs transport
    exceptions only, so an unlogged 403 or 429 would end at the INFO miss line and mislead the operator."""

    def test_a_rejected_direct_lookup_warns_with_endpoint_and_status(self, caplog):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        endpoint = f"/repos/acme/widget/commits/{_MERGE_SHA}/pulls"
        routes = {endpoint: _json_response(_error_body("Resource not accessible by integration"), 403)}

        with patch.object(service, "_api_get", _routed_api_get(routes)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA)) == []

        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1, warnings
        assert endpoint in warnings[0]
        assert "403" in warnings[0]

    def test_a_rejected_commit_lookup_warns_with_endpoint_and_status(self, caplog):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        endpoint = f"/repos/acme/widget/commits/{_MERGE_SHA}"
        routes = {
            f"{endpoint}/pulls": _json_response([]),
            endpoint: _json_response(_error_body("API rate limit exceeded for installation ID 1234."), 429),
        }

        with patch.object(service, "_api_get", _routed_api_get(routes)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert asyncio.run(service.get_pull_requests_for_commit("acme", "widget", _MERGE_SHA)) == []

        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1, warnings
        assert endpoint in warnings[0]
        assert "429" in warnings[0]


class TestGetPullRequestComments:
    def test_lists_issue_comments_uncapped(self):
        """Spec §6: the scan comment can sit past page 10 on a long-lived PR."""
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_get_paginated", new_callable=AsyncMock, return_value=[]) as paginated:
            asyncio.run(service.get_pull_request_comments("acme", "widget", 7))

        paginated.assert_awaited_once_with("/repos/acme/widget/issues/7/comments", max_pages=None)

    def test_parses_comments_and_tolerates_a_missing_body(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        raw = [
            {"id": 11, "body": "<!-- dependency-control:scan-comment -->\nold", "user": {"login": "bot"}},
            {"id": 12, "user": {"login": "someone"}},
        ]
        with patch.object(service, "_api_get_paginated", new_callable=AsyncMock, return_value=raw):
            comments = asyncio.run(service.get_pull_request_comments("acme", "widget", 7))

        assert [c.id for c in comments] == [11, 12]
        assert comments[1].body is None

    def test_returns_empty_list_on_api_failure(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_get_paginated", new_callable=AsyncMock, return_value=None):
            assert asyncio.run(service.get_pull_request_comments("acme", "widget", 7)) == []


class TestWritePullRequestComments:
    def test_post_returns_true_only_on_201(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_post", new_callable=AsyncMock, return_value=MagicMock(status_code=201)) as p:
            assert asyncio.run(service.post_pull_request_comment("acme", "widget", 7, "body")) is True
        p.assert_awaited_once_with("/repos/acme/widget/issues/7/comments", json_data={"body": "body"})

    def test_post_returns_false_on_403(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        failed = MagicMock(status_code=403)
        failed.text = "Resource not accessible by integration"
        with patch.object(service, "_api_post", new_callable=AsyncMock, return_value=failed):
            assert asyncio.run(service.post_pull_request_comment("acme", "widget", 7, "body")) is False

    def test_update_patches_the_comment_scoped_endpoint(self):
        """The update path carries the comment id, not the PR number."""
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_patch", new_callable=AsyncMock, return_value=MagicMock(status_code=200)) as p:
            assert asyncio.run(service.update_pull_request_comment("acme", "widget", 99, "new")) is True
        p.assert_awaited_once_with("/repos/acme/widget/issues/comments/99", json_data={"body": "new"})

    def test_update_returns_false_when_the_client_returned_nothing(self):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        with patch.object(service, "_api_patch", new_callable=AsyncMock, return_value=None):
            assert asyncio.run(service.update_pull_request_comment("acme", "widget", 99, "new")) is False

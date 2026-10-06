"""GitHub pull-request decoration: guards, filtering and comment upsert."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.github_api import GitHubIssueComment, GitHubPullRequest
from app.models.project import Project, Scan
from app.models.stats import Stats
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_MARKER = "<!-- dependency-control:scan-comment -->"
# The user GET /user resolves the instance token to.
_BOT = 4242

_USABLE_INSTANCE_DOC = {
    "_id": "gh-1",
    "name": "GitHub.com",
    "url": "https://token.actions.githubusercontent.com",
    "github_url": "https://github.com",
    "oidc_audience": "dependency-control",
    "access_token": "ghp-token",
    "is_active": True,
    "created_by": "admin",
}


def _make_scan(**kwargs):
    defaults = {"project_id": "test-proj", "branch": "main"}
    defaults.update(kwargs)
    return Scan(**defaults)


def _pr(number, state="open", draft=False, head="abc"):
    """One item of GET /repos/{owner}/{repo}/commits/{sha}/pulls."""
    return GitHubPullRequest.model_validate(
        {
            "number": number,
            "state": state,
            "draft": draft,
            "user": {"login": "octocat", "id": 1},
            "head": {"ref": "feature", "sha": head},
            "base": {"ref": "main", "sha": "base"},
            "merge_commit_sha": f"m-{head}",
        }
    )


def _comment(comment_id, body, author=_BOT):
    """One item of GET /repos/{owner}/{repo}/issues/{number}/comments."""
    return GitHubIssueComment.model_validate(
        {"id": comment_id, "body": body, "user": {"login": f"user{author}", "id": author}}
    )


def _enabled_project(**overrides):
    defaults = {
        "name": "Test",
        "owner_id": "u1",
        "github_instance_id": "gh-1",
        "github_repository_id": "42",
        "github_repository_path": "acme/widget",
        "github_pr_comments_enabled": True,
    }
    defaults.update(overrides)
    return Project(**defaults)


class TestPrDecorationEarlyReturns:
    """Each guard has to stop before GitHubService is constructed; the body sits inside a blanket
    except Exception, so a test without that assertion passes whatever the guard does.

    Asserting on logger.exception too is what makes the missing-instance guard testable: without it
    the next line raises AttributeError on None and the blanket except swallows it, so the guard's
    removal is invisible."""

    @classmethod
    def _run_and_assert_no_service(cls, project, scan_doc, instance_doc=_USABLE_INSTANCE_DOC):
        from app.services.analysis.integrations import decorate_github_pr

        db = create_mock_db({"github_instances": create_mock_collection(find_one=instance_doc)})
        with patch("app.services.analysis.integrations.GitHubService") as MockService:
            with patch("app.services.analysis.integrations.logger") as mock_logger:
                asyncio.run(decorate_github_pr("s1", Stats(), SCAN_STATUS_COMPLETED, None, scan_doc, project, db))

        MockService.assert_not_called()
        mock_logger.exception.assert_not_called()

    def test_skips_when_pr_comments_disabled(self):
        self._run_and_assert_no_service(
            _enabled_project(github_pr_comments_enabled=False), _make_scan(commit_hash="abc")
        )

    def test_skips_when_repository_path_missing(self):
        self._run_and_assert_no_service(_enabled_project(github_repository_path=None), _make_scan(commit_hash="abc"))

    def test_skips_when_repository_path_has_no_slash(self):
        self._run_and_assert_no_service(_enabled_project(github_repository_path="widget"), _make_scan(commit_hash="a"))

    def test_skips_when_instance_id_missing(self):
        self._run_and_assert_no_service(_enabled_project(github_instance_id=None), _make_scan(commit_hash="abc"))

    def test_skips_when_commit_hash_missing(self):
        self._run_and_assert_no_service(_enabled_project(), _make_scan())

    def test_skips_when_instance_not_found(self):
        self._run_and_assert_no_service(_enabled_project(), _make_scan(commit_hash="abc"), instance_doc=None)

    def test_an_unusable_instance_is_logged_as_a_warning(self, caplog):
        from app.services.analysis.integrations import decorate_github_pr

        db = create_mock_db({"github_instances": create_mock_collection(find_one=None)})
        project, scan_doc = _enabled_project(github_instance_id="gh-gone"), _make_scan(commit_hash="abc")
        with caplog.at_level(logging.INFO, logger="app.services.analysis.integrations"):
            asyncio.run(decorate_github_pr("s1", Stats(), SCAN_STATUS_COMPLETED, None, scan_doc, project, db))

        assert [(r.levelno, "gh-gone" in r.getMessage()) for r in caplog.records] == [(logging.WARNING, True)]

    def test_skips_when_instance_inactive(self):
        self._run_and_assert_no_service(
            _enabled_project(), _make_scan(commit_hash="abc"), instance_doc={**_USABLE_INSTANCE_DOC, "is_active": False}
        )

    def test_skips_when_instance_has_no_token(self):
        self._run_and_assert_no_service(
            _enabled_project(),
            _make_scan(commit_hash="abc"),
            instance_doc={**_USABLE_INSTANCE_DOC, "access_token": None},
        )


def _run_with_service(project, scan_doc, mock_svc, instance_doc=_USABLE_INSTANCE_DOC, stats=None):
    """Runs the decoration with GitHubService stubbed; returns the patched class mock."""
    from app.services.analysis.integrations import decorate_github_pr

    db = create_mock_db({"github_instances": create_mock_collection(find_one=instance_doc)})
    with patch("app.services.analysis.integrations.GitHubService", return_value=mock_svc) as MockService:
        asyncio.run(decorate_github_pr("s1", stats or Stats(), SCAN_STATUS_COMPLETED, None, scan_doc, project, db))
    return MockService


def _service(prs, comments=(), post=True, update=True, bot=_BOT):
    svc = MagicMock()
    svc.get_pull_requests_for_commit = AsyncMock(return_value=("abc", list(prs)))
    svc.get_current_user_id = AsyncMock(return_value=bot)
    svc.get_pull_request_comments = AsyncMock(return_value=list(comments))
    svc.post_pull_request_comment = AsyncMock(return_value=post)
    svc.update_pull_request_comment = AsyncMock(return_value=update)
    return svc


class TestPullRequestFiltering:
    def test_service_is_built_from_the_projects_github_instance(self):
        svc = _service([])
        instance_doc = {**_USABLE_INSTANCE_DOC, "_id": "gh-2", "name": "GHES", "url": "https://ghes.corp"}
        mock_service = _run_with_service(
            _enabled_project(github_instance_id="gh-2"), _make_scan(commit_hash="abc"), svc, instance_doc=instance_doc
        )

        created_instance = mock_service.call_args.args[0]
        assert (created_instance.id, created_instance.url) == ("gh-2", "https://ghes.corp")

    def test_only_open_non_draft_pull_requests_are_decorated(self):
        svc = _service(
            [
                _pr(7),
                _pr(8, draft=True),
                _pr(9, state="closed"),
            ]
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        assert [c.args[2] for c in svc.post_pull_request_comment.await_args_list] == [7]

    def test_repository_path_is_split_into_owner_and_repo(self):
        svc = _service([_pr(7)])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.get_pull_requests_for_commit.assert_awaited_once_with("acme", "widget", "abc", "main")

    def test_a_pull_request_whose_head_moved_past_the_scanned_commit_is_left_alone(self):
        svc = _service([_pr(7, head="abc"), _pr(8, head="def")])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        assert [c.args[2] for c in svc.post_pull_request_comment.await_args_list] == [7]

    def test_no_open_pull_request_posts_nothing(self):
        svc = _service([_pr(9, state="closed")])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_not_awaited()
        svc.update_pull_request_comment.assert_not_awaited()


_TEST_MERGE = "1f0e9c2a3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"
_RETESTED_MERGE = "5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c"
_BASE = "9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"
_HEAD = "3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"
_NEWER_HEAD = "7b6a5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"


def _json_response(payload, status_code=200):
    response = MagicMock(status_code=status_code)
    response.json.return_value = payload
    return response


class TestPullRequestWorkflowScans:
    """GITHUB_SHA is the test-merge commit; GitHub replaces merge_commit_sha whenever it re-tests mergeability."""

    @staticmethod
    def _decorate(pr_head, branch="42/merge", comments_page=()):
        """The endpoints decorating the scan read through _api_get, and the ones it posted to."""
        from app.services.analysis.integrations import decorate_github_pr
        from app.services.github import GitHubService

        routes = {
            f"/repos/acme/widget/commits/{_TEST_MERGE}/pulls": _json_response([]),
            f"/repos/acme/widget/commits/{_TEST_MERGE}": _json_response(
                {"sha": _TEST_MERGE, "parents": [{"sha": _BASE}, {"sha": _HEAD}]}
            ),
            f"/repos/acme/widget/commits/{_HEAD}/pulls": _json_response(
                [
                    {
                        "number": 42,
                        "state": "open",
                        "draft": False,
                        "head": {"ref": "feature", "sha": pr_head},
                        "base": {"ref": "main", "sha": _BASE},
                        "merge_commit_sha": _RETESTED_MERGE,
                    }
                ]
            ),
            "/user": _json_response({"login": "dc-bot", "id": _BOT}),
        }
        api_get = AsyncMock(side_effect=lambda endpoint, params=None: routes.get(endpoint))
        api_post = AsyncMock(return_value=_json_response({"id": 1}, 201))
        db = create_mock_db({"github_instances": create_mock_collection(find_one=_USABLE_INSTANCE_DOC)})
        with (
            patch.object(GitHubService, "_api_get", api_get),
            patch.object(
                GitHubService,
                "_api_get_paginated",
                AsyncMock(return_value=None if comments_page is None else list(comments_page)),
            ),
            patch.object(GitHubService, "_api_post", api_post),
        ):
            scan = _make_scan(commit_hash=_TEST_MERGE, branch=branch)
            asyncio.run(decorate_github_pr("s1", Stats(), SCAN_STATUS_COMPLETED, None, scan, _enabled_project(), db))
        return [call.args[0] for call in api_get.await_args_list], [call.args[0] for call in api_post.await_args_list]

    def test_the_current_head_is_decorated_after_github_retested_the_merge(self):
        _, posted = self._decorate(pr_head=_HEAD)
        assert posted == ["/repos/acme/widget/issues/42/comments"]

    def test_a_test_merge_of_a_superseded_head_is_left_alone(self):
        _, posted = self._decorate(pr_head=_NEWER_HEAD)
        assert posted == []

    def test_a_comment_listing_that_failed_posts_no_second_comment(self):
        _, posted = self._decorate(pr_head=_HEAD, comments_page=None)
        assert posted == []

    def test_a_merge_build_decorates_only_its_own_pull_request(self):
        """PRs opened from one branch share its head, and #7's test merge must not write #42's comment."""
        _, posted = self._decorate(pr_head=_HEAD, branch="7/merge")
        assert posted == []

    def test_a_pushed_merge_of_a_branch_leaves_that_branchs_pull_request_alone(self):
        """Merging feature into a branch without a PR and pushing gives a commit of the same shape,
        whose second parent heads the feature's PR; that PR is not this build's to look up or comment on."""
        requested, posted = self._decorate(pr_head=_HEAD, branch="integration")
        assert requested == [f"/repos/acme/widget/commits/{_TEST_MERGE}/pulls"]
        assert posted == []


class TestCommentUpsert:
    def test_posts_when_no_marked_comment_exists(self):
        svc = _service(
            [_pr(7)],
            comments=[_comment(1, "looks good"), _comment(2, None)],
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_awaited_once()
        svc.update_pull_request_comment.assert_not_awaited()
        assert _MARKER in svc.post_pull_request_comment.await_args.args[3]

    def test_updates_the_marked_comment_in_place(self):
        """A duplicate marked comment must not shift the target: the oldest match wins."""
        svc = _service(
            [_pr(7)],
            comments=[
                _comment(55, f"{_MARKER}\nstale"),
                _comment(56, "chatter"),
                _comment(57, f"{_MARKER}\nduplicate from a raced run"),
            ],
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_not_awaited()
        svc.update_pull_request_comment.assert_awaited_once()
        owner, repo, comment_id, body = svc.update_pull_request_comment.await_args.args
        assert (owner, repo, comment_id) == ("acme", "widget", 55)
        assert _MARKER in body

    def test_a_marker_comment_by_another_author_is_not_taken_over(self):
        svc = _service([_pr(7)], comments=[_comment(55, f"{_MARKER}\nLGTM", author=99)])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.update_pull_request_comment.assert_not_awaited()
        svc.post_pull_request_comment.assert_awaited_once()

    def test_nothing_is_decorated_when_the_token_user_cannot_be_resolved(self):
        svc = _service([_pr(7)], bot=None)
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.get_pull_request_comments.assert_not_awaited()
        svc.post_pull_request_comment.assert_not_awaited()

    def test_identical_body_is_left_alone(self):
        from app.services.analysis.integrations import _build_scan_comment

        stats = Stats()
        body = _build_scan_comment(stats, "http://localhost:3000/projects/p1/scans/s1", SCAN_STATUS_COMPLETED, None)
        svc = _service(
            [_pr(7)],
            comments=[_comment(55, body)],
        )
        project = _enabled_project(id="p1")
        with patch("app.core.config.settings.FRONTEND_BASE_URL", "http://localhost:3000"):
            _run_with_service(project, _make_scan(commit_hash="abc"), svc, stats=stats)

        svc.update_pull_request_comment.assert_not_awaited()
        svc.post_pull_request_comment.assert_not_awaited()

    def test_body_is_byte_identical_to_the_gitlab_comment(self):
        """Spec §10: the GitHub comment must match the GitLab one for the same scan."""
        from app.services.analysis.integrations import _build_scan_comment

        stats = Stats()
        expected = _build_scan_comment(stats, "http://localhost:3000/projects/p1/scans/s1", SCAN_STATUS_COMPLETED, None)
        svc = _service([_pr(7)])
        with patch("app.core.config.settings.FRONTEND_BASE_URL", "http://localhost:3000"):
            _run_with_service(_enabled_project(id="p1"), _make_scan(commit_hash="abc"), svc, stats=stats)

        assert svc.post_pull_request_comment.await_args.args[3] == expected


class TestFailureIsolation:
    def test_one_failing_pull_request_does_not_stop_the_next(self):
        svc = _service(
            [
                _pr(7),
                _pr(8),
            ]
        )
        svc.get_pull_request_comments = AsyncMock(side_effect=[RuntimeError("boom"), []])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        assert [c.args[2] for c in svc.post_pull_request_comment.await_args_list] == [8]

    def test_an_api_explosion_never_propagates(self):
        svc = _service([])
        svc.get_pull_requests_for_commit = AsyncMock(side_effect=RuntimeError("github down"))
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

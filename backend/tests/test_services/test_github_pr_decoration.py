"""GitHub pull-request decoration: guards, filtering and comment upsert."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.github_api import GitHubIssueComment, GitHubPullRequest
from app.models.project import Project, Scan
from app.models.stats import Stats
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_MARKER = "<!-- dependency-control:scan-comment -->"

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
                asyncio.run(decorate_github_pr(scan_id="s1", stats=Stats(), scan_doc=scan_doc, project=project, db=db))

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
        asyncio.run(
            decorate_github_pr(scan_id="s1", stats=stats or Stats(), scan_doc=scan_doc, project=project, db=db)
        )
    return MockService


def _service(prs, comments=(), post=True, update=True):
    svc = MagicMock()
    svc.get_pull_requests_for_commit = AsyncMock(return_value=list(prs))
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
                GitHubPullRequest(number=7, state="open", draft=False),
                GitHubPullRequest(number=8, state="open", draft=True),
                GitHubPullRequest(number=9, state="closed", draft=False),
            ]
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        assert [c.args[2] for c in svc.post_pull_request_comment.await_args_list] == [7]

    def test_repository_path_is_split_into_owner_and_repo(self):
        svc = _service([GitHubPullRequest(number=7, state="open", draft=False)])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.get_pull_requests_for_commit.assert_awaited_once_with("acme", "widget", "abc")

    def test_no_open_pull_request_posts_nothing(self):
        svc = _service([GitHubPullRequest(number=9, state="closed", draft=False)])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_not_awaited()
        svc.update_pull_request_comment.assert_not_awaited()


class TestCommentUpsert:
    def test_posts_when_no_marked_comment_exists(self):
        svc = _service(
            [GitHubPullRequest(number=7, state="open", draft=False)],
            comments=[GitHubIssueComment(id=1, body="looks good"), GitHubIssueComment(id=2, body=None)],
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_awaited_once()
        svc.update_pull_request_comment.assert_not_awaited()
        assert _MARKER in svc.post_pull_request_comment.await_args.args[3]

    def test_updates_the_marked_comment_in_place(self):
        """A duplicate marked comment must not shift the target: the oldest match wins."""
        svc = _service(
            [GitHubPullRequest(number=7, state="open", draft=False)],
            comments=[
                GitHubIssueComment(id=55, body=f"{_MARKER}\nstale"),
                GitHubIssueComment(id=56, body="chatter"),
                GitHubIssueComment(id=57, body=f"{_MARKER}\nduplicate from a raced run"),
            ],
        )
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        svc.post_pull_request_comment.assert_not_awaited()
        svc.update_pull_request_comment.assert_awaited_once()
        owner, repo, comment_id, body = svc.update_pull_request_comment.await_args.args
        assert (owner, repo, comment_id) == ("acme", "widget", 55)
        assert _MARKER in body

    def test_identical_body_is_left_alone(self):
        from app.services.analysis.integrations import _build_mr_comment

        stats = Stats()
        body = _build_mr_comment("s1", stats, "http://localhost:3000/projects/p1/scans/s1")
        svc = _service(
            [GitHubPullRequest(number=7, state="open", draft=False)],
            comments=[GitHubIssueComment(id=55, body=body)],
        )
        project = _enabled_project(id="p1")
        with patch("app.core.config.settings.FRONTEND_BASE_URL", "http://localhost:3000"):
            _run_with_service(project, _make_scan(commit_hash="abc"), svc, stats=stats)

        svc.update_pull_request_comment.assert_not_awaited()
        svc.post_pull_request_comment.assert_not_awaited()

    def test_body_is_byte_identical_to_the_gitlab_comment(self):
        """Spec §10: the GitHub comment must match the GitLab one for the same scan."""
        from app.services.analysis.integrations import _build_mr_comment

        stats = Stats()
        expected = _build_mr_comment("s1", stats, "http://localhost:3000/projects/p1/scans/s1")
        svc = _service([GitHubPullRequest(number=7, state="open", draft=False)])
        with patch("app.core.config.settings.FRONTEND_BASE_URL", "http://localhost:3000"):
            _run_with_service(_enabled_project(id="p1"), _make_scan(commit_hash="abc"), svc, stats=stats)

        assert svc.post_pull_request_comment.await_args.args[3] == expected


class TestFailureIsolation:
    def test_one_failing_pull_request_does_not_stop_the_next(self):
        svc = _service(
            [
                GitHubPullRequest(number=7, state="open", draft=False),
                GitHubPullRequest(number=8, state="open", draft=False),
            ]
        )
        svc.get_pull_request_comments = AsyncMock(side_effect=[RuntimeError("boom"), []])
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

        assert [c.args[2] for c in svc.post_pull_request_comment.await_args_list] == [8]

    def test_an_api_explosion_never_propagates(self):
        svc = _service([])
        svc.get_pull_requests_for_commit = AsyncMock(side_effect=RuntimeError("github down"))
        _run_with_service(_enabled_project(), _make_scan(commit_hash="abc"), svc)

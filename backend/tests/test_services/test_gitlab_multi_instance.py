"""Tests for GitLab multi-instance behavior."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.gitlab_api import GitLabMember
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.models.team import GitLabGroupBinding
from app.repositories.teams import MemberSubset
from app.services.gitlab import GitLabGroupLookup, GitLabService
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.gitlab import (
    make_gitlab_instance,
    make_merge_request,
    make_note,
    make_project_details,
    make_repositories,
)
from tests.mocks.mongodb import create_mock_collection, create_mock_db

# The subset instance A's sync replaces: its own, and nothing else.
_OWN = team_source(TEAM_SOURCE_GITLAB, "instance-a-id")

_USABLE_INSTANCE_DOC = {
    "_id": "inst-1",
    "name": "Test",
    "url": "https://gitlab.com",
    "access_token": "token-1",
    "is_active": True,
    "created_by": "admin",
}


def _make_scan(**kwargs):
    """Create a Scan with sensible defaults for testing."""
    defaults = {"project_id": "test-proj", "branch": "main"}
    defaults.update(kwargs)
    return Scan(**defaults)


class TestApiMethodTokenGuards:
    """API methods must check self.instance.access_token, not self.settings."""

    def test_api_get_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service._api_get("/projects/1"))
        assert result is None

    def test_api_post_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service._api_post("/projects/1/notes", {"body": "x"}))
        assert result is None

    def test_api_put_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service._api_put("/test", {"body": "x"}))
        assert result is None

    def test_api_get_paginated_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service._api_get_paginated("/test"))
        assert result is None

    def test_get_project_members_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service.get_project_members(123))
        assert result is None

    def test_get_group_members_returns_none_without_token(self):
        service = GitLabService(make_gitlab_instance(access_token=None))
        result = asyncio.run(service.get_group_members(456))
        assert result is None


class TestTeamMemberSyncResolveOnly:
    """Sync resolves members to EXISTING local users only; it never creates users."""

    def test_resolves_existing_user_by_email_no_create(self):
        service = GitLabService(make_gitlab_instance())
        existing = {"_id": "u-1", "email": "real@example.com", "username": "real"}
        user_repo = MagicMock()
        user_repo.get_raw_by_email_ci = AsyncMock(return_value=existing)
        user_repo.get_raw_by_username = AsyncMock(return_value=None)
        user_repo.create = AsyncMock()
        members = [GitLabMember(username="real", email="real@example.com", access_level=40)]
        result, _ = asyncio.run(service._build_team_members(members, user_repo))
        assert len(result) == 1
        assert result[0].user_id == "u-1"
        user_repo.create.assert_not_called()

    def test_resolves_existing_user_case_insensitive_email(self):
        # GitLab returns the email in different case than the address stored at login.
        service = GitLabService(make_gitlab_instance())
        existing = {"_id": "u-1", "email": "alice@corp.com", "username": "alice"}
        user_repo = MagicMock()
        user_repo.get_raw_by_email_ci = AsyncMock(return_value=existing)
        user_repo.get_raw_by_username = AsyncMock(return_value=None)
        user_repo.create = AsyncMock()
        members = [GitLabMember(username="alice", email="Alice@Corp.com", access_level=40)]
        result, _ = asyncio.run(service._build_team_members(members, user_repo))
        assert len(result) == 1
        assert result[0].user_id == "u-1"
        user_repo.get_raw_by_email_ci.assert_awaited_once_with("Alice@Corp.com")

    def test_skips_bot_member_without_local_account_no_create(self):
        # GitLab service-account / bot: no matching local user -> skipped, NOT created.
        service = GitLabService(make_gitlab_instance())
        user_repo = MagicMock()
        user_repo.get_raw_by_email = AsyncMock(return_value=None)
        user_repo.get_raw_by_username = AsyncMock(return_value=None)
        user_repo.create = AsyncMock()
        members = [GitLabMember(username="group_875_bot_f4597604b42b729d0de22d01e5126164", access_level=40)]
        result, unresolved = asyncio.run(service._build_team_members(members, user_repo))
        assert (result, unresolved) == ([], 1)
        user_repo.create.assert_not_called()


class TestMrDecorationEarlyReturns:
    """Each guard has to stop before GitLabService is constructed; the body sits inside a blanket
    except Exception, so a test without that assertion passes whatever the guard does."""

    @staticmethod
    def _db(instance_doc):
        """A usable instance behind every guard, so a dropped guard reaches GitLabService."""
        return create_mock_db({"gitlab_instances": create_mock_collection(find_one=instance_doc)})

    @classmethod
    def _run_and_assert_no_service(cls, project, scan_doc, instance_doc=_USABLE_INSTANCE_DOC):
        from app.services.analysis.integrations import decorate_gitlab_mr

        db = cls._db(instance_doc)
        with patch("app.services.analysis.integrations.GitLabService") as MockService:
            asyncio.run(decorate_gitlab_mr(scan_id="s1", stats=Stats(), scan_doc=scan_doc, project=project, db=db))

        MockService.assert_not_called()

    def test_skips_when_mr_comments_disabled(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=False,
        )
        self._run_and_assert_no_service(project, _make_scan(commit_hash="abc"))

    def test_skips_when_no_gitlab_ids(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_mr_comments_enabled=True,
            gitlab_instance_id=None,
            gitlab_project_id=None,
        )
        self._run_and_assert_no_service(project, _make_scan(commit_hash="abc"))

    def test_skips_when_no_commit_hash(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        self._run_and_assert_no_service(project, _make_scan())

    def test_skips_when_instance_not_found(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="nonexistent",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        self._run_and_assert_no_service(project, _make_scan(commit_hash="abc"), instance_doc=None)

    def test_skips_when_instance_inactive(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        self._run_and_assert_no_service(
            project, _make_scan(commit_hash="abc"), instance_doc={**_USABLE_INSTANCE_DOC, "is_active": False}
        )

    def test_skips_when_instance_has_no_access_token(self):
        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )

        self._run_and_assert_no_service(
            project, _make_scan(commit_hash="abc"), instance_doc={**_USABLE_INSTANCE_DOC, "access_token": None}
        )


class TestMrDecorationInstanceRouting:
    """MR decoration must use the correct GitLab instance for each project."""

    def test_creates_service_with_correct_instance(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-a",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        instance_doc = {
            "_id": "inst-a",
            "name": "GitLab A",
            "url": "https://gitlab-a.com",
            "access_token": "token-a",
            "is_active": True,
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": collection})

        with patch("app.services.analysis.integrations.GitLabService") as MockService:
            mock_svc = MagicMock()
            mock_svc.get_merge_requests_for_commit = AsyncMock(return_value=[])
            MockService.return_value = mock_svc

            asyncio.run(
                decorate_gitlab_mr(
                    scan_id="s1",
                    stats=Stats(),
                    scan_doc=_make_scan(commit_hash="abc123"),
                    project=project,
                    db=db,
                )
            )

            MockService.assert_called_once()
            created_instance = MockService.call_args[0][0]
            assert created_instance.url == "https://gitlab-a.com"
            assert created_instance.name == "GitLab A"

    def test_two_projects_use_different_instances(self):
        """Two projects linked to different instances should use different services."""
        from app.services.analysis.integrations import decorate_gitlab_mr

        projects = [
            Project(
                name="Proj A",
                owner_id="u1",
                gitlab_instance_id="inst-a",
                gitlab_project_id=100,
                gitlab_mr_comments_enabled=True,
            ),
            Project(
                name="Proj B",
                owner_id="u1",
                gitlab_instance_id="inst-b",
                gitlab_project_id=100,
                gitlab_mr_comments_enabled=True,
            ),
        ]
        instance_docs = {
            "inst-a": {
                "_id": "inst-a",
                "name": "GitLab A",
                "url": "https://gitlab-a.com",
                "access_token": "token-a",
                "is_active": True,
                "created_by": "admin",
            },
            "inst-b": {
                "_id": "inst-b",
                "name": "GitLab B",
                "url": "https://gitlab-b.com",
                "access_token": "token-b",
                "is_active": True,
                "created_by": "admin",
            },
        }

        urls_used = []

        for proj in projects:
            doc = instance_docs[proj.gitlab_instance_id]
            collection = create_mock_collection(find_one=doc)
            db = create_mock_db({"gitlab_instances": collection})

            with patch("app.services.analysis.integrations.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.get_merge_requests_for_commit = AsyncMock(return_value=[])
                MockService.return_value = mock_svc

                asyncio.run(
                    decorate_gitlab_mr(
                        scan_id="s1",
                        stats=Stats(),
                        scan_doc=_make_scan(commit_hash="abc"),
                        project=proj,
                        db=db,
                    )
                )

                created_instance = MockService.call_args[0][0]
                urls_used.append(created_instance.url)

        assert urls_used == ["https://gitlab-a.com", "https://gitlab-b.com"]

    def test_filters_to_open_non_draft_mrs(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-a",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        instance_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": collection})

        mrs = [
            make_merge_request(iid=1, state="opened", draft=False, work_in_progress=False),
            make_merge_request(iid=2, state="closed", draft=False, work_in_progress=False),
            make_merge_request(iid=3, state="opened", draft=True, work_in_progress=False),
            make_merge_request(iid=4, state="opened", draft=False, work_in_progress=True),
        ]

        with patch("app.services.analysis.integrations.GitLabService") as MockService:
            mock_svc = MagicMock()
            mock_svc.get_merge_requests_for_commit = AsyncMock(return_value=mrs)
            mock_svc.get_merge_request_notes = AsyncMock(return_value=[])
            mock_svc.post_merge_request_comment = AsyncMock(return_value=True)
            MockService.return_value = mock_svc

            asyncio.run(
                decorate_gitlab_mr(
                    scan_id="s1",
                    stats=Stats(),
                    scan_doc=_make_scan(commit_hash="abc"),
                    project=project,
                    db=db,
                )
            )

            # Only MR !1 should get a comment (open, non-draft, non-WIP)
            assert mock_svc.post_merge_request_comment.call_count == 1
            call_args = mock_svc.post_merge_request_comment.call_args[0]
            assert call_args[1] == 1  # mr_iid

    def test_updates_existing_comment_instead_of_creating(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-a",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        instance_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": collection})

        mrs = [make_merge_request(iid=10, state="opened")]
        existing_notes = [
            make_note(id=999, body="<!-- dependency-control:scan-comment -->\nOld content"),
        ]

        with patch("app.services.analysis.integrations.GitLabService") as MockService:
            mock_svc = MagicMock()
            mock_svc.get_merge_requests_for_commit = AsyncMock(return_value=mrs)
            mock_svc.get_merge_request_notes = AsyncMock(return_value=existing_notes)
            mock_svc.update_merge_request_comment = AsyncMock(return_value=True)
            mock_svc.post_merge_request_comment = AsyncMock(return_value=True)
            MockService.return_value = mock_svc

            asyncio.run(
                decorate_gitlab_mr(
                    scan_id="s1",
                    stats=Stats(),
                    scan_doc=_make_scan(commit_hash="abc"),
                    project=project,
                    db=db,
                )
            )

            mock_svc.update_merge_request_comment.assert_called_once()
            mock_svc.post_merge_request_comment.assert_not_called()
            update_args = mock_svc.update_merge_request_comment.call_args[0]
            assert update_args[2] == 999  # note_id

    def test_skips_update_when_comment_unchanged(self):
        """If existing comment body matches new content, skip the update."""
        from app.services.analysis.integrations import (
            _build_mr_comment,
            decorate_gitlab_mr,
        )

        project = Project(
            id="fixed-proj-id",
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-a",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        instance_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": collection})

        stats = Stats()
        scan_url = "http://localhost:3000/projects/fixed-proj-id/scans/s1"
        expected_body = _build_mr_comment("s1", stats, scan_url)

        mrs = [make_merge_request(iid=10, state="opened")]
        existing_notes = [make_note(id=888, body=expected_body)]

        with patch("app.services.analysis.integrations.GitLabService") as MockService:
            mock_svc = MagicMock()
            mock_svc.get_merge_requests_for_commit = AsyncMock(return_value=mrs)
            mock_svc.get_merge_request_notes = AsyncMock(return_value=existing_notes)
            mock_svc.update_merge_request_comment = AsyncMock(return_value=True)
            mock_svc.post_merge_request_comment = AsyncMock(return_value=True)
            MockService.return_value = mock_svc

            asyncio.run(
                decorate_gitlab_mr(
                    scan_id="s1",
                    stats=stats,
                    scan_doc=_make_scan(commit_hash="abc"),
                    project=project,
                    db=db,
                )
            )

            # Neither update nor create should be called
            mock_svc.update_merge_request_comment.assert_not_called()
            mock_svc.post_merge_request_comment.assert_not_called()


class TestTeamSyncNamespaceCheck:
    """Team sync should only run for group-namespace projects."""

    def test_reports_no_owner_for_a_user_namespace(self, gitlab_instance_a):
        """Determined, not unknown: GitLab says a person owns this project, so the group owner it
        carried from before the move is retired."""
        service = GitLabService(gitlab_instance_a)

        result = asyncio.run(
            service.sync_team_from_gitlab(
                db=MagicMock(),
                gitlab_project_id=100,
                gitlab_project_path="john/proj",
                gitlab_project_data=make_project_details(
                    namespace_kind="user",
                    namespace_id=1,
                    namespace_path="john",
                ),
            )
        )
        assert result.team_ids == []

    def test_returns_none_when_no_project_data(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        result = asyncio.run(
            service.sync_team_from_gitlab(
                db=MagicMock(),
                gitlab_project_id=100,
                gitlab_project_path="group/proj",
                gitlab_project_data=None,
            )
        )
        assert result.team_ids is None


class TestTeamSyncGroupMembers:
    """Team sync should fetch and map group members correctly."""

    def test_fetches_group_members_by_group_id(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = None

            teams_coll = create_mock_collection(find_one=None)
            db = create_mock_db({"teams": teams_coll, "users": create_mock_collection()})

            asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="my-group/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=42,
                        namespace_path="my-group",
                    ),
                )
            )

            mock_members.assert_called_once_with(42)

    def test_maps_access_level_to_roles(self, gitlab_instance_a):
        """access_level >= 40 (Maintainer) should map to 'admin', otherwise 'member'."""
        service = GitLabService(gitlab_instance_a)

        members = [
            GitLabMember(username="dev", email="dev@test.com", access_level=30),
            GitLabMember(username="maintainer", email="maint@test.com", access_level=40),
            GitLabMember(username="owner", email="owner@test.com", access_level=50),
        ]

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = members

            # Users found by email - use _id as key (raw MongoDB format)
            user_doc = {"_id": "user-id", "username": "test"}
            users_coll = create_mock_collection(find_one=user_doc)
            teams_coll = create_mock_collection(find_one=None)
            teams_coll.insert_one = AsyncMock()
            db = create_mock_db({"teams": teams_coll, "users": users_coll})

            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="grp/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=42,
                        namespace_path="grp",
                    ),
                )
            )

            # A team should have been created
            assert result is not None

    def test_team_name_includes_group_path(self, gitlab_instance_a):
        """Team created from sync should use team_sync_depth to truncate path."""
        service = GitLabService(gitlab_instance_a)

        members = [
            GitLabMember(username="dev", email="dev@test.com", access_level=30),
        ]

        with (
            patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members,
            patch.object(service, "_resolve_group_by_path", new_callable=AsyncMock) as mock_resolve,
        ):
            mock_members.return_value = members
            mock_resolve.return_value = GitLabGroupLookup(reachable=True, group={"id": 10})

            user_doc = {"_id": "uid", "username": "dev"}
            users_coll = create_mock_collection(find_one=user_doc)
            teams_coll = create_mock_collection(find_one=None)
            teams_coll.insert_one = AsyncMock()
            db = create_mock_db({"teams": teams_coll, "users": users_coll})

            asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="org/subgroup/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=42,
                        namespace_path="org/subgroup",
                    ),
                )
            )

            # With team_sync_depth=1 (default), team name should be truncated to top-level
            teams_coll.insert_one.assert_called_once()
            team_data = teams_coll.insert_one.call_args[0][0]
            assert team_data["name"] == "GitLab Group: org"

    def test_updates_existing_team_members(self, gitlab_instance_a):
        """If team already exists, should update members instead of creating."""
        service = GitLabService(gitlab_instance_a)

        members = [
            GitLabMember(username="dev", email="dev@test.com", access_level=30),
        ]

        existing_team = {"_id": "existing-team-id", "name": "GitLab Group: grp"}

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = members

            user_doc = {"_id": "uid", "username": "dev"}
            users_coll = create_mock_collection(find_one=user_doc)
            teams_coll = create_mock_collection(find_one=existing_team)
            db = create_mock_db({"teams": teams_coll, "users": users_coll})

            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="grp/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=42,
                        namespace_path="grp",
                    ),
                )
            )

            # Should return existing team ID
            assert result.team_ids == ["existing-team-id"]
            # Should have called update_one to set members
            teams_coll.update_one.assert_called_once()


class TestTeamSyncSilentReturnsAreLogged:
    """Every silent return-None path in sync_team_from_gitlab must emit a log so operators can detect projects created without a team_id."""

    def test_logs_when_project_data_is_none(self, gitlab_instance_a, caplog):
        service = GitLabService(gitlab_instance_a)

        with caplog.at_level("WARNING", logger="app.services.gitlab"):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=999,
                    gitlab_project_path="grp/proj",
                    gitlab_project_data=None,
                )
            )

        assert result.team_ids is None
        assert any("999" in r.message and "project details" in r.message.lower() for r in caplog.records), (
            f"Expected warning naming project_id 999 and 'project details'. Got: {[r.message for r in caplog.records]}"
        )

    def test_logs_when_namespace_is_user(self, gitlab_instance_a, caplog):
        service = GitLabService(gitlab_instance_a)

        with caplog.at_level("INFO", logger="app.services.gitlab"):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=777,
                    gitlab_project_path="alice/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="user",
                        namespace_id=1,
                        namespace_path="alice",
                    ),
                )
            )

        assert result.team_ids == []
        assert any("777" in r.message and "user namespace" in r.message.lower() for r in caplog.records), (
            f"Expected info naming project_id 777 and 'user namespace'. Got: {[r.message for r in caplog.records]}"
        )

    def test_logs_when_group_members_empty_and_no_existing_team(self, gitlab_instance_a, caplog):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = None
            teams_coll = create_mock_collection(find_one=None)
            db = create_mock_db({"teams": teams_coll, "users": create_mock_collection()})

            with caplog.at_level("WARNING", logger="app.services.gitlab"):
                result = asyncio.run(
                    service.sync_team_from_gitlab(
                        db=db,
                        gitlab_project_id=555,
                        gitlab_project_path="my-group/proj",
                        gitlab_project_data=make_project_details(
                            namespace_kind="group",
                            namespace_id=42,
                            namespace_path="my-group",
                        ),
                    )
                )

        assert result.team_ids is None
        assert any("555" in r.message for r in caplog.records), (
            f"Expected the warning to mention project_id 555 so operators can locate the orphaned project. "
            f"Got: {[r.message for r in caplog.records]}"
        )

    def test_logs_when_exception_is_caught(self, gitlab_instance_a, caplog):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.side_effect = RuntimeError("kaboom")
            db = create_mock_db({"teams": create_mock_collection(), "users": create_mock_collection()})

            with caplog.at_level("ERROR", logger="app.services.gitlab"):
                result = asyncio.run(
                    service.sync_team_from_gitlab(
                        db=db,
                        gitlab_project_id=222,
                        gitlab_project_path="grp/proj",
                        gitlab_project_data=make_project_details(
                            namespace_kind="group",
                            namespace_id=10,
                            namespace_path="grp",
                        ),
                    )
                )

        assert result.team_ids is None
        # error log must include the project id so operators can find the orphan
        assert any("222" in r.message for r in caplog.records), (
            f"Expected error log to include project_id 222. Got: {[r.message for r in caplog.records]}"
        )


class TestTeamSyncResolveGroupFallback:
    """A parent path that will not resolve leaves the owner undetermined rather than binding a team
    of different granularity than every other run of the instance."""

    def _sync(self, gitlab_instance_a, lookup):
        service = GitLabService(gitlab_instance_a)
        members = [GitLabMember(username="dev", email="dev@test.com", access_level=30)]

        with (
            make_repositories(user_doc={"_id": "uid", "username": "dev"}) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=members)),
            patch.object(service, "_resolve_group_by_path", new=AsyncMock(return_value=lookup)),
        ):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path="org/subgroup/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=42,  # deep "org/subgroup" id
                        namespace_path="org/subgroup",
                    ),
                )
            )
        return result, team_repo

    def test_a_truncated_path_the_instance_does_not_carry_creates_nothing(self, gitlab_instance_a):
        result, team_repo = self._sync(gitlab_instance_a, GitLabGroupLookup(reachable=True, group=None))

        assert result.team_ids is None
        team_repo.create.assert_not_called()

    def test_a_truncated_path_that_went_unanswered_creates_nothing(self, gitlab_instance_a):
        result, team_repo = self._sync(gitlab_instance_a, GitLabGroupLookup(reachable=False, group=None))

        assert result.team_ids is None
        team_repo.create.assert_not_called()

    def test_a_resolved_parent_binds_the_truncated_group(self, gitlab_instance_a):
        result, team_repo = self._sync(gitlab_instance_a, GitLabGroupLookup(reachable=True, group={"id": 10}))

        assert result.team_ids is not None
        created = team_repo.create.await_args.args[0]
        assert created.name == "GitLab Group: org"
        assert created.bindings[0].external_id == 10


class TestTeamSyncInstanceScoping:
    """GitLab team matching must be scoped to the (instance, group) composite key; two instances owning a group with the SAME path must NOT collide."""

    @staticmethod
    def _db():
        db = FakeDatabase()
        asyncio.run(db.users.insert_one({"_id": "uid", "username": "dev", "email": "dev@test.com"}))
        return db

    @staticmethod
    def _teams(db):
        return asyncio.run(db.teams.find({}).to_list(None))

    def _sync(self, instance, db, group_id, group_path):
        """The one team the group resolves to, or None."""
        service = GitLabService(instance)
        members = [GitLabMember(username="dev", email="dev@test.com", access_level=30)]
        with patch.object(service, "get_group_members", new=AsyncMock(return_value=members)):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path=f"{group_path}/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group",
                        namespace_id=group_id,
                        namespace_path=group_path,
                    ),
                )
            )
        return result.team_ids[0] if result.team_ids else None

    def test_same_group_path_across_instances_does_not_collide(self):
        """Instance A and B both own a group at path 'shared-grp' (same group id, different instances); syncing B must create a NEW team, not adopt/mutate A's."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        instance_b = make_gitlab_instance(id="inst-b", name="B", url="https://b.com")
        db = self._db()

        team_a_id = self._sync(instance_a, db, group_id=7, group_path="shared-grp")
        team_b_id = self._sync(instance_b, db, group_id=7, group_path="shared-grp")

        assert team_a_id is not None
        assert team_b_id is not None
        # The two instances must own DISTINCT teams.
        assert team_a_id != team_b_id, (
            "Instance B adopted instance A's team via the unscoped name fallback — "
            "this is the cross-tenant collision (Finding 8)."
        )
        # Two separate team documents must exist, each tagged to its own instance.
        teams = self._teams(db)
        assert len(teams) == 2
        assert {d["bindings"][0]["instance_id"] for d in teams} == {"inst-a", "inst-b"}

    def test_instance_a_members_not_mutated_by_instance_b_sync(self):
        """Instance A's team and its member list must be untouched after B syncs."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        instance_b = make_gitlab_instance(id="inst-b", name="B", url="https://b.com")
        db = self._db()

        team_a_id = self._sync(instance_a, db, group_id=7, group_path="shared-grp")
        team_a_before = next(d for d in self._teams(db) if d["_id"] == team_a_id)
        members_before = [dict(m) for m in team_a_before["members"]]

        self._sync(instance_b, db, group_id=7, group_path="shared-grp")

        team_a_after = next(d for d in self._teams(db) if d["_id"] == team_a_id)
        assert [binding["key"] for binding in team_a_after["bindings"]] == ["gitlab:inst-a:7"]
        assert team_a_after["members"] == members_before

    def test_repeated_sync_same_instance_group_reuses_team(self):
        """Re-syncing the SAME (instance, group) must re-use the same team, not create a duplicate."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        db = self._db()

        first_id = self._sync(instance_a, db, group_id=7, group_path="shared-grp")
        second_id = self._sync(instance_a, db, group_id=7, group_path="shared-grp")

        assert first_id == second_id
        assert len(self._teams(db)) == 1


class TestMemberResolution:
    """A member is looked for under both keys GitLab offers: the email it reports, and the handle."""

    @staticmethod
    def _resolved(gitlab_instance_a, member, **user_lookups):
        service = GitLabService(gitlab_instance_a)

        with (
            make_repositories(**user_lookups) as (team_repo, user_repo),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=[member])),
        ):
            asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path="grp/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path="grp"
                    ),
                )
            )
        return team_repo, user_repo

    def test_a_member_whose_email_matches_nobody_is_still_found_by_their_handle(self, gitlab_instance_a):
        """GitLab reports the address on the account, which need not be the one the local user was
        created with; dropping the member costs them every project the team owns."""
        member = GitLabMember(username="ada", email="ada@personal.example", access_level=30)

        team_repo, user_repo = self._resolved(gitlab_instance_a, member, by_username={"_id": "u-ada"})

        user_repo.get_raw_by_username.assert_awaited_once_with("ada")
        created = team_repo.create.await_args.args[0]
        assert [m.user_id for m in created.members] == ["u-ada"]

    def test_a_member_the_email_names_is_not_looked_up_twice(self, gitlab_instance_a):
        """The email comes with the listing, so it costs no request and is tried first."""
        member = GitLabMember(username="ada", email="ada@corp.com", access_level=30)

        team_repo, user_repo = self._resolved(gitlab_instance_a, member, by_email={"_id": "u-ada"})

        user_repo.get_raw_by_username.assert_not_awaited()
        assert [m.user_id for m in team_repo.create.await_args.args[0].members] == ["u-ada"]

    def test_a_member_neither_key_names_is_skipped(self, gitlab_instance_a):
        member = GitLabMember(username="ghost", email="ghost@corp.com", access_level=30)

        team_repo, _ = self._resolved(gitlab_instance_a, member)

        team_repo.create.assert_not_called()


class TestTeamSyncMergeSemantics:
    """A sync hands the server the subset it resolved, and the server replaces exactly that subset:
    a hand-added member and every other instance's survive, this instance's stale ones do not."""

    @staticmethod
    def _sync(service, existing_team, members, user_doc, *, namespace_path="grp"):
        with (
            make_repositories(existing_team=existing_team, user_doc=user_doc) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=members)),
        ):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path=f"{namespace_path}/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path=namespace_path
                    ),
                )
            )
        return result, team_repo

    @staticmethod
    def _team(doc_id, members, *, path=None, name="GitLab Group: grp"):
        binding = GitLabGroupBinding(instance_id="instance-a-id", external_id=42, path=path)
        return {"_id": doc_id, "name": name, "bindings": [binding.model_dump()], "members": members}

    def test_the_write_claims_only_the_subset_this_instance_resolved(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        existing_team = self._team(
            "team-1",
            [
                {"user_id": "manual-user", "role": "admin", "source": "manual"},
                {"user_id": "stale-gitlab-user", "role": "member", "source": _OWN},
            ],
            path="grp",
        )
        members = [GitLabMember(username="newdev", email="newdev@test.com", access_level=30)]

        result, team_repo = self._sync(service, existing_team, members, {"_id": "new-gitlab-user"})

        assert result.team_ids == ["team-1"]
        assert team_repo.update_with_binding.await_args.args[4] == MemberSubset(
            _OWN, [{"user_id": "new-gitlab-user", "role": "member", "source": _OWN}]
        )

    def test_the_write_carries_no_member_of_another_provenance(self, gitlab_instance_a):
        """A team bound to several instances holds several subsets; a sync owns exactly one of them,
        and the write never mentions the rest."""
        service = GitLabService(gitlab_instance_a)
        foreign = [
            {"user_id": "manual-user", "role": "admin", "source": "manual"},
            {"user_id": "gh-user", "role": "member", "source": team_source(TEAM_SOURCE_GITHUB, "gh-1")},
            {"user_id": "gl-b-user", "role": "member", "source": team_source(TEAM_SOURCE_GITLAB, "instance-b-id")},
            {"user_id": "unmigrated-user", "role": "member", "source": TEAM_SOURCE_GITLAB},
        ]
        members = [GitLabMember(username="newdev", email="newdev@test.com", access_level=30)]

        _, team_repo = self._sync(
            service, self._team("team-3", list(foreign), path="grp"), members, {"_id": "new-gitlab-user"}
        )

        subset = team_repo.update_with_binding.await_args.args[4]
        assert subset == MemberSubset(_OWN, [{"user_id": "new-gitlab-user", "role": "member", "source": _OWN}])

    def test_a_user_the_group_also_holds_is_resolved_once_with_the_gitlab_role(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        existing_team = self._team("team-2", [{"user_id": "dual-user", "role": "member", "source": "manual"}], path="grp")
        # GitLab reports the same user as a Maintainer (admin).
        members = [GitLabMember(username="dual", email="dual@test.com", access_level=40)]

        _, team_repo = self._sync(service, existing_team, members, {"_id": "dual-user"})

        assert team_repo.update_with_binding.await_args.args[4] == MemberSubset(
            _OWN, [{"user_id": "dual-user", "role": "admin", "source": _OWN}]
        )

    def test_two_gitlab_members_resolving_to_one_user_keep_the_admin_entry(self, gitlab_instance_a):
        """A duplicate entry breaks add_member's $ne guard, and a last-wins merge demotes the admin."""
        service = GitLabService(gitlab_instance_a)
        members = [
            GitLabMember(username="ada", email="ada@test.com", access_level=50),
            GitLabMember(username="ada-bot", email="ada.bot@test.com", access_level=10),
        ]

        _, team_repo = self._sync(service, self._team("team-4", [], path="grp"), members, {"_id": "u-ada"})

        assert team_repo.update_with_binding.await_args.args[4] == MemberSubset(
            _OWN, [{"user_id": "u-ada", "role": "admin", "source": _OWN}]
        )

    def test_a_moved_group_restamps_the_path_on_the_binding_it_resolved_through(self, gitlab_instance_a):
        """The path is display-only, so nothing else notices it going stale: a group that moved
        would go on naming the namespace it left, on the binding and in the picker, until somebody
        rebound it by hand."""
        service = GitLabService(gitlab_instance_a)
        existing_team = self._team("team-moved", [], path="old/grp", name="GitLab Group: old/grp")
        members = [GitLabMember(username="dev", email="dev@test.com", access_level=30)]

        _, team_repo = self._sync(service, existing_team, members, {"_id": "u-dev"}, namespace_path="new")

        # Addressed by key, so a team bound to several instances restamps only the one that answered.
        assert team_repo.update_with_binding.await_args.args[2] == "gitlab:instance-a-id:42"
        assert team_repo.update_with_binding.await_args.args[3] == {"path": "new"}


class TestTeamSyncEmaillessMembers:
    """Sync resolves members to EXISTING local users only and never creates users (which would pull in GitLab service accounts / bots)."""

    def test_emailless_member_without_local_account_is_skipped(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        # GitLab member with NO email and a username, and no existing local user.
        members = [GitLabMember(username="ghost", email=None, access_level=30)]

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = members
            users_coll = create_mock_collection(find_one=None)  # no local user matches
            users_coll.insert_one = AsyncMock()
            teams_coll = create_mock_collection(find_one=None)
            teams_coll.insert_one = AsyncMock()
            db = create_mock_db({"teams": teams_coll, "users": users_coll})

            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="grp/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path="grp"
                    ),
                )
            )

        # Sync NEVER creates users (which would pull GitLab service accounts / bots in).
        users_coll.insert_one.assert_not_called()
        # The only member was skipped -> empty member set -> no new team created.
        teams_coll.insert_one.assert_not_called()
        assert result.team_ids == []

    def test_member_without_email_or_username_is_skipped(self, gitlab_instance_a, caplog):
        service = GitLabService(gitlab_instance_a)

        # Pathological member: neither email nor username.
        members = [GitLabMember(username=None, email=None, access_level=30)]

        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = members
            users_coll = create_mock_collection(find_one=None)
            users_coll.insert_one = AsyncMock()
            teams_coll = create_mock_collection(find_one=None)
            teams_coll.insert_one = AsyncMock()
            db = create_mock_db({"teams": teams_coll, "users": users_coll})

            with caplog.at_level("DEBUG", logger="app.services.gitlab"):
                asyncio.run(
                    service.sync_team_from_gitlab(
                        db=db,
                        gitlab_project_id=100,
                        gitlab_project_path="grp/proj",
                        gitlab_project_data=make_project_details(
                            namespace_kind="group", namespace_id=42, namespace_path="grp"
                        ),
                    )
                )

        # No user is created, and the skip is logged (not silent).
        users_coll.insert_one.assert_not_called()
        assert any("member" in r.message.lower() for r in caplog.records), (
            f"Expected a skip log. Got: {[r.message for r in caplog.records]}"
        )


class TestApiGetPaginatedCap:
    """Membership fetches must not be silently truncated at the default cap: fetch all pages, or at minimum WARN when a cap is hit."""

    def test_get_group_members_fetches_beyond_default_1000(self, gitlab_instance_a):
        """A group with 12 pages (1200 members) must have all members fetched, not truncated at 1000."""
        service = GitLabService(gitlab_instance_a)

        total_pages = 12
        per_page = 100

        def _make_response(page: int):
            resp = MagicMock()
            resp.status_code = 200
            # Each page returns a full page of distinct members.
            resp.json.return_value = [
                {"username": f"u{(page - 1) * per_page + i}", "email": f"u{i}p{page}@t.com", "access_level": 30}
                for i in range(per_page)
            ]
            resp.headers = {"x-total-pages": str(total_pages)}
            return resp

        call_pages: list[int] = []

        async def fake_get(url, headers=None, params=None):
            page = params["page"]
            call_pages.append(page)
            return _make_response(page)

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=fake_get)

        class _CM:
            async def __aenter__(self):
                return mock_client

            async def __aexit__(self, *a):
                return False

        with patch.object(service, "_api_client", return_value=_CM()):
            result = asyncio.run(service.get_group_members(42))

        assert result is not None
        # All 1200 members fetched, NOT truncated at 1000.
        assert len(result) == total_pages * per_page
        assert max(call_pages) == total_pages

    def test_paginated_logs_warning_when_cap_reached(self, gitlab_instance_a, caplog):
        """If a hard cap is ever hit while more pages remain, a WARNING must fire."""
        service = GitLabService(gitlab_instance_a)

        def _make_response(page: int):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = [{"id": i, "username": f"u{page}_{i}"} for i in range(100)]
            # Always claims there are far more pages than the cap.
            resp.headers = {"x-total-pages": "9999"}
            return resp

        async def fake_get(url, headers=None, params=None):
            return _make_response(params["page"])

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=fake_get)

        class _CM:
            async def __aenter__(self):
                return mock_client

            async def __aexit__(self, *a):
                return False

        with patch.object(service, "_api_client", return_value=_CM()):
            with caplog.at_level("WARNING", logger="app.services.gitlab"):
                asyncio.run(service._api_get_paginated("/groups/42/members/all", max_pages=3))

        assert any("cap" in r.message.lower() or "truncat" in r.message.lower() for r in caplog.records), (
            f"Expected a cap/truncation warning. Got: {[r.message for r in caplog.records]}"
        )

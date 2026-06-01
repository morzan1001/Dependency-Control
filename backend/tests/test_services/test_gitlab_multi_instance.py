"""Tests for GitLab multi-instance behavior."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


from app.models.gitlab_api import GitLabMember
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.services.gitlab import GitLabService
from tests.mocks.gitlab import (
    make_gitlab_instance,
    make_merge_request,
    make_note,
    make_project_details,
)
from tests.mocks.mongodb import create_mock_collection, create_mock_db


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


class TestMrDecorationEarlyReturns:
    """MR decoration should bail early in various conditions."""

    def test_skips_when_mr_comments_disabled(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=False,
        )
        asyncio.run(
            decorate_gitlab_mr(
                scan_id="s1",
                stats=Stats(),
                scan_doc=_make_scan(commit_hash="abc"),
                project=project,
                db=MagicMock(),
            )
        )

    def test_skips_when_no_gitlab_ids(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_mr_comments_enabled=True,
            gitlab_instance_id=None,
            gitlab_project_id=None,
        )
        asyncio.run(
            decorate_gitlab_mr(
                scan_id="s1",
                stats=Stats(),
                scan_doc=_make_scan(commit_hash="abc"),
                project=project,
                db=MagicMock(),
            )
        )

    def test_skips_when_no_commit_hash(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        asyncio.run(
            decorate_gitlab_mr(
                scan_id="s1",
                stats=Stats(),
                scan_doc=_make_scan(),
                project=project,
                db=MagicMock(),
            )
        )

    def test_skips_when_instance_not_found(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="nonexistent",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        collection = create_mock_collection(find_one=None)
        db = create_mock_db({"gitlab_instances": collection})

        asyncio.run(
            decorate_gitlab_mr(
                scan_id="s1",
                stats=Stats(),
                scan_doc=_make_scan(commit_hash="abc"),
                project=project,
                db=db,
            )
        )

    def test_skips_when_instance_inactive(self):
        from app.services.analysis.integrations import decorate_gitlab_mr

        project = Project(
            name="Test",
            owner_id="u1",
            gitlab_instance_id="inst-1",
            gitlab_project_id=100,
            gitlab_mr_comments_enabled=True,
        )
        instance_doc = {
            "_id": "inst-1",
            "name": "Test",
            "url": "https://gitlab.com",
            "is_active": False,
            "created_by": "admin",
        }
        collection = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": collection})

        asyncio.run(
            decorate_gitlab_mr(
                scan_id="s1",
                stats=Stats(),
                scan_doc=_make_scan(commit_hash="abc"),
                project=project,
                db=db,
            )
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

    def test_returns_none_for_user_namespace(self, gitlab_instance_a):
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
        assert result is None

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
        assert result is None


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
            mock_resolve.return_value = {"id": 10}  # Parent group ID

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
            assert result == "existing-team-id"
            # Should have called update_one to set members
            teams_coll.update_one.assert_called_once()


class TestTeamSyncSilentReturnsAreLogged:
    """Every silent return None path in sync_team_from_gitlab MUST emit a log
    so operators can detect projects that were created without a team_id."""

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

        assert result is None
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

        assert result is None
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

        assert result is None
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

        assert result is None
        # error log must include the project id so operators can find the orphan
        assert any("222" in r.message for r in caplog.records), (
            f"Expected error log to include project_id 222. Got: {[r.message for r in caplog.records]}"
        )


class TestTeamSyncResolveGroupFallback:
    """When _resolve_group_by_path fails, the team must be created consistently
    (no team named for the truncated path but tagged with the deep subgroup's id)."""

    def test_falls_back_to_deep_group_id_and_path_when_truncation_unresolvable(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        members = [
            GitLabMember(username="dev", email="dev@test.com", access_level=30),
        ]

        with (
            patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members,
            patch.object(service, "_resolve_group_by_path", new_callable=AsyncMock) as mock_resolve,
        ):
            mock_members.return_value = members
            mock_resolve.return_value = None  # truncated path "org" cannot be resolved

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
                        namespace_id=42,  # deep "org/subgroup" id
                        namespace_path="org/subgroup",
                    ),
                )
            )

            teams_coll.insert_one.assert_called_once()
            team_data = teams_coll.insert_one.call_args[0][0]
            # group_id and name must reference the SAME level — either both deep or
            # both truncated. The current bug uses truncated name + deep group_id.
            if team_data["gitlab_group_id"] == 42:
                assert team_data["name"] == "GitLab Group: org/subgroup", (
                    f"If gitlab_group_id is the deep namespace.id (42), the team name must reflect "
                    f"the deep path, not the unresolvable truncated path. Got name={team_data['name']!r}"
                )


class _StatefulTeamsCollection:
    """In-memory teams collection that mimics MongoDB find_one/insert_one/update_one
    filter semantics, so cross-instance collisions are observable the same way they
    would be against a real database."""

    def __init__(self):
        self.docs: list[dict] = []

    @staticmethod
    def _matches(doc: dict, query: dict) -> bool:
        return all(doc.get(k) == v for k, v in query.items())

    async def find_one(self, query, *args, **kwargs):
        for doc in self.docs:
            if self._matches(doc, query):
                return dict(doc)
        return None

    async def insert_one(self, doc):
        self.docs.append(dict(doc))
        return MagicMock(inserted_id=doc.get("_id", "mock-id"))

    async def update_one(self, query, update, *args, **kwargs):
        for doc in self.docs:
            if self._matches(doc, query):
                doc.update(update.get("$set", {}))
                return MagicMock(modified_count=1)
        return MagicMock(modified_count=0)


class TestTeamSyncInstanceScoping:
    """Finding 8: GitLab team matching must be scoped to the (instance, group)
    composite key. Two instances owning a group with the SAME path must NOT collide."""

    def _sync(self, instance, teams_coll, group_id, group_path):
        service = GitLabService(instance)
        members = [GitLabMember(username="dev", email="dev@test.com", access_level=30)]
        user_doc = {"_id": "uid", "username": "dev"}
        users_coll = create_mock_collection(find_one=user_doc)
        db = create_mock_db({"teams": teams_coll, "users": users_coll})
        with patch.object(service, "get_group_members", new_callable=AsyncMock) as mock_members:
            mock_members.return_value = members
            return asyncio.run(
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

    def test_same_group_path_across_instances_does_not_collide(self):
        """Instance A and instance B both own a group at path 'shared-grp' (same
        gitlab_group_id number, different instances). Syncing B must create a NEW
        team and must NOT adopt/mutate instance A's team."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        instance_b = make_gitlab_instance(id="inst-b", name="B", url="https://b.com")
        teams = _StatefulTeamsCollection()

        team_a_id = self._sync(instance_a, teams, group_id=7, group_path="shared-grp")
        team_b_id = self._sync(instance_b, teams, group_id=7, group_path="shared-grp")

        assert team_a_id is not None
        assert team_b_id is not None
        # The two instances must own DISTINCT teams.
        assert team_a_id != team_b_id, (
            "Instance B adopted instance A's team via the unscoped name fallback — "
            "this is the cross-tenant collision (Finding 8)."
        )
        # Two separate team documents must exist, each tagged to its own instance.
        assert len(teams.docs) == 2
        by_instance = {d["gitlab_instance_id"]: d for d in teams.docs}
        assert set(by_instance) == {"inst-a", "inst-b"}

    def test_instance_a_members_not_mutated_by_instance_b_sync(self):
        """Instance A's team and its member list must be untouched after B syncs."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        instance_b = make_gitlab_instance(id="inst-b", name="B", url="https://b.com")
        teams = _StatefulTeamsCollection()

        team_a_id = self._sync(instance_a, teams, group_id=7, group_path="shared-grp")
        team_a_before = next(d for d in teams.docs if d["_id"] == team_a_id)
        members_before = [dict(m) for m in team_a_before["members"]]

        self._sync(instance_b, teams, group_id=7, group_path="shared-grp")

        team_a_after = next(d for d in teams.docs if d["_id"] == team_a_id)
        assert team_a_after["gitlab_instance_id"] == "inst-a"
        assert team_a_after["members"] == members_before

    def test_repeated_sync_same_instance_group_reuses_team(self):
        """Composite-key match: re-syncing the SAME (instance, group) must re-use the
        same team, not create a duplicate."""
        instance_a = make_gitlab_instance(id="inst-a", name="A", url="https://a.com")
        teams = _StatefulTeamsCollection()

        first_id = self._sync(instance_a, teams, group_id=7, group_path="shared-grp")
        second_id = self._sync(instance_a, teams, group_id=7, group_path="shared-grp")

        assert first_id == second_id
        assert len(teams.docs) == 1

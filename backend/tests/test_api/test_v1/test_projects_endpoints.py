"""Tests for project API endpoints (notification settings)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.project import Project, ProjectMember, Scan
from app.models.user import User
from app.schemas.project import ProjectNotificationSettings

MODULE = "app.api.v1.endpoints.projects"


def _make_admin_user(user_id="admin-member-1"):
    return User(
        id=user_id,
        username="proj-admin",
        email="proj-admin@test.com",
        permissions=[],
    )


def _make_project(admin_id="admin-member-1"):
    return Project(
        id="proj-1",
        name="Demo",
        members=[ProjectMember(user_id=admin_id, role="admin")],
    )


class TestUpdateNotificationSettingsAdmin:
    """A project admin's own notification_preferences must be persisted."""

    def _run(self, current_user, project, settings, project_repo):
        from app.api.v1.endpoints.projects import update_notification_settings

        with patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)):
            with patch(f"{MODULE}.ProjectRepository", return_value=project_repo):
                return asyncio.run(
                    update_notification_settings(
                        project_id="proj-1",
                        settings=settings,
                        current_user=current_user,
                        db=MagicMock(),
                    )
                )

    def test_admin_preferences_are_persisted(self):
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"analysis_completed": ["email", "slack"]},
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update_member.assert_awaited_once()
        args = project_repo.update_member.await_args.args
        assert args[0] == "proj-1"
        assert args[1] == user.id
        assert args[2] == {"notification_preferences": {"analysis_completed": ["email", "slack"]}}

    def test_admin_preferences_only_no_enforcement_is_not_a_noop(self):
        """With no enforcement change, update_data is empty; prefs must still persist."""
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"vulnerability_found": ["slack"]},
            # enforce_notification_settings omitted, so update_data is empty
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update.assert_not_awaited()
        project_repo.update_member.assert_awaited_once()
        assert project_repo.update_member.await_args.args[2] == {
            "notification_preferences": {"vulnerability_found": ["slack"]}
        }

    def test_admin_enforcement_and_preferences_both_persisted(self):
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"analysis_completed": ["email"]},
            enforce_notification_settings=True,
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update.assert_awaited_once()
        assert project_repo.update.await_args.args[1] == {"enforce_notification_settings": True}
        project_repo.update_member.assert_awaited_once()


class TestScanHistoryLineage:
    """Housekeeping re-scans a branch tip daily, so a lineage outgrows one page within months."""

    _LINEAGE_RUNS = 340

    def _run(self, scan_repo):
        from app.api.v1.endpoints.projects import read_scan_history

        with patch(f"{MODULE}.check_project_access", AsyncMock()):
            with patch(f"{MODULE}.ScanRepository", return_value=scan_repo):
                return asyncio.run(
                    read_scan_history(
                        project_id="proj-1",
                        scan_id="scan-root",
                        current_user=_make_admin_user(),
                        db=MagicMock(),
                    )
                )

    def _repo(self, page_size):
        scan_repo = MagicMock()
        scan_repo.find_one = AsyncMock(return_value={"_id": "scan-root", "project_id": "proj-1"})
        scan_repo.find_many = AsyncMock(
            return_value=[
                Scan(id=f"scan-{i}", project_id="proj-1", branch="main", status="completed") for i in range(page_size)
            ]
        )
        scan_repo.count = AsyncMock(return_value=self._LINEAGE_RUNS)
        return scan_repo

    def test_the_lineage_is_counted_over_the_lineage_not_over_the_page(self):
        from app.api.v1.endpoints.projects import _SCAN_HISTORY_PAGE_SIZE

        response = self._run(self._repo(_SCAN_HISTORY_PAGE_SIZE))

        assert len(response.runs) == _SCAN_HISTORY_PAGE_SIZE
        assert response.total == self._LINEAGE_RUNS
        assert response.page_size == _SCAN_HISTORY_PAGE_SIZE

    def test_the_count_query_is_the_query_the_page_was_read_with(self):
        from app.api.v1.endpoints.projects import _SCAN_HISTORY_PAGE_SIZE

        scan_repo = self._repo(_SCAN_HISTORY_PAGE_SIZE)

        self._run(scan_repo)

        assert scan_repo.count.await_args.args[0] == scan_repo.find_many.await_args.args[0]


class TestProjectMemberWritesAddressTheMemberByIdentity:
    """A concurrent removal shifts the member array, so a positional write lands on a bystander."""

    _CALLER = "caller-user"
    _EARLIER = "earlier-user"
    _TARGET = "target-user"
    _BYSTANDER = "bystander-user"

    def _db(self):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        project = Project(
            id="proj-1",
            name="Demo",
            members=[
                ProjectMember(user_id=self._CALLER, role="admin"),
                ProjectMember(user_id=self._EARLIER, role="viewer"),
                ProjectMember(user_id=self._TARGET, role="viewer"),
                ProjectMember(user_id=self._BYSTANDER, role="viewer"),
            ],
        )
        db.projects._docs["proj-1"] = project.model_dump(by_alias=True)
        return db

    @staticmethod
    def _remove_between_read_and_write(db, user_id):
        write = db.projects.update_one

        async def remove_then_write(*args, **kwargs):
            db.projects.update_one = write
            await write({"_id": "proj-1"}, {"$pull": {"members": {"user_id": user_id}}})
            return await write(*args, **kwargs)

        db.projects.update_one = remove_then_write

    @staticmethod
    def _caller(user_id):
        return User(id=user_id, username="caller", email="caller@test.com", permissions=["project:update"])

    def test_a_removal_landing_between_the_read_and_the_write_cannot_redirect_the_role(self):
        from app.api.v1.endpoints.projects import update_project_member
        from app.schemas.project import ProjectMemberUpdate

        db = self._db()
        self._remove_between_read_and_write(db, self._EARLIER)

        asyncio.run(
            update_project_member(
                project_id="proj-1",
                user_id=self._TARGET,
                member_in=ProjectMemberUpdate(role="admin"),
                current_user=self._caller(self._CALLER),
                db=db,
            )
        )

        roles = {m["user_id"]: m["role"] for m in db.projects._docs["proj-1"]["members"]}
        assert roles == {self._CALLER: "admin", self._TARGET: "admin", self._BYSTANDER: "viewer"}

    def test_a_removal_landing_between_the_read_and_the_write_cannot_redirect_preferences(self):
        from app.api.v1.endpoints.projects import update_notification_settings

        db = self._db()
        self._remove_between_read_and_write(db, self._EARLIER)
        preferences = {"analysis_completed": ["slack"]}

        asyncio.run(
            update_notification_settings(
                project_id="proj-1",
                settings=ProjectNotificationSettings(notification_preferences=preferences),
                current_user=self._caller(self._TARGET),
                db=db,
            )
        )

        stored = {m["user_id"]: m["notification_preferences"] for m in db.projects._docs["proj-1"]["members"]}
        assert stored == {self._CALLER: {}, self._TARGET: preferences, self._BYSTANDER: {}}

"""Tests for project API endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

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
        project_repo.update_raw = AsyncMock()
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
        project_repo.update_raw = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update_raw.assert_not_awaited()
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
        project_repo.update_raw = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update_raw.assert_awaited_once()
        assert project_repo.update_raw.await_args.args[1] == {"$set": {"enforce_notification_settings": True}}
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


class TestProjectLimitCountsOnlyProjectsTheUserAdmins:
    """The limit query has to require user_id and role on the SAME member, and the fake has to run it."""

    _LIMIT = 2
    _CALLER = "limited-user"

    def _db(self, projects):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        for index, members in enumerate(projects):
            db.projects._docs[f"proj-{index}"] = Project(
                id=f"proj-{index}",
                name=f"Demo {index}",
                members=[ProjectMember(user_id=user_id, role=role) for user_id, role in members],
            ).model_dump(by_alias=True)
        return db

    def _create(self, db):
        from app.api.v1.endpoints.projects import create_project
        from app.models.system import SystemSettings
        from app.schemas.project import ProjectCreate

        return asyncio.run(
            create_project(
                project_in=ProjectCreate(name="New"),
                current_user=User(
                    id=self._CALLER,
                    username="limited",
                    email="limited@test.com",
                    permissions=["project:create"],
                ),
                db=db,
                settings=SystemSettings(project_limit_per_user=self._LIMIT),
            )
        )

    def test_a_user_at_the_limit_is_refused(self):
        db = self._db([[(self._CALLER, "admin")], [(self._CALLER, "admin")]])

        with pytest.raises(HTTPException) as exc_info:
            self._create(db)

        assert exc_info.value.status_code == 403

    def test_projects_the_user_only_views_do_not_count_towards_the_limit(self):
        db = self._db(
            [
                [(self._CALLER, "admin")],
                [("other-user", "admin"), (self._CALLER, "viewer")],
                [("other-user", "admin"), (self._CALLER, "editor")],
            ]
        )

        response = self._create(db)

        assert response.api_key.startswith(f"{response.project_id}.")
        assert len(db.projects._docs) == len([1, 2, 3]) + 1


class TestCreateProjectStoresWhatTheDialogChose:
    """A dropped retention_action is stored as "delete", and housekeeping then purges scans the user chose to keep."""

    def _create(self, project_in, settings=None, db=None):
        from app.api.v1.endpoints.projects import create_project
        from app.models.system import SystemSettings
        from tests.mocks.fake_mongo import FakeDatabase

        db = db or FakeDatabase()
        response = asyncio.run(
            create_project(
                project_in=project_in,
                current_user=User(
                    id="creator", username="creator", email="creator@test.com", permissions=["project:create"]
                ),
                db=db,
                settings=settings or SystemSettings(),
            )
        )
        return db, db.projects._docs[response.project_id]

    @pytest.mark.parametrize("action", ["archive", "none"])
    def test_the_chosen_retention_is_stored(self, action):
        from app.schemas.project import ProjectCreate

        _, stored = self._create(ProjectCreate(name="New", retention_days=30, retention_action=action))

        assert (stored["retention_days"], stored["retention_action"]) == (30, action)

    def test_global_retention_mode_overrides_the_request(self):
        from app.models.system import SystemSettings
        from app.schemas.project import ProjectCreate

        _, stored = self._create(
            ProjectCreate(name="New", retention_days=30, retention_action="archive"),
            SystemSettings(retention_mode="global"),
        )

        assert (stored["retention_days"], stored["retention_action"]) == (90, "delete")

    def test_explicit_nulls_fall_back_to_the_defaults(self):
        from app.schemas.project import ProjectCreate

        _, stored = self._create(ProjectCreate(name="New", retention_days=None, retention_action=None))

        assert (stored["retention_days"], stored["retention_action"]) == (90, "delete")

    def test_analyzer_settings_are_stored_and_the_license_policy_audited(self):
        from app.schemas.project import LicensePolicySchema, ProjectCreate

        analyzer_settings = {"license_compliance": {"deployment_model": "cli_batch"}, "trivy": {"x": 1}}
        db, stored = self._create(ProjectCreate(name="New", analyzer_settings=analyzer_settings))

        assert stored["analyzer_settings"] == analyzer_settings
        [entry] = db.crypto_policy_history._docs.values()
        assert (entry["policy_type"], entry["action"], entry["change_summary"]) == (
            "license",
            "create",
            "deployment_model: network_facing -> cli_batch",
        )
        assert entry["snapshot"] == LicensePolicySchema(deployment_model="cli_batch").model_dump()

    def test_a_project_created_with_the_default_policy_writes_no_license_audit_entry(self):
        from app.schemas.project import ProjectCreate

        db, _ = self._create(ProjectCreate(name="New", analyzer_settings={"trivy": {"x": 1}}))

        assert list(db.crypto_policy_history._docs.values()) == []

    def test_the_license_policy_change_reaches_the_team(self):
        from app.schemas.project import ProjectCreate
        from app.services.notifications.service import notification_service
        from app.services.webhooks import webhook_service
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        for user_id in ("creator", "teammate"):
            db.users._docs[user_id] = {
                "_id": user_id,
                "username": user_id,
                "email": f"{user_id}@test.com",
                "is_active": True,
                "notification_preferences": {"license_policy_changed": ["email"]},
            }
        db.teams._docs["team-1"] = {
            "_id": "team-1",
            "name": "Team",
            "members": [{"user_id": "creator", "role": "admin"}, {"user_id": "teammate", "role": "member"}],
        }
        db.webhooks._docs["team-hook"] = {
            "_id": "team-hook",
            "team_id": "team-1",
            "url": "https://example.com/hook",
            "events": ["license_policy.changed"],
            "is_active": True,
        }

        with (
            patch.object(webhook_service, "_send_webhook", AsyncMock(return_value=True)) as sent,
            patch.object(notification_service, "_send_based_on_prefs", AsyncMock()) as notified,
        ):
            self._create(
                ProjectCreate(
                    name="New",
                    team_id="team-1",
                    analyzer_settings={"license_compliance": {"deployment_model": "cli_batch"}},
                ),
                db=db,
            )

        assert [call.args[1].id for call in sent.call_args_list] == ["team-hook"]
        assert sorted(call.args[0].username for call in notified.call_args_list) == ["creator", "teammate"]


class TestHideHistoricalSecretsNarrowsTheResult:
    """The $nor has to run for real: a filter the fake ignored would leave the buried secret visible."""

    _SCAN_ID = "scan-1"
    _CALLER = "reader"

    def _db(self):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        db.projects._docs["proj-1"] = Project(
            id="proj-1",
            name="Demo",
            members=[ProjectMember(user_id=self._CALLER, role="admin")],
        ).model_dump(by_alias=True)
        db.scans._docs[self._SCAN_ID] = {"_id": self._SCAN_ID, "project_id": "proj-1", "status": "completed"}
        db.findings._docs = {
            "gone": self._finding("gone", "secret", {"in_current_tree": False}),
            "present": self._finding("present", "secret", {"in_current_tree": True}),
            "unknown": self._finding("unknown", "secret", {}),
            "sast-gone": self._finding("sast-gone", "sast", {"in_current_tree": False}),
        }
        return db

    def _finding(self, finding_id, finding_type, details):
        return {
            "_id": finding_id,
            "finding_id": finding_id,
            "scan_id": self._SCAN_ID,
            "project_id": "proj-1",
            "type": finding_type,
            "severity": "HIGH",
            "component": finding_id,
            "details": details,
        }

    def _read(self, db, hide_historical_secrets):
        from app.api.v1.endpoints.projects import read_scan_findings

        return asyncio.run(
            read_scan_findings(
                scan_id=self._SCAN_ID,
                current_user=User(
                    id=self._CALLER,
                    username="reader",
                    email="reader@test.com",
                    permissions=["project:read"],
                ),
                db=db,
                hide_historical_secrets=hide_historical_secrets,
            )
        )

    def test_a_secret_gone_from_the_tree_is_the_only_finding_dropped(self):
        db = self._db()

        shown = self._read(db, True)

        assert sorted(item["finding_id"] for item in shown["items"]) == ["present", "sast-gone", "unknown"]
        assert shown["total"] == len(shown["items"])

    def test_without_the_flag_the_buried_secret_is_visible(self):
        db = self._db()

        shown = self._read(db, None)

        assert "gone" in {item["finding_id"] for item in shown["items"]}


class TestDashboardStats:
    """The estate tile: a persisted risk score wins, an absent one is derived from severity counts."""

    _PERSISTED_RISK = 42.0
    _CRITICALS = 3
    _HIGHS = 2
    _TOP_RISKY_CAP = 5

    def _db(self, projects):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        for project_id, stats in projects:
            db.projects._docs[project_id] = {"_id": project_id, "name": project_id, "stats": stats}
        return db

    def _read(self, db, permissions=("project:read_all",)):
        from app.api.v1.endpoints.projects import get_dashboard_stats

        return asyncio.run(
            get_dashboard_stats(
                db=db,
                current_user=User(id="u1", username="u", email="u@test.com", permissions=list(permissions)),
            )
        )

    def test_an_empty_estate_reports_zeroes(self):
        stats = self._read(self._db([]))

        assert stats["total_projects"] == 0
        assert stats["avg_risk_score"] == 0.0
        assert stats["top_risky_projects"] == []

    def test_severity_totals_and_the_average_span_the_estate(self):
        db = self._db(
            [
                ("p-persisted", {"risk_score": self._PERSISTED_RISK, "critical": self._CRITICALS, "high": self._HIGHS}),
                ("p-clean", {"critical": 0, "high": 0}),
            ]
        )

        stats = self._read(db)

        assert stats["total_projects"] == 2
        assert stats["total_critical"] == self._CRITICALS
        assert stats["total_high"] == self._HIGHS
        assert stats["avg_risk_score"] == round(self._PERSISTED_RISK / 2, 1)

    def test_a_project_without_a_persisted_score_is_ranked_on_a_derived_one(self):
        db = self._db(
            [
                ("p-derived", {"critical": self._CRITICALS, "high": self._HIGHS}),
                ("p-clean", {"critical": 0, "high": 0}),
            ]
        )

        stats = self._read(db)

        derived = next(p for p in stats["top_risky_projects"] if p.id == "p-derived")
        assert derived.risk > 0
        assert [p.id for p in stats["top_risky_projects"]] == ["p-derived", "p-clean"]

    def test_the_persisted_score_is_used_rather_than_recomputed(self):
        db = self._db([("p-persisted", {"risk_score": self._PERSISTED_RISK, "critical": 0, "high": 0})])

        stats = self._read(db)

        assert stats["top_risky_projects"][0].risk == self._PERSISTED_RISK

    def test_only_the_riskiest_five_projects_are_listed(self):
        db = self._db([(f"p-{index}", {"risk_score": float(index)}) for index in range(self._TOP_RISKY_CAP + 3)])

        stats = self._read(db)

        assert [p.id for p in stats["top_risky_projects"]] == [
            f"p-{index}" for index in range(self._TOP_RISKY_CAP + 2, self._TOP_RISKY_CAP - 3, -1)
        ]

    def test_a_user_without_read_all_only_sees_the_projects_they_belong_to(self):
        db = self._db([("mine", {"critical": 1}), ("theirs", {"critical": 1})])
        db.projects._docs["mine"]["members"] = [{"user_id": "u1", "role": "admin"}]

        stats = self._read(db, permissions=("project:read",))

        assert stats["total_projects"] == 1
        assert [p.id for p in stats["top_risky_projects"]] == ["mine"]


class TestWritesReadTheProjectBackOnce:
    """A write answers with one read of the stored project, not a read per write."""

    @staticmethod
    async def _seeded_db(project):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        await db.projects.insert_one(project.model_dump(by_alias=True))
        return db

    @pytest.mark.asyncio
    async def test_the_notification_update_reads_the_project_back_once(self):
        from app.api.v1.endpoints.projects import update_notification_settings
        from app.repositories.projects import ProjectRepository

        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        db = await self._seeded_db(project)
        settings = ProjectNotificationSettings(
            notification_preferences={"analysis_completed": ["email"]}, enforce_notification_settings=True
        )

        with (
            patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)),
            patch.object(
                ProjectRepository, "get_by_id", autospec=True, side_effect=ProjectRepository.get_by_id
            ) as reads,
        ):
            updated = await update_notification_settings("proj-1", settings, user, db)

        assert updated.enforce_notification_settings is True
        assert reads.await_count == 1

    @pytest.mark.asyncio
    async def test_a_key_rotation_reads_no_project_after_the_write(self):
        from app.api.v1.endpoints.projects import rotate_api_key
        from app.repositories.projects import ProjectRepository

        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        db = await self._seeded_db(project)

        with (
            patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)),
            patch.object(
                ProjectRepository, "get_by_id", autospec=True, side_effect=ProjectRepository.get_by_id
            ) as reads,
        ):
            await rotate_api_key("proj-1", user, db)

        assert reads.await_count == 0
        assert (await db.projects.find_one({"_id": "proj-1"}))["api_key_hash"]


class TestAnalyzerNamesAreCheckedWhereTheyEnter:
    """The engine skips an analyzer name it does not know without a trace, so a typo stops a scanner silently."""

    def test_creating_a_project_with_an_unknown_analyzer_is_refused(self):
        from app.api.v1.endpoints.projects import create_project
        from app.models.system import SystemSettings
        from app.schemas.project import ProjectCreate
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                create_project(
                    project_in=ProjectCreate(name="New", active_analyzers=["trivy", "TruffleHog"]),
                    current_user=User(id="c", username="c", email="c@test.com", permissions=["project:create"]),
                    db=db,
                    settings=SystemSettings(),
                )
            )

        assert exc.value.status_code == 422
        assert "TruffleHog" in exc.value.detail
        assert db.projects._docs == {}

    @pytest.mark.asyncio
    async def test_updating_a_project_with_an_unknown_analyzer_writes_nothing(self):
        from app.api.v1.endpoints.projects import update_project
        from app.schemas.project import ProjectUpdate

        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        db = await TestWritesReadTheProjectBackOnce._seeded_db(project)

        with (
            patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)),
            pytest.raises(HTTPException) as exc,
        ):
            await update_project("proj-1", ProjectUpdate(active_analyzers=["osv "]), user, db)

        assert exc.value.status_code == 422
        assert (await db.projects.find_one({"_id": "proj-1"}))["active_analyzers"] == project.active_analyzers

    def test_every_name_the_project_settings_offer_is_selectable(self):
        """Mirrors AVAILABLE_ANALYZERS in frontend/src/lib/constants.ts."""
        from app.services.analysis.registry import SELECTABLE_ANALYZERS

        assert {
            "trivy", "grype", "osv", "deps_dev", "epss_kev", "reachability", "end_of_life", "license_compliance",
            "os_malware", "typosquatting", "hash_verification", "maintainer_risk", "outdated_packages",
            "opengrep", "kics", "bearer", "trufflehog",
        } == SELECTABLE_ANALYZERS  # fmt: skip


def test_the_scan_findings_table_ranks_severity_like_every_other_surface():
    """A hand-written copy ranked INFO above NEGLIGIBLE, the reverse of SEVERITY_ORDER."""
    from app.api.v1.endpoints.projects import _scan_findings_add_fields_stage
    from app.core.constants import SEVERITY_ORDER

    switch = _scan_findings_add_fields_stage()["$addFields"]["severity_rank"]["$switch"]
    ranks = {branch["case"]["$eq"][1]: branch["then"] for branch in switch["branches"]}

    assert {severity: ranks.get(severity, switch["default"]) for severity in SEVERITY_ORDER} == SEVERITY_ORDER

import asyncio
from unittest.mock import AsyncMock

from app.core import init_db as init_db_module
from app.core.constants import TEAM_SOURCE_GITLAB, team_binding_key, team_source
from app.core.init_db import _backfill_gitlab_owner_provenance, create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def _gitlab_binding(instance_id: str, group_id: int) -> dict:
    return {
        "provider": TEAM_SOURCE_GITLAB,
        "instance_id": instance_id,
        "external_id": group_id,
        "path": "acme",
        "key": team_binding_key(TEAM_SOURCE_GITLAB, instance_id, group_id),
    }


def _seed_team(db, _id, name, **fields):
    doc = {"_id": _id, "name": name, "members": [], "bindings": []}
    doc.update(fields)
    db.teams._docs[_id] = doc


def _seed_project(db, _id, team_id, provenance=None, **fields):
    doc = {
        "_id": _id,
        "name": _id,
        "team_ids": [team_id] if team_id else [],
        "team_sources": {team_id: provenance} if team_id and provenance else {},
    }
    doc.update(fields)
    db.projects._docs[_id] = doc


class TestBackfillProvenance:
    def test_does_not_stamp_gitlab_source_on_existing_synced_team_members(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-synced",
            "GitLab Group: acme",
            bindings=[_gitlab_binding("inst-a", 42)],
            members=[{"user_id": "u1", "role": "member"}, {"user_id": "u2", "role": "admin"}],
        )

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        members = db.teams._docs["t-synced"]["members"]
        assert all(m.get("source") != "gitlab" for m in members), (
            f"Backfill must not mass-stamp members as gitlab; got {members}"
        )

    def test_does_not_touch_manual_team_members(self):
        db = FakeDatabase()
        _seed_team(db, "t-manual", "Atlas", members=[{"user_id": "u1", "role": "admin"}])

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        members = db.teams._docs["t-manual"]["members"]
        # No source stamped (defaults to manual at model level), never "gitlab".
        assert members[0].get("source") != "gitlab"

    def test_preserves_existing_member_source(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-mixed",
            "GitLab Group: acme",
            bindings=[_gitlab_binding("inst-a", 42)],
            members=[
                {"user_id": "manual-u", "role": "admin", "source": "manual"},
                {"user_id": "legacy-u", "role": "member"},
            ],
        )

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        members = {m["user_id"]: m for m in db.teams._docs["t-mixed"]["members"]}
        assert members["manual-u"]["source"] == "manual"
        # An unstamped member stays unstamped, reading as 'manual', so it survives the next sync merge.
        assert members["legacy-u"].get("source") != "gitlab"

    def test_stamps_the_owner_entry_of_projects_of_a_synced_team(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-a")}

    def test_leaves_a_co_owner_this_team_did_not_supply_alone(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)
        db.projects._docs["p1"]["team_ids"].append("t-hand")
        db.projects._docs["p1"]["team_sources"]["t-hand"] = "manual"

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {
            "t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-a"),
            "t-hand": "manual",
        }

    def test_a_team_bound_to_two_gitlab_instances_leaves_the_owner_unstamped(self):
        """Stamping the wrong instance would let its next ingest delete the owner; unstamped reads as hand-assigned."""
        db = FakeDatabase()
        _seed_team(
            db,
            "t-two",
            "GitLab Group: acme",
            bindings=[_gitlab_binding("inst-a", 42), _gitlab_binding("inst-b", 43)],
        )
        _seed_project(db, "p1", "t-two")

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {}

    def test_a_github_only_binding_is_not_stamped_as_gitlab(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-github",
            "GitHub Team: acme/payments",
            bindings=[{"provider": "github", "instance_id": "gh-1", "external_id": 7, "key": "github:gh-1:7"}],
        )
        _seed_project(db, "p1", "t-github")

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {}

    def test_does_not_stamp_team_source_for_manual_team_projects(self):
        db = FakeDatabase()
        _seed_team(db, "t-manual", "Atlas")
        _seed_project(db, "p1", "t-manual")

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"].get("team_sources") == {}

    def test_does_not_overwrite_existing_team_source(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", provenance="manual")

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": "manual"}

    def test_does_not_move_an_owner_to_this_teams_instance(self):
        """An entry naming another instance is its attribution; restamped, this instance's ingest would retire it."""
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", provenance=team_source(TEAM_SOURCE_GITLAB, "inst-b"))

        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-b")}

    def test_idempotent_second_run_is_noop(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-synced",
            "GitLab Group: acme",
            bindings=[_gitlab_binding("inst-a", 42)],
            members=[{"user_id": "u1", "role": "member"}],
        )
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_gitlab_owner_provenance(db))
        teams_first = dict(db.teams._docs["t-synced"])
        proj_first = dict(db.projects._docs["p1"])
        asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.teams._docs["t-synced"] == teams_first
        assert db.projects._docs["p1"] == proj_first

    def test_per_team_failure_is_isolated(self, caplog):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-bad",
            "GitLab Group: bad",
            bindings=[_gitlab_binding("inst-a", 1)],
            members=[{"user_id": "u1"}],
        )
        _seed_project(db, "p-bad", "t-bad", gitlab_instance_id="inst-a", gitlab_project_id=1)
        _seed_team(
            db,
            "t-good",
            "GitLab Group: good",
            bindings=[_gitlab_binding("inst-a", 2)],
            members=[{"user_id": "u2"}],
        )
        _seed_project(db, "p-good", "t-good", gitlab_instance_id="inst-a", gitlab_project_id=2)

        original_update_many = db.projects.update_many

        async def failing_update_many(query, update, **kwargs):
            if query.get("team_ids") == "t-bad":
                raise RuntimeError("boom")
            return await original_update_many(query, update, **kwargs)

        db.projects.update_many = failing_update_many  # type: ignore[method-assign]

        with caplog.at_level("ERROR", logger="app.core.init_db"):
            asyncio.run(_backfill_gitlab_owner_provenance(db))

        assert db.projects._docs["p-good"]["team_sources"] == {"t-good": team_source(TEAM_SOURCE_GITLAB, "inst-a")}
        assert any("t-bad" in r.message for r in caplog.records)


class TestBackfillRunsAtStartupBeforeTheIndexes:
    def _synced_project(self) -> FakeDatabase:
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)
        return db

    def test_index_creation_leaves_the_projects_data_alone(self):
        db = self._synced_project()

        asyncio.run(create_indexes(db))

        assert db.projects._docs["p1"]["team_sources"] == {}

    def test_startup_stamps_the_owner_entry(self, monkeypatch):
        db = self._synced_project()
        monkeypatch.setattr(init_db_module, "get_database", AsyncMock(return_value=db))

        asyncio.run(init_db_module.init_db())

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-a")}

"""The startup provenance backfill, and the guard around the teams unique index build.

The backfill stamps the GitLab instance that holds the group onto the owner entry of the projects
a bound team owns, and never stamps a member: a pre-existing member moved into the gitlab subset
would be deleted by the next sync's merge.
"""

import asyncio

import pytest
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.core.constants import TEAM_SOURCE_GITLAB, team_binding_key, team_source
from app.core.init_db import (
    TEAM_BINDING_KEY_FIELD,
    _backfill_member_and_team_provenance,
    create_indexes,
)
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


def _seed_project(db, _id, team_id, team_source=None, **fields):
    """A project as the phase-1 migration leaves it: the owner in the list, the scalar mirroring it."""
    doc = {
        "_id": _id,
        "name": _id,
        "team_ids": [team_id] if team_id else [],
        "team_sources": {team_id: team_source} if team_id and team_source else {},
        "team_id": team_id,
        "team_source": team_source,
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

        asyncio.run(_backfill_member_and_team_provenance(db))

        members = db.teams._docs["t-synced"]["members"]
        assert all(m.get("source") != "gitlab" for m in members), (
            f"Backfill must not mass-stamp members as gitlab; got {members}"
        )

    def test_does_not_touch_manual_team_members(self):
        db = FakeDatabase()
        _seed_team(db, "t-manual", "Atlas", members=[{"user_id": "u1", "role": "admin"}])

        asyncio.run(_backfill_member_and_team_provenance(db))

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

        asyncio.run(_backfill_member_and_team_provenance(db))

        members = {m["user_id"]: m for m in db.teams._docs["t-mixed"]["members"]}
        assert members["manual-u"]["source"] == "manual"
        # A legacy (unstamped) member is intentionally left unstamped so it defaults
        # to 'manual' on read and survives the next sync merge.
        assert members["legacy-u"].get("source") != "gitlab"

    def test_stamps_the_owner_entry_of_projects_of_a_synced_team(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-a")}
        assert db.projects._docs["p1"]["team_source"] == team_source(TEAM_SOURCE_GITLAB, "inst-a")

    def test_leaves_a_co_owner_this_team_did_not_supply_alone(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)
        db.projects._docs["p1"]["team_ids"].append("t-hand")
        db.projects._docs["p1"]["team_sources"]["t-hand"] = "manual"

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {
            "t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-a"),
            "t-hand": "manual",
        }

    def test_a_team_bound_to_two_gitlab_instances_leaves_the_owner_unstamped(self):
        """Either instance could have established the owner, and stamping the wrong one hands it to
        that instance's next ingest to delete. Unstamped reads as hand-assigned, which keeps it."""
        db = FakeDatabase()
        _seed_team(
            db,
            "t-two",
            "GitLab Group: acme",
            bindings=[_gitlab_binding("inst-a", 42), _gitlab_binding("inst-b", 43)],
        )
        _seed_project(db, "p1", "t-two")

        asyncio.run(_backfill_member_and_team_provenance(db))

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

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {}

    def test_does_not_stamp_team_source_for_manual_team_projects(self):
        db = FakeDatabase()
        _seed_team(db, "t-manual", "Atlas")
        _seed_project(db, "p1", "t-manual")

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"].get("team_sources") == {}

    def test_does_not_overwrite_existing_team_source(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        # A project already explicitly marked manual must be preserved.
        _seed_project(db, "p1", "t-synced", team_source="manual")

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": "manual"}
        assert db.projects._docs["p1"]["team_source"] == "manual"

    def test_does_not_move_an_owner_to_this_teams_instance(self):
        """The guard is absent-and-null and nothing else. An entry already naming another instance
        is that instance's attribution, and restamping it on a startup would hand the owner to this
        instance's next ingest to retire."""
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", bindings=[_gitlab_binding("inst-a", 42)])
        _seed_project(db, "p1", "t-synced", team_source=team_source(TEAM_SOURCE_GITLAB, "inst-b"))

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_sources"] == {"t-synced": team_source(TEAM_SOURCE_GITLAB, "inst-b")}
        assert db.projects._docs["p1"]["team_source"] == team_source(TEAM_SOURCE_GITLAB, "inst-b")

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

        asyncio.run(_backfill_member_and_team_provenance(db))
        teams_first = dict(db.teams._docs["t-synced"])
        proj_first = dict(db.projects._docs["p1"])
        asyncio.run(_backfill_member_and_team_provenance(db))

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
            asyncio.run(_backfill_member_and_team_provenance(db))  # must NOT raise

        # The good team's project must still have been stamped despite the bad team failing.
        assert db.projects._docs["p-good"]["team_sources"] == {"t-good": team_source(TEAM_SOURCE_GITLAB, "inst-a")}
        assert any("t-bad" in r.message for r in caplog.records)


class TestTeamsUniqueIndexGuard:
    """The teams unique binding-key index build must degrade gracefully (log + skip) on a startup
    duplicate. create_indexes runs at pod startup; an unhandled failure from that one build would
    crash the pod into CrashLoopBackOff instead of continuing.
    """

    @staticmethod
    def _wrap_teams_index_to_raise(db, exc):
        teams = db["teams"]
        original_create_index = teams.create_index

        async def create_index(keys, **kwargs):
            if isinstance(keys, list) and [k[0] for k in keys] == [TEAM_BINDING_KEY_FIELD] and kwargs.get("unique"):
                raise exc
            return await original_create_index(keys, **kwargs)

        teams.create_index = create_index  # type: ignore[method-assign]

    def test_duplicate_key_error_does_not_propagate(self, caplog):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(
            db, DuplicateKeyError("E11000 duplicate key error", details={"keyValue": {"bindings.key": "gitlab:a:42"}})
        )

        with caplog.at_level("ERROR", logger="app.core.init_db"):
            # Must complete without raising — graceful degradation, not CrashLoopBackOff.
            asyncio.run(create_indexes(db))

        assert any("teams" in r.message.lower() or "index" in r.message.lower() for r in caplog.records), (
            f"Skipped teams unique index must be logged at ERROR. Got: {[r.message for r in caplog.records]}"
        )

    def test_operation_failure_does_not_propagate(self):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(db, OperationFailure("index build failed"))

        # Must complete without raising.
        asyncio.run(create_indexes(db))

    def test_unrelated_index_failures_still_propagate(self):
        """The guard must be narrow: a failure on a DIFFERENT index must NOT be swallowed."""
        db = FakeDatabase()
        users = db["users"]

        async def failing_create_index(keys, **kwargs):
            raise OperationFailure("unrelated users index failure")

        users.create_index = failing_create_index  # type: ignore[method-assign]

        with pytest.raises(OperationFailure):
            asyncio.run(create_indexes(db))


class TestStartupBuildsTheBindingKey:
    """create_team_indexes is what the live index tests build; startup has to still call it,
    or the uniqueness those tests prove would never reach a deployed installation."""

    def test_the_binding_key_gets_its_unique_index(self):
        db = FakeDatabase()

        asyncio.run(create_indexes(db))

        assert (TEAM_BINDING_KEY_FIELD,) in db["teams"].created_indexes

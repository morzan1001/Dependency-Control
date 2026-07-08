"""Tests for the one-time, idempotent legacy-team GitLab-id backfill in init_db.

A legacy synced team ("GitLab Group: {path}" name, no gitlab ids) can only have its
gitlab_instance_id safely derived from a single linked-project instance; gitlab_group_id
is not locally recoverable and must never be fabricated. Already-tagged teams stay untouched.
"""

import asyncio

import pytest
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.core.init_db import (
    _backfill_synced_team_gitlab_ids,
    _backfill_member_and_team_provenance,
    create_indexes,
)
from tests.mocks.fake_mongo import FakeDatabase


def _seed_team(db, _id, name, **fields):
    doc = {"_id": _id, "name": name, "members": []}
    doc.update(fields)
    db.teams._docs[_id] = doc


def _seed_project(db, _id, team_id, **fields):
    doc = {"_id": _id, "name": _id, "team_id": team_id}
    doc.update(fields)
    db.projects._docs[_id] = doc


class TestBackfillSyncedTeamIds:
    def test_stamps_instance_id_when_single_instance_unambiguous(self):
        db = FakeDatabase()
        _seed_team(db, "team-1", "GitLab Group: acme")
        # Two projects both link to the team and share ONE gitlab instance.
        _seed_project(db, "p1", "team-1", gitlab_instance_id="inst-a", gitlab_project_id=1)
        _seed_project(db, "p2", "team-1", gitlab_instance_id="inst-a", gitlab_project_id=2)

        asyncio.run(_backfill_synced_team_gitlab_ids(db))

        team = db.teams._docs["team-1"]
        assert team["gitlab_instance_id"] == "inst-a"
        # group_id is NOT locally derivable and must never be fabricated.
        assert team.get("gitlab_group_id") is None

    def test_leaves_team_untouched_when_projects_span_multiple_instances(self, caplog):
        db = FakeDatabase()
        _seed_team(db, "team-2", "GitLab Group: shared")
        _seed_project(db, "p1", "team-2", gitlab_instance_id="inst-a", gitlab_project_id=1)
        _seed_project(db, "p2", "team-2", gitlab_instance_id="inst-b", gitlab_project_id=2)

        with caplog.at_level("WARNING", logger="app.core.init_db"):
            asyncio.run(_backfill_synced_team_gitlab_ids(db))

        team = db.teams._docs["team-2"]
        assert team.get("gitlab_instance_id") is None
        assert any("team-2" in r.message for r in caplog.records), (
            f"Ambiguous (multi-instance) team must be logged. Got: {[r.message for r in caplog.records]}"
        )

    def test_leaves_team_untouched_when_no_linked_projects(self, caplog):
        db = FakeDatabase()
        _seed_team(db, "team-3", "GitLab Group: orphan")

        with caplog.at_level("WARNING", logger="app.core.init_db"):
            asyncio.run(_backfill_synced_team_gitlab_ids(db))

        team = db.teams._docs["team-3"]
        assert team.get("gitlab_instance_id") is None
        assert any("team-3" in r.message for r in caplog.records)

    def test_does_not_touch_already_tagged_teams(self):
        db = FakeDatabase()
        _seed_team(db, "team-4", "GitLab Group: tagged", gitlab_instance_id="inst-a", gitlab_group_id=99)
        _seed_project(db, "p1", "team-4", gitlab_instance_id="inst-b", gitlab_project_id=1)

        asyncio.run(_backfill_synced_team_gitlab_ids(db))

        team = db.teams._docs["team-4"]
        # Must remain exactly as it was — never re-stamped from project data.
        assert team["gitlab_instance_id"] == "inst-a"
        assert team["gitlab_group_id"] == 99

    def test_ignores_non_synced_manual_teams(self):
        db = FakeDatabase()
        _seed_team(db, "team-5", "BOS")  # manual team, no GitLab prefix
        _seed_project(db, "p1", "team-5", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_synced_team_gitlab_ids(db))

        team = db.teams._docs["team-5"]
        assert team.get("gitlab_instance_id") is None

    def test_idempotent_second_run_is_noop(self):
        db = FakeDatabase()
        _seed_team(db, "team-6", "GitLab Group: acme")
        _seed_project(db, "p1", "team-6", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_synced_team_gitlab_ids(db))
        first = dict(db.teams._docs["team-6"])
        asyncio.run(_backfill_synced_team_gitlab_ids(db))
        second = dict(db.teams._docs["team-6"])

        assert first == second

    def test_per_team_failure_is_isolated_and_loop_continues(self, caplog):
        """A failure on one team must be logged and skipped, not abort the whole backfill loop."""
        db = FakeDatabase()
        # "bad" sorts before "good", so the loop must still reach the good team after failing.
        _seed_team(db, "team-bad", "GitLab Group: bad")
        _seed_project(db, "p-bad", "team-bad", gitlab_instance_id="inst-bad", gitlab_project_id=1)
        _seed_team(db, "team-good", "GitLab Group: good")
        _seed_project(db, "p-good", "team-good", gitlab_instance_id="inst-good", gitlab_project_id=2)

        original_update_one = db.teams.update_one

        async def failing_update_one(query, update, **kwargs):
            if query.get("_id") == "team-bad":
                raise RuntimeError("simulated write failure on team-bad")
            return await original_update_one(query, update, **kwargs)

        db.teams.update_one = failing_update_one  # type: ignore[method-assign]

        with caplog.at_level("ERROR", logger="app.core.init_db"):
            # Must not raise: the failure is swallowed and logged.
            asyncio.run(_backfill_synced_team_gitlab_ids(db))

        assert db.teams._docs["team-good"]["gitlab_instance_id"] == "inst-good"
        assert db.teams._docs["team-bad"].get("gitlab_instance_id") is None
        assert any("team-bad" in r.message for r in caplog.records), (
            f"Per-team failure must be logged. Got: {[r.message for r in caplog.records]}"
        )


class TestBackfillProvenance:
    """One-time idempotent provenance backfill: stamp Project.team_source but never stamp existing members as gitlab.

    Stamping a pre-existing member 'gitlab' would place a manually-added member in the
    gitlab-sourced subset the next sync merge replaces, silently removing them. Left
    unstamped, members default to 'manual' on read and the merge preserves them.
    """

    def test_does_not_stamp_gitlab_source_on_existing_synced_team_members(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-synced",
            "GitLab Group: acme",
            gitlab_instance_id="inst-a",
            gitlab_group_id=42,
            members=[{"user_id": "u1", "role": "member"}, {"user_id": "u2", "role": "admin"}],
        )

        asyncio.run(_backfill_member_and_team_provenance(db))

        members = db.teams._docs["t-synced"]["members"]
        assert all(m.get("source") != "gitlab" for m in members), (
            f"Backfill must not mass-stamp members as gitlab; got {members}"
        )

    def test_does_not_touch_manual_team_members(self):
        db = FakeDatabase()
        # Manual team: no gitlab_group_id -> members must stay manual/untouched.
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
            gitlab_instance_id="inst-a",
            gitlab_group_id=42,
            members=[
                {"user_id": "manual-u", "role": "admin", "source": "manual"},
                {"user_id": "legacy-u", "role": "member"},
            ],
        )

        asyncio.run(_backfill_member_and_team_provenance(db))

        members = {m["user_id"]: m for m in db.teams._docs["t-mixed"]["members"]}
        # A pre-existing manual member must NOT be flipped to gitlab.
        assert members["manual-u"]["source"] == "manual"
        # A legacy (unstamped) member is intentionally left unstamped so it defaults
        # to 'manual' on read and survives the next sync merge.
        assert members["legacy-u"].get("source") != "gitlab"

    def test_stamps_team_source_gitlab_on_projects_of_synced_team(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", gitlab_instance_id="inst-a", gitlab_group_id=42)
        _seed_project(db, "p1", "t-synced", gitlab_instance_id="inst-a", gitlab_project_id=1)

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_source"] == "gitlab"

    def test_does_not_stamp_team_source_for_manual_team_projects(self):
        db = FakeDatabase()
        _seed_team(db, "t-manual", "Atlas")  # no gitlab_group_id
        _seed_project(db, "p1", "t-manual")

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"].get("team_source") is None

    def test_does_not_overwrite_existing_team_source(self):
        db = FakeDatabase()
        _seed_team(db, "t-synced", "GitLab Group: acme", gitlab_instance_id="inst-a", gitlab_group_id=42)
        # A project already explicitly marked manual must be preserved.
        _seed_project(db, "p1", "t-synced", team_source="manual")

        asyncio.run(_backfill_member_and_team_provenance(db))

        assert db.projects._docs["p1"]["team_source"] == "manual"

    def test_idempotent_second_run_is_noop(self):
        db = FakeDatabase()
        _seed_team(
            db,
            "t-synced",
            "GitLab Group: acme",
            gitlab_instance_id="inst-a",
            gitlab_group_id=42,
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
            gitlab_instance_id="inst-a",
            gitlab_group_id=1,
            members=[{"user_id": "u1"}],
        )
        _seed_project(db, "p-bad", "t-bad", gitlab_instance_id="inst-a", gitlab_project_id=1)
        _seed_team(
            db,
            "t-good",
            "GitLab Group: good",
            gitlab_instance_id="inst-a",
            gitlab_group_id=2,
            members=[{"user_id": "u2"}],
        )
        _seed_project(db, "p-good", "t-good", gitlab_instance_id="inst-a", gitlab_project_id=2)

        original_update_many = db.projects.update_many

        async def failing_update_many(query, update, **kwargs):
            if query.get("team_id") == "t-bad":
                raise RuntimeError("boom")
            return await original_update_many(query, update, **kwargs)

        db.projects.update_many = failing_update_many  # type: ignore[method-assign]

        with caplog.at_level("ERROR", logger="app.core.init_db"):
            asyncio.run(_backfill_member_and_team_provenance(db))  # must NOT raise

        # The good team's project must still have been stamped despite the bad team failing.
        assert db.projects._docs["p-good"]["team_source"] == "gitlab"
        assert any("t-bad" in r.message for r in caplog.records)


class TestTeamsUniqueIndexGuard:
    """The teams unique compound-index build must degrade gracefully (log + skip) on a startup duplicate.

    create_indexes runs at pod startup; an unhandled DuplicateKeyError / OperationFailure from that
    one build would crash the pod into CrashLoopBackOff instead of continuing.
    """

    @staticmethod
    def _wrap_teams_index_to_raise(db, exc):
        """Make only the teams unique compound (instance, group) index build raise *exc*."""
        teams = db["teams"]
        original_create_index = teams.create_index

        async def create_index(keys, **kwargs):
            # The guarded index is the unique compound (instance, group) key.
            if (
                isinstance(keys, list)
                and [k[0] for k in keys] == ["gitlab_instance_id", "gitlab_group_id"]
                and kwargs.get("unique")
            ):
                raise exc
            return await original_create_index(keys, **kwargs)

        teams.create_index = create_index  # type: ignore[method-assign]

    def test_duplicate_key_error_does_not_propagate(self, caplog):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(
            db, DuplicateKeyError("E11000 duplicate key error", details={"keyValue": {"gitlab_group_id": 42}})
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


if __name__ == "__main__":
    pytest.main([__file__, "-q"])

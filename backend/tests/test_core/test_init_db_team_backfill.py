"""Tests for the one-time legacy-team backfill in init_db (W1.2, Finding 8).

Legacy synced teams (created before the (instance, group) composite key existed)
have a name like "GitLab Group: {path}" but no gitlab_instance_id / gitlab_group_id.
With the unscoped name fallback removed, the next OIDC sync no longer re-matches
these teams by name — it would create a NEW team and orphan the legacy one.

The numeric gitlab_group_id is NOT recoverable from any local data (projects store
gitlab_project_id, never the group's numeric id), so the backfill cannot
unambiguously resolve the full (instance, group) key from the database alone. The
conservative, safe behavior is therefore: stamp ONLY the unambiguously resolvable
gitlab_instance_id (derived from the single instance of the team's linked projects),
never fabricate a gitlab_group_id, and emit a warning for every legacy team so an
operator knows it must be reconciled by a live re-sync. The migration must be
idempotent and must never touch already-tagged teams.
"""

import asyncio

import pytest

from app.core.init_db import _backfill_synced_team_gitlab_ids
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


if __name__ == "__main__":
    pytest.main([__file__, "-q"])

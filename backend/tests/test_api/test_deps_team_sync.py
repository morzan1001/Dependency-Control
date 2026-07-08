"""Tests for the hybrid team_id update guard used by _handle_gitlab_oidc."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.deps import _gitlab_team_sync_update, _should_overwrite_team_id_from_sync
from app.models.project import Project


def _team_repo_with(raw_team):
    repo = MagicMock()
    repo.get_raw_by_id = AsyncMock(return_value=raw_team)
    return repo


def _project(team_id=None):
    return Project(id="p-1", name="proj", team_id=team_id, gitlab_instance_id="inst-1", gitlab_project_id=100)


def _service_returning(team_id):
    svc = MagicMock()
    svc.get_project_details = AsyncMock(return_value=MagicMock())
    svc.sync_team_from_gitlab = AsyncMock(return_value=team_id)
    return svc


class TestShouldOverwriteTeamIdFromSync:
    def test_returns_true_when_project_has_no_team(self):
        repo = _team_repo_with(None)
        assert asyncio.run(_should_overwrite_team_id_from_sync(None, repo)) is True

    def test_returns_true_when_project_team_id_is_empty_string(self):
        repo = _team_repo_with(None)
        assert asyncio.run(_should_overwrite_team_id_from_sync("", repo)) is True

    def test_returns_true_when_current_team_was_synced_from_gitlab(self):
        repo = _team_repo_with(
            {"_id": "t-1", "name": "GitLab Group: bkg", "gitlab_group_id": 875, "gitlab_instance_id": "inst-1"}
        )
        assert asyncio.run(_should_overwrite_team_id_from_sync("t-1", repo)) is True

    def test_returns_false_when_current_team_is_manual(self):
        repo = _team_repo_with({"_id": "t-2", "name": "Atlas"})
        assert asyncio.run(_should_overwrite_team_id_from_sync("t-2", repo)) is False

    def test_returns_false_when_gitlab_group_id_is_none_explicitly(self):
        repo = _team_repo_with({"_id": "t-3", "name": "Avengers", "gitlab_group_id": None})
        assert asyncio.run(_should_overwrite_team_id_from_sync("t-3", repo)) is False

    def test_returns_true_when_referenced_team_was_deleted(self):
        repo = _team_repo_with(None)
        assert asyncio.run(_should_overwrite_team_id_from_sync("orphan-id", repo)) is True


class TestShouldOverwriteTeamIdProvenanceGate:
    """A manual reassignment must never be reverted by sync even when the target team is GitLab-synced; project provenance is authoritative, not the target team's gitlab_group_id."""

    def test_manual_team_source_blocks_overwrite_even_for_gitlab_team(self):
        repo = _team_repo_with(
            {"_id": "t-1", "name": "GitLab Group: other", "gitlab_group_id": 999, "gitlab_instance_id": "inst-1"}
        )
        result = asyncio.run(_should_overwrite_team_id_from_sync("t-1", repo, team_source="manual"))
        assert result is False

    def test_gitlab_team_source_allows_overwrite(self):
        repo = _team_repo_with(
            {"_id": "t-1", "name": "GitLab Group: x", "gitlab_group_id": 5, "gitlab_instance_id": "inst-1"}
        )
        result = asyncio.run(_should_overwrite_team_id_from_sync("t-1", repo, team_source="gitlab"))
        assert result is True


class TestGitlabTeamSyncUpdate:
    """Integration: _gitlab_team_sync_update wires sync_team_from_gitlab + hybrid guard."""

    def test_returns_empty_when_sync_returns_none(self):
        project = _project(team_id=None)
        svc = _service_returning(None)
        result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
        assert result == {}

    def test_returns_empty_when_sync_returns_same_team(self):
        project = _project(team_id="t-same")
        svc = _service_returning("t-same")
        # No team_repo lookup must happen on the no-change path
        with patch("app.api.deps.TeamRepository") as TR:
            result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
            assert result == {}
            TR.assert_not_called()

    def test_assigns_team_when_project_has_none(self):
        project = _project(team_id=None)
        svc = _service_returning("t-new")
        with patch("app.api.deps.TeamRepository") as TR:
            TR.return_value.get_raw_by_id = AsyncMock(return_value=None)
            result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
        # A sync-driven assignment must stamp gitlab provenance.
        assert result == {"team_id": "t-new", "team_source": "gitlab"}

    def test_overwrites_team_when_current_came_from_gitlab(self):
        project = _project(team_id="t-old-gitlab")
        svc = _service_returning("t-new-gitlab")
        with patch("app.api.deps.TeamRepository") as TR:
            TR.return_value.get_raw_by_id = AsyncMock(return_value={"_id": "t-old-gitlab", "gitlab_group_id": 875})
            result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
        assert result == {"team_id": "t-new-gitlab", "team_source": "gitlab"}

    def test_keeps_manual_team_assignment(self, caplog):
        project = _project(team_id="t-manual")
        project.team_source = "manual"
        svc = _service_returning("t-new-from-sync")
        with patch("app.api.deps.TeamRepository") as TR:
            TR.return_value.get_raw_by_id = AsyncMock(
                return_value={"_id": "t-manual", "name": "Atlas"}  # no gitlab_group_id
            )
            with caplog.at_level("INFO", logger="app.api.deps"):
                result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
        assert result == {}
        assert any("Keeping manual team assignment" in r.message for r in caplog.records), (
            f"Expected info log about kept manual assignment. Got: {[r.message for r in caplog.records]}"
        )

    def test_manual_provenance_blocks_overwrite_to_another_gitlab_team(self):
        project = _project(team_id="t-manual-but-gitlab")
        project.team_source = "manual"
        svc = _service_returning("t-sync-target")
        with patch("app.api.deps.TeamRepository") as TR:
            TR.return_value.get_raw_by_id = AsyncMock(
                return_value={"_id": "t-manual-but-gitlab", "gitlab_group_id": 321, "gitlab_instance_id": "inst-1"}
            )
            result = asyncio.run(_gitlab_team_sync_update(project, 100, "grp/proj", svc, MagicMock()))
        assert result == {}

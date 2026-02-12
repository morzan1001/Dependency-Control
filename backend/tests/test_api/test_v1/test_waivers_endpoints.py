"""Tests for waiver API endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.models.waiver import Waiver

MODULE = "app.api.v1.endpoints.waivers"

_LIST_DEFAULTS = dict(
    finding_id=None,
    package_name=None,
    search=None,
    sort_by="created_at",
    sort_order="desc",
    skip=0,
    limit=50,
)


def _make_waiver(id="waiver-1", project_id="proj-1", reason="Accepted risk", created_by="admin", **kwargs):
    """Create a Waiver with sensible defaults."""
    return Waiver(id=id, project_id=project_id, reason=reason, created_by=created_by, **kwargs)


def _call_list_waivers(current_user, db=None, **overrides):
    """Call list_waivers with sensible defaults, overriding as needed."""
    from app.api.v1.endpoints.waivers import list_waivers

    kwargs = {**_LIST_DEFAULTS, "project_id": None, "current_user": current_user, "db": db or MagicMock()}
    kwargs.update(overrides)
    return asyncio.run(list_waivers(**kwargs))


class TestCreateWaiver:
    def test_admin_can_create_global_waiver(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.recalculate_all_projects"):
                result = asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(project_id=None, reason="Global waiver"),
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert result.project_id is None
        assert result.created_by == admin_user.username
        mock_repo.create.assert_called_once()

    def test_created_by_is_set_to_username(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    result = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", reason="Test"),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        assert result.created_by == "admin"


class TestListWaivers:
    def test_admin_sees_all_waivers(self, admin_user):
        waiver_docs = [
            _make_waiver(id="w1").model_dump(by_alias=True),
            _make_waiver(id="w2").model_dump(by_alias=True),
        ]
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=2)
        mock_repo.find_many = AsyncMock(return_value=waiver_docs)

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            result = _call_list_waivers(admin_user)

        assert result["total"] == 2
        assert len(result["items"]) == 2

    def test_filter_by_project_id(self, admin_user):
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=1)
        mock_repo.find_many = AsyncMock(
            return_value=[
                _make_waiver().model_dump(by_alias=True),
            ]
        )

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
                _call_list_waivers(admin_user, project_id="proj-1")

        count_query = mock_repo.count.call_args[0][0]
        assert count_query["project_id"] == "proj-1"

    def test_no_permission_raises_403(self, viewer_user):
        # Remove waiver:read permissions
        viewer_user.permissions = []

        with pytest.raises(HTTPException) as exc_info:
            _call_list_waivers(viewer_user)
        assert exc_info.value.status_code == 403


class TestDeleteWaiver:
    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.waivers import delete_waiver

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    delete_waiver(
                        waiver_id="missing",
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 404

    def test_deletes_global_waiver_with_manage_permission(self, admin_user):
        from app.api.v1.endpoints.waivers import delete_waiver

        waiver = _make_waiver(project_id=None)
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=waiver)
        mock_repo.delete = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.recalculate_all_projects"):
                asyncio.run(
                    delete_waiver(
                        waiver_id="waiver-1",
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        mock_repo.delete.assert_called_once()


class TestCreateWaiverPermissions:
    """create_waiver checks editor access for project, waiver:manage for global."""

    def test_project_waiver_requires_editor_role(self, regular_user):
        """Verify that check_project_access is called with editor role."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock) as mock_access:
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", reason="Test"),
                            background_tasks=bg_tasks,
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )

        mock_access.assert_called_once()
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == "editor"

    def test_global_waiver_requires_manage_permission(self, regular_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        bg_tasks = BackgroundTasks()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                create_waiver(
                    waiver_in=WaiverCreate(project_id=None, reason="Global waiver"),
                    background_tasks=bg_tasks,
                    current_user=regular_user,
                    db=MagicMock(),
                )
            )
        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail.lower()


class TestDeleteWaiverPermissions:
    """delete_waiver has dual-path logic for project vs global waivers."""

    def test_project_waiver_with_delete_perm_bypasses_project_check(self, admin_user):
        """User with waiver:delete does not need project admin role."""
        from app.api.v1.endpoints.waivers import delete_waiver

        waiver = _make_waiver(project_id="proj-1")
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=waiver)
        mock_repo.delete = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock) as mock_access:
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        delete_waiver(
                            waiver_id="waiver-1",
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        # Admin has waiver:delete, so check_project_access should NOT be called
        mock_access.assert_not_called()
        mock_repo.delete.assert_called_once()

    def test_project_waiver_without_delete_perm_requires_project_admin(self, regular_user):
        """User without waiver:delete needs project admin role."""
        from app.api.v1.endpoints.waivers import delete_waiver

        waiver = _make_waiver(project_id="proj-1")
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=waiver)
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock) as mock_access:
                mock_access.side_effect = HTTPException(status_code=403, detail="Not enough permissions")
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        delete_waiver(
                            waiver_id="waiver-1",
                            background_tasks=bg_tasks,
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )

        assert exc_info.value.status_code == 403
        # Verify PROJECT_ROLE_ADMIN was required
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == "admin"

    def test_global_waiver_needs_manage_or_delete(self, viewer_user):
        """Global waiver deletion needs either waiver:manage or waiver:delete."""
        from app.api.v1.endpoints.waivers import delete_waiver

        waiver = _make_waiver(project_id=None)
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=waiver)
        bg_tasks = BackgroundTasks()

        # Viewer has neither waiver:manage nor waiver:delete
        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    delete_waiver(
                        waiver_id="waiver-1",
                        background_tasks=bg_tasks,
                        current_user=viewer_user,
                        db=MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 403


class TestListWaiversPermissions:
    """list_waivers checks waiver:read_all vs waiver:read."""

    def test_read_all_skips_project_filter(self, admin_user):
        """User with waiver:read_all sees all waivers without $or filter."""
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=0)
        mock_repo.find_many = AsyncMock(return_value=[])

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            _call_list_waivers(admin_user)

        # Query should NOT have $or filter for accessible projects
        count_query = mock_repo.count.call_args[0][0]
        assert "$or" not in count_query

    def test_read_only_gets_own_projects_plus_global(self, regular_user):
        """User with waiver:read but not waiver:read_all gets filtered view."""
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=0)
        mock_repo.find_many = AsyncMock(return_value=[])

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_user_project_ids", new_callable=AsyncMock, return_value=["proj-1", "proj-2"]):
                _call_list_waivers(regular_user)

        count_query = mock_repo.count.call_args[0][0]
        assert "$or" in count_query
        # Should include global waivers (project_id=None) and user's projects
        or_clauses = count_query["$or"]
        assert {"project_id": None} in or_clauses
        assert {"project_id": {"$in": ["proj-1", "proj-2"]}} in or_clauses

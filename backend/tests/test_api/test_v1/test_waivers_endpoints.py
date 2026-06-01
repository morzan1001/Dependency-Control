"""Tests for waiver API endpoints."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.models.waiver import Waiver

MODULE = "app.api.v1.endpoints.waivers"

_LIST_DEFAULTS = {
    "finding_id": None,
    "package_name": None,
    "search": None,
    "sort_by": "created_at",
    "sort_order": "desc",
    "skip": 0,
    "limit": 50,
}


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

        # Project has no latest scan → finding-match validation short-circuits.
        db = MagicMock()
        db.projects.find_one = AsyncMock(return_value={"_id": "proj-1", "latest_scan_id": None})

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    result = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", reason="Test"),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert result.created_by == "admin"


class TestCreateWaiverValidatesFindingMatch:
    """A finding-scope waiver must match at least one finding in the project's
    latest scan; otherwise it is a zombie waiver that will never apply."""

    @staticmethod
    def _mock_db_with_latest_scan(scan_id="scan-1", project_id="proj-1"):
        """Build a MagicMock db whose .projects.find_one returns a project
        with the given latest_scan_id."""

        async def _project_find_one(query, projection=None):
            return {"_id": project_id, "latest_scan_id": scan_id}

        db = MagicMock()
        db.projects.find_one = _project_find_one
        return db

    def test_finding_scope_waiver_with_no_match_raises_422(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            create_waiver(
                                waiver_in=WaiverCreate(
                                    project_id="proj-1",
                                    finding_id="artemis-server:2.40.0",
                                    finding_type="vulnerability",
                                    package_name="artemis-server",
                                    package_version="2.40.0",
                                    scope="finding",
                                    reason="test",
                                ),
                                background_tasks=bg_tasks,
                                current_user=admin_user,
                                db=db,
                            )
                        )

        assert exc_info.value.status_code == 422
        # The error message should be actionable — name what to verify.
        assert "finding_id" in exc_info.value.detail or "match" in exc_info.value.detail.lower()
        # The waiver must NOT have been written.
        mock_repo.create.assert_not_called()

    def test_finding_scope_waiver_with_match_succeeds(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value={"_id": "fid1", "type": "quality", "component": None})

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="QUALITY:artemis-commons:2.43.0",
                                finding_type="quality",
                                scope="finding",
                                reason="ok",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()

    def test_rule_scope_waiver_skips_match_check(self, admin_user):
        """rule-scope is preventive — covers future matches — so no current-scan match is required."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="BEARER-rule_x-src/file.js-1",
                                finding_type="sast",
                                package_name="src/file.js",
                                scope="rule",
                                reason="future",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()

    def test_file_scope_waiver_skips_match_check(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="BEARER-rule_x-src/file.js-1",
                                finding_type="sast",
                                package_name="src/file.js",
                                scope="file",
                                reason="file scope",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()

    def test_global_waiver_skips_match_check(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = MagicMock()
        # If the validator wrongly tried to look up findings, this AsyncMock would be hit.
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.recalculate_all_projects"):
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(
                            project_id=None,
                            finding_id="CVE-9999-9",
                            finding_type="vulnerability",
                            scope="finding",
                            reason="global",
                        ),
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=db,
                    )
                )

        mock_repo.create.assert_called_once()
        db.findings.count_documents.assert_not_called()

    def test_unscanned_project_skips_match_check(self, admin_user):
        """If the project has no latest_scan_id yet, accept the waiver — no scan to validate against."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        async def _project_find_one(query, projection=None):
            return {"_id": "proj-1", "latest_scan_id": None}

        db = MagicMock()
        db.projects.find_one = _project_find_one
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="QUALITY:foo:1.0",
                                finding_type="quality",
                                scope="finding",
                                reason="early",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()
        db.findings.find_one.assert_not_called()

    def test_vulnerability_id_scoped_waiver_skips_finding_id_check(self, admin_user):
        """Waivers targeted at a specific CVE go through apply_vulnerability_waiver,
        which matches by vulnerability_id rather than finding_id, so the finding_id
        format mismatch is irrelevant. Don't 422 these."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value=None)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                vulnerability_id="CVE-2024-1234",
                                package_name="lodash",
                                package_version="4.17.0",
                                scope="finding",
                                reason="cve waived globally for this package",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()

    def test_create_waiver_copies_match_signature(self, admin_user):
        """A finding-scope project waiver should snapshot the matched finding's
        MatchSignature so it can be used for line-drift matching later."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        finding_doc = {
            "_id": "fid",
            "type": "sast",
            "component": "a.py",
            "match": {
                "rule_key": "opengrep:r",
                "file_key": "a.py",
                "anchor": "fp1",
                "anchor_kind": "scanner_fp",
                "content_hash": "c1",
                "last_line": 10,
            },
        }

        db = self._mock_db_with_latest_scan()
        db.findings.find_one = AsyncMock(return_value=finding_doc)

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    created = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="OPENGREP-r-a.py-10",
                                finding_type="sast",
                                package_name="a.py",
                                scope="finding",
                                reason="test match snapshot",
                            ),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert created.match is not None
        assert created.match.anchor == "fp1"
        assert created.match.rule_key == "opengrep:r"
        assert created.match.file_key == "a.py"
        assert created.match.anchor_kind == "scanner_fp"
        assert created.match.content_hash == "c1"
        assert created.match.last_line == 10
        mock_repo.create.assert_called_once()


class TestGetWaiver:
    def test_get_waiver_returns_waiver_for_authorized_user(self, admin_user):
        from app.api.v1.endpoints.waivers import get_waiver

        waiver = _make_waiver(id="waiver-42", project_id="proj-1", reason="Known issue")
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=waiver)

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
                result = asyncio.run(
                    get_waiver(
                        waiver_id="waiver-42",
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert result.id == "waiver-42"
        assert result.reason == "Known issue"
        mock_repo.get_by_id.assert_called_once_with("waiver-42")

    def test_get_waiver_returns_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.waivers import get_waiver

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_waiver(
                        waiver_id="nonexistent",
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Waiver not found"


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

    def test_includes_is_active_flag_per_waiver(self, admin_user):
        """Listed waivers must expose is_active so callers can distinguish
        live waivers from expired ones without re-deriving the rule."""
        now = datetime.now(timezone.utc)
        expired = _make_waiver(id="w-expired", expiration_date=now - timedelta(days=5))
        active = _make_waiver(id="w-active", expiration_date=now + timedelta(days=5))
        no_expiry = _make_waiver(id="w-no-exp", expiration_date=None)
        docs = [w.model_dump(by_alias=True) for w in (expired, active, no_expiry)]

        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=len(docs))
        mock_repo.find_many = AsyncMock(return_value=docs)

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            result = _call_list_waivers(admin_user)

        flags = {item["id"]: item["is_active"] for item in result["items"]}
        assert flags == {"w-expired": False, "w-active": True, "w-no-exp": True}


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

        db = MagicMock()
        db.projects.find_one = AsyncMock(return_value={"_id": "proj-1", "latest_scan_id": None})

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock) as mock_access:
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", reason="Test"),
                            background_tasks=bg_tasks,
                            current_user=regular_user,
                            db=db,
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

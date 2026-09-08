"""Tests for waiver API endpoints."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_PENDING
from app.models.waiver import Waiver
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.waivers"

_PROJECT = "proj-1"
_BRANCH = "main"
_HEAD_SCAN = "scan-1"
_QUEUED_SCAN = "scan-2"

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
    return Waiver(id=id, project_id=project_id, reason=reason, created_by=created_by, **kwargs)


def _call_list_waivers(current_user, db=None, **overrides):
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
    """A finding-scope waiver must match at least one finding on the project's head build, else it is a zombie waiver that never applies."""

    @staticmethod
    def _db_with_head_scan(scan_id=_HEAD_SCAN, project_id=_PROJECT, findings=(), scans=True):
        """A project whose head resolves to ``scan_id``, plus whatever findings that build holds."""
        db = FakeDatabase()
        db.projects._docs[project_id] = {
            "_id": project_id,
            "name": "P",
            "default_branch": _BRANCH,
            "deleted_branches": [],
            "latest_scan_id": scan_id if scans else None,
        }
        if scans:
            db.scans._docs[scan_id] = {
                "_id": scan_id,
                "project_id": project_id,
                "branch": _BRANCH,
                "status": SCAN_STATUS_COMPLETED,
                "created_at": datetime.now(timezone.utc),
            }
        for i, finding in enumerate(findings):
            db.findings._docs[f"f-{i}"] = {"scan_id": scan_id, "project_id": project_id, **finding}
        return db

    def test_finding_scope_waiver_with_no_match_raises_422(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()

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
        assert "finding_id" in exc_info.value.detail or "match" in exc_info.value.detail.lower()
        mock_repo.create.assert_not_called()

    def test_finding_scope_waiver_with_match_succeeds(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan(
            findings=[{"finding_id": "QUALITY:artemis-commons:2.43.0", "type": "quality", "component": None}]
        )

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

    def test_validation_reads_the_head_build_not_the_queued_scan_the_pointer_names(self, admin_user):
        """A queued scan holds no findings, so validating against the pointer would reject a waiver
        for a finding the head build really reports."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan(
            findings=[{"finding_id": "QUALITY:artemis-commons:2.43.0", "type": "quality", "component": None}]
        )
        db.scans._docs[_QUEUED_SCAN] = {
            "_id": _QUEUED_SCAN,
            "project_id": _PROJECT,
            "branch": _BRANCH,
            "status": SCAN_STATUS_PENDING,
            "created_at": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        db.projects._docs[_PROJECT]["latest_scan_id"] = _QUEUED_SCAN

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.recalculate_project_stats"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id=_PROJECT,
                                finding_id="QUALITY:artemis-commons:2.43.0",
                                finding_type="quality",
                                scope="finding",
                                reason="ok",
                            ),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=db,
                        )
                    )

        mock_repo.create.assert_called_once()

    def test_rule_scope_waiver_skips_match_check(self, admin_user):
        """rule-scope is preventive — covers future matches — so no current-scan match is required."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()

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

        db = self._db_with_head_scan()

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

    def test_unscoped_license_waiver_is_rejected(self, admin_user):
        """finding_id is not unique per scan for license/eol; prod scan fe02e2bf has 115
        documents under LIC-GPL-2.0-only, so an unscoped waiver would blanket all of them."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = MagicMock()
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(
                            project_id=None,
                            finding_id="LIC-GPL-2.0-only",
                            finding_type="license",
                            scope="finding",
                            reason="approved",
                        ),
                        background_tasks=BackgroundTasks(),
                        current_user=admin_user,
                        db=db,
                    )
                )

        assert exc.value.status_code == 422
        assert "package_name" in exc.value.detail
        mock_repo.create.assert_not_called()

    def test_unknown_placeholder_does_not_count_as_a_package_scope(self, admin_user):
        """The waiver form sends 'Unknown' when it cannot resolve a package; _build_waiver_query
        drops it, so it must not satisfy the scope requirement either."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(
                            project_id=None,
                            finding_id="LIC-GPL-2.0-only",
                            finding_type="license",
                            package_name="Unknown",
                            scope="finding",
                            reason="approved",
                        ),
                        background_tasks=BackgroundTasks(),
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert exc.value.status_code == 422
        mock_repo.create.assert_not_called()

    def test_scoped_license_waiver_is_accepted(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = MagicMock()
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.recalculate_all_projects"):
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(
                            project_id=None,
                            finding_id="LIC-GPL-2.0-only",
                            finding_type="license",
                            package_name="spring-core",
                            scope="finding",
                            reason="approved",
                        ),
                        background_tasks=BackgroundTasks(),
                        current_user=admin_user,
                        db=db,
                    )
                )

        mock_repo.create.assert_called_once()

    def test_unscanned_project_skips_match_check(self, admin_user):
        """If the project has no latest_scan_id yet, accept the waiver — no scan to validate against."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan(scans=False)

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

    def test_vulnerability_id_scoped_waiver_skips_finding_id_check(self, admin_user):
        """CVE-targeted waivers match by vulnerability_id, not finding_id, so the finding_id format mismatch must not 422."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()

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
        """A finding-scope project waiver snapshots the matched finding's MatchSignature for later line-drift matching."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        finding_doc = {
            "finding_id": "OPENGREP-r-a.py-10",
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

        db = self._db_with_head_scan(findings=[finding_doc])

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


class TestUpdateWaiverRecalc:
    """update_waiver must re-run stats recalc whenever a field gating waiver application changes; active state is driven by expiration_date, so expiring/extending must trigger recalculation."""

    def _run_update(self, admin_user, update_kwargs):
        from app.api.v1.endpoints.waivers import update_waiver
        from app.schemas.waiver import WaiverUpdate

        existing = _make_waiver(id="waiver-1", project_id="proj-1")
        updated = _make_waiver(id="waiver-1", project_id="proj-1", **update_kwargs)
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=existing)
        mock_repo.update = AsyncMock(return_value=updated)
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
                with patch(f"{MODULE}.recalculate_project_stats") as mock_recalc:
                    asyncio.run(
                        update_waiver(
                            waiver_id="waiver-1",
                            waiver_in=WaiverUpdate(**update_kwargs),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )
        return bg_tasks, mock_recalc

    def test_expiration_date_change_triggers_recalc(self, admin_user):
        """Expiring/extending a waiver changes the active set and must schedule recalculate_project_stats."""
        new_expiry = datetime.now(timezone.utc) - timedelta(days=1)
        bg_tasks, mock_recalc = self._run_update(admin_user, {"expiration_date": new_expiry})

        scheduled = [t.func for t in bg_tasks.tasks]
        assert mock_recalc in scheduled

    def test_status_change_still_triggers_recalc(self, admin_user):
        bg_tasks, mock_recalc = self._run_update(admin_user, {"status": "false_positive"})

        scheduled = [t.func for t in bg_tasks.tasks]
        assert mock_recalc in scheduled

    def test_reason_only_change_does_not_trigger_recalc(self, admin_user):
        bg_tasks, mock_recalc = self._run_update(admin_user, {"reason": "Updated reason"})

        scheduled = [t.func for t in bg_tasks.tasks]
        assert mock_recalc not in scheduled


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
        viewer_user.permissions = []

        with pytest.raises(HTTPException) as exc_info:
            _call_list_waivers(viewer_user)
        assert exc_info.value.status_code == 403

    def test_includes_is_active_flag_per_waiver(self, admin_user):
        """Listed waivers must expose is_active so callers can distinguish live from expired without re-deriving the rule."""
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


class TestOrphanedFilter:
    """FakeDatabase-backed: the orphaned filter is a query, so a mock that answers every query the
    same way cannot tell whether it selected anything."""

    _NOW = datetime.now(timezone.utc)
    _WINDOW = timedelta(days=5)

    def _db(self):
        db = FakeDatabase()
        for waiver in (
            _make_waiver(id="w-orphaned", last_eval_scan_id="s1", last_match_count=0),
            _make_waiver(id="w-matching", last_eval_scan_id="s1", last_match_count=1),
            _make_waiver(id="w-unevaluated", last_eval_scan_id=None, last_match_count=0),
            _make_waiver(
                id="w-orphaned-expired",
                last_eval_scan_id="s1",
                last_match_count=0,
                expiration_date=self._NOW - self._WINDOW,
            ),
            _make_waiver(
                id="w-orphaned-expiring",
                last_eval_scan_id="s1",
                last_match_count=0,
                expiration_date=self._NOW + self._WINDOW,
            ),
        ):
            db.waivers._docs[waiver.id] = waiver.model_dump(by_alias=True)
        return db

    def test_only_evaluated_unexpired_waivers_matching_nothing_are_orphaned(self, admin_user):
        db = self._db()

        result = _call_list_waivers(admin_user, db=db, orphaned=True)

        assert sorted(item["id"] for item in result["items"]) == ["w-orphaned", "w-orphaned-expiring"]
        assert result["total"] == len(result["items"])

    def test_without_the_filter_every_waiver_is_listed(self, admin_user):
        db = self._db()

        result = _call_list_waivers(admin_user, db=db)

        assert result["total"] == len(db.waivers._docs)

    def test_the_evaluation_state_is_exposed_on_each_item(self, admin_user):
        db = self._db()

        result = _call_list_waivers(admin_user, db=db, orphaned=True)

        orphaned = next(item for item in result["items"] if item["id"] == "w-orphaned")
        assert (orphaned["last_eval_scan_id"], orphaned["last_match_count"]) == ("s1", 0)


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

        # admin has waiver:delete, so project access is not checked
        mock_access.assert_not_called()
        mock_repo.delete.assert_called_once()

    def test_project_waiver_without_delete_perm_requires_project_admin(self, regular_user):
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
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == "admin"

    def test_global_waiver_needs_manage_or_delete(self, viewer_user):
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
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=0)
        mock_repo.find_many = AsyncMock(return_value=[])

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            _call_list_waivers(admin_user)

        count_query = mock_repo.count.call_args[0][0]
        assert "$or" not in count_query

    def test_read_only_gets_own_projects_plus_global(self, regular_user):
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=0)
        mock_repo.find_many = AsyncMock(return_value=[])

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_user_project_ids", new_callable=AsyncMock, return_value=["proj-1", "proj-2"]):
                _call_list_waivers(regular_user)

        count_query = mock_repo.count.call_args[0][0]
        assert "$or" in count_query
        or_clauses = count_query["$or"]
        assert {"project_id": None} in or_clauses
        assert {"project_id": {"$in": ["proj-1", "proj-2"]}} in or_clauses

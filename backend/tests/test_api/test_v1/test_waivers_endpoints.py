"""Tests for waiver API endpoints."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_PENDING
from app.models.project import Project
from app.models.waiver import Waiver
from app.services.stats import run_waiver_recalc
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.waivers"

_PROJECT = "proj-1"
_BRANCH = "main"
_HEAD_SCAN = "scan-1"
_QUEUED_SCAN = "scan-2"
_BRANCH_SCAN = "scan-feature"

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


def _stored_bearer_finding(finding_id: str, rule_id: str, scan_id: str) -> dict:
    return {
        "_id": f"{scan_id}:{finding_id}",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "finding_id": finding_id,
        "type": "sast",
        "details": {"sast_findings": [{"id": rule_id, "scanner": "bearer"}]},
    }


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
            with patch(f"{MODULE}.request_waiver_recalc") as mock_request:
                result = asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(project_id=None, package_name="requests", reason="Global waiver"),
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert result.project_id is None
        assert result.created_by == admin_user.username
        mock_repo.create.assert_called_once()
        assert mock_request.await_args.args[1] is result
        assert [t.func for t in bg_tasks.tasks] == [run_waiver_recalc]

    def test_created_by_is_set_to_username(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        # Project has no scan to head it → finding-match validation short-circuits.
        db = MagicMock()
        db.projects.find_one = AsyncMock(return_value={"_id": "proj-1", "latest_scan_id": None})
        db.scans.find_one = AsyncMock(return_value=None)

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
                    result = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", package_name="requests", reason="Test"),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert result.created_by == "admin"


def _project_access(db):
    """check_project_access answering with the project the fake database holds."""
    return AsyncMock(return_value=Project(**db.projects._docs[_PROJECT]))


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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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
        db.findings._docs["elsewhere"] = _stored_bearer_finding("BEARER-rule_x-src/file.js-1", "rule_x", "other-scan")

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

    @pytest.mark.parametrize("scope", ["file", "rule"])
    def test_a_widened_scope_takes_its_rule_from_the_finding_it_was_taken_from(self, admin_user, scope):
        """A merged SAST id names no rule; the finding's own details do."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()
        db.findings._docs["merged"] = _stored_bearer_finding(
            "SAST-AGG-src/file.rb-12", "ruby_lang_weak-hash", _HEAD_SCAN
        )

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
                    created = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_id="SAST-AGG-src/file.rb-12",
                                finding_type="sast",
                                package_name="src/file.rb",
                                scope=scope,
                                reason="future",
                            ),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert created.rule_id == "ruby_lang_weak-hash"

    def test_file_scope_waiver_skips_match_check(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()
        db.findings._docs["elsewhere"] = _stored_bearer_finding("BEARER-rule_x-src/file.js-1", "rule_x", "other-scan")

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        bg_tasks = BackgroundTasks()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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
            with patch(f"{MODULE}.request_waiver_recalc"):
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

    @pytest.mark.parametrize("project_id", [None, _PROJECT])
    def test_a_waiver_naming_nothing_to_match_is_rejected(self, admin_user, project_id):
        """It would match no finding, or every one; the restamp skips it and it sits orphaned."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock):
                with pytest.raises(HTTPException) as exc:
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id=project_id, package_name="Unknown", reason="r"),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )

        assert exc.value.status_code == 422
        mock_repo.create.assert_not_called()

    @pytest.mark.parametrize("finding_id", ["LIC-GPL-2.0-only", "EOL-python-3.8"])
    def test_an_unscoped_shared_id_is_rejected_without_its_type(self, admin_user, finding_id):
        """The id names the type the caller left out, and a global waiver never reaches the head-build check."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(project_id=None, finding_id=finding_id, reason="approved"),
                        background_tasks=BackgroundTasks(),
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert exc.value.status_code == 422
        mock_repo.create.assert_not_called()

    def test_unknown_placeholder_does_not_count_as_a_package_scope(self, admin_user):
        """The waiver form sends 'Unknown' when it cannot resolve a package, which is no package scope."""
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

    @pytest.mark.parametrize("scope", ["file", "rule"])
    def test_a_widened_scope_needs_a_finding_or_a_rule_to_widen(self, admin_user, scope):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(project_id=None, finding_type="sast", scope=scope, reason="approved"),
                        background_tasks=BackgroundTasks(),
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        assert exc.value.status_code == 422
        mock_repo.create.assert_not_called()

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"scope": "file", "rule_id": "weak_rng"}, id="file scope without its file"),
            pytest.param(
                {"scope": "rule", "finding_id": "BEARER-weak_rng-src/a.js-3", "package_name": "src/a.js"},
                id="global widened scope without its rule_id",
            ),
            pytest.param(
                {"scope": "rule", "rule_id": "x", "finding_type": "license", "package_name": "lib"},
                id="widened scope on a type without a location",
            ),
        ],
    )
    def test_a_widened_scope_that_cannot_name_its_rule_and_place_is_rejected(self, admin_user, fields):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    create_waiver(
                        waiver_in=WaiverCreate(project_id=None, reason="approved", **fields),
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
            with patch(f"{MODULE}.request_waiver_recalc"):
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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
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

    def test_a_waiver_naming_no_finding_is_not_pinned_to_the_one_the_check_found(self, admin_user):
        """Type and file describe every secret in the file; one signature would narrow that to a single one."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        signature = {"rule_key": "AWS", "file_key": "values.yaml", "anchor": "aaaa", "anchor_kind": "secret_hash"}
        secret = {"type": "secret", "component": "values.yaml", "match": signature}
        db = self._db_with_head_scan(findings=[{**secret, "finding_id": "SECRET-AWS-aaaa"}])

        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
                    created = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id="proj-1",
                                finding_type="secret",
                                package_name="values.yaml",
                                reason="fixtures",
                            ),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert created.match is None

    def test_a_finding_only_the_waived_scan_reports_is_validated_on_that_scan(self, admin_user):
        """A waiver written from a feature-branch scan names a finding the default branch does not have yet."""
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()
        db.scans._docs[_BRANCH_SCAN] = {
            "_id": _BRANCH_SCAN,
            "project_id": _PROJECT,
            "branch": "feature",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
        db.findings._docs["f-branch"] = {
            "scan_id": _BRANCH_SCAN,
            "project_id": _PROJECT,
            "finding_id": "OPENGREP-r-a.py-10",
            "type": "sast",
            "component": "a.py",
            "match": {"rule_key": "opengrep:r", "file_key": "a.py", "anchor": "fp-branch", "anchor_kind": "scanner_fp"},
        }
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc") as recalc:
                    created = asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id=_PROJECT,
                                scan_id=_BRANCH_SCAN,
                                finding_id="OPENGREP-r-a.py-10",
                                finding_type="sast",
                                package_name="a.py",
                                scope="finding",
                                reason="branch only",
                            ),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert created.match is not None and created.match.anchor == "fp-branch"
        assert "scan_id" not in created.model_dump()
        assert recalc.call_args.kwargs == {"restamp": [_BRANCH_SCAN]}

    def test_a_scan_of_another_project_is_refused(self, admin_user):
        from app.api.v1.endpoints.waivers import create_waiver
        from app.schemas.waiver import WaiverCreate

        db = self._db_with_head_scan()
        db.scans._docs["scan-foreign"] = {
            "_id": "scan-foreign",
            "project_id": "proj-2",
            "status": SCAN_STATUS_COMPLETED,
        }
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()

        with patch(f"{MODULE}.check_project_access", _project_access(db)):
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(
                                project_id=_PROJECT,
                                scan_id="scan-foreign",
                                finding_id="QUALITY:foo:1.0",
                                finding_type="quality",
                                scope="rule",
                                reason="r",
                            ),
                            background_tasks=BackgroundTasks(),
                            current_user=admin_user,
                            db=db,
                        )
                    )

        assert exc_info.value.status_code == 404
        mock_repo.create.assert_not_called()


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
    """Every writable field (reason, status, expiration_date) changes what the stamped findings say."""

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
                with patch(f"{MODULE}.request_waiver_recalc") as mock_request:
                    asyncio.run(
                        update_waiver(
                            waiver_id="waiver-1",
                            waiver_in=WaiverUpdate(**update_kwargs),
                            background_tasks=bg_tasks,
                            current_user=admin_user,
                            db=MagicMock(),
                        )
                    )
        queued = [call.args[1] for call in mock_request.await_args_list]
        return [waiver.id for waiver in queued], [t.func for t in bg_tasks.tasks]

    def test_expiration_date_change_triggers_recalc(self, admin_user):
        """Expiring/extending a waiver changes the active set and must queue the recalculation."""
        new_expiry = datetime.now(timezone.utc) - timedelta(days=1)

        assert self._run_update(admin_user, {"expiration_date": new_expiry}) == (["waiver-1"], [run_waiver_recalc])

    def test_status_change_still_triggers_recalc(self, admin_user):
        assert self._run_update(admin_user, {"status": "false_positive"}) == (["waiver-1"], [run_waiver_recalc])

    def test_reason_only_change_triggers_recalc(self, admin_user):
        """Findings carry the reason of the waiver that covers them, so a new reason is restamped."""
        assert self._run_update(admin_user, {"reason": "Updated reason"}) == (["waiver-1"], [run_waiver_recalc])


class TestListWaivers:
    def test_admin_sees_all_waivers(self, admin_user):
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=2)
        mock_repo.find_many = AsyncMock(return_value=[_make_waiver(id="w1"), _make_waiver(id="w2")])

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            result = _call_list_waivers(admin_user)

        assert result["total"] == 2
        assert len(result["items"]) == 2

    def test_filter_by_project_id(self, admin_user):
        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=1)
        mock_repo.find_many = AsyncMock(return_value=[_make_waiver()])

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
        waivers = [expired, active, no_expiry]

        mock_repo = MagicMock()
        mock_repo.count = AsyncMock(return_value=len(waivers))
        mock_repo.find_many = AsyncMock(return_value=waivers)

        with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
            result = _call_list_waivers(admin_user)

        flags = {item["id"]: item["is_active"] for item in result["items"]}
        assert flags == {"w-expired": False, "w-active": True, "w-no-exp": True}


class TestWaiverResponseShape:
    """Every waiver endpoint answers one shape: is_active computed on read, the match signature internal."""

    def test_a_waiver_stored_while_active_lists_as_expired_once_it_lapses(self, admin_user):
        db = FakeDatabase()
        lapsed = _make_waiver(id="w-lapsed", expiration_date=datetime.now(timezone.utc) - timedelta(days=1))
        match = {"rule_key": "bearer:r1", "file_key": "app.py", "anchor": "a1", "anchor_kind": "scanner_fp"}
        db.waivers._docs[lapsed.id] = {**lapsed.model_dump(by_alias=True), "is_active": True, "match": match}

        (item,) = _call_list_waivers(admin_user, db=db)["items"]

        assert item["is_active"] is False
        assert "match" not in item

    def test_a_legacy_status_does_not_fail_the_page(self, admin_user):
        db = FakeDatabase()
        legacy = _make_waiver(id="w-legacy", status="risk_accepted_legacy", scope="component")
        db.waivers._docs[legacy.id] = legacy.model_dump(by_alias=True)

        (item,) = _call_list_waivers(admin_user, db=db)["items"]

        assert (item["status"], item["scope"]) == ("risk_accepted_legacy", "component")

    def test_a_single_waiver_response_carries_is_active(self):
        from app.schemas.waiver import WaiverResponse

        waiver = _make_waiver(id="w-1", expiration_date=None)

        assert WaiverResponse.model_validate(waiver).model_dump()["is_active"] is True

    def test_the_computed_flag_is_not_persisted(self):
        assert "is_active" not in _make_waiver(id="w-1").model_dump(by_alias=True)


class TestListFilters:
    """FakeDatabase-backed: the filters are queries, so a mock that answers every query the same
    way cannot tell whether they selected anything."""

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

    def test_the_active_filter_lists_every_waiver_that_has_not_expired(self, admin_user):
        db = self._db()

        result = _call_list_waivers(admin_user, db=db, active=True)

        listed = sorted(item["id"] for item in result["items"])
        assert listed == ["w-matching", "w-orphaned", "w-orphaned-expiring", "w-unevaluated"]
        assert result["total"] == len(listed)

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
            with patch(f"{MODULE}.request_waiver_recalc") as mock_request:
                asyncio.run(
                    delete_waiver(
                        waiver_id="waiver-1",
                        background_tasks=bg_tasks,
                        current_user=admin_user,
                        db=MagicMock(),
                    )
                )

        mock_repo.delete.assert_called_once()
        assert mock_request.await_args.args[1] is waiver
        assert [t.func for t in bg_tasks.tasks] == [run_waiver_recalc]


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
        db.scans.find_one = AsyncMock(return_value=None)

        with patch(f"{MODULE}.check_project_access", new_callable=AsyncMock) as mock_access:
            with patch(f"{MODULE}.WaiverRepository", return_value=mock_repo):
                with patch(f"{MODULE}.request_waiver_recalc"):
                    asyncio.run(
                        create_waiver(
                            waiver_in=WaiverCreate(project_id="proj-1", package_name="requests", reason="Test"),
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
                    waiver_in=WaiverCreate(project_id=None, package_name="requests", reason="Global waiver"),
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
                with patch(f"{MODULE}.request_waiver_recalc"):
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

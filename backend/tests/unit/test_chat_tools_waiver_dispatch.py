"""Dispatch-level tests for waiver-related chat tools.

Verify that the MCP-exposed chat tools honour ``expiration_date``: an expired
waiver must not appear as active. The application path
(``find_active_for_project``) already filters expired waivers; the read path
(``get_waiver_status``, ``list_project_waivers``, ``list_global_waivers``) must
match that contract or the user sees a stale picture.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


def _seed_project(db, project_id: str = "proj-1") -> None:
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": "test-project",
        "team_id": None,
    }


def _seed_waiver(db, **overrides) -> dict:
    waiver_id = overrides.pop("id", "w-1")
    doc = {
        "_id": waiver_id,
        "project_id": overrides.pop("project_id", "proj-1"),
        "finding_id": overrides.pop("finding_id", "QUALITY:foo:1.0"),
        "package_name": overrides.pop("package_name", "foo"),
        "package_version": overrides.pop("package_version", "1.0"),
        "finding_type": overrides.pop("finding_type", "quality"),
        "scope": overrides.pop("scope", "finding"),
        "reason": overrides.pop("reason", "test"),
        "status": overrides.pop("status", "accepted_risk"),
        "expiration_date": overrides.pop("expiration_date", None),
        "created_by": overrides.pop("created_by", "tester"),
        "created_at": overrides.pop("created_at", datetime.now(timezone.utc)),
    }
    doc.update(overrides)
    db.waivers._docs[waiver_id] = doc
    return doc


class TestGetWaiverStatusExpiry:
    @pytest.mark.asyncio
    async def test_expired_waiver_reports_not_waived(self, db, admin_user):
        _seed_project(db)
        past = datetime.now(timezone.utc) - timedelta(days=30)
        _seed_waiver(db, expiration_date=past)

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "proj-1", "finding_id": "QUALITY:foo:1.0"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert "expired_waiver" in result, "expired waiver must be surfaced for transparency"
        assert result["expired_waiver"]["id"] == "w-1"

    @pytest.mark.asyncio
    async def test_active_waiver_no_finding_doc_reports_present_but_not_suppressing(self, db, admin_user):
        # No finding doc in latest scan → active waiver exists but is NOT suppressing anything.
        # Old assertion (waived:true) encoded the bug; new contract: waived:false, waiver_present:true.
        _seed_project(db)
        future = datetime.now(timezone.utc) + timedelta(days=30)
        _seed_waiver(db, expiration_date=future)

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "proj-1", "finding_id": "QUALITY:foo:1.0"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert result["waiver_present"] is True
        assert result["suppressing"] is False
        assert result["reason"]  # reason text must be non-empty
        assert result["waiver"]["id"] == "w-1"

    @pytest.mark.asyncio
    async def test_waiver_without_expiry_no_finding_doc_reports_present_but_not_suppressing(self, db, admin_user):
        # No finding doc in latest scan → no-expiry waiver exists but is NOT suppressing anything.
        # Old assertion (waived:true) encoded the bug; new contract: waived:false, waiver_present:true.
        _seed_project(db)
        _seed_waiver(db, expiration_date=None)

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "proj-1", "finding_id": "QUALITY:foo:1.0"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert result["waiver_present"] is True
        assert result["suppressing"] is False


class TestGetWaiverStatusNoFindingDoc:
    @pytest.mark.asyncio
    async def test_get_waiver_status_no_latest_scan_id_reports_present_but_not_suppressing(self, db, admin_user):
        # Scenario: project has NO latest_scan_id at all (never scanned or scan id cleared).
        # finding stays None because latest_scan_id is falsy → skip the DB lookup entirely.
        # An active waiver exists, but with nothing to suppress it should report present-but-not-suppressing.
        # This is distinct from the TestGetWaiverStatusExpiry cases where a scan exists but the
        # finding doc is simply absent from it.
        _seed_project(db)  # deliberately omits latest_scan_id
        future = datetime.now(timezone.utc) + timedelta(days=30)
        _seed_waiver(db, expiration_date=future)

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "proj-1", "finding_id": "QUALITY:foo:1.0"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert result["waiver_present"] is True
        assert result["suppressing"] is False
        assert result["reason"]  # reason text must be non-empty


class TestGetWaiverStatusFindingFlags:
    @pytest.mark.asyncio
    async def test_reports_waived_from_finding_flag(self, db, admin_user):
        # finding waived in latest scan by recalc; waiver may have a different/old finding_id
        await db["findings"].insert_one(
            {
                "_id": "x",
                "scan_id": "scan1",
                "finding_id": "OPENGREP-r-a.py-99",
                "project_id": "p1",
                "type": "sast",
                "waived": True,
                "waiver_reason": "fp",
            }
        )
        db.projects._docs["p1"] = {"_id": "p1", "name": "test", "team_id": None, "latest_scan_id": "scan1"}

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "p1", "finding_id": "OPENGREP-r-a.py-99"},
            admin_user,
            db,
        )

        assert result["waived"] is True

    @pytest.mark.asyncio
    async def test_reports_lapsed(self, db, admin_user):
        await db["findings"].insert_one(
            {
                "_id": "y",
                "scan_id": "scan1",
                "finding_id": "OPENGREP-r-a.py-10",
                "project_id": "p1",
                "type": "sast",
                "waived": False,
                "waiver_lapsed": True,
                "lapsed_waiver_id": "w1",
            }
        )
        db.projects._docs["p1"] = {"_id": "p1", "name": "test", "team_id": None, "latest_scan_id": "scan1"}

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "p1", "finding_id": "OPENGREP-r-a.py-10"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert result.get("lapsed") is True


class TestListProjectWaiversIsActive:
    @pytest.mark.asyncio
    async def test_active_and_expired_waivers_get_is_active_flag(self, db, admin_user):
        _seed_project(db)
        future = datetime.now(timezone.utc) + timedelta(days=30)
        past = datetime.now(timezone.utc) - timedelta(days=30)
        _seed_waiver(db, id="w-active", finding_id="QUALITY:a:1", expiration_date=future)
        _seed_waiver(db, id="w-expired", finding_id="QUALITY:b:1", expiration_date=past)
        _seed_waiver(db, id="w-no-expiry", finding_id="QUALITY:c:1", expiration_date=None)

        result = await ChatToolRegistry()._dispatch(
            "list_project_waivers",
            {"project_id": "proj-1"},
            admin_user,
            db,
        )

        flags = {w["id"]: w["is_active"] for w in result["waivers"]}
        assert flags == {"w-active": True, "w-expired": False, "w-no-expiry": True}


class TestListGlobalWaiversIsActive:
    @pytest.mark.asyncio
    async def test_global_waivers_get_is_active_flag(self, db, admin_user):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        past = datetime.now(timezone.utc) - timedelta(days=30)
        _seed_waiver(db, id="g-active", project_id=None, finding_id="CVE-1", expiration_date=future)
        _seed_waiver(db, id="g-expired", project_id=None, finding_id="CVE-2", expiration_date=past)

        result = await ChatToolRegistry()._dispatch(
            "list_global_waivers",
            {},
            admin_user,
            db,
        )

        flags = {w["id"]: w["is_active"] for w in result["waivers"]}
        assert flags == {"g-active": True, "g-expired": False}

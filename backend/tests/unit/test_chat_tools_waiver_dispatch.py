"""Waiver chat tool read paths must honour expiration_date so expired waivers never appear active."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.services.chat.tools import ChatToolRegistry

_BRANCH = "main"


def _seed_project(db, project_id: str = "proj-1") -> None:
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": "test-project",
    }


def _seed_scanned_project(db, project_id: str, scan_id: str) -> None:
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": "test",
        "default_branch": _BRANCH,
        "deleted_branches": [],
        "latest_scan_id": scan_id,
    }
    db.scans._docs[scan_id] = {
        "_id": scan_id,
        "project_id": project_id,
        "branch": _BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": datetime.now(timezone.utc),
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
        _seed_scanned_project(db, "proj-1", "scan-1")
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
    async def test_an_expired_waiver_is_reported_inactive_whatever_its_document_says(self, db, admin_user):
        _seed_scanned_project(db, "proj-1", "scan-1")
        _seed_waiver(db, expiration_date=datetime.now(timezone.utc) - timedelta(days=1), is_active=True)

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "proj-1", "finding_id": "QUALITY:foo:1.0"},
            admin_user,
            db,
        )

        assert result["expired_waiver"]["is_active"] is False

    @pytest.mark.asyncio
    async def test_active_waiver_no_finding_doc_reports_present_but_not_suppressing(self, db, admin_user):
        _seed_scanned_project(db, "proj-1", "scan-1")
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
        assert result["reason"]
        assert result["waiver"]["id"] == "w-1"

    @pytest.mark.asyncio
    async def test_waiver_without_expiry_no_finding_doc_reports_present_but_not_suppressing(self, db, admin_user):
        _seed_scanned_project(db, "proj-1", "scan-1")
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


class TestGetWaiverStatusFindingFlags:
    @pytest.mark.asyncio
    async def test_reports_waived_from_finding_flag(self, db, admin_user):
        # The finding is waived in the latest scan even though the waiver's finding_id differs.
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
        _seed_scanned_project(db, "p1", "scan1")

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
        _seed_scanned_project(db, "p1", "scan1")

        result = await ChatToolRegistry()._dispatch(
            "get_waiver_status",
            {"project_id": "p1", "finding_id": "OPENGREP-r-a.py-10"},
            admin_user,
            db,
        )

        assert result["waived"] is False
        assert result["findings"][0]["lapsed"] is True


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

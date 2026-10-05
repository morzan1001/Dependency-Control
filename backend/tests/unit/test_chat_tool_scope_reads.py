"""An estate-wide tool reads the caller's scope once per call, and an unseen project_id is unknown."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER
from tests.mocks.fake_mongo import FakeCollection, FakeDatabase

_NOW = datetime.now(timezone.utc)
_CALLER = "u-scope"
_PROJECTS = ("p-a", "p-b")
_UNSCANNED = "p-unscanned"
_CVE = "CVE-2026-50001"
_COMPONENT = "libscope"
_ERR_PROJECT = "Project not found or access denied"
_ERR_NO_SCAN_DATA = "No scan data available"


def _user(permissions: list[str]) -> User:
    return User(id=_CALLER, username="scope", email="scope@test.com", permissions=[*permissions, "chat:access"])


def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    for pid in (*_PROJECTS, _UNSCANNED):
        scan_id = f"{pid}-scan"
        db.projects._docs[pid] = {
            "_id": pid,
            "name": f"name-{pid}",
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": None if pid == _UNSCANNED else scan_id,
            "members": [{"user_id": _CALLER, "role": "viewer"}],
        }
        if pid == _UNSCANNED:
            continue
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": pid,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": _NOW,
            "stats": {"critical": 1, "high": 0},
        }
        for finding_type in ("license", "vulnerability"):
            db.findings._docs[f"{pid}-{finding_type}"] = {
                "_id": f"{pid}-{finding_type}",
                "finding_id": _CVE,
                "scan_id": scan_id,
                "project_id": pid,
                "severity": "CRITICAL",
                "type": finding_type,
                "component": _COMPONENT,
                "version": "1.0",
                "created_at": _NOW - timedelta(days=90),
                "details": {
                    "vulnerabilities": [{"id": _CVE, "severity": "CRITICAL", "in_kev": True, "fixed_version": "1.0.1"}],
                    "exploit_maturity": "active",
                    "fixed_version": "1.0.1",
                },
            }
        db.dependencies._docs[f"{pid}-d"] = {
            "_id": f"{pid}-d",
            "scan_id": scan_id,
            "project_id": pid,
            "name": _COMPONENT,
        }
        db.waivers._docs[f"{pid}-w"] = {
            "_id": f"{pid}-w",
            "project_id": pid,
            "finding_id": _CVE,
            "expiration_date": _NOW + timedelta(days=3),
        }
    return db


def _record(collection: FakeCollection) -> list[Any]:
    """Every filter the collection is read with."""
    seen: list[Any] = []
    for method in ("find", "find_one", "aggregate", "count_documents"):
        original = getattr(collection, method)

        def spy(query=None, *args, _original=original, **kwargs):
            seen.append(query)
            return _original(query, *args, **kwargs)

        setattr(collection, method, spy)
    return seen


async def _call(tool_name: str, args: dict, user: User, db: FakeDatabase) -> dict:
    return await ChatToolRegistry().execute_tool(tool_name, args, user, db)


@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("get_analytics_summary", {}),
        ("get_top_priority_findings", {}),
        ("find_component_usage", {"component_name": _COMPONENT}),
        ("get_hotspots", {}),
        ("get_kev_findings", {}),
        ("get_auto_fixable_findings", {}),
        ("get_license_violations", {}),
        ("get_findings_by_cve", {"cve_id": _CVE}),
        ("search_findings", {"query": _CVE}),
    ],
)
@pytest.mark.asyncio
async def test_an_estate_wide_tool_reads_the_callers_projects_once(tool_name: str, args: dict) -> None:
    db = _seeded()
    project_reads = _record(db.projects)

    result = await _call(tool_name, args, _user(PRESET_USER), db)

    assert "error" not in result
    assert f"name-{_PROJECTS[0]}" in json.dumps(result, default=str)
    assert len(project_reads) == 1


@pytest.mark.asyncio
async def test_a_caller_reading_every_project_sends_no_project_id_list() -> None:
    db = _seeded()
    queries = _record(db.waivers)
    project_reads = _record(db.projects)

    result = await _call("get_expiring_waivers", {}, _user(PRESET_ADMIN), db)

    assert "error" not in result
    assert all("$in" not in json.dumps(q.get("project_id", {}), default=str) for q in queries if q)
    assert {} not in project_reads


@pytest.mark.parametrize(
    "tool_name", ["get_kev_findings", "get_auto_fixable_findings", "get_stale_findings", "get_license_violations"]
)
@pytest.mark.asyncio
async def test_an_unknown_project_id_is_answered_as_unknown_not_as_empty(tool_name: str) -> None:
    db = _seeded()
    user = _user(PRESET_USER)

    unknown = await _call(tool_name, {"project_id": "p-absent"}, user, db)
    unscanned = await _call(tool_name, {"project_id": _UNSCANNED}, user, db)

    assert unknown == {"error": _ERR_PROJECT}
    assert unscanned["message"] == _ERR_NO_SCAN_DATA

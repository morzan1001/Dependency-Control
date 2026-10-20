"""The chat links an entity only through project_id and scan_id, which _inject_urls and chat-entities.ts key on."""

from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.services.chat.tools import ChatToolRegistry

_PROJECT = "p-links"
_PROJECT_NAME = "links-project"
_SCAN = "scan-links"
_TEAM = "team-links"
_PROJECT_URL = f"{settings.FRONTEND_BASE_URL}/projects/{_PROJECT}"
_SCAN_URL = f"{_PROJECT_URL}/scans/{_SCAN}"


@pytest.fixture
def seeded(db):
    now = datetime(2026, 10, 20, tzinfo=timezone.utc)
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": _PROJECT_NAME,
        "team_ids": [_TEAM],
        "latest_scan_id": _SCAN,
        "default_branch": "main",
        "last_scan_at": now,
        "created_at": now,
    }
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": now,
        "stats": {},
    }
    db.teams._docs[_TEAM] = {"_id": _TEAM, "name": "links-team", "members": []}
    db.system_settings._docs["current"] = {"_id": "current"}
    return db


async def _run(db, user, tool: str, **arguments) -> dict:
    return await ChatToolRegistry().execute_tool(tool, arguments, user, db)


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "arguments"), [("list_projects", {}), ("get_team_projects", {"team_id": _TEAM})])
async def test_a_project_row_names_its_project_and_links_it(seeded, admin_user, tool, arguments):
    (row,) = (await _run(seeded, admin_user, tool, **arguments))["projects"]

    assert (row["id"], row["project_id"], row["project_name"]) == (_PROJECT, _PROJECT, _PROJECT_NAME)
    assert row["url"] == _PROJECT_URL


@pytest.mark.asyncio
async def test_the_project_details_name_their_project_and_link_it(seeded, admin_user):
    project = (await _run(seeded, admin_user, "get_project_details", project_id=_PROJECT))["project"]

    assert (project["id"], project["project_id"], project["project_name"]) == (_PROJECT, _PROJECT, _PROJECT_NAME)
    assert project["url"] == _PROJECT_URL


@pytest.mark.asyncio
async def test_a_scan_history_row_links_its_scan(seeded, admin_user):
    (row,) = (await _run(seeded, admin_user, "get_scan_history", project_id=_PROJECT))["scans"]

    assert (row["id"], row["project_id"], row["scan_id"]) == (_SCAN, _PROJECT, _SCAN)
    assert row["url"] == _SCAN_URL


@pytest.mark.asyncio
async def test_the_scan_details_link_the_scan_not_its_project(seeded, admin_user):
    scan = (await _run(seeded, admin_user, "get_scan_details", project_id=_PROJECT))["scan"]

    assert (scan["id"], scan["scan_id"]) == (_SCAN, _SCAN)
    assert scan["url"] == _SCAN_URL

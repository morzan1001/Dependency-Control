"""The project-scoped analytics routes admit and refuse exactly as check_project_access does."""

from datetime import datetime, timezone

import pytest

from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers

_ANALYTICS = [Permissions.ANALYTICS_READ, Permissions.ANALYTICS_RECOMMENDATIONS]
# project:update opens every project on every other project route, without project:read.
_WRITE_SUPERUSER = bearer_headers("editor-of-all", [*_ANALYTICS, Permissions.PROJECT_UPDATE])
_MEMBER_OF_NOTHING = bearer_headers("stranger", [*_ANALYTICS, Permissions.PROJECT_READ])


_ROUTES = ["recommendations", "update-frequency", "scan-delta"]


def _request(route: str, project_id: str) -> tuple[str, dict[str, str]]:
    if route == "scan-delta":
        params = {"project_id": project_id, "from_scan_id": "s1", "to_scan_id": "s2", "category": "findings"}
        return "/api/v1/analytics/scan-delta", params
    return f"/api/v1/analytics/projects/{project_id}/{route}", {}


async def _seed_project_with_scans(db) -> None:
    await db.projects.insert_one({"_id": "gp", "name": "gated", "members": []})
    now = datetime.now(timezone.utc)
    for scan_id in ("s1", "s2"):
        await db.scans.insert_one(
            {"_id": scan_id, "project_id": "gp", "branch": "main", "status": "completed", "created_at": now}
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _ROUTES)
async def test_a_write_superuser_opens_a_project_they_are_not_a_member_of(client, db, route):
    await _seed_project_with_scans(db)
    path, params = _request(route, "gp")

    resp = await client.get(path, params=params, headers=_WRITE_SUPERUSER)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _ROUTES)
async def test_a_non_member_is_refused(client, db, route):
    await _seed_project_with_scans(db)
    path, params = _request(route, "gp")

    resp = await client.get(path, params=params, headers=_MEMBER_OF_NOTHING)

    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _ROUTES)
async def test_an_unknown_project_is_not_found(client, route):
    path, params = _request(route, "absent")

    resp = await client.get(path, params=params, headers=_WRITE_SUPERUSER)

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "Project not found"

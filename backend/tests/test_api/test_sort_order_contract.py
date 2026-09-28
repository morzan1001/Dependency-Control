"""sort_order means one thing on every listing: "asc" or "desc", anything else is refused rather than guessed."""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_current_active_user
from app.api.v1.endpoints import analytics, inventory, projects, teams, users, waivers
from app.core.permissions import ALL_PERMISSIONS
from app.db.mongodb import get_database
from app.models.user import User


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    user = User(id="u1", username="u1", email="u1@test.com", permissions=list(ALL_PERMISSIONS))

    async def _user() -> User:
        return user

    async def _db() -> MagicMock:
        return MagicMock()

    app.dependency_overrides[get_current_active_user] = _user
    app.dependency_overrides[get_database] = _db
    app.include_router(projects.router, prefix="/projects")
    app.include_router(teams.router, prefix="/teams")
    app.include_router(users.router, prefix="/users")
    app.include_router(waivers.router, prefix="/waivers")
    app.include_router(analytics.router, prefix="/analytics")
    app.include_router(inventory.router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/projects/", {}),
        ("/projects/scans", {}),
        ("/projects/p1/scans", {}),
        ("/projects/scans/s1/findings", {}),
        ("/teams/", {}),
        ("/users/", {}),
        ("/waivers/", {}),
        ("/analytics/search", {"q": "lodash"}),
        ("/analytics/vulnerability-search", {"q": "CVE-2021"}),
        ("/analytics/hotspots", {}),
        ("/projects/p1/inventory/components", {}),
    ],
)
@pytest.mark.parametrize("sort_order", ["ASC", "DESC", "descending"])
def test_a_sort_order_other_than_asc_or_desc_is_refused(client, path, params, sort_order):
    response = client.get(path, params={**params, "sort_order": sort_order})

    assert response.status_code == 422
    assert [error["loc"] for error in response.json()["detail"]] == [["query", "sort_order"]]

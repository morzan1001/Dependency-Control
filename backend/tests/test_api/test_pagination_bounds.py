"""Tests that skip/limit on the core listing endpoints are bounded and rejected with 422 when out of range."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ENDPOINTS = "app.api.v1.endpoints.projects"


# FastAPI Query validators run at framework level, so we inspect the Annotated
# metadata on each parameter rather than calling the coroutine directly.


def _get_query_object(func, param_name: str):
    """Return the FastAPI Query object attached to *param_name* via Annotated."""
    import inspect
    from typing import Annotated, get_args, get_origin

    from fastapi.params import Query as FastAPIQuery

    sig = inspect.signature(func)
    if param_name not in sig.parameters:
        return None
    annotation = sig.parameters[param_name].annotation
    if get_origin(annotation) is Annotated:
        args = get_args(annotation)
        for meta in args[1:]:
            if isinstance(meta, FastAPIQuery):
                return meta
    return None


def _bound(func, param_name: str, bound: str):
    """Return the ge/le/gt/lt value for *param_name* on *func*, or None."""
    query_obj = _get_query_object(func, param_name)
    if query_obj is None:
        return None
    # FastAPI/pydantic stores constraints in Query.metadata as Ge/Le/Gt/Lt objects.
    for item in getattr(query_obj, "metadata", []):
        val = getattr(item, bound, None)
        if val is not None:
            return val
    return None


@pytest.mark.parametrize("name", ["read_projects", "read_all_scans", "read_project_scans", "read_scan_findings"])
def test_the_default_page_lies_within_its_bounds(name):
    import importlib
    import inspect

    endpoint = getattr(importlib.import_module(ENDPOINTS), name)
    defaults = {param: value.default for param, value in inspect.signature(endpoint).parameters.items()}

    assert _bound(endpoint, "limit", "ge") <= defaults["limit"] <= _bound(endpoint, "limit", "le")
    assert _bound(endpoint, "skip", "ge") <= defaults["skip"]


def _make_test_app():
    """Build a minimal FastAPI app with the projects router + stub auth so Query validation runs."""
    from fastapi import FastAPI

    from app.api.deps import get_current_active_user
    from app.api.v1.endpoints import projects as proj_module
    from app.core.permissions import ALL_PERMISSIONS
    from app.db.mongodb import get_database
    from app.models.user import User

    stub_user = User(
        id="test-1",
        username="test",
        email="test@test.com",
        permissions=list(ALL_PERMISSIONS),
    )

    app = FastAPI()

    async def _get_user():
        return stub_user

    async def _get_db():
        return MagicMock()

    app.dependency_overrides[get_current_active_user] = _get_user
    app.dependency_overrides[get_database] = _get_db

    app.include_router(proj_module.router, prefix="/projects")
    return app


@pytest.fixture(scope="module")
def test_client():
    from fastapi.testclient import TestClient

    app = _make_test_app()
    return TestClient(app, raise_server_exceptions=False)


class TestHTTP422OnOutOfBoundsParams:
    @pytest.mark.parametrize(
        ("path", "params"),
        [
            pytest.param("/projects/", {"limit": 101}, id="projects_limit_too_large"),
            pytest.param("/projects/", {"limit": 0}, id="projects_limit_zero"),
            pytest.param("/projects/", {"skip": -1}, id="projects_skip_negative"),
            pytest.param("/projects/scans", {"limit": 101}, id="all_scans_limit_too_large"),
            pytest.param("/projects/scans", {"limit": 0}, id="all_scans_limit_zero"),
            pytest.param("/projects/scans", {"skip": -1}, id="all_scans_skip_negative"),
            pytest.param("/projects/proj-1/scans", {"limit": 101}, id="project_scans_limit_too_large"),
            pytest.param("/projects/proj-1/scans", {"limit": 0}, id="project_scans_limit_zero"),
            pytest.param("/projects/proj-1/scans", {"skip": -1}, id="project_scans_skip_negative"),
            pytest.param("/projects/scans/scan-1/findings", {"limit": 10_000_000}, id="findings_limit_too_large"),
            pytest.param("/projects/scans/scan-1/findings", {"limit": 0}, id="findings_limit_zero"),
            pytest.param("/projects/scans/scan-1/findings", {"skip": -1}, id="findings_skip_negative"),
            pytest.param("/projects/scans/scan-1/findings", {"limit": 501}, id="findings_limit_just_over_cap"),
        ],
    )
    def test_out_of_bounds_pagination_params_return_422(self, test_client, path, params):
        r = test_client.get(path, params=params)
        assert r.status_code == 422, f"Expected 422 for {params}, got {r.status_code}: {r.text}"

    def test_read_projects_valid_params_not_422(self, test_client):
        with (
            patch(f"{ENDPOINTS}.ProjectRepository") as mock_repo_cls,
            patch(f"{ENDPOINTS}.TeamRepository") as mock_team_cls,
            patch(f"{ENDPOINTS}.has_permission", return_value=True),
            patch(f"{ENDPOINTS}.build_user_project_query", new_callable=AsyncMock, return_value={}),
            patch(
                f"{ENDPOINTS}.build_pagination_response",
                return_value={"items": [], "total": 0, "page": 1, "pages": 0, "size": 20},
            ),
        ):
            mock_repo = MagicMock()
            mock_repo.count = AsyncMock(return_value=0)
            mock_repo.find_many = AsyncMock(return_value=[])
            mock_repo_cls.return_value = mock_repo
            mock_team_cls.return_value = MagicMock()
            r = test_client.get("/projects/", params={"limit": 20, "skip": 0})
        assert r.status_code != 422, f"Valid params should not return 422, got {r.status_code}"

    def _patched_findings_call(self, test_client, limit):
        """Fire a findings request with handler internals stubbed so only Query validation decides 422."""
        with (
            patch(f"{ENDPOINTS}._require_scan_access", new_callable=AsyncMock),
            patch(f"{ENDPOINTS}.FindingRepository") as mock_repo_cls,
            patch(
                f"{ENDPOINTS}.build_pagination_response",
                return_value={"items": [], "total": 0, "page": 1, "pages": 0, "size": limit},
            ),
        ):
            mock_repo = MagicMock()
            mock_repo.aggregate = AsyncMock(return_value=[{"data": [], "total": [{"count": 0}]}])
            mock_repo_cls.return_value = mock_repo
            return test_client.get("/projects/scans/scan-1/findings", params={"limit": limit})

    # 200 is what FindingsTable.tsx sends, 500 is the agreed cap.
    @pytest.mark.parametrize("limit", [200, 500])
    def test_read_scan_findings_limit_accepted(self, test_client, limit):
        r = self._patched_findings_call(test_client, limit)
        assert r.status_code != 422, f"limit={limit} must be accepted, got {r.status_code}: {r.text}"


class TestReadUsersPaginationBounds:
    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.users import read_users

        return read_users

    def test_a_zero_or_negative_limit_is_refused(self, endpoint):
        assert _bound(endpoint, "limit", "ge") == 1

    def test_limit_has_le_cap(self, endpoint):
        assert _bound(endpoint, "limit", "le") == 100

    def test_skip_cannot_go_negative(self, endpoint):
        assert _bound(endpoint, "skip", "ge") == 0


@pytest.mark.parametrize("module", ["gitlab_instances", "github_instances"])
class TestVcsInstanceListPaginationBounds:
    @pytest.fixture
    def endpoint(self, module):
        import importlib

        return importlib.import_module(f"app.api.v1.endpoints.{module}").list_instances

    def test_page_starts_at_one(self, endpoint):
        assert _bound(endpoint, "page", "ge") == 1

    def test_a_zero_size_is_refused(self, endpoint):
        assert _bound(endpoint, "size", "ge") == 1

    def test_size_has_le_cap(self, endpoint):
        assert _bound(endpoint, "size", "le") == 100

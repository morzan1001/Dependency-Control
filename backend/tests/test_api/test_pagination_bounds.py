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


class TestReadProjectsPaginationBounds:
    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.projects import read_projects

        return read_projects

    def test_skip_has_ge_zero(self, endpoint):
        assert _bound(endpoint, "skip", "ge") == 0, (
            "skip should have ge=0 — negative skip is nonsensical and can cause issues"
        )

    def test_limit_has_ge_one(self, endpoint):
        assert _bound(endpoint, "limit", "ge") == 1, (
            "limit should have ge=1 — zero limit would return no rows but still hit DB"
        )

    def test_limit_has_le_cap(self, endpoint):
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None, "limit must have an le= upper cap"
        assert cap <= 1000, f"limit cap {cap} looks too large — keep it ≤ 1000"

    def test_default_skip_within_bounds(self, endpoint):
        import inspect

        default = inspect.signature(endpoint).parameters["skip"].default
        ge = _bound(endpoint, "skip", "ge")
        if ge is not None:
            assert default >= ge

    def test_default_limit_within_bounds(self, endpoint):
        import inspect

        default = inspect.signature(endpoint).parameters["limit"].default
        ge = _bound(endpoint, "limit", "ge")
        le = _bound(endpoint, "limit", "le")
        if ge is not None:
            assert default >= ge
        if le is not None:
            assert default <= le


class TestReadAllScansPaginationBounds:
    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.projects import read_all_scans

        return read_all_scans

    def test_skip_has_ge_zero(self, endpoint):
        assert _bound(endpoint, "skip", "ge") == 0

    def test_limit_has_ge_one(self, endpoint):
        assert _bound(endpoint, "limit", "ge") == 1

    def test_limit_has_le_cap(self, endpoint):
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None
        assert cap <= 1000

    def test_default_limit_within_bounds(self, endpoint):
        import inspect

        default = inspect.signature(endpoint).parameters["limit"].default
        le = _bound(endpoint, "limit", "le")
        if le is not None:
            assert default <= le


class TestReadProjectScansPaginationBounds:
    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.projects import read_project_scans

        return read_project_scans

    def test_skip_has_ge_zero(self, endpoint):
        assert _bound(endpoint, "skip", "ge") == 0

    def test_limit_has_ge_one(self, endpoint):
        assert _bound(endpoint, "limit", "ge") == 1

    def test_limit_has_le_cap(self, endpoint):
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None
        assert cap <= 1000

    def test_default_limit_within_bounds(self, endpoint):
        import inspect

        default = inspect.signature(endpoint).parameters["limit"].default
        le = _bound(endpoint, "limit", "le")
        if le is not None:
            assert default <= le


class TestReadScanFindingsPaginationBounds:
    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.projects import read_scan_findings

        return read_scan_findings

    def test_skip_has_ge_zero(self, endpoint):
        assert _bound(endpoint, "skip", "ge") == 0

    def test_limit_has_ge_one(self, endpoint):
        assert _bound(endpoint, "limit", "ge") == 1

    def test_limit_has_le_cap(self, endpoint):
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None
        assert cap <= 1000

    def test_default_limit_within_bounds(self, endpoint):
        import inspect

        default = inspect.signature(endpoint).parameters["limit"].default
        le = _bound(endpoint, "limit", "le")
        if le is not None:
            assert default <= le

    def test_limit_cap_covers_frontend_request_of_200(self, endpoint):
        """FindingsTable.tsx requests up to limit=200, so the cap must be >= 500 for headroom."""
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None, "limit must have an le= upper cap"
        assert cap >= 500, (
            f"read_scan_findings limit cap is {cap}; frontend requests up to 200 "
            "and the agreed cap is 500 — a cap below 500 regresses FindingsTable."
        )


def _make_test_app():
    """Build a minimal FastAPI app with the projects router + stub auth so Query validation runs."""
    from fastapi import FastAPI
    from app.api.v1.endpoints import projects as proj_module
    from app.api.deps import get_current_active_user
    from app.db.mongodb import get_database

    from app.core.permissions import ALL_PERMISSIONS
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
    def test_read_projects_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_projects_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_projects_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

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

    def test_read_all_scans_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_all_scans_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_all_scans_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_project_scans_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_project_scans_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_project_scans_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_scan_findings_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_scan_findings_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_scan_findings_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def _patched_findings_call(self, test_client, limit):
        """Fire a findings request with handler internals stubbed so only Query validation decides 422."""
        with (
            patch(f"{ENDPOINTS}._resolve_scan_for_findings", new_callable=AsyncMock),
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

    def test_read_scan_findings_limit_200_accepted(self, test_client):
        """FindingsTable.tsx sends limit=200; it must NOT 422."""
        r = self._patched_findings_call(test_client, 200)
        assert r.status_code != 422, f"limit=200 must be accepted, got {r.status_code}: {r.text}"

    def test_read_scan_findings_limit_500_accepted(self, test_client):
        r = self._patched_findings_call(test_client, 500)
        assert r.status_code != 422, f"limit=500 must be accepted, got {r.status_code}: {r.text}"

    def test_read_scan_findings_limit_501_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"limit": 501})
        assert r.status_code == 422, f"Expected 422 for limit=501, got {r.status_code}: {r.text}"

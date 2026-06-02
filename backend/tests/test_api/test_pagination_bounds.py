"""Tests for bounded pagination params on core listing endpoints (Finding 11 / W3).

Verifies that ``skip`` / ``limit`` on the four listing endpoints are rejected
(422 Unprocessable Entity) when out of bounds, and that valid values still work.

Endpoints under test:
  - GET /projects/               → read_projects
  - GET /projects/scans          → read_all_scans
  - GET /projects/{id}/scans     → read_project_scans
  - GET /projects/scans/{id}/findings → read_scan_findings

Strategy: call the endpoint functions directly (same pattern as
test_projects_authz.py and test_waivers_endpoints.py) so we don't need a live
HTTP server. FastAPI validates Annotated Query params **before** the route
handler runs; we exercise that by calling through the TestClient which runs the
full request lifecycle, or by inspecting the function signature annotations
directly via the FastAPI parameter system.

We use the lightweight approach: instantiate a FastAPI TestClient on the real
app router and fire real (mocked-transport) requests so FastAPI's validation
runs. If the app fixture isn't available in this test context, we fall back to
direct FastAPI app construction from the router.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ENDPOINTS = "app.api.v1.endpoints.projects"


# ---------------------------------------------------------------------------
# Helper: call the function with keyword args; FastAPI Query validators run
# at framework level so we can't bypass them by calling the coroutine directly.
# Instead we inspect the Annotated metadata on each parameter.
# ---------------------------------------------------------------------------


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
    """Return ge/le/gt/lt value for *param_name* on *func*, or None.

    FastAPI stores numeric constraints in Query.metadata as annotated_types
    instances (Ge, Le, Gt, Lt).  We search those for the requested bound.
    """
    query_obj = _get_query_object(func, param_name)
    if query_obj is None:
        return None
    # FastAPI/pydantic stores constraints in Query.metadata as Ge/Le/Gt/Lt objects
    for item in getattr(query_obj, "metadata", []):
        val = getattr(item, bound, None)
        if val is not None:
            return val
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReadProjectsPaginationBounds:
    """read_projects: skip/limit must be bounded."""

    @pytest.fixture
    def endpoint(self):
        from app.api.v1.endpoints.projects import read_projects
        return read_projects

    def test_skip_has_ge_zero(self, endpoint):
        """skip must not allow negative values."""
        assert _bound(endpoint, "skip", "ge") == 0, (
            "skip should have ge=0 — negative skip is nonsensical and can cause issues"
        )

    def test_limit_has_ge_one(self, endpoint):
        """limit=0 must be rejected."""
        assert _bound(endpoint, "limit", "ge") == 1, (
            "limit should have ge=1 — zero limit would return no rows but still hit DB"
        )

    def test_limit_has_le_cap(self, endpoint):
        """limit must have an upper cap (le) to prevent DoS."""
        cap = _bound(endpoint, "limit", "le")
        assert cap is not None, "limit must have an le= upper cap"
        assert cap <= 1000, f"limit cap {cap} looks too large — keep it ≤ 1000"

    def test_default_skip_within_bounds(self, endpoint):
        """Default skip must satisfy ge=0."""
        import inspect
        default = inspect.signature(endpoint).parameters["skip"].default
        ge = _bound(endpoint, "skip", "ge")
        if ge is not None:
            assert default >= ge

    def test_default_limit_within_bounds(self, endpoint):
        """Default limit must satisfy ge=1 and le=cap."""
        import inspect
        default = inspect.signature(endpoint).parameters["limit"].default
        ge = _bound(endpoint, "limit", "ge")
        le = _bound(endpoint, "limit", "le")
        if ge is not None:
            assert default >= ge
        if le is not None:
            assert default <= le


class TestReadAllScansPaginationBounds:
    """read_all_scans: skip/limit must be bounded."""

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
    """read_project_scans: skip/limit must be bounded."""

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
    """read_scan_findings: skip/limit must be bounded."""

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


# ---------------------------------------------------------------------------
# HTTP-level validation tests via FastAPI TestClient
# FastAPI rejects out-of-bound Query params with 422 before the handler runs.
# We mount only the projects router with a stub auth dependency so auth does
# not interfere.
# ---------------------------------------------------------------------------

def _make_test_app():
    """Build a minimal FastAPI app with the projects router + stub auth."""
    from fastapi import FastAPI
    from app.api.v1.endpoints import projects as proj_module
    from app.api.deps import get_current_active_user
    from app.db.mongodb import get_database

    # Stub current user and DB so the router can be registered
    from app.core.permissions import ALL_PERMISSIONS
    from app.models.user import User

    stub_user = User(
        id="test-1",
        username="test",
        email="test@test.com",
        permissions=list(ALL_PERMISSIONS),
    )

    app = FastAPI()

    # Override deps
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
    """End-to-end: FastAPI must return 422 for out-of-bound pagination params."""

    # --- read_projects ---

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
        with patch(f"{ENDPOINTS}.ProjectRepository") as mock_repo_cls, \
             patch(f"{ENDPOINTS}.TeamRepository") as mock_team_cls, \
             patch(f"{ENDPOINTS}.has_permission", return_value=True), \
             patch(f"{ENDPOINTS}.build_user_project_query", new_callable=AsyncMock, return_value={}), \
             patch(f"{ENDPOINTS}.build_pagination_response", return_value={"items": [], "total": 0, "page": 1, "pages": 0, "size": 20}):
            mock_repo = MagicMock()
            mock_repo.count = AsyncMock(return_value=0)
            mock_repo.find_many = AsyncMock(return_value=[])
            mock_repo_cls.return_value = mock_repo
            mock_team_cls.return_value = MagicMock()
            r = test_client.get("/projects/", params={"limit": 20, "skip": 0})
        assert r.status_code != 422, f"Valid params should not return 422, got {r.status_code}"

    # --- read_all_scans ---

    def test_read_all_scans_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_all_scans_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_all_scans_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/scans", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    # --- read_project_scans ---

    def test_read_project_scans_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_project_scans_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_project_scans_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/proj-1/scans", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    # --- read_scan_findings ---

    def test_read_scan_findings_limit_too_large_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"limit": 10_000_000})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_scan_findings_limit_zero_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"limit": 0})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_read_scan_findings_skip_negative_returns_422(self, test_client):
        r = test_client.get("/projects/scans/scan-1/findings", params={"skip": -1})
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

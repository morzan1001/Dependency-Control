"""Every scoped analytics route and the chat tool accept the same four scopes and refuse anything else."""

from typing import get_args

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_current_active_user, get_database
from app.api.v1.endpoints import compliance_reports, crypto_analytics, pqc_migration
from app.models.user import User
from app.schemas.analytics import ScopeKind
from app.services.chat.tools.definitions import TOOL_DEFINITIONS
from tests.mocks.fake_mongo import FakeDatabase

_SCOPED_ROUTES = [
    "/compliance/reports?",
    "/analytics/crypto/hotspots?",
    "/analytics/crypto/trends?range_start=2026-01-01T00:00:00Z&range_end=2026-02-01T00:00:00Z&",
    "/analytics/crypto/pqc-migration?",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _SCOPED_ROUTES)
async def test_an_unknown_scope_is_rejected_before_resolution(route):
    app = FastAPI()
    for module in (compliance_reports, crypto_analytics, pqc_migration):
        app.include_router(module.router)
    app.dependency_overrides[get_current_active_user] = lambda: User(
        id="u-1", username="u-1", email="u-1@corp.com", permissions=[]
    )
    app.dependency_overrides[get_database] = FakeDatabase

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"{route}scope=everything")

    assert response.status_code == 422


def test_the_chat_tool_offers_exactly_the_api_scopes():
    tool = next(t for t in TOOL_DEFINITIONS if t["function"]["name"] == "get_framework_evaluation_summary")

    assert tool["function"]["parameters"]["properties"]["scope"]["enum"] == list(get_args(ScopeKind))

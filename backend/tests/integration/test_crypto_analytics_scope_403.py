"""Crypto-analytics scope-authorization failures surface as HTTP 403 (with a detail body) via the app-level exception handler, not 500."""

from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_hotspots_returns_403_for_non_member(client, owner_auth_headers_proj_p2):
    """A member of project p2 must NOT resolve the 'p' project scope."""
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name"},
        headers=owner_auth_headers_proj_p2,
    )
    assert resp.status_code == 403, resp.text
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_trends_returns_403_for_non_member(client, owner_auth_headers_proj_p2):
    """Same scope guard on the trends endpoint, via the app-level handler."""
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/api/v1/analytics/crypto/trends",
        params={
            "scope": "project",
            "scope_id": "p",
            "range_start": (now - timedelta(days=30)).isoformat(),
            "range_end": now.isoformat(),
        },
        headers=owner_auth_headers_proj_p2,
    )
    assert resp.status_code == 403, resp.text
    assert "detail" in resp.json()

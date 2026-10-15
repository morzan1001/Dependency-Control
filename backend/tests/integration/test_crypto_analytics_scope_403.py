from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_hotspots_returns_403_for_non_member(client, owner_auth_headers_proj_p2):
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name"},
        headers=owner_auth_headers_proj_p2,
    )
    assert resp.status_code == 403, resp.text
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_trends_returns_403_for_non_member(client, owner_auth_headers_proj_p2):
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

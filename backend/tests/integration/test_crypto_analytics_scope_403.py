"""
Regression tests for the centralized ScopeResolutionError handler.

The per-endpoint ``try/except ScopeResolutionError -> HTTPException(403)``
boilerplate was replaced by a single ``@app.exception_handler`` in
``app.main``. These tests exercise the crypto-analytics endpoints
(hotspots + trends) end-to-end and assert that a scope-authorization
failure still surfaces as HTTP 403 with a ``detail`` body -- i.e. the
handler is wired up and the error is not leaking as a 500.
"""

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

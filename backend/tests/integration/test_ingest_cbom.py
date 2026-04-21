"""
Integration tests for POST /api/v1/ingest/cbom.

Authentication and database dependencies are overridden in conftest.py, so no
live MongoDB or API key infrastructure is required.
"""

import asyncio
import json
from pathlib import Path

import pytest

from app.repositories.crypto_asset import CryptoAssetRepository

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


async def _wait_for_scan(db, scan_id: str, timeout: float = 5.0) -> None:
    """Poll the scans collection until scan status is non-pending, or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("status") not in ("running", "pending", None):
            return
        await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_ingest_cbom_creates_assets(client, db, api_key_headers):
    """Submitting a valid CBOM returns 202 and eventually creates CryptoAsset records."""
    payload = {
        "scan_metadata": {"git_ref": "main", "commit_sha": "abc123"},
        "cbom": _load("legacy_crypto_mixed.json"),
    }
    resp = await client.post(
        "/api/v1/ingest/cbom", json=payload, headers=api_key_headers
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    scan_id = body["scan_id"]
    assert body["status"] in ("accepted", "completed")

    # Background task runs in-process; wait briefly for it to complete
    await _wait_for_scan(db, scan_id)

    # legacy_crypto_mixed.json has 3 cryptographic-asset components
    project_id = "test-project-id"
    count = await CryptoAssetRepository(db).count_by_scan(project_id, scan_id)
    assert count == 3, f"Expected 3 crypto assets, got {count}"


@pytest.mark.asyncio
async def test_ingest_cbom_rejects_empty_cbom(client, db, api_key_headers):
    """A CBOM with no cryptographic-asset components returns 400."""
    payload = {
        "cbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
    }
    resp = await client.post(
        "/api/v1/ingest/cbom", json=payload, headers=api_key_headers
    )
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_ingest_cbom_rejects_unauthenticated(db):
    """Requests without auth credentials must be rejected with 401 or 403."""
    from app.main import app
    from app.api.deps import get_system_settings
    from app.db.mongodb import get_database
    from app.models.system import SystemSettings
    from httpx import AsyncClient, ASGITransport

    # Override only the DB and system-settings deps; leave auth dep real so it
    # enforces credential checking.
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    async def _fake_get_database():
        return db

    def _fake_system_settings():
        return SystemSettings()

    app.dependency_overrides[get_database] = _fake_get_database
    app.dependency_overrides[get_system_settings] = _fake_system_settings

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v1/ingest/cbom", json={"cbom": {}})
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)

    assert resp.status_code in (401, 403), resp.text

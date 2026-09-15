"""Integration tests for POST /api/v1/ingest/cbom."""

import asyncio
import json
from pathlib import Path

import pytest
from prometheus_client import REGISTRY

from app.repositories.crypto_asset import CryptoAssetRepository

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


def _ingests(status: str) -> float:
    return REGISTRY.get_sample_value("cbom_ingests_total", {"status": status}) or 0.0


async def _wait_for_scan(db, scan_id: str, timeout: float = 5.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("status") not in ("running", "pending", None):
            return
        await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_ingest_cbom_creates_assets(client, db, api_key_headers):
    payload = {
        "scan_metadata": {"git_ref": "main", "commit_sha": "abc123"},
        "cbom": _load("legacy_crypto_mixed.json"),
    }
    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    scan_id = body["scan_id"]
    assert body["status"] in ("accepted", "completed")

    await _wait_for_scan(db, scan_id)

    # legacy_crypto_mixed.json has 3 cryptographic-asset components.
    project_id = "test-project-id"
    count = await CryptoAssetRepository(db).count_by_scan(project_id, scan_id)
    assert count == 3, f"Expected 3 crypto assets, got {count}"


@pytest.mark.asyncio
async def test_ingest_cbom_rejects_empty_cbom(client, db, api_key_headers):
    payload = {
        "cbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
    }
    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_ingest_cbom_rejects_unauthenticated(db):
    from httpx import ASGITransport, AsyncClient

    from app.api.deps import get_system_settings
    from app.db.mongodb import get_database
    from app.main import app
    from app.models.system import SystemSettings

    # Override only the DB and system-settings deps; leave the auth dep real so it enforces credential checking.
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


@pytest.mark.asyncio
async def test_legacy_git_ref_becomes_the_scan_branch(client, db, api_key_headers):
    """The GitLab-shaped envelope spells the branch ``git_ref``; scan identity and lineage key on it."""
    payload = {
        "scan_metadata": {"git_ref": "release/7.2", "commit_sha": "abc123"},
        "cbom": _load("legacy_crypto_mixed.json"),
    }

    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    scan = await db.scans.find_one({"_id": resp.json()["scan_id"]})
    assert scan is not None
    assert scan["branch"] == "release/7.2"


@pytest.mark.asyncio
async def test_top_level_fields_win_over_the_legacy_envelope(client, db, api_key_headers):
    payload = {
        "branch": "feature/explicit",
        "commit_hash": "feedface",
        "scan_metadata": {"git_ref": "stale-main", "commit_sha": "0000000"},
        "cbom": _load("legacy_crypto_mixed.json"),
    }

    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    scan = await db.scans.find_one({"_id": resp.json()["scan_id"]})
    assert scan is not None
    assert scan["branch"] == "feature/explicit"
    assert scan["commit_hash"] == "feedface"


@pytest.mark.asyncio
async def test_successful_ingest_counts_as_a_success_in_the_ingest_metric(client, db, api_key_headers):
    before = _ingests("success")

    resp = await client.post(
        "/api/v1/ingest/cbom",
        json={"cbom": _load("legacy_crypto_mixed.json")},
        headers=api_key_headers,
    )

    assert resp.status_code == 202, resp.text
    assert _ingests("success") == before + 1

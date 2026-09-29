"""Integration tests for POST /api/v1/ingest/cbom."""

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


@pytest.mark.asyncio
async def test_a_queueing_failure_after_the_store_announces_nothing_and_leaves_the_scan_pending(
    client, db, api_key_headers
):
    """The assets are stored, so the retry must find the scan claimable and announce the ingest once."""
    from unittest.mock import AsyncMock, patch

    before = _ingests("error")
    with (
        patch(
            "app.services.scan_manager.ScanManager.register_result",
            AsyncMock(side_effect=RuntimeError("primary stepped down")),
        ),
        patch("app.api.v1.endpoints.cbom_ingest.webhook_service.safe_trigger_webhooks", AsyncMock()) as webhooks,
        pytest.raises(RuntimeError, match="primary stepped down"),
    ):
        await client.post(
            "/api/v1/ingest/cbom",
            json={"pipeline_id": 7, "commit_hash": "abc123", "cbom": _load("legacy_crypto_mixed.json")},
            headers=api_key_headers,
        )

    webhooks.assert_not_awaited()
    assert _ingests("error") == before, "a stored upload is not a persistence error"
    scan = await db.scans.find_one({"pipeline_id": 7})
    assert (scan["status"], scan["scan_type"]) == ("pending", "cbom")


@pytest.mark.asyncio
async def test_another_scanner_of_the_pipeline_keeps_the_cbom_tag(client, db, api_key_headers):
    """The engine selects crypto analyzers from the tag, so a later scanner upload must not clear it."""
    pipeline = {"pipeline_id": 8, "commit_hash": "abc123", "branch": "main"}
    cbom = await client.post(
        "/api/v1/ingest/cbom", json={**pipeline, "cbom": _load("legacy_crypto_mixed.json")}, headers=api_key_headers
    )
    scanner = await client.post("/api/v1/ingest/opengrep", json={**pipeline, "findings": []}, headers=api_key_headers)

    assert (cbom.status_code, scanner.status_code) == (202, 200), scanner.text
    assert (await db.scans.find_one({"_id": cbom.json()["scan_id"]}))["scan_type"] == "cbom"


@pytest.mark.asyncio
async def test_a_failed_asset_store_leaves_the_shared_pipeline_scan_readable(client, db, api_key_headers):
    """The pipeline's SBOM analysis lives in the same scan, so a CBOM write error must not fail it."""
    from unittest.mock import AsyncMock, patch

    pipeline = {"pipeline_id": 9, "commit_hash": "abc123", "cbom": _load("legacy_crypto_mixed.json")}
    first = await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)
    await db.scans.update_one({"_id": first.json()["scan_id"]}, {"$set": {"status": "completed"}})

    with patch.object(CryptoAssetRepository, "bulk_upsert", AsyncMock(side_effect=RuntimeError("write failed"))):
        resp = await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)

    assert resp.status_code == 500
    assert (await db.scans.find_one({"_id": first.json()["scan_id"]}))["status"] == "completed"

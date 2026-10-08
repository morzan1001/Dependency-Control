"""Integration tests for POST /api/v1/ingest/cbom."""

import json
from pathlib import Path

from unittest.mock import AsyncMock, patch

import pytest
from prometheus_client import REGISTRY

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.crypto_policy import CryptoPolicy
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.scans import ScanRepository
from app.services.analysis import engine
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.cbom import OLD_ASSET_CAP, cbom_of, filler_components, fixture_component

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

    from app.db.mongodb import get_database
    from app.main import app

    # Override only the DB dep; leave the auth dep real so it enforces credential checking.
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    async def _fake_get_database():
        return db

    app.dependency_overrides[get_database] = _fake_get_database

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v1/ingest/cbom", json={"cbom": {}})
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)

    assert resp.status_code == 401, resp.text


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
@pytest.mark.live_mongo
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
    pipeline = {"pipeline_id": 9, "commit_hash": "abc123", "cbom": _load("legacy_crypto_mixed.json")}
    first = await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)
    await db.scans.update_one({"_id": first.json()["scan_id"]}, {"$set": {"status": "completed"}})

    with patch.object(CryptoAssetRepository, "bulk_upsert", AsyncMock(side_effect=RuntimeError("write failed"))):
        resp = await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)

    assert resp.status_code == 500
    assert (await db.scans.find_one({"_id": first.json()["scan_id"]}))["status"] == "completed"


@pytest.mark.asyncio
async def test_a_cbom_posted_during_the_analysis_makes_the_running_one_start_over(client, db, api_key_headers):
    """The crypto analyzers read the assets this post replaced, and a run that began before it
    has not seen them; its finalize matches on the input generation it claimed."""
    pipeline = {"pipeline_id": 10, "commit_hash": "abc123", "branch": "main", "cbom": _load("legacy_crypto_mixed.json")}
    scan_id = (await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)).json()["scan_id"]
    claimed = (await db.scans.find_one({"_id": scan_id})).get("sbom_generation")
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing"}})

    resp = await client.post("/api/v1/ingest/cbom", json=pipeline, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    assert (await db.scans.find_one({"_id": scan_id})).get("sbom_generation") != claimed


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_retried_cbom_upload_replaces_its_own_assets_and_keeps_the_embedded_ones(client, db, api_key_headers):
    from app.models.crypto_asset import CryptoAsset
    from app.services.cbom_parser import parse_cbom

    pipeline = {"pipeline_id": 11, "commit_hash": "abc123", "branch": "main"}
    first = await client.post(
        "/api/v1/ingest/cbom", json={**pipeline, "cbom": _load("legacy_crypto_mixed.json")}, headers=api_key_headers
    )
    scan_id = first.json()["scan_id"]
    [embedded] = parse_cbom(_load("cyclonedx_1_6_with_crypto_assets.json")).assets
    await CryptoAssetRepository(db).bulk_upsert(
        "test-project-id",
        scan_id,
        [CryptoAsset(project_id="test-project-id", scan_id=scan_id, **embedded.model_dump())],
    )

    retry = await client.post(
        "/api/v1/ingest/cbom", json={**pipeline, "cbom": _load("modern_crypto.json")}, headers=api_key_headers
    )

    assert (retry.status_code, retry.json()["scan_id"]) == (202, scan_id)
    stored = await db.crypto_assets.find({"scan_id": scan_id}).to_list(None)
    assert sorted(a["bom_ref"] for a in stored) == sorted(["algo-aes", "algo-rsa4096", "proto-tls13", embedded.bom_ref])
    assert retry.json()["assets_stored"] == 4


@pytest.mark.asyncio
async def test_a_cbom_is_persisted_before_the_response_returns(client, db, api_key_headers):
    resp = await client.post(
        "/api/v1/ingest/cbom", json={"cbom": cbom_of(filler_components(range(5)))}, headers=api_key_headers
    )

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert await db.crypto_assets.count_documents({"scan_id": body["scan_id"]}) == 5
    assert (body["assets_received"], body["assets_stored"]) == (5, 5)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_crypto_assets_nested_under_a_component_are_stored(client, db, api_key_headers):
    library = {"type": "library", "name": "app-crypto", "bom-ref": "lib", "components": filler_components(range(2))}

    resp = await client.post(
        "/api/v1/ingest/cbom", json={"cbom": cbom_of([*filler_components([2]), library])}, headers=api_key_headers
    )

    assert resp.status_code == 202, resp.text
    stored = await db.crypto_assets.find({"scan_id": resp.json()["scan_id"]}).to_list(None)
    assert sorted(asset["bom_ref"] for asset in stored) == ["hash-000000", "hash-000001", "hash-000002"]


@pytest.mark.asyncio
async def test_duplicate_bom_refs_report_the_actually_stored_count(client, db, api_key_headers):
    """Upserts keyed on bom_ref collapse in-payload duplicates; assets_stored must say so."""
    cbom = cbom_of(filler_components(range(3)))
    cbom["components"][1]["bom-ref"] = cbom["components"][0]["bom-ref"]

    resp = await client.post("/api/v1/ingest/cbom", json={"cbom": cbom}, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert await db.crypto_assets.count_documents({"scan_id": body["scan_id"]}) == 2
    assert body["assets_stored"] == 2, "assets_stored must reflect persisted docs, not submitted ops"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("owner", "name"), [(CryptoAssetRepository, "bulk_upsert"), (ScanRepository, "touch")], ids=["assets", "scan"]
)
async def test_a_failed_asset_store_leaves_no_scan_and_no_release(client, db, api_key_headers, owner, name):
    payload = {
        "pipeline_id": 12,
        "commit_hash": "abc123",
        "branch": "main",
        "is_release": True,
        "commit_tag": "v1.0.0",
        "cbom": _load("legacy_crypto_mixed.json"),
    }
    errors = _ingests("error")

    with patch.object(owner, name, AsyncMock(side_effect=RuntimeError("write failed"))):
        resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)

    assert (resp.status_code, resp.json()["detail"]) == (
        500,
        "Failed to persist crypto assets. Please retry the upload.",
    )
    assert _ingests("error") == errors + 1
    assert await db.scans.count_documents({}) == 0
    assert await db.releases.count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_cbom_past_the_old_asset_cap_is_stored_and_evaluated_whole(client, db, api_key_headers):
    await create_indexes(db)
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", rules=list(load_seed_rules()), version=1)
    )
    md5 = fixture_component("legacy_crypto_mixed.json", "algo-md5")
    cbom = cbom_of([*filler_components(range(OLD_ASSET_CAP)), md5])

    resp = await client.post("/api/v1/ingest/cbom", json={"cbom": cbom}, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    assert resp.json()["assets_stored"] == OLD_ASSET_CAP + 1
    scan = await db.scans.find_one_and_update(
        {"_id": scan_id}, {"$set": {"status": "processing", "worker_id": "pod-a/worker-0"}}, return_document=True
    )
    status = await engine.run_analysis(
        scan_id, [], [], db, worker_id="pod-a/worker-0", sbom_generation=scan["sbom_generation"]
    )
    assert status == SCAN_STATUS_COMPLETED
    findings = await db.findings.find({"scan_id": scan_id}).to_list(None)
    assert [(f["type"], f["component"]) for f in findings] == [("crypto_weak_algorithm", "MD5 [bom-ref:algo-md5]")]
    repo = AnalysisResultRepository(db)
    results = [
        await repo.load_result(row) for row in await db.analysis_results.find({"scan_id": scan_id}).to_list(None)
    ]
    assert results
    assert not [r for r in results if "partial_components_skipped" in r]

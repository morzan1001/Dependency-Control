"""Release marks survive the other jobs of the same pipeline (promote-only)."""

from unittest.mock import patch

import pytest

_COMMIT = "b" * 40


def _sbom_payload(**extra):
    return {
        "pipeline_id": 4242,
        "commit_hash": _COMMIT,
        "branch": "main",
        "sboms": [{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}],
        **extra,
    }


async def _fake_process_sboms(*_args, **_kwargs):
    return ([{"gridfs_id": "fake-1", "filename": "fake.json"}], [], 1, 0, 0)


@pytest.mark.asyncio
async def test_sbom_ingest_stores_the_release_mark(client, db, api_key_headers):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        resp = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(commit_tag="v2.1.0", is_release=True),
            headers=api_key_headers,
        )
    assert resp.status_code == 202, resp.text
    scan = await db.scans.find_one({"_id": resp.json()["scan_id"]})
    assert scan["is_release"] is True
    assert scan["release_version"] == "v2.1.0"
    assert scan["release_environment"] == "production"
    assert scan["released_at"] is not None


@pytest.mark.asyncio
async def test_a_later_job_without_the_field_does_not_clear_the_mark(client, db, api_key_headers):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        first = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment="staging", release_version="v3"),
            headers=api_key_headers,
        )
        assert first.status_code == 202, first.text
        second = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
        assert second.status_code == 202, second.text

    scan_id = first.json()["scan_id"]
    assert second.json()["scan_id"] == scan_id
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert scan["release_environment"] == "staging"
    assert scan["release_version"] == "v3"


@pytest.mark.asyncio
async def test_findings_ingest_of_the_same_pipeline_does_not_clear_the_mark(client, db, api_key_headers):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        sbom = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_version="v4"),
            headers=api_key_headers,
        )
    assert sbom.status_code == 202, sbom.text
    scan_id = sbom.json()["scan_id"]

    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json={"pipeline_id": 4242, "commit_hash": _COMMIT, "branch": "main", "findings": []},
        headers=api_key_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_id"] == scan_id

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert scan["release_version"] == "v4"


@pytest.mark.asyncio
async def test_findings_ingest_can_promote_a_scan_created_by_the_sbom_job(client, db, api_key_headers):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        sbom = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
    scan_id = sbom.json()["scan_id"]

    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json={
            "pipeline_id": 4242,
            "commit_hash": _COMMIT,
            "branch": "main",
            "findings": [],
            "is_release": True,
            "release_environment": "canary",
        },
        headers=api_key_headers,
    )
    assert resp.status_code == 200, resp.text

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert scan["release_environment"] == "canary"


@pytest.mark.asyncio
async def test_sbom_ingest_can_promote_an_existing_scan_with_release(client, db, api_key_headers):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        first = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
        assert first.status_code == 202, first.text

        second = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment="canary"),
            headers=api_key_headers,
        )
        assert second.status_code == 202, second.text

    scan_id = first.json()["scan_id"]
    assert second.json()["scan_id"] == scan_id
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert scan["release_environment"] == "canary"


@pytest.mark.asyncio
async def test_findings_ingest_creates_scan_with_release_mark(client, db, api_key_headers):
    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json={
            "pipeline_id": 4242,
            "commit_hash": _COMMIT,
            "branch": "main",
            "findings": [],
            "is_release": True,
            "release_environment": "prod",
        },
        headers=api_key_headers,
    )
    assert resp.status_code == 200, resp.text

    scan_id = resp.json()["scan_id"]
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert scan["release_environment"] == "prod"

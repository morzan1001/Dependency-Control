"""Release marks survive the other jobs of the same CI pipeline (promote-only) and are kept per environment."""

import uuid
from unittest.mock import patch

import pymongo
import pytest

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT

_COMMIT = "b" * 40
_BRANCH = "main"
_PIPELINE_ID = 4242
_PROJECT_ID = "test-project-id"
_STAGING = "staging"
_CANARY = "canary"
_VERSION = "v2.1.0"
_OTHER_VERSION = "v3"
_ONE_RECORD = 1
_TWO_RECORDS = 2
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}


def _sbom_payload(**extra):
    return {
        "pipeline_id": _PIPELINE_ID,
        "commit_hash": _COMMIT,
        "branch": _BRANCH,
        "sboms": [_SBOM],
        **extra,
    }


def _findings_payload(**extra):
    return {"pipeline_id": _PIPELINE_ID, "commit_hash": _COMMIT, "branch": _BRANCH, "findings": [], **extra}


async def _fake_process_sboms(*_args, **_kwargs):
    return ([{"gridfs_id": "fake-1", "filename": "fake.json"}], [], 1, 0, 0)


def _patched_sbom_ingest():
    return (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    )


async def _latest_release(db, environment: str):
    return await db.releases.find_one(
        {"project_id": _PROJECT_ID, "environment": environment},
        sort=[("released_at", pymongo.DESCENDING)],
    )


@pytest.mark.asyncio
async def test_sbom_ingest_records_the_release(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        resp = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(commit_tag=_VERSION, is_release=True),
            headers=api_key_headers,
        )
    assert resp.status_code == 202, resp.text

    scan_id = resp.json()["scan_id"]
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True

    release = await _latest_release(db, DEFAULT_RELEASE_ENVIRONMENT)
    assert release["scan_id"] == scan_id
    assert release["version"] == _VERSION
    assert release["released_at"] is not None


@pytest.mark.asyncio
async def test_one_scan_marked_into_two_environments_keeps_both(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        first = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment=_STAGING, release_version=_VERSION),
            headers=api_key_headers,
        )
        assert first.status_code == 202, first.text
        second = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment=DEFAULT_RELEASE_ENVIRONMENT),
            headers=api_key_headers,
        )
        assert second.status_code == 202, second.text

    scan_id = first.json()["scan_id"]
    assert second.json()["scan_id"] == scan_id

    releases = await db.releases.find({"scan_id": scan_id}).to_list(None)
    assert len(releases) == _TWO_RECORDS
    assert {r["environment"] for r in releases} == {_STAGING, DEFAULT_RELEASE_ENVIRONMENT}
    assert len({uuid.UUID(r["_id"]) for r in releases}) == _TWO_RECORDS
    for environment in (_STAGING, DEFAULT_RELEASE_ENVIRONMENT):
        assert (await _latest_release(db, environment))["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_redeploying_the_same_scan_refreshes_one_record(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        payload = _sbom_payload(is_release=True, release_environment=_STAGING, release_version=_VERSION)
        first = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
        assert first.status_code == 202, first.text
        first_released_at = (await _latest_release(db, _STAGING))["released_at"]

        second = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
        assert second.status_code == 202, second.text

    releases = await db.releases.find({"environment": _STAGING}).to_list(None)
    assert len(releases) == _ONE_RECORD
    assert releases[0]["released_at"] >= first_released_at


@pytest.mark.asyncio
async def test_a_later_job_without_the_field_keeps_the_flag_and_the_record(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        first = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment=_STAGING, release_version=_OTHER_VERSION),
            headers=api_key_headers,
        )
        assert first.status_code == 202, first.text
        second = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
        assert second.status_code == 202, second.text

    scan_id = first.json()["scan_id"]
    assert second.json()["scan_id"] == scan_id
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True

    release = await _latest_release(db, _STAGING)
    assert release["scan_id"] == scan_id
    assert release["version"] == _OTHER_VERSION


@pytest.mark.asyncio
async def test_findings_ingest_of_the_same_pipeline_keeps_the_flag_and_the_record(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        sbom = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_version=_OTHER_VERSION),
            headers=api_key_headers,
        )
    assert sbom.status_code == 202, sbom.text
    scan_id = sbom.json()["scan_id"]

    resp = await client.post("/api/v1/ingest/opengrep", json=_findings_payload(), headers=api_key_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_id"] == scan_id

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True

    release = await _latest_release(db, DEFAULT_RELEASE_ENVIRONMENT)
    assert release["scan_id"] == scan_id
    assert release["version"] == _OTHER_VERSION


@pytest.mark.asyncio
async def test_findings_ingest_can_promote_a_scan_created_by_the_sbom_job(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        sbom = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
    assert sbom.status_code == 202, sbom.text
    scan_id = sbom.json()["scan_id"]

    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json=_findings_payload(is_release=True, release_environment=_CANARY),
        headers=api_key_headers,
    )
    assert resp.status_code == 200, resp.text

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert (await _latest_release(db, _CANARY))["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_sbom_ingest_can_promote_an_existing_scan(client, db, api_key_headers):
    process_sboms, gridfs = _patched_sbom_ingest()
    with process_sboms, gridfs:
        first = await client.post("/api/v1/ingest", json=_sbom_payload(), headers=api_key_headers)
        assert first.status_code == 202, first.text

        second = await client.post(
            "/api/v1/ingest",
            json=_sbom_payload(is_release=True, release_environment=_CANARY),
            headers=api_key_headers,
        )
        assert second.status_code == 202, second.text

    scan_id = first.json()["scan_id"]
    assert second.json()["scan_id"] == scan_id
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert (await _latest_release(db, _CANARY))["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_findings_ingest_creates_a_scan_with_the_release_record(client, db, api_key_headers):
    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json=_findings_payload(is_release=True, release_environment=_CANARY),
        headers=api_key_headers,
    )
    assert resp.status_code == 200, resp.text

    scan_id = resp.json()["scan_id"]
    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["is_release"] is True
    assert (await _latest_release(db, _CANARY))["scan_id"] == scan_id

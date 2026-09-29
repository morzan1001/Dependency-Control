"""Every scanner post is CI activity for its project, from any branch and before any analysis."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

_PIPELINE = {"pipeline_id": 5150, "commit_hash": "c" * 40, "branch": "feature/spike"}
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
_CBOM = json.loads((Path(__file__).parent.parent / "fixtures" / "cbom" / "legacy_crypto_mixed.json").read_text())


async def _fake_process_sboms(*_args, **_kwargs):
    return ([{"gridfs_id": "fake-1", "filename": "fake.json"}], [], 1, 0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "upload"),
    [
        ("/api/v1/ingest", {"sboms": [_SBOM]}),
        ("/api/v1/ingest/cbom", {"cbom": _CBOM}),
        ("/api/v1/ingest/opengrep", {"findings": []}),
    ],
    ids=["sbom", "cbom", "findings"],
)
async def test_every_scanner_post_records_the_project_activity(client, db, api_key_headers, route, upload):
    with (
        patch("app.api.v1.endpoints.ingest._process_sboms", side_effect=_fake_process_sboms),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        resp = await client.post(route, json={**_PIPELINE, **upload}, headers=api_key_headers)

    assert resp.status_code in (200, 202), resp.text
    assert (await db.projects.find_one({"_id": "test-project-id"}))["last_scan_at"] is not None

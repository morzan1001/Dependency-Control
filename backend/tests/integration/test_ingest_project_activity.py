"""Every scanner post is CI activity for its project, from any branch and before any analysis."""

import json
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent.parent / "fixtures"
_PIPELINE = {"pipeline_id": 5150, "commit_hash": "c" * 40, "branch": "feature/spike"}
_SBOM = json.loads((_FIXTURES / "sbom" / "mono.syft.json").read_text())
_CBOM = json.loads((_FIXTURES / "cbom" / "legacy_crypto_mixed.json").read_text())


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
@pytest.mark.live_mongo
async def test_every_scanner_post_records_the_project_activity(client, db, api_key_headers, route, upload):
    resp = await client.post(route, json={**_PIPELINE, **upload}, headers=api_key_headers)

    assert resp.status_code in (200, 202), resp.text
    assert (await db.projects.find_one({"_id": "test-project-id"}))["last_scan_at"] is not None

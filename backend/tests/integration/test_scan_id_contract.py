"""The SBOM, the scanner results and the callgraph of one CI run land on one scan, by one id rule."""

import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.services.scan_manager import deterministic_scan_id

_PIPELINE_ID = 5150
_COMMIT = "c" * 40
_RUN = {"pipeline_id": _PIPELINE_ID, "commit_hash": _COMMIT, "branch": "main"}
_SBOM = json.loads((Path(__file__).parents[1] / "fixtures" / "sbom" / "mono.syft.json").read_text())
_CALLGRAPH = {"format": "generic", "language": "python", "data": {"imports": [], "analyzed_modules": []}}


def _uuid5(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


@pytest.mark.parametrize(
    ("pipeline_id", "commit_hash", "expected"),
    [(7, "abc", _uuid5("p-7-abc")), (7, None, _uuid5("p-7")), (None, "abc", None), (0, "abc", None)],
)
def test_the_rule(pipeline_id, commit_hash, expected):
    assert deterministic_scan_id("p", pipeline_id, commit_hash) == expected


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_one_ci_run_lands_on_one_scan(client, db, api_key_headers, _project):
    sbom = await client.post("/api/v1/ingest", json={**_RUN, "sboms": [_SBOM]}, headers=api_key_headers)
    findings = await client.post("/api/v1/ingest/opengrep", json={**_RUN, "findings": []}, headers=api_key_headers)
    with patch("app.api.deps._authenticate_ci", new_callable=AsyncMock, return_value=_project):
        callgraph = await client.post(
            f"/api/v1/projects/{_project.id}/callgraph", json={**_RUN, **_CALLGRAPH}, headers=api_key_headers
        )

    assert (sbom.status_code, findings.status_code, callgraph.status_code) == (202, 200, 200)
    expected = _uuid5(f"{_project.id}-{_PIPELINE_ID}-{_COMMIT}")
    assert sbom.json()["scan_id"] == findings.json()["scan_id"] == expected
    assert (await db.callgraphs.find_one({"project_id": _project.id}))["scan_id"] == expected
    assert await db.scans.count_documents({}) == 1

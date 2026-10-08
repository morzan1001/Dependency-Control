"""A callgraph's graph lives in one GridFS file: any size is stored and read, legacy inline graphs stay readable."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from bson import ObjectId

from app.api.v1.helpers.callgraph import parse_madge_format
from app.core.housekeeping import run_housekeeping
from app.core.init_db import create_indexes
from app.models.callgraph import Callgraph
from app.models.project import Project
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import MAX_TOOL_RESULT_BYTES
from app.services.reachability_enrichment import fetch_callgraphs
from app.services.scan_manager import deterministic_scan_id
from tests.helpers.permission_presets import PRESET_ADMIN

_PROJECT_ID = "test-project-id"
_PIPELINE_ID = 1
_COMMIT = "e" * 40
_SCAN_ID = deterministic_scan_id(_PROJECT_ID, _PIPELINE_ID, _COMMIT)
_DEPENDENCIES_PER_FILE = 10
_MONGO_DOCUMENT_LIMIT = 16 * 1024 * 1024
_ADMIN = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


def _madge(files: int, path_length: int, packages: int) -> dict[str, list[str]]:
    """madge `--json --include-npm` output whose files import from a pool of `packages` npm packages."""
    return {
        f"src/features/f{i}/".ljust(path_length - 4, "x") + ".tsx": [
            f"../node_modules/pkg-{(i * _DEPENDENCIES_PER_FILE + j) % packages}/index.js"
            for j in range(_DEPENDENCIES_PER_FILE)
        ]
        for i in range(files)
    }


async def _upload(client, data: dict[str, list[str]]):
    with patch(
        "app.api.deps._authenticate_ci",
        new_callable=AsyncMock,
        return_value=Project(id=_PROJECT_ID, name="test-project"),
    ):
        return await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json={"format": "madge", "pipeline_id": _PIPELINE_ID, "commit_hash": _COMMIT, "data": data},
            headers={"Job-Token": "gitlab.oidc.token"},
        )


async def _seed_scan_with_finding(db, component: str) -> None:
    await db.scans.insert_one(
        {"_id": _SCAN_ID, "project_id": _PROJECT_ID, "status": "completed", "reachability_pending": True}
    )
    await db.findings.insert_one(
        {
            "_id": "f-CVE-1",
            "id": "CVE-1",
            "finding_id": "CVE-1",
            "scan_id": _SCAN_ID,
            "project_id": _PROJECT_ID,
            "type": "vulnerability",
            "severity": "HIGH",
            "component": component,
            "version": "1.0.0",
            "description": f"CVE-1 in {component}",
            "scanners": ["osv"],
            "details": {"risk_score": 40.0, "vulnerabilities": [{"id": "CVE-1", "severity": "HIGH"}]},
        }
    )
    await db.dependencies.insert_one(
        {
            "_id": f"dep-{component}",
            "scan_id": _SCAN_ID,
            "name": component,
            "version": "1.0.0",
            "type": "npm",
            "purl": f"pkg:npm/{component}@1.0.0",
        }
    )


def _legacy_inline(data: dict[str, list[str]]) -> dict:
    """A callgraph document as the upload stored it inline, graph included."""
    parsed = parse_madge_format(data, "javascript")
    return Callgraph(
        project_id=_PROJECT_ID,
        pipeline_id=_PIPELINE_ID,
        commit_hash=_COMMIT,
        scan_id=_SCAN_ID,
        language="javascript",
        tool="madge",
        module_usage=parsed.module_usage,
        analyzed_modules=sorted(parsed.module_usage),
        total_imports=parsed.total_imports,
    ).model_dump(by_alias=True)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_callgraph_over_16_mib_and_200k_entries_is_stored_and_enriches_the_scan(client, db):
    await create_indexes(db)
    await _seed_scan_with_finding(db, "pkg-7")

    resp = await _upload(client, _madge(20_001, 100, 2_000))

    assert resp.status_code == 200, resp.text
    assert (resp.json()["imports_parsed"], resp.json()["warnings"]) == (200_010, [])
    assert "reachability_pending" not in await db.scans.find_one({"_id": _SCAN_ID})
    doc = await db.callgraphs.find_one({"scan_id": _SCAN_ID})
    assert "module_usage" not in doc
    assert "analyzed_modules" not in doc
    graph_file = await db["fs.files"].find_one({"_id": ObjectId(doc["graph_gridfs_id"])})
    assert graph_file["length"] > _MONGO_DOCUMENT_LIMIT
    [callgraph] = await fetch_callgraphs(_PROJECT_ID, _SCAN_ID, db)
    assert len(callgraph.module_usage) == 2_000
    assert (await db.findings.find_one({"_id": "f-CVE-1"}))["reachable"] is True
    chat = await ChatToolRegistry().execute_tool("get_callgraph", {"project_id": _PROJECT_ID}, _ADMIN, db)
    [chat_graph] = chat["callgraphs"]
    assert (chat_graph["module_usage_total"], len(chat_graph["module_usage"])) == (2_000, 25)
    assert len(json.dumps(chat).encode()) <= MAX_TOOL_RESULT_BYTES


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_legacy_inline_callgraph_is_read_by_reachability_and_chat(client, db):
    await db.callgraphs.insert_one(_legacy_inline(_madge(3, 40, 2)))

    [callgraph] = await fetch_callgraphs(_PROJECT_ID, _SCAN_ID, db)
    chat = await ChatToolRegistry().execute_tool("get_callgraph", {"project_id": _PROJECT_ID}, _ADMIN, db)

    [chat_graph] = chat["callgraphs"]
    assert set(callgraph.module_usage) == set(chat_graph["module_usage"]) == {"pkg-0", "pkg-1"}
    assert callgraph.analyzed_modules == chat_graph["analyzed_modules"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_reupload_over_a_legacy_doc_drops_the_inline_graph(client, db):
    legacy = _legacy_inline(_madge(3, 40, 2))
    await db.callgraphs.insert_one(legacy)

    resp = await _upload(client, _madge(3, 40, 3))

    assert resp.status_code == 200, resp.text
    [doc] = await db.callgraphs.find({}).to_list(None)
    assert (doc["_id"], "module_usage" in doc, "analyzed_modules" in doc) == (legacy["_id"], False, False)
    assert doc["graph_gridfs_id"]
    await db.scans.insert_one({"_id": "same-pipeline", "project_id": _PROJECT_ID, "pipeline_id": _PIPELINE_ID})
    [by_scan] = await fetch_callgraphs(_PROJECT_ID, _SCAN_ID, db)
    [by_pipeline] = await fetch_callgraphs(_PROJECT_ID, "same-pipeline", db)
    assert set(by_scan.module_usage) == set(by_pipeline.module_usage) == {"pkg-0", "pkg-1", "pkg-2"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_reaped_orphan_callgraph_frees_its_file_in_the_same_cycle(client, db, monkeypatch):
    resp = await _upload(client, _madge(3, 40, 2))
    assert resp.status_code == 200, resp.text
    graph_file = ObjectId((await db.callgraphs.find_one({"scan_id": _SCAN_ID}))["graph_gridfs_id"])
    monkeypatch.setattr("app.core.housekeeping.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr("app.core.housekeeping.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)
    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)

    await run_housekeeping()

    assert await db.callgraphs.count_documents({}) == 0
    assert await db["fs.files"].count_documents({"_id": graph_file}) == 0

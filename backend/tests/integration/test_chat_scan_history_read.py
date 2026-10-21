"""A scan document carries its SBOM references and analyzer bookkeeping, none of which a history row shows."""

from datetime import datetime, timedelta, timezone

import bson
import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT = "p-history"
_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_SBOM_REFS = [{"gridfs_id": f"sbom-{i:04d}", "filename": f"service-{i:04d}.cdx.json"} for i in range(200)]


async def test_the_scan_history_reads_only_the_fields_its_rows_show(db):
    await db.projects.insert_one({"_id": _PROJECT, "name": "history-project", "default_branch": "main"})
    await db.scans.insert_many(
        [
            {
                "_id": f"scan-{n}",
                "project_id": _PROJECT,
                "branch": "main",
                "commit_hash": f"c{n}",
                "status": SCAN_STATUS_COMPLETED,
                "created_at": _NOW - timedelta(hours=n),
                "completed_at": _NOW - timedelta(hours=n),
                "stats": {"critical": n, "high": 0, "medium": 0, "low": 0, "risk_score": 0.0},
                "sbom_refs": _SBOM_REFS,
            }
            for n in range(3)
        ]
    )

    result, entries = await profiled(
        db, ChatToolRegistry().execute_tool("get_scan_history", {"project_id": _PROJECT}, make_admin(), db)
    )

    assert [(s["scan_id"], s["commit_hash"], s["stats"]["critical"]) for s in result["scans"]] == [
        ("scan-0", "c0", 0),
        ("scan-1", "c1", 1),
        ("scan-2", "c2", 2),
    ]
    assert result["scans"][0]["completed_at"] == _NOW.isoformat()
    (history_read,) = [
        e
        for e in entries
        if e["ns"].endswith(".scans") and e["op"] == "query" and e["command"].get("filter") == {"project_id": _PROJECT}
    ]
    assert history_read["responseLength"] < len(bson.encode({"sbom_refs": _SBOM_REFS}))

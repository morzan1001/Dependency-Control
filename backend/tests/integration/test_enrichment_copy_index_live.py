"""The per-scan enrichment copy runs one update per enriched purl, so each has to stay inside the
(scan_id, purl) index range of its own purl; walking the whole scan makes the copy quadratic."""

import pytest

from app.core.init_db import create_indexes
from app.services.analysis.engine import _enrich_dependencies

_SCAN = "scan-1"
_ROWS = 300


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_each_copy_update_examines_only_its_purls_index_keys(db):
    await create_indexes(db)
    rows = [
        {"scan_id": _SCAN, "name": f"n{i}", "version": "1.0.0", "purl": f"pkg:npm/%40sc/n{i}@1.0.0"}
        for i in range(_ROWS)
    ]
    rows.append({"scan_id": _SCAN, "name": "n7", "version": "1.0.0", "purl": "pkg:npm/%40sc/n7@1.0.0?arch=x"})
    await db.dependencies.insert_many(rows)
    entry = {"name": "n7", "version": "1.0.0", "purl": "pkg:npm/%40sc/n7@1.0.0", "data": {"license_category": "x"}}

    await db.command("profile", 2)
    await _enrich_dependencies([entry], _SCAN, db)
    await db.command("profile", 0)

    updates = await db.system.profile.find({"op": "update", "ns": f"{db.name}.dependencies"}).to_list(None)
    assert [u["nModified"] for u in updates] == [2]
    assert updates[0]["keysExamined"] <= 3

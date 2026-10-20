"""A kept inventory takes one update per enriched purl, which must stay in its own (scan_id, purl) index range."""

import pytest

from app.core.init_db import create_indexes
from app.models.project import Scan
from app.services.analysis.engine import _store_dependencies
from tests.helpers.analyzers import analyse_scan, serve_analyzer
from tests.helpers.sboms import store_sbom

_SCAN = "scan-1"
_ROWS = 300
_WORKER = "pod-a/worker-0"


async def _profiled_updates(db, run) -> list[dict]:
    await db.command("profile", 2)
    await run
    await db.command("profile", 0)
    return await db.system.profile.find({"op": "update", "ns": f"{db.name}.dependencies"}).to_list(None)


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

    updates = await _profiled_updates(db, _store_dependencies([None], "p", _SCAN, db, [entry]))

    assert [u["nModified"] for u in updates] == [2]
    assert updates[0]["keysExamined"] <= 3


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_copied_license_reaches_both_twins_in_one_update_and_keeps_a_declared_one(db):
    await create_indexes(db)
    purl = "pkg:maven/javax.enterprise/cdi-api@1.0"
    await db.dependencies.insert_many(
        [
            {"scan_id": _SCAN, "name": "cdi-api", "version": "1.0", "purl": f"{purl}?type=jar", "license": "EPL-2.0"},
            {"scan_id": _SCAN, "name": "cdi-api", "version": "1.0", "purl": purl, "license": ""},
        ]
    )
    entry = {
        "name": "cdi-api",
        "version": "1.0",
        "purl": purl,
        "data": {"license": "Apache-2.0", "license_category": "permissive"},
    }

    updates = await _profiled_updates(db, _store_dependencies([None], "p", _SCAN, db, [entry]))

    assert [u["nModified"] for u in updates] == [2]
    stored = {d["purl"]: (d["license"], d["license_category"]) async for d in db.dependencies.find({"scan_id": _SCAN})}
    assert stored == {f"{purl}?type=jar": ("EPL-2.0", "permissive"), purl: ("Apache-2.0", "permissive")}


class _ClassifiesRequests:
    async def analyze(self, sbom, settings=None, parsed_components=None):
        classification = {"component": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
        return {"component_licenses": [classification | {"license": "Apache-2.0", "category": "permissive"}]}


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_inventory_the_run_writes_carries_the_copies_without_a_single_update(db, monkeypatch):
    await create_indexes(db)
    serve_analyzer(monkeypatch, "license_compliance", _ClassifiesRequests())
    component = {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
    ref = await store_sbom(db, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [component]})
    scan = Scan(project_id="p", branch="main", sbom_refs=[ref], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    updates = await _profiled_updates(db, analyse_scan(db, scan.id, [ref], ["license_compliance"], worker_id=_WORKER))

    assert updates == []
    (dependency,) = await db.dependencies.find({"scan_id": scan.id}).to_list(None)
    assert (dependency["license"], dependency["license_category"]) == ("Apache-2.0", "permissive")

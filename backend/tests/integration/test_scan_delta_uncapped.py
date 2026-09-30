"""A scan delta compares both scans whole, however many rows a side holds."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.init_db import create_indexes
from app.models.waiver import Waiver
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.analytics.components_delta import compare_components
from app.services.analytics.findings_delta import compare_findings
from app.services.dependency_store import store_scan_dependencies
from app.services.sbom_parser import parse_sbom
from tests.helpers.findings import grype_findings

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_PROJECT = "delta-project"
_SBOM = json.loads((Path(__file__).parents[1] / "fixtures/sbom/npmpeer.syft.cdx.json").read_text())
_COMPONENT = next(c for c in _SBOM["components"] if c.get("purl"))
_DEPENDENCIES = 60_000
# Sorts past the 50,000th row of the scan's name order.
_BUMPED = 55_000
_EXTRA_CVE = "CVE-2026-00001"


def _package(index: int) -> str:
    return f"js-tokens-{index:06d}"


def _sbom(versions: dict[int, str]) -> dict:
    components = []
    for index in range(_DEPENDENCIES):
        name, version = _package(index), versions.get(index, _COMPONENT["version"])
        purl = f"pkg:npm/{name}@{version}"
        components.append(
            {**_COMPONENT, "bom-ref": f"{purl}?package-id={index:016x}", "name": name, "version": version, "purl": purl}
        )
    return {**_SBOM, "components": components, "dependencies": []}


async def _store(db, scan_id: str, versions: dict[int, str] | None = None) -> None:
    stored = await store_scan_dependencies(
        [parse_sbom(_sbom(versions or {}))], _PROJECT, scan_id, DependencyRepository(db)
    )
    assert stored == _DEPENDENCIES


async def test_the_components_delta_reads_every_dependency_of_both_scans(db):
    await create_indexes(db)
    await _store(db, "scan-a")
    await _store(db, "scan-b")
    await _store(db, "scan-c", {_BUMPED: "4.0.1"})

    identical = await compare_components(db, project_id=_PROJECT, from_scan="scan-a", to_scan="scan-b")
    bumped = await compare_components(db, project_id=_PROJECT, from_scan="scan-a", to_scan="scan-c")

    assert identical.totals.model_dump(include={"added", "removed", "changed", "unchanged"}) == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": _DEPENDENCIES,
    }
    assert "truncation" not in identical.model_dump()
    assert (bumped.totals.changed, bumped.totals.unchanged) == (1, _DEPENDENCIES - 1)
    [item] = bumped.items
    assert (item.change, item.name, item.from_version, item.to_version) == (
        "version_changed",
        _package(_BUMPED),
        _COMPONENT["version"],
        "4.0.1",
    )


def _brace(index: int) -> str:
    return f"brace-expansion-{index:06d}"


async def _persist(db, scan_id: str, findings: list) -> None:
    records, _ = _prepare_finding_records(findings, scan_id, _PROJECT, datetime.now(timezone.utc))
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)


async def _waive(db, **fields) -> None:
    waiver = Waiver(project_id=_PROJECT, reason="accepted", created_by="u", **fields)
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))


async def _count(db, scan_id: str, clause: dict) -> int:
    return await db.findings.count_documents({"project_id": _PROJECT, "scan_id": scan_id, **clause})


@pytest.mark.parametrize("side_size", [40, 52_000], ids=["small", "past-the-old-cap"])
async def test_the_findings_delta_reads_every_finding_and_every_waiver_of_both_scans(db, side_size):
    """The last indices hold every waiver and change, so on the large side they sit past row 50,000."""
    await create_indexes(db)
    partial, full, lapsing, removed, bumped = range(side_size - 6, side_size - 1)
    shared = [(_brace(i), "2.0.1", None) for i in range(side_size) if i not in (removed, bumped)]
    extra = [(_brace(i), "2.0.1", _EXTRA_CVE) for i in (partial - 1, partial)]
    for index in (partial - 1, partial):
        await _waive(db, vulnerability_id=_EXTRA_CVE, package_name=_brace(index))
    await _waive(db, finding_id=f"{_brace(full)}:2.0.1", finding_type="vulnerability", package_name=_brace(full))
    from_side = [*shared, *extra, (_brace(removed), "2.0.1", None), (_brace(bumped), "2.0.1", None)]
    await _persist(db, "from", grype_findings(from_side))
    await _waive(db, finding_id=f"{_brace(lapsing)}:2.0.1", finding_type="vulnerability", package_name=_brace(lapsing))
    to_side = [*shared, *extra, (_brace(bumped), "2.0.2", None), (_brace(side_size), "2.0.1", None)]
    await _persist(db, "to", grype_findings(to_side))

    resp = await compare_findings(
        db, project_id=_PROJECT, from_scan="from", to_scan="to", severity=None, finding_type=None
    )

    touched = {"$or": [{"waived": True}, {"details.vulnerabilities.waived": True}]}
    live = {"waived": {"$ne": True}}
    assert (resp.from_waived_excluded, resp.to_waived_excluded) == (3, 4)
    assert resp.from_waived_excluded == await _count(db, "from", touched)
    assert resp.to_waived_excluded == await _count(db, "to", touched)
    totals = resp.totals
    assert (totals.added, totals.removed, totals.changed, totals.unchanged) == (1, 2, 1, side_size - 4)
    assert totals.unchanged + totals.removed + totals.changed == await _count(db, "from", live)
    assert totals.unchanged + totals.added + totals.changed == await _count(db, "to", live)
    assert resp.waiver_only_changes == 1
    assert {(i.change, i.component) for i in resp.items} == {
        ("added", _brace(side_size)),
        ("removed", _brace(removed)),
        ("removed", _brace(lapsing)),
        ("changed", _brace(bumped)),
    }
    assert "truncation" not in resp.model_dump()

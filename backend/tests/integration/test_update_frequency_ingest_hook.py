"""The ingest path must record an update-frequency delta, and a rollup failure must not fail the scan."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.constants import ANALYSIS_MAX_RETRIES, SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.models.project import Scan
from app.services.analysis.engine import run_analysis

_PROJECT_ID = "test-project-id"
_WORKER = "pod-a/worker-0"
_FILE_ID_OLD = "69d5332257c8763c8d8c82d7"
_FILE_ID_NEW = "69d5332357c8763c8d8c82de"


def _cyclonedx(components: list[tuple[str, str]]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
            for name, version in components
        ],
    }


_SBOM_OLD = _cyclonedx([("requests", "2.31.0"), ("urllib3", "2.1.0")])
_SBOM_NEW = _cyclonedx([("requests", "2.32.0"), ("urllib3", "2.1.0")])


def _gridfs_ref(file_id: str) -> dict:
    return {
        "storage": "gridfs",
        "file_id": file_id,
        "filename": f"sbom-{file_id}.json",
        "type": "gridfs_reference",
        "gridfs_id": file_id,
    }


@pytest.fixture
def _gridfs_patched(monkeypatch):
    sboms = {_FILE_ID_OLD: _SBOM_OLD, _FILE_ID_NEW: _SBOM_NEW}
    fs = MagicMock()

    async def _open(object_id):
        stream = MagicMock()
        stream.read = AsyncMock(return_value=json.dumps(sboms[str(object_id)]).encode())
        return stream

    fs.open_download_stream = AsyncMock(side_effect=_open)
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)
    return fs


async def _ingest(db, file_id: str) -> str:
    scan = Scan(
        project_id=_PROJECT_ID, branch="main", sbom_refs=[_gridfs_ref(file_id)], status="processing", worker_id=_WORKER
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    assert await run_analysis(scan.id, [_gridfs_ref(file_id)], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED
    return scan.id


@pytest.mark.asyncio
async def test_ingest_records_delta_for_each_scan(db, _gridfs_patched):
    first = await _ingest(db, _FILE_ID_OLD)
    second = await _ingest(db, _FILE_ID_NEW)

    baseline = await db.scan_update_deltas.find_one({"_id": first})
    assert baseline is not None, "the ingest path never wrote a delta for the first scan"
    assert baseline["is_baseline"] is True
    assert baseline["dep_count"] == 2

    delta = await db.scan_update_deltas.find_one({"_id": second})
    assert delta is not None, "the ingest path never wrote a delta for the second scan"
    assert delta["prev_scan_id"] == first
    assert delta["is_baseline"] is False
    assert delta["updates"] == {"patch": 0, "minor": 1, "major": 0, "unknown": 0, "downgrade": 0}
    assert [s["n"] for s in delta["updates_sample"]] == ["requests"]

    # No analyzer ran, so the scan has no outdated measurement to store.
    assert delta["outdated_count"] is None
    assert await db.scan_outdated_sets.find_one({"_id": second}) is None


@pytest.mark.asyncio
async def test_a_re_analysis_whose_sbom_fails_to_load_keeps_the_scan_and_its_delta(db, _gridfs_patched):
    first = await _ingest(db, _FILE_ID_OLD)
    second = await _ingest(db, _FILE_ID_NEW)

    await db.scans.update_one(
        {"_id": first}, {"$set": {"status": "processing", "retry_count": ANALYSIS_MAX_RETRIES - 1}}
    )
    assert (
        await run_analysis(first, [_gridfs_ref("69d5332457c8763c8d8c82df")], [], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    assert await db.scan_update_deltas.find_one({"_id": first}) is not None
    successor = await db.scan_update_deltas.find_one({"_id": second})
    assert (successor["prev_scan_id"], successor["updates"]["minor"]) == (first, 1)


@pytest.mark.asyncio
async def test_scan_still_completes_when_the_delta_write_fails(db, _gridfs_patched):
    """The rollup's own handler must absorb a Mongo failure, including the error-doc fallback."""
    failing_write = AsyncMock(side_effect=RuntimeError("no space left on device"))
    db.scan_update_deltas.update_one = failing_write

    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[_gridfs_ref(_FILE_ID_OLD)],
        status="processing",
        worker_id=_WORKER,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))

    assert await run_analysis(scan.id, [_gridfs_ref(_FILE_ID_OLD)], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED
    failing_write.assert_awaited()
    stored = await db.scans.find_one({"_id": scan.id})
    assert stored["status"] == "completed"

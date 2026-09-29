"""Scheduled rescans must repopulate the dependencies collection for the new scan_id."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS, SCAN_STATUS_FAILED
from app.models.dependency import Dependency
from app.models.project import Scan
from app.services.analysis.engine import run_analysis

_PROJECT_ID = "test-project-id"
_WORKER = "pod-a/worker-0"
_ORIGINAL_SCAN_ID = "0d90b4bd-1291-5949-8e0d-8d0d76a59e01"

# 24-hex-char GridFS ObjectIds, as stored in prod sbom_refs.
_FILE_ID_A = "69d5332257c8763c8d8c82d7"
_FILE_ID_B = "69d5332357c8763c8d8c82de"


def _cyclonedx_sbom(components: list[tuple[str, str, str]]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
            }
            for name, version, purl in components
        ],
    }


_SBOM_A = _cyclonedx_sbom(
    [
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("urllib3", "2.1.0", "pkg:pypi/urllib3@2.1.0"),
        ("certifi", "2024.2.2", "pkg:pypi/certifi@2024.2.2"),
    ]
)
_SBOM_B = _cyclonedx_sbom([("flask", "3.0.0", "pkg:pypi/flask@3.0.0")])
# The parser rejects a non-object metadata.
_MALFORMED_SBOM = {**_SBOM_B, "metadata": []}


def _gridfs_ref(file_id: str) -> dict:
    # Mirrors the sbom_refs entries stored in prod scans.
    return {
        "storage": "gridfs",
        "file_id": file_id,
        "filename": f"sbom-{file_id}.json",
        "type": "gridfs_reference",
        "gridfs_id": file_id,
    }


def _fake_gridfs(sboms_by_file_id: dict[str, dict]) -> MagicMock:
    fs = MagicMock()

    async def _open(object_id):
        stream = MagicMock()
        stream.read = AsyncMock(return_value=json.dumps(sboms_by_file_id[str(object_id)]).encode())
        return stream

    fs.open_download_stream = AsyncMock(side_effect=_open)
    return fs


async def _seed_rescan(db, sbom_refs: list[dict]) -> str:
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=sbom_refs,
        status="processing",
        worker_id=_WORKER,
        is_rescan=True,
        original_scan_id=_ORIGINAL_SCAN_ID,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id


async def _dependency_docs(db, scan_id: str) -> list[dict]:
    return [doc async for doc in db.dependencies.find({"scan_id": scan_id})]


async def _seed_stored_dependency(db, scan_id: str, name: str, version: str, purl: str) -> None:
    # Same doc shape the ingest path writes: a full Dependency model dump.
    dep = Dependency(project_id=_PROJECT_ID, scan_id=scan_id, name=name, version=version, purl=purl, type="library")
    await db.dependencies.insert_one(dep.model_dump(by_alias=True))


@pytest.fixture
def _gridfs_patched(monkeypatch):
    fs = _fake_gridfs({_FILE_ID_A: _SBOM_A, _FILE_ID_B: _SBOM_B})
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)
    return fs


@pytest.mark.asyncio
async def test_rescan_repopulates_dependencies_for_new_scan_id(db, _gridfs_patched):
    scan_id = await _seed_rescan(db, [_gridfs_ref(_FILE_ID_A)])
    await _seed_stored_dependency(db, _ORIGINAL_SCAN_ID, "requests", "2.31.0", "pkg:pypi/requests@2.31.0")

    completed = await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER)

    assert completed == SCAN_STATUS_COMPLETED
    docs = await _dependency_docs(db, scan_id)
    assert len(docs) == 3, f"rescan must store one dependency doc per parsed component, got {len(docs)}"
    assert {(d["name"], d["version"], d["purl"]) for d in docs} == {
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("urllib3", "2.1.0", "pkg:pypi/urllib3@2.1.0"),
        ("certifi", "2024.2.2", "pkg:pypi/certifi@2024.2.2"),
    }
    assert all(d["project_id"] == _PROJECT_ID for d in docs)
    original_docs = await _dependency_docs(db, _ORIGINAL_SCAN_ID)
    assert len(original_docs) == 1, "the original scan's dependencies must not be touched"


@pytest.mark.asyncio
async def test_rerunning_the_same_rescan_does_not_duplicate_dependencies(db, _gridfs_patched):
    scan_id = await _seed_rescan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing"}})
    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    assert len(docs) == 3, f"a retried run must replace, not append, got {len(docs)}"


@pytest.mark.asyncio
async def test_multi_sbom_run_deletes_once_and_keeps_all_sboms_dependencies(db, _gridfs_patched):
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan_id = await _seed_rescan(db, refs)

    assert await run_analysis(scan_id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    names = {d["name"] for d in docs}
    assert names == {"requests", "urllib3", "certifi", "flask"}, (
        f"deps of every SBOM in the run must survive (delete once per run), got {names}"
    )


@pytest.mark.asyncio
async def test_partial_gridfs_failure_keeps_all_stored_dependencies(db, _gridfs_patched, monkeypatch):
    """If any SBOM of the run fails to resolve, the scan's stored deps must survive untouched."""

    async def _fail_second_file(fs, file_id, **_kwargs):
        if str(file_id) == _FILE_ID_B:
            raise OSError("transient gridfs outage")
        return await fs.open_download_stream(file_id)

    monkeypatch.setattr("app.services.gridfs_maintenance.open_gridfs_download_with_retry", _fail_second_file)

    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    ingest_stored = [
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("urllib3", "2.1.0", "pkg:pypi/urllib3@2.1.0"),
        ("certifi", "2024.2.2", "pkg:pypi/certifi@2024.2.2"),
        ("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),
    ]
    for name, version, purl in ingest_stored:
        await _seed_stored_dependency(db, scan.id, name, version, purl)

    assert await run_analysis(scan.id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    docs = await _dependency_docs(db, scan.id)
    assert {(d["name"], d["version"]) for d in docs} == {(n, v) for n, v, _ in ingest_stored}, (
        "a partially resolved run must not wipe or halve the stored dependency set"
    )


@pytest.mark.asyncio
async def test_an_unparsable_sbom_keeps_the_stored_dependencies_and_flags_the_scan(db, monkeypatch):
    fs = _fake_gridfs({_FILE_ID_A: _SBOM_A, _FILE_ID_B: _MALFORMED_SBOM})
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _seed_stored_dependency(db, scan.id, "flask", "3.0.0", "pkg:pypi/flask@3.0.0")

    assert await run_analysis(scan.id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    assert [d["name"] for d in await _dependency_docs(db, scan.id)] == ["flask"]
    assert "1 of 2 SBOMs failed to parse" in (await db.scans.find_one({"_id": scan.id}))["error"]


@pytest.mark.asyncio
async def test_a_rescan_with_an_unparsable_sbom_fails_and_leaves_the_lineage_on_the_earlier_analysis(db, monkeypatch):
    fs = _fake_gridfs({_FILE_ID_A: _SBOM_A, _FILE_ID_B: _MALFORMED_SBOM})
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    await db.scans.insert_one(
        {"_id": _ORIGINAL_SCAN_ID, "project_id": _PROJECT_ID, "status": "completed", "latest_rescan_id": "earlier"}
    )
    scan_id = await _seed_rescan(db, refs)

    assert await run_analysis(scan_id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_FAILED

    assert (await db.scans.find_one({"_id": _ORIGINAL_SCAN_ID}))["latest_rescan_id"] == "earlier"
    assert (await db.scans.find_one({"_id": scan_id}))["error"] == "SBOM could not be loaded or parsed for analysis"


@pytest.mark.asyncio
async def test_a_rescan_with_an_unreadable_sbom_fails_and_leaves_the_lineage_on_the_earlier_analysis(
    db, _gridfs_patched, monkeypatch
):
    """A rescan has no stored inventory to keep, so a partial load would make it a head without dependencies."""

    async def _fail_second_file(fs, file_id, **_kwargs):
        if str(file_id) == _FILE_ID_B:
            raise OSError("transient gridfs outage")
        return await fs.open_download_stream(file_id)

    monkeypatch.setattr("app.services.analysis.engine.open_gridfs_download_with_retry", _fail_second_file)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    await db.scans.insert_one({"_id": _ORIGINAL_SCAN_ID, "project_id": _PROJECT_ID, "status": "completed"})
    scan_id = await _seed_rescan(db, refs)

    assert await run_analysis(scan_id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_FAILED

    assert (await db.scans.find_one({"_id": _ORIGINAL_SCAN_ID})).get("latest_rescan_id") is None


@pytest.mark.asyncio
async def test_ingest_prestored_dependencies_are_not_double_stored(db, _gridfs_patched):
    """On the normal ingest path the deps already exist for the scan_id; the run must stay at N docs."""
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[_gridfs_ref(_FILE_ID_A)],
        status="processing",
        worker_id=_WORKER,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    for name, version, purl in [
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("urllib3", "2.1.0", "pkg:pypi/urllib3@2.1.0"),
        ("certifi", "2024.2.2", "pkg:pypi/certifi@2024.2.2"),
    ]:
        await _seed_stored_dependency(db, scan.id, name, version, purl)

    assert await run_analysis(scan.id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan.id)
    assert len(docs) == 3, f"ingest-stored deps must not be stored a second time, got {len(docs)}"


# Same package described by two SBOMs of one payload (app image + base image), each carrying
# evidence the other lacks — the shape 3,698 of 45,084 production scans (8.2%) upload.
_SHARED_PURL = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64"


def _shared_component(bom_ref: str, location: str, cpe: str, layer: str | None) -> dict:
    properties = [
        {"name": "syft:location:0:path", "value": location},
        {"name": "syft:cpe23", "value": cpe},
    ]
    if layer:
        properties.append({"name": "syft:location:0:layerID", "value": layer})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "bom-ref": bom_ref,
                "name": "libssl3",
                "version": "3.0.11-1~deb12u2",
                "purl": _SHARED_PURL,
                "properties": properties,
            }
        ],
    }


@pytest.mark.asyncio
async def test_cross_sbom_duplicate_is_merged_by_the_analysis_run(db, monkeypatch):
    """The analysis run rewrites the inventory after ingest, so it must merge across SBOMs too."""
    from app.core.init_db import create_indexes

    await create_indexes(db)
    sbom_app = _shared_component(
        "ref-app", "/usr/lib/libssl.so.3", "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*", "sha256:" + "a" * 64
    )
    sbom_base = _shared_component(
        "ref-base", "/usr/share/doc/libssl3/copyright", "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*", None
    )
    fs = _fake_gridfs({_FILE_ID_A: sbom_app, _FILE_ID_B: sbom_base})
    monkeypatch.setattr("app.services.analysis.engine.AsyncIOMotorGridFSBucket", lambda _db: fs)

    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan_id = await _seed_rescan(db, refs)

    assert await run_analysis(scan_id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    assert len(docs) == 1
    assert docs[0]["locations"] == ["/usr/lib/libssl.so.3", "/usr/share/doc/libssl3/copyright"]
    assert docs[0]["cpes"] == [
        "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
        "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*",
    ]

"""Raw downloads stream the stored bytes of an SBOM, the SBOM export and an analyzer result; the lists carry metadata."""

import functools
import hashlib
import io
import json
import tempfile
import tracemalloc
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import bson
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.api.v1.endpoints import projects
from app.core.permissions import Permissions
from app.models.project import Project, Scan
from app.models.user import User
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.gridfs_maintenance import make_gridfs_ref
from app.services.rescan import build_rescan
from tests.helpers.analyzers import process_sbom_document

_MIB = 1024 * 1024
_MONGO_DOCUMENT_LIMIT = 16 * _MIB
# pymongo reads fs.chunks in server batches of up to 16 MiB and holds one batch raw and decoded.
_STREAM_PEAK_BOUND = 40 * _MIB
_LARGE_SBOM_BYTES = 3 * _MONGO_DOCUMENT_LIMIT
_SBOM_FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
_SYFT_COMPONENT = json.loads((_SBOM_FIXTURES / "npmpeer.syft.cdx.json").read_text())["components"][0]
_PROJECT_ID = "test-project-id"
_AUDITOR = User(id="auditor", username="auditor", email="auditor@test.com", permissions=[Permissions.PROJECT_READ_ALL])
_SECRET_FINDING = {"DetectorType": 2, "RawHash": "317e5726", "Verified": True}


def _fixture(name: str) -> bytes:
    """A real SBOM as ingest stores it: the compact dump."""
    return json.dumps(json.loads((_SBOM_FIXTURES / name).read_text())).encode()


@functools.cache
def _large_sbom() -> bytes:
    """The real uv syft SBOM, its components repeated under distinct names past three times the document limit."""
    sbom = json.loads((_SBOM_FIXTURES / "uvdev.syft.cdx.json").read_text())
    components = sbom["components"]
    copies = _LARGE_SBOM_BYTES // len(json.dumps(components)) + 1
    sbom["components"] = [
        {**component, "bom-ref": f"{component['bom-ref']}-{n}", "name": f"{component['name']}-{n}"}
        for n in range(copies)
        for component in components
    ]
    return json.dumps(sbom).encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _gridfs_bytes(db, ref: dict[str, Any]) -> bytes:
    return await (await AsyncIOMotorGridFSBucket(db).open_download_stream(ObjectId(ref["gridfs_id"]))).read()


async def _scan_with_sboms(db, *sboms: bytes, scan_id: str = "scan-1") -> Scan:
    fs = AsyncIOMotorGridFSBucket(db)
    refs = [
        make_gridfs_ref(await fs.upload_from_stream(f"sbom-{i}.json", data), f"sbom-{i}.json")
        for i, data in enumerate(sboms)
    ]
    scan = Scan(id=scan_id, project_id=_PROJECT_ID, branch="main", status="completed", sbom_refs=refs)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan


async def _delete_file(db, ref: dict[str, Any]) -> None:
    await AsyncIOMotorGridFSBucket(db).delete(ObjectId(ref["gridfs_id"]))


async def _drain_measured(endpoint_call) -> tuple[Any, bytes, int]:
    """The response, its body, and the peak traced memory while it is built and streamed to disk."""
    with tempfile.TemporaryFile() as body:
        tracemalloc.start()
        try:
            response = await endpoint_call
            async for chunk in response.body_iterator:
                body.write(chunk)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        body.seek(0)
        return response, body.read(), peak


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_sbom_over_16_mib_downloads_byte_identical_for_the_scan_and_its_rescan(
    client, db, member_auth_headers
):
    scan = await _scan_with_sboms(db, _large_sbom())
    rescan = build_rescan(scan.model_dump(by_alias=True))
    await db.scans.insert_one(rescan.model_dump(by_alias=True))

    served = await client.get(f"/api/v1/projects/scans/{scan.id}/sboms/0", headers=member_auth_headers)
    rescanned = await client.get(f"/api/v1/projects/scans/{rescan.id}/sboms/0", headers=member_auth_headers)

    assert served.status_code == 200, served.text[:500]
    assert served.headers["content-type"] == "application/json"
    assert served.headers["content-disposition"] == f'attachment; filename="scan_{scan.id}_sbom_1.json"'
    stored = await _gridfs_bytes(db, scan.sbom_refs[0])
    assert len(stored) > _MONGO_DOCUMENT_LIMIT
    assert _sha(served.content) == _sha(rescanned.content) == _sha(stored)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("index", [1, -1])
async def test_an_sbom_index_outside_the_scan_is_404(client, db, member_auth_headers, index):
    scan = await _scan_with_sboms(db, _fixture("npmpeer.syft.cdx.json"))

    served = await client.get(f"/api/v1/projects/scans/{scan.id}/sboms/{index}", headers=member_auth_headers)

    assert served.status_code == 404, served.text


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_sbom_over_16_mib_streams_in_memory_bounded_below_its_size(db):
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="shop").model_dump(by_alias=True))
    scan = await _scan_with_sboms(db, _large_sbom())
    stored_sha = _sha(await _gridfs_bytes(db, scan.sbom_refs[0]))

    _, body, peak = await _drain_measured(projects.download_scan_sbom(scan.id, 0, current_user=_AUDITOR, db=db))

    assert _sha(body) == stored_sha
    assert peak < _STREAM_PEAK_BOUND < len(_large_sbom())


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_multi_sbom_export_zips_each_stored_file_byte_for_byte_in_bounded_memory(db):
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="shop").model_dump(by_alias=True))
    scan = await _scan_with_sboms(db, _large_sbom(), _fixture("npmpeer.syft.cdx.json"))
    stored = [_sha(await _gridfs_bytes(db, ref)) for ref in scan.sbom_refs]

    response, body, peak = await _drain_measured(
        projects.export_project_sbom(_PROJECT_ID, current_user=_AUDITOR, db=db)
    )

    assert response.media_type == "application/zip"
    assert response.headers["content-disposition"] == f'attachment; filename="project_{_PROJECT_ID}_sboms.zip"'
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        entries = {name: _sha(archive.read(name)) for name in archive.namelist()}
    assert entries == {"sbom-1.json": stored[0], "sbom-2.json": stored[1]}
    assert peak < _STREAM_PEAK_BOUND < len(_large_sbom())


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_single_sbom_export_is_the_stored_upload_byte_for_byte(client, db, member_auth_headers):
    scan = await _scan_with_sboms(db, _fixture("uvdev.syft.cdx.json"))

    served = await client.get(f"/api/v1/projects/{_PROJECT_ID}/export/sbom", headers=member_auth_headers)

    assert served.status_code == 200, served.text[:500]
    assert served.headers["content-disposition"] == f'attachment; filename="project_{_PROJECT_ID}_sbom.json"'
    assert served.content == await _gridfs_bytes(db, scan.sbom_refs[0])


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("sbom_count", [1, 2])
async def test_an_export_with_a_deleted_sbom_file_is_404_before_any_byte(client, db, member_auth_headers, sbom_count):
    scan = await _scan_with_sboms(db, *[_fixture("npmpeer.syft.cdx.json")] * sbom_count)
    await _delete_file(db, scan.sbom_refs[-1])

    served = await client.get(f"/api/v1/projects/{_PROJECT_ID}/export/sbom", headers=member_auth_headers)

    assert served.status_code == 404, served.text[:500]
    assert served.json() == {"detail": "SBOM file not found in GridFS"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_sbom_list_carries_index_filename_and_size_and_none_for_a_deleted_file(
    client, db, member_auth_headers
):
    first, last = _fixture("npmpeer.syft.cdx.json"), _fixture("uvdev.syft.cdx.json")
    scan = await _scan_with_sboms(db, first, _fixture("mono.syft.cdx.json"), last)
    await _delete_file(db, scan.sbom_refs[1])

    served = await client.get(f"/api/v1/projects/scans/{scan.id}/sboms", headers=member_auth_headers)

    assert served.status_code == 200, served.text[:500]
    assert served.json() == [
        {"index": 0, "filename": "sbom-0.json", "size": len(first)},
        {"index": 1, "filename": "sbom-1.json", "size": None},
        {"index": 2, "filename": "sbom-2.json", "size": len(last)},
    ]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_engine_result_over_16_mib_downloads_as_the_stored_file(client, db, member_auth_headers):
    scan = await _scan_with_sboms(db)
    components = [
        {
            **_SYFT_COMPONENT,
            "bom-ref": f"pkg:npm/js-tokens-{i}@4.0.0",
            "name": f"js-tokens-{i}",
            "purl": f"pkg:npm/js-tokens-{i}@4.0.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        }
        for i in range(12_000)
    ]
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    await process_sbom_document(0, sbom, scan.id, db, ResultAggregator(), ["license_compliance"], None)
    row = await db.analysis_results.find_one({"scan_id": scan.id})

    served = await client.get(
        f"/api/v1/projects/scans/{scan.id}/results/{quote(row['_id'], safe='')}", headers=member_auth_headers
    )

    assert row["_id"] == f"{scan.id}:license_compliance:SBOM #1"
    assert served.status_code == 200, served.text[:500]
    stored = await _gridfs_bytes(db, {"gridfs_id": row["result_gridfs_id"]})
    assert len(stored) > _MONGO_DOCUMENT_LIMIT
    assert _sha(served.content) == _sha(stored)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_legacy_inline_result_row_is_served_from_the_row(client, db, member_auth_headers):
    scan = await _scan_with_sboms(db)
    result = {"findings": [_SECRET_FINDING]}
    await db.analysis_results.insert_one(
        {
            "_id": "0b6f2a4e-3c1d-4f5a-9e8b-7d6c5b4a3f21",
            "scan_id": scan.id,
            "analyzer_name": "trufflehog",
            "result": result,
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
    )

    served = await client.get(
        f"/api/v1/projects/scans/{scan.id}/results/0b6f2a4e-3c1d-4f5a-9e8b-7d6c5b4a3f21", headers=member_auth_headers
    )

    assert served.status_code == 200, served.text[:500]
    assert served.json() == result


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_result_of_another_scan_is_404(client, db, member_auth_headers):
    mine = await _scan_with_sboms(db, scan_id="scan-mine")
    await _scan_with_sboms(db, scan_id="scan-other")
    await db.analysis_results.insert_one(
        {"_id": "scan-other:trufflehog", "scan_id": "scan-other", "analyzer_name": "trufflehog", "result": {}}
    )

    served = await client.get(
        f"/api/v1/projects/scans/{mine.id}/results/scan-other:trufflehog", headers=member_auth_headers
    )

    assert served.status_code == 404, served.text


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_result_list_carries_each_rows_stored_size_and_none_for_a_deleted_file(
    client, db, member_auth_headers
):
    scan = await _scan_with_sboms(db)
    repo = AnalysisResultRepository(db)
    await repo.save_result(scan.id, "trivy", {"Results": []}, source="SBOM #1")
    await repo.save_result(scan.id, "grype", {"matches": []}, source="SBOM #1")
    await repo.save_result(scan.id, "osv", {"results": [{"packages": []}]}, source="SBOM #1")
    stored = {row["analyzer_name"]: {"gridfs_id": row["result_gridfs_id"]} async for row in db.analysis_results.find()}
    await _delete_file(db, stored["grype"])
    legacy = {"findings": [_SECRET_FINDING]}
    await db.analysis_results.insert_one(
        {
            "_id": "legacy-row",
            "scan_id": scan.id,
            "analyzer_name": "trufflehog",
            "result": legacy,
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
    )

    served = await client.get(f"/api/v1/projects/scans/{scan.id}/results", headers=member_auth_headers)

    assert served.status_code == 200, served.text[:500]
    rows = {row["analyzer_name"]: row for row in served.json()}
    assert {name: (row["source"], row["size"]) for name, row in rows.items()} == {
        "trivy": ("SBOM #1", len(await _gridfs_bytes(db, stored["trivy"]))),
        "osv": ("SBOM #1", len(await _gridfs_bytes(db, stored["osv"]))),
        "grype": ("SBOM #1", None),
        "trufflehog": (None, len(bson.encode(legacy))),
    }
    assert rows["trufflehog"]["created_at"].startswith("2026-01-01T00:00:00")
    assert all(set(row) == {"id", "scan_id", "analyzer_name", "source", "created_at", "size"} for row in rows.values())


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("in_gridfs", [False, True], ids=["legacy-inline", "gridfs"])
async def test_the_result_list_sizes_a_result_without_reading_it(db, in_gridfs):
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="shop").model_dump(by_alias=True))
    scan = await _scan_with_sboms(db)
    large = {"findings": [{**_SECRET_FINDING, "RawHash": f"{i:08x}"} for i in range(80_000)]}
    if in_gridfs:
        await AnalysisResultRepository(db).save_result(scan.id, "trufflehog", large)
        stored_size = len(json.dumps(large).encode())
    else:
        await db.analysis_results.insert_one(
            {"_id": "legacy-row", "scan_id": scan.id, "analyzer_name": "trufflehog", "result": large}
        )
        stored_size = len(bson.encode(large))

    tracemalloc.start()
    try:
        [listed] = await projects.read_analysis_results(scan.id, current_user=_AUDITOR, db=db)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert listed.size == stored_size > 4 * _MIB
    assert peak < _MIB

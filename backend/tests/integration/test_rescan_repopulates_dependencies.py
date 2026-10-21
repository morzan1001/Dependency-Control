import json
from pathlib import Path

import pytest
import pytest_asyncio

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS, SCAN_STATUS_FAILED
from app.core.init_db import create_indexes
from app.models.dependency import Dependency
from app.models.project import Scan
from tests.helpers.analyzers import analyse_scan, serve_analyzer
from tests.helpers.sboms import sbom_ref, store_sbom, unreadable_downloads

pytestmark = pytest.mark.live_mongo

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
# trufflehog v3 --json, one filesystem hit.
_SECRET = json.loads((Path(__file__).parents[1] / "fixtures/secrets/trufflehog_v3_line.json").read_text())


async def _store_sboms(db, sbom_a: dict, sbom_b: dict) -> None:
    await create_indexes(db)
    await store_sbom(db, sbom_a, _FILE_ID_A)
    await store_sbom(db, sbom_b, _FILE_ID_B)


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
    dep = Dependency(project_id=_PROJECT_ID, scan_id=scan_id, name=name, version=version, purl=purl, type="library")
    await db.dependencies.insert_one(dep.model_dump(by_alias=True))


@pytest_asyncio.fixture
async def _stored_sboms(db):
    await _store_sboms(db, _SBOM_A, _SBOM_B)


@pytest.fixture
def _second_file_unreadable(monkeypatch):
    unreadable_downloads(monkeypatch, {_FILE_ID_B})


@pytest.mark.asyncio
async def test_rescan_repopulates_dependencies_for_new_scan_id(db, _stored_sboms):
    scan_id = await _seed_rescan(db, [sbom_ref(_FILE_ID_A)])
    await _seed_stored_dependency(db, _ORIGINAL_SCAN_ID, "requests", "2.31.0", "pkg:pypi/requests@2.31.0")

    completed = await analyse_scan(db, scan_id, [sbom_ref(_FILE_ID_A)], [], worker_id=_WORKER)

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
async def test_rerunning_the_same_rescan_does_not_duplicate_dependencies(db, _stored_sboms):
    scan_id = await _seed_rescan(db, [sbom_ref(_FILE_ID_A)])

    assert await analyse_scan(db, scan_id, [sbom_ref(_FILE_ID_A)], [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing"}})
    assert await analyse_scan(db, scan_id, [sbom_ref(_FILE_ID_A)], [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    assert len(docs) == 3, f"a retried run must replace, not append, got {len(docs)}"


@pytest.mark.asyncio
async def test_multi_sbom_run_deletes_once_and_keeps_all_sboms_dependencies(db, _stored_sboms):
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    scan_id = await _seed_rescan(db, refs)

    assert await analyse_scan(db, scan_id, refs, [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    names = {d["name"] for d in docs}
    assert names == {"requests", "urllib3", "certifi", "flask"}, (
        f"deps of every SBOM in the run must survive (delete once per run), got {names}"
    )


@pytest.mark.asyncio
async def test_partial_gridfs_failure_keeps_all_stored_dependencies(db, _stored_sboms, _second_file_unreadable):
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
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

    assert await analyse_scan(db, scan.id, refs, [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    docs = await _dependency_docs(db, scan.id)
    assert {(d["name"], d["version"]) for d in docs} == {(n, v) for n, v, _ in ingest_stored}, (
        "a partially loaded run must not wipe or halve the stored dependency set"
    )
    assert "1 of 2 SBOMs failed to load" in (await db.scans.find_one({"_id": scan.id}))["error"]


@pytest.mark.asyncio
async def test_an_unparsable_sbom_keeps_the_stored_dependencies_and_flags_the_scan(db):
    await _store_sboms(db, _SBOM_A, _MALFORMED_SBOM)
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _seed_stored_dependency(db, scan.id, "flask", "3.0.0", "pkg:pypi/flask@3.0.0")

    assert await analyse_scan(db, scan.id, refs, [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    assert [d["name"] for d in await _dependency_docs(db, scan.id)] == ["flask"]
    assert "1 of 2 SBOMs failed to parse" in (await db.scans.find_one({"_id": scan.id}))["error"]


@pytest.mark.asyncio
async def test_a_rescan_with_an_unparsable_sbom_fails_and_leaves_the_lineage_on_the_earlier_analysis(db):
    await _store_sboms(db, _SBOM_A, _MALFORMED_SBOM)
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    await db.scans.insert_one(
        {"_id": _ORIGINAL_SCAN_ID, "project_id": _PROJECT_ID, "status": "completed", "latest_rescan_id": "earlier"}
    )
    scan_id = await _seed_rescan(db, refs)

    assert await analyse_scan(db, scan_id, refs, [], worker_id=_WORKER) == SCAN_STATUS_FAILED

    assert (await db.scans.find_one({"_id": _ORIGINAL_SCAN_ID}))["latest_rescan_id"] == "earlier"
    assert (await db.scans.find_one({"_id": scan_id}))["error"] == "SBOM could not be loaded or parsed for analysis"


@pytest.mark.asyncio
async def test_a_rescan_with_an_unreadable_sbom_fails_and_leaves_the_lineage_on_the_earlier_analysis(
    db, _stored_sboms, _second_file_unreadable
):
    """A rescan has no stored inventory to keep, so a partial load would make it a head without dependencies."""
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    await db.scans.insert_one({"_id": _ORIGINAL_SCAN_ID, "project_id": _PROJECT_ID, "status": "completed"})
    scan_id = await _seed_rescan(db, refs)

    assert await analyse_scan(db, scan_id, refs, [], worker_id=_WORKER) == SCAN_STATUS_FAILED

    assert (await db.scans.find_one({"_id": _ORIGINAL_SCAN_ID})).get("latest_rescan_id") is None


class _MatchesRequests:
    async def analyze(self, sbom, settings=None, parsed_components=None):
        artifact = {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
        return {"matches": [{"vulnerability": {"id": "CVE-2024-35195", "severity": "Medium"}, "artifact": artifact}]}


async def _post_secret(db, scan_id: str) -> None:
    await db.analysis_results.insert_one(
        {"scan_id": scan_id, "analyzer_name": "trufflehog", "result": {"findings": [_SECRET]}}
    )


async def _finding_types(db, scan_id: str) -> list[str]:
    return sorted([f["type"] async for f in db.findings.find({"scan_id": scan_id})])


@pytest.mark.asyncio
async def test_a_failed_rescan_keeps_the_findings_of_its_readable_sbom_and_the_carried_scanner_results(db, monkeypatch):
    await _store_sboms(db, _SBOM_A, _MALFORMED_SBOM)
    serve_analyzer(monkeypatch, "grype", _MatchesRequests())
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    await db.scans.insert_one({"_id": _ORIGINAL_SCAN_ID, "project_id": _PROJECT_ID, "status": "completed"})
    await _post_secret(db, _ORIGINAL_SCAN_ID)
    scan_id = await _seed_rescan(db, refs)

    assert await analyse_scan(db, scan_id, refs, ["grype"], worker_id=_WORKER) == SCAN_STATUS_FAILED

    scan = await db.scans.find_one({"_id": scan_id})
    assert (scan["error"], scan["findings_count"]) == ("SBOM could not be loaded or parsed for analysis", 2)
    assert await _finding_types(db, scan_id) == ["secret", "vulnerability"]
    assert await _dependency_docs(db, scan_id) == []


@pytest.mark.asyncio
async def test_a_first_analysis_whose_sboms_all_fail_to_load_keeps_the_ci_scanner_findings(
    db, _stored_sboms, monkeypatch
):
    unreadable_downloads(monkeypatch, {_FILE_ID_A, _FILE_ID_B})
    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    await _post_secret(db, scan.id)

    assert await analyse_scan(db, scan.id, refs, [], worker_id=_WORKER) == SCAN_STATUS_FAILED

    assert await _finding_types(db, scan.id) == ["secret", "system_warning"]
    assert (await db.scans.find_one({"_id": scan.id}))["error"] == "SBOM could not be loaded or parsed for analysis"


@pytest.mark.asyncio
async def test_ingest_prestored_dependencies_are_not_double_stored(db, _stored_sboms):
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=[sbom_ref(_FILE_ID_A)],
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

    assert await analyse_scan(db, scan.id, [sbom_ref(_FILE_ID_A)], [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan.id)
    assert len(docs) == 3, f"ingest-stored deps must not be stored a second time, got {len(docs)}"


# One package in two SBOMs of a payload (app and base image), each carrying evidence the other lacks.
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
async def test_cross_sbom_duplicate_is_merged_by_the_analysis_run(db):
    """The analysis run rewrites the inventory after ingest, so it must merge across SBOMs too."""
    sbom_app = _shared_component(
        "ref-app", "/usr/lib/libssl.so.3", "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*", "sha256:" + "a" * 64
    )
    sbom_base = _shared_component(
        "ref-base", "/usr/share/doc/libssl3/copyright", "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*", None
    )
    await _store_sboms(db, sbom_app, sbom_base)

    refs = [sbom_ref(_FILE_ID_A), sbom_ref(_FILE_ID_B)]
    scan_id = await _seed_rescan(db, refs)

    assert await analyse_scan(db, scan_id, refs, [], worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    docs = await _dependency_docs(db, scan_id)
    assert len(docs) == 1
    assert docs[0]["locations"] == ["/usr/lib/libssl.so.3", "/usr/share/doc/libssl3/copyright"]
    assert docs[0]["cpes"] == [
        "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
        "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*",
    ]

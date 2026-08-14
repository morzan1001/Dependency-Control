"""W14 + cluster-2 follow-ups: re-ingest replaces sbom_refs (no GridFS pile-up), mixed payloads
cannot wipe stored dependencies, and component loss is surfaced in the ingest response."""

import pytest
from bson import ObjectId

from app.api.v1.endpoints.ingest import _process_sboms
from app.repositories.dependencies import DependencyRepository

_PROJECT_ID = "test-project-id"
_SCAN_ID = "8e0d76a5-1291-5949-8e0d-0d90b4bd9e01"


def _cyclonedx(components: list[dict]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


_GOOD_SBOM = _cyclonedx(
    [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    ]
)

# Document-level malformed: metadata must be an object (prod retries carry this shape).
_MALFORMED_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": [],
    "components": [{"type": "library", "name": "valid", "version": "1.0", "purl": "pkg:pypi/valid@1.0"}],
}


class _FakeGridFSBucket:
    """Stores uploads in db['fs.files'] so reference/delete bookkeeping is observable."""

    def __init__(self, db):
        self._files = db["fs.files"]

    async def upload_from_stream(self, filename, data, metadata=None):
        oid = ObjectId()
        await self._files.insert_one(
            {"_id": str(oid), "filename": filename, "length": len(data), "metadata": metadata or {}}
        )
        return oid

    async def delete(self, oid):
        await self._files.delete_one({"_id": str(oid)})


async def _seed_existing_dependencies(db) -> None:
    for name, version in (("requests", "2.31.0"), ("urllib3", "2.1.0")):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{name}",
                "project_id": _PROJECT_ID,
                "scan_id": _SCAN_ID,
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )


@pytest.mark.asyncio
async def test_mixed_payload_keeps_stored_dependencies(db):
    """A good SBOM's delete-once must not wipe a sibling malformed SBOM's prior contribution."""
    await _seed_existing_dependencies(db)
    dep_repo = DependencyRepository(db)

    _, warnings, _processed, failed, inserted = await _process_sboms(
        [_GOOD_SBOM, _MALFORMED_SBOM], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, dep_repo
    )

    assert failed == 1
    assert inserted == 0, "no partial replacement: either all SBOMs parse or the stored inventory is kept"
    survivors = await db.dependencies.count_documents({"scan_id": _SCAN_ID})
    assert survivors == 2, "prior dependency inventory must survive a mixed [good, malformed] payload"
    assert any("inventory" in w.lower() for w in warnings), f"the kept inventory must be surfaced, got {warnings}"


@pytest.mark.asyncio
async def test_all_good_payload_replaces_dependencies(db):
    await _seed_existing_dependencies(db)
    dep_repo = DependencyRepository(db)

    _, _warnings, processed, failed, inserted = await _process_sboms(
        [_GOOD_SBOM], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, dep_repo
    )

    assert failed == 0
    assert processed == 1
    assert inserted == 1
    docs = [d async for d in db.dependencies.find({"scan_id": _SCAN_ID})]
    assert {d["name"] for d in docs} == {"requests"}


@pytest.mark.asyncio
async def test_skipped_components_are_surfaced_in_warnings(db):
    """A component-loss event must reach the ingest response, not just pod logs."""
    sbom = _cyclonedx(
        [
            {
                "type": "library",
                "bom-ref": "pkg:pypi/requests@2.31.0",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {"type": "file", "bom-ref": "f-1", "name": "some-file.txt"},
        ]
    )

    _, warnings, _, failed, _ = await _process_sboms(
        [sbom], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert failed == 0
    assert any("skipped" in w.lower() and "file" in w.lower() for w in warnings), (
        f"skipped component counts and reasons must be surfaced, got {warnings}"
    )


@pytest.mark.asyncio
async def test_w14_reingest_replaces_sbom_refs_and_deletes_superseded_files(client, db, api_key_headers, monkeypatch):
    from app.api.v1.endpoints import ingest as ingest_module
    from app.services import gridfs_maintenance

    monkeypatch.setattr(ingest_module, "AsyncIOMotorGridFSBucket", _FakeGridFSBucket)
    monkeypatch.setattr(gridfs_maintenance, "AsyncIOMotorGridFSBucket", _FakeGridFSBucket)

    payload = {
        "pipeline_id": 424242,
        "commit_hash": "b" * 40,
        "branch": "main",
        "project_url": "https://example.invalid/p",
        "sboms": [_GOOD_SBOM],
    }

    resp1 = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
    assert resp1.status_code == 202, resp1.text
    scan_id = resp1.json()["scan_id"]
    scan = await db.scans.find_one({"_id": scan_id})
    first_refs = scan["sbom_refs"]
    assert len(first_refs) == 1

    resp2 = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
    assert resp2.status_code == 202, resp2.text
    assert resp2.json()["scan_id"] == scan_id, "same pipeline+commit must map to the same scan"

    scan = await db.scans.find_one({"_id": scan_id})
    assert len(scan["sbom_refs"]) == 1, f"re-ingest must replace sbom_refs, got {len(scan['sbom_refs'])}"
    assert scan["sbom_refs"][0]["gridfs_id"] != first_refs[0]["gridfs_id"]

    stored_files = await db["fs.files"].count_documents({})
    assert stored_files == 1, f"the superseded GridFS upload must be deleted, got {stored_files} files"

"""A scan's unique dependency index spans the whole scan, so duplicates across the payload's
SBOMs must be merged before the first insert. 3,698 of 45,084 production scans (8.2%) carry
two or more SBOMs; a 60-scan sample of them index-dropped 2,772 of 21,730 parsed dependencies."""

import pytest
from bson import ObjectId

from app.api.v1.endpoints.ingest import _process_sboms
from app.core.init_db import create_indexes
from app.repositories.dependencies import DependencyRepository

_PROJECT_ID = "test-project-id"
_SCAN_ID = "8e0d76a5-1291-5949-8e0d-0d90b4bd9e02"

_PURL = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64"


def _syft_cyclonedx(component: dict, dependencies: list[dict]) -> dict:
    """Shape emitted by `syft ... -o cyclonedx-json`, which is what production uploads."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "container", "name": "registry.example/app", "bom-ref": "root"},
            "tools": [{"name": "syft", "version": "1.18.1"}],
        },
        "components": [component],
        "dependencies": dependencies,
    }


_SBOM_APP_LAYER = _syft_cyclonedx(
    {
        "type": "library",
        "bom-ref": "ref-app",
        "name": "libssl3",
        "version": "3.0.11-1~deb12u2",
        "purl": _PURL,
        "properties": [
            {"name": "syft:location:0:path", "value": "/usr/lib/x86_64-linux-gnu/libssl.so.3"},
            {
                "name": "syft:location:0:layerID",
                "value": "sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
            },
            {"name": "syft:cpe23", "value": "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"},
        ],
    },
    [{"ref": "root", "dependsOn": ["ref-app"]}],
)

_SBOM_BASE_LAYER = _syft_cyclonedx(
    {
        "type": "library",
        "bom-ref": "ref-base",
        "name": "libssl3",
        "version": "3.0.11-1~deb12u2",
        "purl": _PURL,
        "properties": [
            {"name": "syft:location:0:path", "value": "/usr/share/doc/libssl3/copyright"},
            {"name": "syft:cpe23", "value": "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*"},
        ],
    },
    [{"ref": "root", "dependsOn": ["ref-base"]}],
)


class _FakeGridFSBucket:
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


@pytest.mark.asyncio
async def test_duplicate_across_sboms_is_merged_not_index_dropped(db):
    # The app's own index definitions, so the test cannot pass by ignoring the unique key.
    await create_indexes(db)

    _refs, warnings, processed, failed, inserted = await _process_sboms(
        [_SBOM_APP_LAYER, _SBOM_BASE_LAYER], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert (processed, failed) == (2, 0)
    assert inserted == 1, "the two SBOMs describe one package; it must be stored once"
    assert not warnings, f"a merged duplicate is not a storage loss, got {warnings}"

    docs = [d async for d in db.dependencies.find({"scan_id": _SCAN_ID})]
    assert len(docs) == 1
    stored = docs[0]
    assert stored["locations"] == [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/share/doc/libssl3/copyright",
    ]
    assert stored["cpes"] == [
        "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
        "cpe:2.3:a:openssl:libssl3:3.0.11:*:*:*:*:*:*:*",
    ]
    assert stored["layer_digest"] == "sha256:aaa1111111111111111111111111111111111111111111111111111111111111"


@pytest.mark.asyncio
async def test_the_same_sbom_uploaded_twice_stores_one_inventory(db):
    """14 identical uploads on one production scan index-dropped 1,586 of 1,708 rows and
    reported them as a storage loss in the ingest response."""
    await create_indexes(db)

    _refs, warnings, _processed, failed, inserted = await _process_sboms(
        [_SBOM_APP_LAYER, _SBOM_APP_LAYER], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert failed == 0
    assert inserted == 1
    assert not warnings
    assert await db.dependencies.count_documents({"scan_id": _SCAN_ID}) == 1


@pytest.mark.asyncio
async def test_a_component_without_its_own_purl_is_still_merged(db):
    """The parser fabricates a pkg:generic purl for an unidentified component, so these rows
    reach the index too; the merge has to collapse them like any other duplicate."""
    await create_indexes(db)
    no_purl = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "bom-ref": "r1", "name": "vendored-blob", "version": "1.0"}],
    }

    _refs, warnings, _processed, failed, inserted = await _process_sboms(
        [no_purl, no_purl], _FakeGridFSBucket(db), _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert (failed, inserted) == (0, 1)
    assert not warnings
    assert await db.dependencies.count_documents({"scan_id": _SCAN_ID}) == 1


@pytest.mark.asyncio
async def test_the_fake_index_treats_a_null_purl_as_a_colliding_value(db):
    """Guards the emulation, not the app. A sparse COMPOUND index only skips a document when
    every indexed field is absent, and a missing field is indexed as null — so two purl-less
    rows for one name@version collide in real Mongo exactly as an explicit-null pair does.
    init_db._migrate_project_indexes documents the same trap for the project indexes."""
    from pymongo.errors import DuplicateKeyError

    await create_indexes(db)
    explicit_null = {"scan_id": _SCAN_ID, "name": "vendored-blob", "version": "1.0", "purl": None}
    await db.dependencies.insert_one({"_id": "a", **explicit_null})
    with pytest.raises(DuplicateKeyError):
        await db.dependencies.insert_one({"_id": "b", **explicit_null})

    # An omitted purl produces the same index key as an explicit null.
    with pytest.raises(DuplicateKeyError):
        await db.dependencies.insert_one({"_id": "c", "scan_id": _SCAN_ID, "name": "vendored-blob", "version": "1.0"})

    # A different artifact does not collide, so the guard is not matching everything.
    await db.dependencies.insert_one({"_id": "d", **explicit_null, "name": "other-blob"})
    assert await db.dependencies.count_documents({"scan_id": _SCAN_ID}) == 2

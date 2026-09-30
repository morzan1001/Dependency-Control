"""A scan's unique dependency index spans the whole scan, so duplicates across the payload's
SBOMs must be merged before the first insert. 3,698 of 45,084 production scans (8.2%) carry
two or more SBOMs; a 60-scan sample of them index-dropped 2,772 of 21,730 parsed dependencies."""

import asyncio
import json
from pathlib import Path

import pytest

from app.core.init_db import create_indexes
from app.repositories.dependencies import DependencyRepository
from app.schemas.sbom import ParsedDependency, ParsedSBOM, SBOMFormat
from app.services import dependency_store
from app.services.dependency_store import store_scan_dependencies
from app.services.sbom_parser import parse_sbom

_PROJECT_ID = "test-project-id"
_SCAN_ID = "8e0d76a5-1291-5949-8e0d-0d90b4bd9e02"

_PURL = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64"
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_MIB = 1024 * 1024


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


@pytest.mark.asyncio
async def test_duplicate_across_sboms_is_merged_not_index_dropped(db):
    # The app's own index definitions, so the test cannot pass by ignoring the unique key.
    await create_indexes(db)

    inserted = await store_scan_dependencies(
        [parse_sbom(_SBOM_APP_LAYER), parse_sbom(_SBOM_BASE_LAYER)], _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert inserted == 1, "the two SBOMs describe one package; it must be stored once"

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
    """14 identical uploads on one production scan index-dropped 1,586 of 1,708 rows."""
    await create_indexes(db)

    inserted = await store_scan_dependencies(
        [parse_sbom(_SBOM_APP_LAYER), parse_sbom(_SBOM_APP_LAYER)], _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert inserted == 1
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

    inserted = await store_scan_dependencies(
        [parse_sbom(no_purl), parse_sbom(no_purl)], _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert inserted == 1
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


@pytest.mark.asyncio
async def test_the_store_merges_duplicates_its_caller_did_not(db):
    await create_indexes(db)
    first = ParsedDependency(name="libssl3", version="3.0.11", purl=_PURL, locations=["/usr/lib/libssl.so.3"])
    second = ParsedDependency(name="libssl3", version="3.0.11", purl=_PURL, locations=["/usr/share/doc/libssl3"])

    stored = await store_scan_dependencies(
        [_sbom(first), _sbom(second)], _PROJECT_ID, _SCAN_ID, DependencyRepository(db)
    )

    assert stored == 1
    docs = [d async for d in db.dependencies.find({"scan_id": _SCAN_ID})]
    assert [d["locations"] for d in docs] == [["/usr/lib/libssl.so.3", "/usr/share/doc/libssl3"]]


def _sbom(*dependencies: ParsedDependency) -> ParsedSBOM:
    return ParsedSBOM(format=SBOMFormat.CYCLONEDX, dependencies=list(dependencies))


def _dep(name: str, **fields) -> ParsedDependency:
    return ParsedDependency(name=name, version="1.0", purl=f"pkg:npm/{name}@1.0", **fields)


async def _inventory(db) -> dict[str, dict]:
    return {d["name"]: d async for d in db.dependencies.find({"scan_id": _SCAN_ID})}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_store_that_fails_part_way_keeps_the_previous_inventory(db, monkeypatch):
    """A re-ingest that dies between chunks must not leave the scan with a truncated inventory."""
    await create_indexes(db)
    repo = DependencyRepository(db)
    await store_scan_dependencies([_sbom(_dep("old-only"), _dep("shared"))], _PROJECT_ID, _SCAN_ID, repo)

    build = dependency_store._parsed_dep_to_dependency

    def fail_on_second_chunk(parsed_dep, *args):
        if parsed_dep.name == "new-b":
            raise ConnectionResetError("network gone mid-replace")
        return build(parsed_dep, *args)

    monkeypatch.setattr(dependency_store, "_DEP_CHUNK_SIZE", 2)
    monkeypatch.setattr(dependency_store, "_parsed_dep_to_dependency", fail_on_second_chunk)
    with pytest.raises(ConnectionResetError):
        await store_scan_dependencies(
            [_sbom(_dep("shared", scope="runtime"), _dep("new-a"), _dep("new-b"))], _PROJECT_ID, _SCAN_ID, repo
        )

    assert sorted(await _inventory(db)) == ["new-a", "old-only", "shared"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_finished_store_leaves_exactly_the_new_inventory(db):
    await create_indexes(db)
    repo = DependencyRepository(db)
    unidentified = ParsedDependency(name="vendored-blob", version="1.0")
    await store_scan_dependencies([_sbom(_dep("old-only"), _dep("shared"), unidentified)], _PROJECT_ID, _SCAN_ID, repo)
    kept_id = (await _inventory(db))["shared"]["_id"]

    stored = await store_scan_dependencies(
        [_sbom(_dep("shared", scope="runtime"), _dep("new"), unidentified)], _PROJECT_ID, _SCAN_ID, repo
    )

    inventory = await _inventory(db)
    assert stored == 3
    assert sorted(inventory) == ["new", "shared", "vendored-blob"]
    assert (inventory["shared"]["_id"], inventory["shared"]["scope"]) == (kept_id, "runtime")
    assert all(isinstance(doc["_id"], str) for doc in inventory.values())


class _CleanupAfterBothWrote(DependencyRepository):
    """Holds each store's cleanup delete until both overlapping stores have written their rows."""

    def __init__(self, db, both_written: asyncio.Barrier):
        super().__init__(db)
        self._both_written = both_written

    async def delete_older_writes(self, query, written_at):
        await self._both_written.wait()
        await super().delete_older_writes(query, written_at)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        pytest.param(["a", "b", "shared"], ["a", "b", "shared"], id="one-scan-claimed-by-two-workers"),
        pytest.param(["old-only", "shared"], ["new-only", "shared"], id="re-ingest-during-the-analysis"),
    ],
)
async def test_overlapping_stores_of_one_scan_leave_the_later_inventory(db, earlier, later):
    await create_indexes(db)
    repo = _CleanupAfterBothWrote(db, asyncio.Barrier(2))

    async def later_store():
        await asyncio.sleep(0.01)  # a later millisecond, so the two writes carry distinct markers
        await store_scan_dependencies([_sbom(*map(_dep, later))], _PROJECT_ID, _SCAN_ID, repo)

    await asyncio.gather(
        store_scan_dependencies([_sbom(*map(_dep, earlier))], _PROJECT_ID, _SCAN_ID, repo), later_store()
    )

    assert sorted(await _inventory(db)) == sorted(later)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_description_past_the_document_limit_is_stored_clipped(db):
    """Mongo refuses a dependency row over 16 MiB (BulkWriteError 17420); the full text stays in the stored SBOM."""
    await create_indexes(db)
    sbom = json.loads((_FIXTURES / "sbom/mono.syft.cdx.json").read_text())
    first = sbom["components"][0]
    first["description"] = "An async networking library. " * (17 * _MIB // 29 + 1)
    parsed = parse_sbom(sbom)

    stored = await store_scan_dependencies([parsed], _PROJECT_ID, _SCAN_ID, DependencyRepository(db))

    assert stored == len(parsed.dependencies) == await db.dependencies.count_documents({"scan_id": _SCAN_ID})
    row = await db.dependencies.find_one({"scan_id": _SCAN_ID, "name": first["name"]})
    assert row["description"] == first["description"][:2048]

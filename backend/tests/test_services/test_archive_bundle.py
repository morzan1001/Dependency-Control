import json
from typing import Dict, List

import pytest


async def _async_iter(items):
    for item in items:
        yield item


async def _collect(stream):
    out: list[bytes] = []
    async for chunk in stream:
        out.append(chunk)
    return b"".join(out)


@pytest.mark.asyncio
async def test_write_then_read_roundtrip():
    from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

    stats = BundleStats()
    scan_doc = {"_id": "scan-1", "project_id": "p1", "branch": "main"}

    async def gen():
        async for chunk in BundleFrames.write(
            scan_doc=scan_doc,
            collections={
                "findings": _async_iter([{"_id": "f1", "severity": "CRITICAL"}, {"_id": "f2", "severity": "HIGH"}]),
                "dependencies": _async_iter([{"_id": "d1", "name": "lib"}]),
                "gridfs_sboms": _async_iter([{"gridfs_id": "g1", "filename": "sbom.json", "data": {"x": 1}}]),
            },
            stats=stats,
        ):
            yield chunk

    raw = await _collect(gen())

    # Stats updated as we write
    assert stats.findings == 2
    assert stats.dependencies == 1
    assert stats.critical_findings == 1
    assert stats.high_findings == 1

    # Round-trip read
    parsed_header = None
    rows_by_coll: Dict[str, List[dict]] = {}
    footer = None

    async def source():
        yield raw

    async for event in read_bundle_frames(source()):
        if event["type"] == "header":
            parsed_header = event["data"]
        elif event["type"] == "doc":
            rows_by_coll.setdefault(event["collection"], []).append(event["data"])
        elif event["type"] == "footer":
            footer = event["data"]

    assert parsed_header is not None
    assert parsed_header["scan_id"] == "scan-1"
    assert parsed_header["version"] == 2
    assert len(rows_by_coll["findings"]) == 2
    assert rows_by_coll["dependencies"][0]["name"] == "lib"
    assert rows_by_coll["gridfs_sboms"][0]["filename"] == "sbom.json"
    assert footer is not None
    assert footer["stats"]["findings"] == 2
    assert "sha256" in footer


@pytest.mark.asyncio
async def test_write_includes_crypto_assets_in_bundle_and_stats():
    """crypto_assets must round-trip through the bundle and bump the stats counter."""
    from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

    stats = BundleStats()
    scan_doc = {"_id": "scan-cb", "project_id": "p1"}

    async def gen():
        async for chunk in BundleFrames.write(
            scan_doc=scan_doc,
            collections={
                "crypto_assets": _async_iter(
                    [
                        {"_id": "ca1", "name": "MD5", "primitive": "hash"},
                        {"_id": "ca2", "name": "SHA-256", "primitive": "hash"},
                    ]
                ),
            },
            stats=stats,
        ):
            yield chunk

    raw = await _collect(gen())

    assert stats.crypto_assets == 2

    rows_by_coll: Dict[str, List[dict]] = {}
    footer = None

    async def source():
        yield raw

    async for event in read_bundle_frames(source()):
        if event["type"] == "doc":
            rows_by_coll.setdefault(event["collection"], []).append(event["data"])
        elif event["type"] == "footer":
            footer = event["data"]

    assert len(rows_by_coll["crypto_assets"]) == 2
    assert rows_by_coll["crypto_assets"][0]["name"] == "MD5"
    assert footer is not None
    assert footer["stats"]["crypto_assets"] == 2


@pytest.mark.asyncio
async def test_roundtrip_preserves_datetime_and_objectid_bson_types():
    """Restore must get real BSON datetime/ObjectId back, not strings.

    Regression: _serialize used to stringify datetimes/ObjectIds at write time and
    the reader parsed with plain json.loads, so restored scans/findings had
    string dates -> date-range ($gte) filters and created_at sorts silently
    failed to match/order restored docs.
    """
    import datetime as dt

    from bson import ObjectId

    from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

    created = dt.datetime(2023, 5, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    # json_util decodes $date to naive-UTC (exactly how Mongo stores/compares dates).
    created_utc_naive = created.replace(tzinfo=None)
    scan_oid = ObjectId()
    finding_oid = ObjectId()
    scan_doc = {"_id": scan_oid, "project_id": "p1", "created_at": created, "completed_at": created}

    stats = BundleStats()

    async def gen():
        async for chunk in BundleFrames.write(
            scan_doc=scan_doc,
            collections={
                "findings": _async_iter([{"_id": finding_oid, "severity": "HIGH", "detected_at": created}]),
            },
            stats=stats,
        ):
            yield chunk

    raw = await _collect(gen())

    async def source():
        yield raw

    header = None
    findings: List[dict] = []
    async for event in read_bundle_frames(source()):
        if event["type"] == "header":
            header = event["data"]
        elif event["type"] == "doc" and event["collection"] == "findings":
            findings.append(event["data"])

    assert header is not None
    restored_scan = header["scan"]
    # Datetime fields come back as real datetimes so $gte/$lte/sort work again.
    assert isinstance(restored_scan["created_at"], dt.datetime)
    assert restored_scan["created_at"] == created_utc_naive
    assert isinstance(restored_scan["completed_at"], dt.datetime)
    # _id comes back as a real ObjectId.
    assert isinstance(restored_scan["_id"], ObjectId)
    assert restored_scan["_id"] == scan_oid
    # Header identification fields stay plain strings by design.
    assert header["scan_id"] == str(scan_oid)

    assert len(findings) == 1
    assert isinstance(findings[0]["_id"], ObjectId)
    assert findings[0]["_id"] == finding_oid
    assert isinstance(findings[0]["detected_at"], dt.datetime)
    assert findings[0]["detected_at"] == created_utc_naive


@pytest.mark.asyncio
async def test_read_rejects_unknown_version():
    from app.services.archive_bundle import read_bundle_frames

    bad_header = json.dumps({"version": 99, "scan_id": "x", "project_id": "y"}).encode() + b"\n"

    async def source():
        yield bad_header

    with pytest.raises(ValueError, match="version"):
        async for _ in read_bundle_frames(source()):
            pass


@pytest.mark.asyncio
async def test_read_detects_integrity_failure():
    from app.services.archive_bundle import read_bundle_frames

    # Build a valid prefix but with a footer SHA-256 that doesn't match
    header = json.dumps({"version": 2, "scan_id": "x", "project_id": "y", "scan": {}}).encode() + b"\n"
    coll = json.dumps({"collection": "findings"}).encode() + b"\n"
    doc = json.dumps({"_id": "f1"}).encode() + b"\n"
    footer = json.dumps({"footer": True, "stats": {}, "sha256": "deadbeef" * 8}).encode() + b"\n"
    payload = header + coll + doc + footer

    async def source():
        yield payload

    with pytest.raises(ValueError, match="checksum|integrity"):
        async for _ in read_bundle_frames(source()):
            pass


@pytest.mark.asyncio
async def test_serialize_handles_nested_lists_and_objectids():
    from bson import ObjectId

    from app.services.archive_bundle import _serialize

    oid_a = ObjectId()
    oid_b = ObjectId()
    nested = {
        "id": oid_a,
        "items": [[oid_b, "plain"], [{"inner": oid_a}]],
        "ts": None,
    }
    result = _serialize(nested)
    # Recursive normalization: inner objectid in nested-list-of-list is normalized
    assert result["id"] == str(oid_a)
    assert result["items"][0][0] == str(oid_b)
    assert result["items"][0][1] == "plain"
    assert result["items"][1][0]["inner"] == str(oid_a)


@pytest.mark.asyncio
async def test_doc_before_collection_marker_raises():
    from app.services.archive_bundle import read_bundle_frames

    header = json.dumps({"version": 2, "scan_id": "x", "project_id": "y", "scan": {}}).encode() + b"\n"
    stray_doc = json.dumps({"_id": "stray"}).encode() + b"\n"

    async def source():
        yield header + stray_doc

    with pytest.raises(ValueError, match="collection marker"):
        async for _ in read_bundle_frames(source()):
            pass


@pytest.mark.asyncio
async def test_empty_bundle_raises():
    from app.services.archive_bundle import read_bundle_frames

    async def source():
        if False:
            yield b""

    with pytest.raises(ValueError, match="header"):
        async for _ in read_bundle_frames(source()):
            pass


@pytest.mark.asyncio
async def test_header_serializes_objectid_id_and_project_id():
    """Header must not crash when scan_doc has BSON ObjectId in _id / project_id."""
    from bson import ObjectId

    from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

    oid_scan = ObjectId()
    oid_proj = ObjectId()
    scan_doc = {"_id": oid_scan, "project_id": oid_proj, "branch": "main"}

    stats = BundleStats()

    async def gen():
        async for chunk in BundleFrames.write(
            scan_doc=scan_doc,
            collections={"findings": _async_iter([])},
            stats=stats,
        ):
            yield chunk

    raw = await _collect(gen())

    async def source():
        yield raw

    header = None
    async for event in read_bundle_frames(source()):
        if event["type"] == "header":
            header = event["data"]
            break
    assert header is not None
    assert header["scan_id"] == str(oid_scan)
    assert header["project_id"] == str(oid_proj)


@pytest.mark.asyncio
async def test_read_raises_when_footer_missing():
    """A bundle stream that ends without the footer line must raise ValueError."""
    from app.services.archive_bundle import read_bundle_frames

    header = json.dumps({"version": 2, "scan_id": "x", "project_id": "y", "scan": {"_id": "x"}}).encode() + b"\n"
    marker = json.dumps({"collection": "findings"}).encode() + b"\n"
    doc = json.dumps({"_id": "f1"}).encode() + b"\n"
    # NO footer line at the end
    truncated = header + marker + doc

    async def source():
        yield truncated

    with pytest.raises(ValueError, match="truncated|footer"):
        async for _ in read_bundle_frames(source()):
            pass  # drive the generator until it raises

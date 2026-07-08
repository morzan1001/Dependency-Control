"""NDJSON-frame archive bundle format (v2).

Each line is a complete JSON document terminated by '\\n': a header line, then per-collection
sections opened by a one-field ``{"collection": ...}`` marker, then a footer line carrying
stats and a sha256 over every byte before the footer.
"""

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict

from bson import ObjectId, json_util

from app.core.constants import ARCHIVE_BUNDLE_VERSION


@dataclass
class BundleStats:
    """Mutable per-archive counters; populated as docs stream through the writer."""

    findings: int = 0
    finding_records: int = 0
    dependencies: int = 0
    analysis_results: int = 0
    callgraphs: int = 0
    crypto_assets: int = 0
    critical_findings: int = 0
    high_findings: int = 0


def _serialize(obj: Any) -> Any:
    """Recursively normalize to plain JSON types (ObjectId->str, datetime->ISO).

    Lossy and NOT round-trippable; used only for the header's plain-string scan_id/project_id.
    Restorable document bodies go through _json_line (Extended JSON, BSON-preserving).
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, dt.datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    return obj


def _json_line(obj: Any) -> bytes:
    """Encode an object as one Extended-JSON line ('\\n'-terminated) via ``bson.json_util``,
    so ObjectId/datetime re-hydrate to BSON types on restore."""
    return (json_util.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


class BundleFrames:
    """Streaming NDJSON frame writer yielding line-bytes to pipe into gzip/encryption/S3."""

    @staticmethod
    async def write(
        *,
        scan_doc: Dict[str, Any],
        collections: Dict[str, AsyncIterator[Dict[str, Any]]],
        stats: BundleStats,
    ) -> AsyncIterator[bytes]:
        sha = hashlib.sha256()

        def emit(line: bytes) -> bytes:
            sha.update(line)
            return line

        header = {
            "version": ARCHIVE_BUNDLE_VERSION,
            "archived_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            # scan_id/project_id are plain-string identifiers; the full "scan" doc keeps
            # its BSON types so restore inserts real datetimes/ObjectIds.
            "scan_id": _serialize(scan_doc.get("_id")),
            "project_id": _serialize(scan_doc.get("project_id")),
            "scan": scan_doc,
        }
        yield emit(_json_line(header))

        for coll_name, doc_iter in collections.items():
            yield emit(_json_line({"collection": coll_name}))
            async for doc in doc_iter:
                yield emit(_json_line(doc))
                # severity is canonicalized uppercase by the scan pipeline; other cases miss the tallies.
                if coll_name == "findings":
                    severity = doc.get("severity", "")
                    if severity == "CRITICAL":
                        stats.critical_findings += 1
                    elif severity == "HIGH":
                        stats.high_findings += 1
                # gridfs_sboms has no counter (filenames live on ArchiveMetadata).
                if hasattr(stats, coll_name):
                    setattr(stats, coll_name, getattr(stats, coll_name) + 1)

        footer = {
            "footer": True,
            "stats": {
                "findings": stats.findings,
                "finding_records": stats.finding_records,
                "dependencies": stats.dependencies,
                "analysis_results": stats.analysis_results,
                "callgraphs": stats.callgraphs,
                "crypto_assets": stats.crypto_assets,
                "critical_findings": stats.critical_findings,
                "high_findings": stats.high_findings,
            },
            "sha256": sha.hexdigest(),
        }
        # Footer carries the digest, so it is not itself part of the digest.
        yield _json_line(footer)


async def read_bundle_frames(source: AsyncIterator[bytes]) -> AsyncIterator[Dict[str, Any]]:
    """Read an NDJSON bundle and yield header/doc/footer events.

    Raises ValueError on unknown version, doc-before-collection-marker, missing header,
    or footer SHA-256 mismatch.
    """
    buffer = bytearray()
    pre_footer_sha = hashlib.sha256()
    current_collection: str | None = None
    header_seen = False

    async def _iter_lines() -> AsyncIterator[bytes]:
        nonlocal buffer
        async for chunk in source:
            buffer.extend(chunk)
            while True:
                idx = buffer.find(b"\n")
                if idx < 0:
                    break
                line = bytes(buffer[: idx + 1])
                del buffer[: idx + 1]
                yield line
        if buffer:
            # Trailing data without a newline: yield as one final line.
            yield bytes(buffer)
            buffer.clear()

    async for line in _iter_lines():
        try:
            # json_util re-hydrates Extended JSON ($date/$oid) back to BSON types.
            obj = json_util.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Malformed bundle line: {e}") from e

        if not header_seen:
            version = obj.get("version")
            if version != ARCHIVE_BUNDLE_VERSION:
                raise ValueError(f"Unsupported bundle version: {version}")
            header_seen = True
            pre_footer_sha.update(line)
            yield {"type": "header", "data": obj}
            continue

        if obj.get("footer") is True:
            expected = obj.get("sha256")
            actual = pre_footer_sha.hexdigest()
            if expected != actual:
                raise ValueError(f"Bundle integrity (checksum) mismatch: expected {expected}, got {actual}")
            yield {"type": "footer", "data": obj}
            return

        pre_footer_sha.update(line)

        if "collection" in obj and len(obj) == 1:
            current_collection = obj["collection"]
            continue

        if current_collection is None:
            raise ValueError("Doc line before any collection marker")

        yield {"type": "doc", "collection": current_collection, "data": obj}

    if not header_seen:
        raise ValueError("Empty bundle (no header)")
    # Reaching here means the source was exhausted before the footer line.
    raise ValueError("Bundle truncated — no footer line found")

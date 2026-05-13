"""NDJSON-frame archive bundle format (v2).

Bundle layout — each line is a complete JSON document terminated by '\\n':
    LINE 1            : header     {"version": 2, "archived_at": ..., "scan_id": ..., "project_id": ..., "scan": {...}}
    LINE M (marker)   : {"collection": "findings"}        (a one-field line opens a collection section)
    LINE M+1..M+N     : per-doc lines for that collection
    ...
    LAST LINE         : footer     {"footer": true, "stats": {...}, "sha256": "<hex>"}

The SHA-256 in the footer covers every byte of the file BEFORE the footer line
(header + all collection markers + all doc lines). The footer line itself is
NOT included in the digest.
"""

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict

from bson import ObjectId

from app.core.constants import ARCHIVE_BUNDLE_VERSION


@dataclass
class BundleStats:
    """Mutable per-archive counters; populated as docs stream through the writer."""

    findings: int = 0
    finding_records: int = 0
    dependencies: int = 0
    analysis_results: int = 0
    callgraphs: int = 0
    critical_findings: int = 0
    high_findings: int = 0


def _serialize(obj: Any) -> Any:
    """Recursively normalize a Mongo document tree to JSON-safe types.

    Converts ObjectId → str, datetime → ISO string. Recurses into dicts and
    lists (including nested lists), so any deeply buried ObjectId/datetime is
    normalized consistently.
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
    """JSON-encode an object as a single line ending with '\\n'."""
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


class BundleFrames:
    """Streaming NDJSON frame writer.

    ``BundleFrames.write(...)`` returns an async generator that yields encoded
    line-bytes. The caller pipes these into gzip / encryption / S3 multipart
    without buffering the whole bundle.
    """

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
            "scan_id": _serialize(scan_doc.get("_id")),
            "project_id": _serialize(scan_doc.get("project_id")),
            "scan": _serialize(scan_doc),
        }
        yield emit(_json_line(header))

        for coll_name, doc_iter in collections.items():
            yield emit(_json_line({"collection": coll_name}))
            async for doc in doc_iter:
                yield emit(_json_line(_serialize(doc)))
                # findings.severity is canonicalized uppercase by the scan pipeline;
                # lower/mixed-case docs will silently miss the critical/high tallies.
                if coll_name == "findings":
                    severity = doc.get("severity", "")
                    if severity == "CRITICAL":
                        stats.critical_findings += 1
                    elif severity == "HIGH":
                        stats.high_findings += 1
                # gridfs_sboms intentionally has no BundleStats counter:
                # the list of SBOM filenames lives on ArchiveMetadata, not here.
                # Per-collection doc counter (matches BundleStats fields)
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
                "critical_findings": stats.critical_findings,
                "high_findings": stats.high_findings,
            },
            "sha256": sha.hexdigest(),
        }
        # Footer is NOT included in the digest (it carries the digest).
        yield _json_line(footer)


async def read_bundle_frames(source: AsyncIterator[bytes]) -> AsyncIterator[Dict[str, Any]]:
    """Read an NDJSON bundle and yield events.

    Yields:
        {"type": "header", "data": {...}}
        {"type": "doc", "collection": "<name>", "data": {...}}
        {"type": "footer", "data": {...}}

    Raises ValueError on: unknown version, doc-before-collection-marker, missing
    header, or SHA-256 mismatch in the footer.
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
            # Trailing data without newline: yield as one final line (defensive).
            yield bytes(buffer)
            buffer.clear()

    async for line in _iter_lines():
        try:
            obj = json.loads(line)
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

        # All non-footer lines after header are part of the digest.
        pre_footer_sha.update(line)

        # Collection marker: a single-key line {"collection": "<name>"}.
        if "collection" in obj and len(obj) == 1:
            current_collection = obj["collection"]
            continue

        if current_collection is None:
            raise ValueError("Doc line before any collection marker")

        yield {"type": "doc", "collection": current_collection, "data": obj}

    if not header_seen:
        raise ValueError("Empty bundle (no header)")
    # If we reach here, the stream ended without yielding the footer event.
    # The `if obj.get("footer") is True:` branch returns early on footer, so
    # falling through means the source iterator was exhausted mid-bundle.
    raise ValueError("Bundle truncated — no footer line found")

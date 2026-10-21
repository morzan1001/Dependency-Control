"""NDJSON bundle v2: a header, {"collection": ...}-opened sections, and a footer hashing every prior byte."""

import datetime as dt
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import asdict, dataclass
from typing import Any, NamedTuple

from bson import json_util
from bson.errors import BSONError

from app.core.constants import ARCHIVE_BUNDLE_VERSION
from app.models.finding import FindingType


class BundleVersionError(ValueError):
    """A bundle or encryption format this release cannot read."""


@dataclass
class BundleStats:
    findings: int = 0
    finding_records: int = 0
    dependencies: int = 0
    analysis_results: int = 0
    callgraphs: int = 0
    crypto_assets: int = 0
    critical_findings: int = 0
    high_findings: int = 0


def json_line(obj: Any) -> bytes:
    """Extended JSON via bson.json_util so ObjectId and datetime re-hydrate to BSON types on restore."""
    return (json_util.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


class BundleFrames:
    @staticmethod
    async def write(
        *,
        scan_doc: dict[str, Any],
        collections: dict[str, AsyncIterator[dict[str, Any]]],
        stats: BundleStats,
        archived_at: dt.datetime,
    ) -> AsyncIterator[bytes]:
        sha = hashlib.sha256()

        def emit(line: bytes) -> bytes:
            sha.update(line)
            return line

        header = {
            "version": ARCHIVE_BUNDLE_VERSION,
            "archived_at": archived_at.isoformat(),
            "scan_id": scan_doc.get("_id"),
            "project_id": scan_doc.get("project_id"),
            "scan": scan_doc,
        }
        yield emit(json_line(header))

        for coll_name, doc_iter in collections.items():
            yield emit(json_line({"collection": coll_name}))
            async for doc in doc_iter:
                yield emit(json_line(doc))
                if coll_name == "findings":
                    # Counted as StatsAccumulator.add counts, so the archive list shows the scan's open findings.
                    if doc.get("waived") is True or doc.get("type") == FindingType.SYSTEM_WARNING:
                        continue
                    # severity is canonicalized uppercase by the scan pipeline; other cases miss the tallies.
                    severity = doc.get("severity", "")
                    if severity == "CRITICAL":
                        stats.critical_findings += 1
                    elif severity == "HIGH":
                        stats.high_findings += 1
                if hasattr(stats, coll_name):
                    setattr(stats, coll_name, getattr(stats, coll_name) + 1)

        footer = {"footer": True, "stats": asdict(stats), "sha256": sha.hexdigest()}
        # Footer carries the digest, so it is not itself part of the digest.
        yield json_line(footer)


_MARKER_PREFIX = b'{"collection":'
_FOOTER_PREFIX = b'{"footer":'


class _Frame(NamedTuple):
    kind: str
    line: bytes
    collection: str
    data: Any


def load_json_line(line: bytes) -> dict[str, Any]:
    try:
        obj = json_util.loads(line)
    except (json.JSONDecodeError, BSONError) as e:
        raise ValueError(f"Malformed bundle line: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"Malformed bundle line: a {type(obj).__name__}, not an object")
    return obj


async def _bundle_lines(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    buffer = bytearray()
    async for chunk in source:
        scanned = len(buffer)
        buffer.extend(chunk)
        # The buffered bytes hold no newline, so searching only the new chunk scans a long line once.
        idx = buffer.find(b"\n", scanned)
        while idx >= 0:
            # Dropped before the yield, so the buffer holds no second copy while the consumer works on it.
            line = bytes(memoryview(buffer)[: idx + 1])
            del buffer[: idx + 1]
            yield line
            idx = buffer.find(b"\n")
    if buffer:
        yield bytes(buffer)


def _parse_header(line: bytes) -> dict[str, Any]:
    header = load_json_line(line)
    version = header.get("version")
    if version != ARCHIVE_BUNDLE_VERSION:
        raise BundleVersionError(f"Unsupported bundle version: {version}")
    return header


def _verify_footer(footer: Any, actual: str) -> None:
    expected = footer.get("sha256")
    if expected != actual:
        raise ValueError(f"Bundle integrity (checksum) mismatch: expected {expected}, got {actual}")


async def _read_frames(source: AsyncIterator[bytes], *, decode_docs: bool) -> AsyncIterator[_Frame]:
    """Undecoded doc lines are told apart because the writer starts every doc with its _id."""
    lines = _bundle_lines(source)
    first = await anext(lines, None)
    if first is None:
        raise ValueError("Empty bundle (no header)")
    pre_footer_sha = hashlib.sha256(first)
    yield _Frame("header", first, "", _parse_header(first))

    current_collection: str | None = None
    async for line in lines:
        decoded = decode_docs or line.startswith((_MARKER_PREFIX, _FOOTER_PREFIX))
        obj: Any = load_json_line(line) if decoded else None
        if decoded and obj.get("footer") is True:
            _verify_footer(obj, pre_footer_sha.hexdigest())
            yield _Frame("footer", line, "", obj)
            return
        pre_footer_sha.update(line)
        if decoded and "collection" in obj and len(obj) == 1:
            current_collection = obj["collection"]
            yield _Frame("marker", line, current_collection, obj)
        elif current_collection is None:
            raise ValueError("Doc line before any collection marker")
        else:
            yield _Frame("doc", line, current_collection, obj)

    raise ValueError("Bundle truncated — no footer line found")


async def read_bundle_frames(source: AsyncIterator[bytes]) -> AsyncIterator[dict[str, Any]]:
    async for frame in _read_frames(source, decode_docs=True):
        if frame.kind == "doc":
            yield {"type": "doc", "collection": frame.collection, "data": frame.data}
        elif frame.kind != "marker":
            yield {"type": frame.kind, "data": frame.data}


async def rewrite_bundle_frames(
    source: AsyncIterator[bytes],
    rewrite_doc_line: Callable[[str, bytes], bytes],
) -> AsyncIterator[bytes]:
    """Doc lines reach the callback undecoded, so an SBOM line costs its bytes, not a decoded copy."""
    sha = hashlib.sha256()
    async for frame in _read_frames(source, decode_docs=False):
        if frame.kind == "footer":
            yield json_line({**frame.data, "sha256": sha.hexdigest()})
        else:
            line = rewrite_doc_line(frame.collection, frame.line) if frame.kind == "doc" else frame.line
            sha.update(line)
            yield line
